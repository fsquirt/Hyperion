using System.Text;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 进程快照集成: 把 ProcessTreeSnapshot 的能力接入 UserService。
///
/// 工作模式:
///   1. 启动时先做一次 Security 模式全量快照 (含句柄/内存/Token/Protection/Modules)
///      → 建立 baseline, 全部进程详情投递到 sink
///   2. 后台定时器每 10 秒做一次 Tree 模式快照 (轻量, 只拿基础信息)
///      → 全部进程列表投递到 sink, 服务端可对比检测新增进程
///   3. 所有快照结果通过 ITrackerSink 投递 (Type="snapshot")
/// </summary>
internal sealed class ProcessSnapshotIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ITrackerSink _sink;
    private System.Threading.Timer? _pollTimer;
    private volatile bool _disposed;

    // 默认轮询间隔: 10 秒(可由服务端配置覆盖)
    private int _pollIntervalMs = 10_000;

    public ProcessSnapshotIntegration(NativeHost host, ITrackerSink sink)
    {
        _host = host;
        _sink = sink;
    }

    /// <summary>
    /// 执行初始 Security 全量快照 (阻塞, 可能几秒~几十秒)。
    /// 在游戏启动前调用, 建立 baseline。全部进程详情投递到 sink。
    /// </summary>
    public void CaptureInitialSecuritySnapshot()
    {
        Console.Error.WriteLine("[Snapshot] 开始 Security 全量快照 (pid=0)...");

        // flags = 0 表示采集全部维度 (句柄/内存/线程/模块/Token)
        var parameters = new SecurityParameters(0, 0);
        using var result = _host.Service.FetchSecurity(parameters);

        if (!result.Success)
        {
            _sink.Post(new TrackedEvent
            {
                Type = "snapshot",
                Timestamp = DateTime.UtcNow,
                Level = "ERR",
                Source = "ProcessSnapshot",
                Title = "Security 全量快照失败",
                Detail = $"ErrorCode={result.Header.ErrorCode}, Message={result.ErrorMessage}",
            });
            Console.Error.WriteLine($"[Snapshot] Security 快照失败: {result.ErrorMessage}");
            return;
        }

        int count = result.Count;
        int abnormal = 0;
        int protectedCount = 0;

        // 全量投递: 每个进程一条事件
        var entries = result.Entries;
        foreach (var proc in entries)
        {
            bool isProtected = !string.IsNullOrEmpty(proc.Protection) &&
                               !proc.Protection.Equals("None", StringComparison.OrdinalIgnoreCase);
            if (isProtected) protectedCount++;

            // PplBroken = 1 表示 PPL 被破坏 (高危)
            bool pplBroken = proc.PplBroken != 0;
            if (pplBroken) abnormal++;

            _sink.Post(new TrackedEvent
            {
                Type = "snapshot",
                Timestamp = DateTime.UtcNow,
                Level = pplBroken ? "HIGH" : (isProtected ? "WARN" : "INFO"),
                Source = "ProcessSnapshot",
                Title = $"进程: PID={proc.Brief.Pid} ({proc.Brief.Name})",
                Detail = BuildProcDetail(proc),
            });
        }

        Console.Error.WriteLine(
            $"[Snapshot] Security 快照完成: {count} 个进程, {protectedCount} 个受保护, {abnormal} 个异常");

        // 投递汇总
        _sink.Post(new TrackedEvent
        {
            Type = "snapshot",
            Timestamp = DateTime.UtcNow,
            Level = "INFO",
            Source = "ProcessSnapshot",
            Title = "Security 全量快照完成 (baseline)",
            Detail = $"进程总数: {count}\n" +
                     $"受保护进程: {protectedCount}\n" +
                     $"异常进程 (PPL broken): {abnormal}",
        });
    }

    /// <summary>构建进程详情字符串。</summary>
    private static string BuildProcDetail(CbnProcDetail proc)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"PID: {proc.Brief.Pid}");
        sb.AppendLine($"Name: {proc.Brief.Name}");
        sb.AppendLine($"PPID: {proc.Brief.Ppid}");
        sb.AppendLine($"Protection: {proc.Protection}");
        sb.AppendLine($"PPL broken: {proc.PplBroken}");
        sb.AppendLine($"ImagePath: {proc.ImagePath}");
        sb.AppendLine($"CommandLine: {proc.CommandLine}");

        if (proc.ThreadInfoCount > 0)
            sb.AppendLine($"Threads: {proc.ThreadInfoCount}");

        if (proc.ModuleCount > 0)
            sb.AppendLine($"Modules: {proc.ModuleCount}");

        if (proc.HandleCount > 0)
            sb.AppendLine($"Handles: {proc.HandleCount}");

        // 特权信息 (Enabled + Disabled)
        if (proc.EnabledPrivCount > 0 || proc.DisabledPrivCount > 0)
        {
            sb.AppendLine($"Privileges (enabled={proc.EnabledPrivCount}, disabled={proc.DisabledPrivCount}):");
            var privs = proc.EnabledPrivs.Take(proc.EnabledPrivCount);
            foreach (var p in privs)
            {
                if (!string.IsNullOrEmpty(p.Name))
                    sb.AppendLine($"  + {p.Name}");
            }
            var disabled = proc.DisabledPrivs.Take(proc.DisabledPrivCount);
            foreach (var p in disabled)
            {
                if (!string.IsNullOrEmpty(p.Name))
                    sb.AppendLine($"  - {p.Name}");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// 启动后台 Tree 轮询。
    /// pollIntervalSec: 轮询间隔(秒),由服务端 /api/tracker/config 配置,默认 10。
    /// 幂等: 重复调用不会启动多个定时器。
    /// 每次轮询的全部进程列表都投递到 sink。
    /// </summary>
    public void StartTreePolling(int pollIntervalSec = 10)
    {
        if (_pollTimer != null) return;

        if (pollIntervalSec < 1) pollIntervalSec = 1;
        if (pollIntervalSec > 3600) pollIntervalSec = 3600;
        _pollIntervalMs = pollIntervalSec * 1000;

        Console.Error.WriteLine($"[Snapshot] 启动 Tree 轮询 ({pollIntervalSec} 秒间隔)...");
        _pollTimer = new System.Threading.Timer(PollCallback, null, _pollIntervalMs, _pollIntervalMs);
    }

    /// <summary>Tree 轮询回调 (在 ThreadPool 线程上执行)。</summary>
    private void PollCallback(object? state)
    {
        if (_disposed) return;

        try
        {
            // Tree 模式: pid=0 全系统, maxDepth=0 不限制, jsonOutput=true 扁平输出
            var parameters = new TreeParameters(0, 0, true);
            using var result = _host.Service.FetchTree(parameters);

            if (!result.Success)
            {
                Console.Error.WriteLine($"[Snapshot] Tree 轮询失败: {result.ErrorMessage}");
                return;
            }

            // 全量投递: 每个进程一条事件
            var entries = result.Entries;
            foreach (var proc in entries)
            {
                _sink.Post(new TrackedEvent
                {
                    Type = "tree",
                    Timestamp = DateTime.UtcNow,
                    Level = "INFO",
                    Source = "ProcessTree",
                    Title = $"进程: PID={proc.Pid} ({proc.Name})",
                    Detail = $"PID: {proc.Pid}\n" +
                             $"PPID: {proc.Ppid}\n" +
                             $"Name: {proc.Name}\n" +
                             $"Threads: {proc.ThreadCount}\n" +
                             $"CreateTime: {proc.CreateTime}",
                });
            }

            Console.Error.WriteLine($"[Snapshot] Tree 轮询: {result.Count} 个进程 (已投递)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Snapshot] Tree 轮询异常: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _pollTimer?.Dispose();
        _pollTimer = null;
        Console.Error.WriteLine("[Snapshot] 已停止 Tree 轮询");
    }
}
