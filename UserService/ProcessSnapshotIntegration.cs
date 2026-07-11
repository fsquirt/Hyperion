using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 进程快照集成: 把 ProcessTreeSnapshot 的能力接入 UserService。
///
/// 工作模式:
///   1. 启动时先做一次 Security 模式全量快照 (含句柄/内存/Token/Protection/Modules)
///      → 建立 baseline, 后续对比用
///   2. 后台定时器每 10 秒做一次 Tree 模式快照 (轻量, 只拿基础信息)
///      → 检测新增进程
///   3. 所有快照结果通过 ITrackerSink 投递 (Type="snapshot")
///      → 未来 ServerTrackerSink 上报 Server
/// </summary>
internal sealed class ProcessSnapshotIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ITrackerSink _sink;
    private System.Threading.Timer? _pollTimer;
    private volatile bool _disposed;

    // 轮询间隔: 10 秒
    private const int PollIntervalMs = 10_000;

    public ProcessSnapshotIntegration(NativeHost host, ITrackerSink sink)
    {
        _host = host;
        _sink = sink;
    }

    /// <summary>
    /// 执行初始 Security 全量快照 (阻塞, 可能几秒~几十秒)。
    /// 在游戏启动前调用, 建立 baseline。
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

        // 分析快照: 统计受保护进程、异常进程
        var entries = result.Entries;
        foreach (var proc in entries)
        {
            if (!string.IsNullOrEmpty(proc.Protection) &&
                !proc.Protection.Equals("None", StringComparison.OrdinalIgnoreCase))
            {
                protectedCount++;
            }

            // PplBroken = 1 表示 PPL 被破坏 (高危)
            if (proc.PplBroken != 0)
            {
                abnormal++;
                _sink.Post(new TrackedEvent
                {
                    Type = "snapshot",
                    Timestamp = DateTime.UtcNow,
                    Level = "HIGH",
                    Source = "ProcessSnapshot",
                    Title = $"PPL 被破坏: PID={proc.Brief.Pid} ({proc.Brief.Name})",
                    Detail = $"Protection={proc.Protection}\n" +
                             $"ImagePath={proc.ImagePath}\n" +
                             $"CommandLine={proc.CommandLine}",
                });
            }
        }

        Console.Error.WriteLine(
            $"[Snapshot] Security 快照完成: {count} 个进程, {protectedCount} 个受保护, {abnormal} 个异常");

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

    /// <summary>
    /// 启动后台 Tree 轮询 (每 10 秒一次)。
    /// 幂等: 重复调用不会启动多个定时器。
    /// </summary>
    public void StartTreePolling()
    {
        if (_pollTimer != null) return;

        Console.Error.WriteLine("[Snapshot] 启动 Tree 轮询 (10 秒间隔)...");
        _pollTimer = new System.Threading.Timer(PollCallback, null, PollIntervalMs, PollIntervalMs);
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

            // Tree 轮询默认 INFO 级别, 不投递 (避免噪声)
            // 只在有变化时投递 (后续可对比 baseline 检测新增进程)
            // 当前先打日志
            Console.Error.WriteLine($"[Snapshot] Tree 轮询: {result.Count} 个进程");
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
