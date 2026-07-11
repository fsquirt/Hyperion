using System.Text.Json;
using SuperUserService;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 进程树快照集成:
///   1. CaptureInitialSecuritySnapshot: Security 全量快照(含句柄/内存/Token/Protection)
///   2. StartTreePolling: Tree 模式 10 秒轮询(轻量,仅基本信息)
///
/// 数据上报:
///   - 每次快照(无论 security 还是 tree)整体作为一个 JSON 投递到 ServerDataClient
///   - 服务端负责 diff 对比
/// </summary>
internal sealed class ProcessSnapshotIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;
    private System.Threading.Timer? _pollTimer;
    private volatile bool _disposed;

    // 默认轮询间隔: 10 秒(可由服务端配置覆盖)
    private int _pollIntervalMs = 10_000;

    public ProcessSnapshotIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 拍一次 Security 全量快照(含句柄/内存/Token/Protection)。
    /// 全量投递到服务端(一次快照一条独立 API 调用)。
    /// </summary>
    public void CaptureInitialSecuritySnapshot()
    {
        Console.Error.WriteLine("[Snapshot] 拍 Security 全量快照...");
        try
        {
            // Security 全量快照: pid=0(整树), flags=0(全部: handles/mem/threads/modules/token)
            var secParams = new SecurityParameters(0, 0);
            using var secResult = _host.Service.FetchSecurity(secParams);
            if (!secResult.Success)
            {
                Console.Error.WriteLine($"[Snapshot] Security 快照失败: {secResult.ErrorMessage}");
                return;
            }
            var entries = secResult.Entries;
            if (entries.Length == 0)
            {
                Console.Error.WriteLine("[Snapshot] 无进程");
                return;
            }

            // 序列化为 JSON 投递
            var procs = entries.Select(p => new
            {
                pid = p.Brief.Pid,
                ppid = p.Brief.Ppid,
                name = p.Brief.Name,
                image = p.ImagePath,
                cmd = p.CommandLine,
                protection = p.Protection,
                pplBroken = p.PplBroken,
                enabledPrivs = p.EnabledPrivs.Take(p.EnabledPrivCount).Select(x => x.Name).ToArray(),
                threads = p.ThreadInfoCount,
                modules = p.ModuleCount,
                handles = p.HandleCount,
            }).ToArray();

            string json = JsonSerializer.Serialize(procs);
            string level = entries.Any(p => p.PplBroken != 0) ? "WARN"
                         : entries.Any(p => p.Protection.Length > 0) ? "INFO"
                         : "INFO";

            Console.Error.WriteLine($"[Snapshot] Security 快照完成: {procs.Length} 进程");

            // 异步发送,不阻塞主流程
            Console.Error.WriteLine($"[Snapshot] [STEP] 准备发送 security 快照到服务端 (sessionId={_server?.SessionId})...");
            _ = _server?.PostSnapshotAsync("security", procs.Length, json).ContinueWith(t =>
            {
                if (t.IsFaulted)
                    Console.Error.WriteLine($"[Snapshot] [STEP] security 发送异常: {t.Exception?.GetBaseException().Message}");
                else
                    Console.Error.WriteLine("[Snapshot] [STEP] security 快照已投递");
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Snapshot] Security 快照异常: {ex.Message}");
        }
    }

    /// <summary>
    /// 启动后台 Tree 轮询。
    /// pollIntervalSec: 轮询间隔(秒),由服务端 /api/tracker/config 配置,默认 10。
    /// 幂等: 重复调用不会启动多个定时器。
    /// 每次轮询的完整进程列表作为一个 JSON 投递到服务端。
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

    /// <summary>Tree 轮询回调:拍一次 Tree 模式快照,整体 JSON 投递。</summary>
    private void PollCallback(object? state)
    {
        if (_disposed) return;

        try
        {
            // Tree 模式: pid=0(整树), maxDepth=0(不限制), jsonOutput=false
            var treeParams = new TreeParameters(0, 0, false);
            using var treeResult = _host.Service.FetchTree(treeParams);
            if (!treeResult.Success) return;

            var entries = treeResult.Entries;
            if (entries.Length == 0) return;

            // Tree 模式只取基本信息
            var procs = entries.Select(p => new
            {
                pid = p.Pid,
                ppid = p.Ppid,
                name = p.Name,
                threads = p.Threads,
                session = p.Session,
                createTime = p.CreateTime,
            }).ToArray();

            string json = JsonSerializer.Serialize(procs);

            // 异步发送,不阻塞轮询线程
            _ = _server?.PostSnapshotAsync("tree", procs.Length, json);
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
        Console.Error.WriteLine("[Snapshot] Tree 轮询已停止");
    }
}
