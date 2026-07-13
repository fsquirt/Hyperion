using System.Text.Json;
using SuperUserService;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 进程树快照集成(事件驱动):
///   1. CaptureInitialSecuritySnapshot: Security 全量快照(含句柄/内存/Token/Protection)
///   2. CaptureFullTreeSnapshot: Tree 全量快照(由 CodeIntegrity 事件回调触发,5 分钟去重)
///
/// 数据上报:
///   - 每次快照(无论 security 还是 tree)整体作为一个 JSON 投递到 ServerDataClient
///   - 服务端负责 diff 对比
/// </summary>
internal sealed class ProcessSnapshotIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;
    private volatile bool _disposed;

    // Tree 全量快照去重时间戳(事件触发,5 分钟内不重复拍)
    private DateTime _lastFullTreeSnapshot = DateTime.MinValue;

    public ProcessSnapshotIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 拍一次 Security 全量快照(含句柄/内存/Token/Protection)。
    /// 全量投递到服务端(一次快照一条独立 API 调用)。
    /// 序列化 CbnProcDetail 的所有维度: Brief/ImagePath/CommandLine/Protection/PPL/
    /// EnabledPrivs/DisabledPrivs/ThreadInfos(含Win32StartAddress)/Modules/MemRegions(含Reason)/Handles(含HighRisk)。
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

            // 序列化完整 CbnProcDetail → JSON (包含所有维度)
            var procs = entries.Select(p => new
            {
                // Brief 基本信息 (全部字段)
                pid = p.Brief.Pid,
                ppid = p.Brief.Ppid,
                name = p.Brief.Name,
                threads = p.Brief.Threads,
                createTime = p.Brief.CreateTime,
                session = p.Brief.Session,
                workingSet = p.Brief.WorkingSet,
                privatePages = p.Brief.PrivatePages,
                handles = p.Brief.Handles,
                basePriority = p.Brief.BasePriority,
                // Security 详情
                image = p.ImagePath,
                cmd = p.CommandLine,
                protection = p.Protection,
                pplBroken = p.PplBroken,
                // 特权列表 (完整: enabled + disabled)
                enabledPrivs = p.EnabledPrivs.Take(p.EnabledPrivCount).Select(x => x.Name).ToArray(),
                disabledPrivs = p.DisabledPrivs.Take(p.DisabledPrivCount).Select(x => x.Name).ToArray(),
                // 线程详情 (含 Win32StartAddress — 检测 manual-map shellcode 的关键字段)
                threadInfos = p.ThreadInfos.Take(p.ThreadInfoCount).Select(t => new
                {
                    tid = t.Tid,
                    startAddress = t.StartAddress,
                    win32StartAddress = t.Win32StartAddress,
                    suspendCount = t.SuspendCount,
                    startModule = t.StartModule,
                    isSuspended = t.IsSuspended,
                }).ToArray(),
                // 模块列表 (完整: Base/Size/Name/Path)
                modules = p.Modules.Take(p.ModuleCount).Select(m => new
                {
                    baseAddr = m.Base,
                    size = m.Size,
                    name = m.Name,
                    path = m.Path,
                }).ToArray(),
                // 可疑内存区域 (含 Reason: RWX / RX-unbacked — 最关键的安全维度)
                memRegions = p.MemRegions.Take(p.MemRegionCount).Select(mr => new
                {
                    baseAddr = mr.Base,
                    size = mr.Size,
                    protect = mr.Protect,
                    type = mr.Type,
                    protectStr = mr.ProtectStr,
                    typeStr = mr.TypeStr,
                    reason = mr.Reason,
                }).ToArray(),
                // 句柄列表 (含 HighRisk 标志 — 跨进程高危句柄)
                extHandles = p.Handles.Take(p.HandleCount).Select(h => new
                {
                    ownerPid = h.OwnerPid,
                    ownerName = h.OwnerName,
                    handleValue = h.HandleValue,
                    grantedAccess = h.GrantedAccess,
                    accessStr = h.AccessStr,
                    targetPid = h.TargetPid,
                    typeName = h.TypeName,
                    highRisk = h.HighRisk,
                }).ToArray(),
            }).ToArray();

            string json = JsonSerializer.Serialize(procs);

            // 计算汇总统计
            int pplBrokenCount = entries.Count(p => p.PplBroken != 0);
            int suspiciousMemCount = entries.Sum(p => p.MemRegionCount);
            int highRiskHandleCount = entries.Sum(p => p.Handles.Take(p.HandleCount).Count(h => h.HighRisk != 0));

            Console.Error.WriteLine($"[Snapshot] Security 快照完成: {procs.Length} 进程, PPL异常={pplBrokenCount}, 可疑内存={suspiciousMemCount}, 高危句柄={highRiskHandleCount}");

            // 异步发送,不阻塞主流程
            Console.Error.WriteLine($"[Snapshot] [STEP] 准备发送 security 快照到服务端 (sessionId={_server?.SessionId})...");
            _ = _server?.PostSnapshotAsync(new ServerDataClient.SnapshotPayload
            {
                Kind = "security",
                ProcessCount = procs.Length,
                ProcessesJson = json,
                PplBrokenCount = pplBrokenCount,
                SuspiciousMemCount = suspiciousMemCount,
                HighRiskHandleCount = highRiskHandleCount,
            }).ContinueWith(t =>
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
    /// 拍一次 Tree 全量快照(事件触发,非轮询)。
    /// 由 CodeIntegrity 事件回调触发,5 分钟内去重。
    /// 投递 kind="tree-triggered" 到服务端 snapshots API。
    /// </summary>
    public void CaptureFullTreeSnapshot()
    {
        if (_disposed) return;

        // 5 分钟去重
        var now = DateTime.UtcNow;
        if (now - _lastFullTreeSnapshot < TimeSpan.FromMinutes(5))
        {
            Console.Error.WriteLine($"[Snapshot] Tree 快照跳过 (5分钟内已触发, 上次={_lastFullTreeSnapshot:HH:mm:ss})");
            return;
        }
        _lastFullTreeSnapshot = now;

        Console.Error.WriteLine("[Snapshot] 事件触发 Tree 全量快照...");
        BuildTreeJsonAndPost("tree-triggered");
    }

    /// <summary>
    /// 执行 Tree 模式快照并投递到服务端。
    /// kind 参数区分触发来源: "tree-triggered" (CodeIntegrity事件触发)。
    /// </summary>
    private void BuildTreeJsonAndPost(string kind)
    {
        try
        {
            // Tree 模式: pid=0(整树), maxDepth=0(不限制), jsonOutput=false
            var treeParams = new TreeParameters(0, 0, false);
            using var treeResult = _host.Service.FetchTree(treeParams);
            if (!treeResult.Success) return;

            var entries = treeResult.Entries;
            if (entries.Length == 0) return;

            // Tree 模式: CbnProcBrief 全字段序列化
            var procs = entries.Select(p => new
            {
                pid = p.Pid,
                ppid = p.Ppid,
                name = p.Name,
                threads = p.Threads,
                createTime = p.CreateTime,
                session = p.Session,
                workingSet = p.WorkingSet,
                privatePages = p.PrivatePages,
                handles = p.Handles,
                basePriority = p.BasePriority,
                threadList = p.ThreadList.Take(p.ThreadCount).Select(t => new
                {
                    tid = t.Tid,
                    startAddress = t.StartAddress,
                }).ToArray(),
            }).ToArray();

            string json = JsonSerializer.Serialize(procs);

            int totalThreads = entries.Sum(p => (int)p.Threads);
            int maxThreads = entries.Length > 0 ? entries.Max(p => (int)p.Threads) : 0;
            ulong topPidByThreads = entries.Length > 0
                ? entries.OrderByDescending(p => p.Threads).First().Pid
                : 0;
            ulong totalWorkingSet = entries.Aggregate(0UL, (acc, p) => acc + p.WorkingSet);
            ulong totalPrivatePages = entries.Aggregate(0UL, (acc, p) => acc + p.PrivatePages);
            int totalHandles = entries.Sum(p => (int)p.Handles);

            Console.Error.WriteLine($"[Snapshot] Tree 快照完成: {procs.Length} 进程 (kind={kind})");

            _ = _server?.PostSnapshotAsync(new ServerDataClient.SnapshotPayload
            {
                Kind = kind,
                ProcessCount = procs.Length,
                ProcessesJson = json,
                TotalThreads = totalThreads,
                MaxThreadsInSingleProc = maxThreads,
                TopPidByThreads = topPidByThreads,
                TotalWorkingSet = totalWorkingSet,
                TotalPrivatePages = totalPrivatePages,
                TotalHandles = totalHandles,
            }).ContinueWith(t =>
            {
                if (t.IsFaulted)
                    Console.Error.WriteLine($"[Snapshot] tree 发送异常: {t.Exception?.GetBaseException().Message}");
                else
                    Console.Error.WriteLine($"[Snapshot] Tree 快照已投递 (kind={kind})");
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Snapshot] Tree 快照异常: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
    }
}
