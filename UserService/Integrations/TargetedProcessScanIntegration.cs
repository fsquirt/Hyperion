using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using UserService.Native;

namespace Hyperion.UserService;

/// <summary>
/// 定向进程深扫集成: 当检测到未签名模块与被附着驱动交互时,
/// 对发起进程 (requestorPid) 采集四类数据并一次性投递到服务端:
///   1. 句柄 (FetchScanHandles)
///   2. 子进程 (FetchTree 限制到该 PID 子树)
///   3. 线程 (FetchSecurity 取线程详情,含 Win32StartAddress)
///   4. 网络连接 (NetworkConnectionCollector)
///
/// 去重: 同一 PID + 同一未签名模块路径在 60 秒内只触发一次。
/// </summary>
internal sealed class TargetedProcessScanIntegration
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;

    // 去重: (pid, modulePath) -> 上次触发时间
    private readonly ConcurrentDictionary<(uint pid, string module), DateTime> _lastScanTime = new();
    private const int DedupWindowSec = 60;

    public TargetedProcessScanIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 对指定 PID 执行定向深扫。
    /// </summary>
    /// <param name="pid">目标进程 PID</param>
    /// <param name="triggerModule">触发的未签名模块路径</param>
    /// <param name="attachId">所属 AttachId</param>
    /// <param name="ioctlCode">触发的 IOCTL 码</param>
    public void Scan(uint pid, string triggerModule, ulong attachId, uint ioctlCode)
    {
        if (pid == 0)
        {
            Console.Error.WriteLine("[TargetedScan] pid=0, 跳过");
            return;
        }

        // 60 秒去重
        var key = (pid, triggerModule);
        var now = DateTime.UtcNow;
        if (_lastScanTime.TryGetValue(key, out var last) &&
            (now - last).TotalSeconds < DedupWindowSec)
        {
            Console.Error.WriteLine($"[TargetedScan] 跳过 (PID={pid}, module={triggerModule} 60秒内已触发)");
            return;
        }
        _lastScanTime[key] = now;

        Console.Error.WriteLine($"[TargetedScan] 开始深扫 PID={pid}, trigger={triggerModule}, attachId={attachId}, ioctl=0x{ioctlCode:X8}");

        // 异步执行,不阻塞 CommsMonitor 回调线程
        _ = Task.Run(() => DoScan(pid, triggerModule, attachId, ioctlCode));
    }

    private void DoScan(uint pid, string triggerModule, ulong attachId, uint ioctlCode)
    {
        try
        {
            // 1. 句柄
            var handles = ScanHandles(pid);
            // 2. 子进程树
            var childProcs = ScanProcessTree(pid);
            // 3. 线程详情 (含 Win32StartAddress)
            var threads = ScanThreads(pid);
            // 4. 网络连接
            var connections = NetworkConnectionCollector.CollectForPid(pid);

            var dataObj = new
            {
                targetPid = pid,
                triggerModule = triggerModule,
                attachId = attachId,
                ioctlCode = ioctlCode,
                timestamp = DateTime.UtcNow,
                handles = handles,
                childProcesses = childProcs,
                threads = threads,
                networkConnections = connections,
            };

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "targeted-scan",
                Level = "HIGH",
                Source = "TargetedScan",
                Title = $"定向深扫: PID={pid}, trigger={Path.GetFileName(triggerModule)}",
                DataJson = JsonSerializer.Serialize(dataObj),
                RequestorPid = pid,
                AttachId = (uint)attachId,
                IoControlCode = ioctlCode,
            });

            Console.Error.WriteLine($"[TargetedScan] 完成 PID={pid}: handles={handles?.Count ?? 0}, children={childProcs?.Count ?? 0}, threads={threads?.Count ?? 0}, conns={connections?.Count ?? 0}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TargetedScan] 异常 PID={pid}: {ex.Message}");
        }
    }

    // ── 四类数据采集 ──

    private List<object>? ScanHandles(uint pid)
    {
        try
        {
            using var result = _host.Service.FetchScanHandles(pid);
            if (!result.Success || result.Entries.Length == 0) return null;

            return result.Entries.Select(e => new
            {
                ownerPid = e.OwnerPid,
                ownerName = e.OwnerName,
                handleValue = e.HandleValue,
                grantedAccess = e.GrantedAccess,
                accessStr = e.AccessStr,
                targetPid = e.TargetPid,
                typeName = e.TypeName,
                highRisk = e.HighRisk,
            }).Cast<object>().ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TargetedScan] 句柄扫描异常: {ex.Message}");
            return null;
        }
    }

    private List<object>? ScanProcessTree(uint pid)
    {
        try
        {
            // 获取整树后过滤出 pid 的子树 (含自身)
            var treeParams = new TreeParameters(0, 0, false);
            using var result = _host.Service.FetchTree(treeParams);
            if (!result.Success || result.Entries.Length == 0) return null;

            // 构建 pid 到子节点的映射, BFS 收集 pid 的所有后代
            var allProcs = result.Entries;
            var children = new List<ulong>();
            var queue = new Queue<ulong>();
            queue.Enqueue(pid);
            var visited = new HashSet<ulong> { pid };

            while (queue.Count > 0)
            {
                var current = queue.Dequeue();
                foreach (var p in allProcs)
                {
                    if (p.Ppid == current && visited.Add(p.Pid))
                    {
                        children.Add(p.Pid);
                        queue.Enqueue(p.Pid);
                    }
                }
            }

            // 返回 pid 自身 + 所有后代
            var targetSet = new HashSet<ulong> { pid };
            foreach (var c in children) targetSet.Add(c);

            return allProcs
                .Where(p => targetSet.Contains(p.Pid))
                .Select(p => new
                {
                    pid = p.Pid,
                    ppid = p.Ppid,
                    name = p.Name,
                    threads = p.Threads,
                    createTime = p.CreateTime,
                    session = p.Session,
                    workingSet = p.WorkingSet,
                    handles = p.Handles,
                })
                .Cast<object>()
                .ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TargetedScan] 进程树扫描异常: {ex.Message}");
            return null;
        }
    }

    private List<object>? ScanThreads(uint pid)
    {
        try
        {
            var secParams = new SecurityParameters(pid, 0);
            using var result = _host.Service.FetchSecurity(secParams);
            if (!result.Success || result.Entries.Length == 0) return null;

            // Security 模式返回单条 CbnProcDetail (pid 过滤)
            var detail = result.SingleEntry;
            return detail.ThreadInfos
                .Take((int)detail.ThreadInfoCount)
                .Select(t => new
                {
                    tid = t.Tid,
                    startAddress = t.StartAddress,
                    win32StartAddress = t.Win32StartAddress,
                    suspendCount = t.SuspendCount,
                    startModule = t.StartModule,
                    isSuspended = t.IsSuspended,
                })
                .Cast<object>()
                .ToList();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[TargetedScan] 线程扫描异常: {ex.Message}");
            return null;
        }
    }
}
