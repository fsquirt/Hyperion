using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// IOCTL 通信监控（移植自 HeuristicDumper/CommsMonitor.cpp 的协调逻辑）。
/// 仅统计 "IOCTL 控制码 → 次数"（不缓存 InputBuffer 内容，零堆分配热路径）；
/// 对每次附着驱动的拦截事件，异步投递 dump 取证（调用方模块 + 对端驱动 sys）。
/// 同时对外抛出 <see cref="OnIntercept"/> 供 ProcTree 的事件触发器订阅。
/// </summary>
public sealed class IoctlCommsMonitor : IDisposable
{
    private readonly EtwSession _etw;
    private readonly AttachManager _attach;
    private readonly ModuleDumper _moduleDumper;
    private readonly DriverDumper _driverDumper;
    private readonly object _subLock = new();
    private Action<IoctlInterceptEvent>? _onIntercept;

    // IOCTL 控制码 → 累计次数（热路径仅做原子累加）
    private readonly System.Collections.Concurrent.ConcurrentDictionary<uint, ulong> _counts = new();

    public event Action<IoctlInterceptEvent>? OnIntercept
    {
        add { lock (_subLock) _onIntercept += value; }
        remove { lock (_subLock) _onIntercept -= value; }
    }

    public IoctlCommsMonitor(EtwSession etw, AttachManager attach,
        ModuleDumper moduleDumper, DriverDumper driverDumper)
    {
        _etw = etw;
        _attach = attach;
        _moduleDumper = moduleDumper;
        _driverDumper = driverDumper;
    }

    public void Start()
    {
        _etw.IoctlIntercept += OnEtwIntercept;
        _etw.Start();
    }

    public void Stop()
    {
        _etw.IoctlIntercept -= OnEtwIntercept;
        _etw.Stop();
    }

    // 在 ETW 线程上执行：仅做轻量累加 + 异步投递重 IO
    private void OnEtwIntercept(IoctlInterceptEvent evt)
    {
        _counts.AddOrUpdate(evt.IoControlCode, 1, (_, v) => v + 1);

        Action<IoctlInterceptEvent>? subscribers;
        lock (_subLock) subscribers = _onIntercept;
        subscribers?.Invoke(evt);

        // 重 IO（dump）投递线程池，避免阻塞 ETW 会话丢事件
        IoctlInterceptEvent captured = evt;
        Task.Run(() => DispatchDump(captured));
    }

    private void DispatchDump(IoctlInterceptEvent evt)
    {
        try
        {
            Console.WriteLine($"[IO] AttachId={evt.AttachId} PID={evt.RequestorPid} " +
                              $"IOCTL=0x{evt.IoControlCode:X8} 累计={_counts[evt.IoControlCode]}");

            // 调用方 exe
            if (!string.IsNullOrEmpty(evt.ExePath))
                _moduleDumper.DumpProcessModule(evt.RequestorPid, evt.ExePath);

            // 调用栈命中的业务模块（排除系统目录）
            if (evt.Frames.Length > 0)
            {
                var callerModules = StackResolver.ResolveCallerModules(evt.RequestorPid, evt.Frames);
                foreach (var m in callerModules)
                    _moduleDumper.DumpProcessModule(evt.RequestorPid, m);
            }

            // 对端驱动 sys（按 AttachId 去重）
            _driverDumper.DumpTargetDriver((uint)evt.AttachId);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[IO] dump 分发异常: {ex.Message}");
        }
    }

    /// <summary>返回当前 IOCTL 统计快照（码 → 次数）。</summary>
    public IReadOnlyDictionary<uint, ulong> GetCounts() => _counts;

    /// <summary>返回并清空统计（用于分段上报）。</summary>
    public Dictionary<uint, ulong> DrainCounts()
    {
        var snapshot = new Dictionary<uint, ulong>(_counts);
        _counts.Clear();
        return snapshot;
    }

    public void Dispose() => Stop();
}
