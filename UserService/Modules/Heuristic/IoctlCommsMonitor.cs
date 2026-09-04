using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// IOCTL 通信监控，移植自 HeuristicDumper/CommsMonitor.cpp 的协调逻辑。
/// 仅统计 "IOCTL 控制码 → 次数"，不缓存 InputBuffer 内容，热路径零堆分配；
/// 对每次附着驱动的拦截事件，异步投递 dump 取证，对象为调用方模块与对端驱动 sys。
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

    // IOCTL 控制码 → 累计次数，热路径仅做原子累加
    private readonly System.Collections.Concurrent.ConcurrentDictionary<uint, ulong> _counts = new();

    // 参与 IOCTL 交互的模块路径集合：本地统计用，含系统 DLL；dump 时另按签名过滤
    private readonly HashSet<string> _interactionModules = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _modLock = new();

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

        // dump 这类重 IO 投递线程池，避免阻塞 ETW 会话丢事件
        IoctlInterceptEvent captured = evt;
        Task.Run(() => DispatchDump(captured));
    }

    private void DispatchDump(IoctlInterceptEvent evt)
    {
        try
        {
            // 调用方 exe：先记入交互模块统计；微软签名的跳过 dump/minidump
            if (!string.IsNullOrEmpty(evt.ExePath))
            {
                lock (_modLock) _interactionModules.Add(evt.ExePath);
                if (!MsSignedCache.IsMicrosoftSigned(evt.ExePath))
                {
                    _moduleDumper.DumpProcessModule(evt.RequestorPid, evt.ExePath);
                    // 未签名模块 ↔ 被附着驱动交互：额外取 minidump + 磁盘原始文件
                    if (DriverClassifier.IsUntrusted(evt.ExePath))
                        _moduleDumper.DumpProcessMiniDump(evt.RequestorPid, evt.ExePath);
                }
            }

            // 调用栈命中的业务模块：排除内核态帧；此处再用微软签名缓存过滤系统 DLL
            if (evt.Frames.Length > 0)
            {
                var callerModules = StackResolver.ResolveCallerModules(evt.RequestorPid, evt.Frames);
                foreach (var m in callerModules)
                {
                    lock (_modLock) _interactionModules.Add(m); // 统计：参与交互的模块，含系统 DLL
                    // 高频 IOCTL 下系统 DLL(ntdll/KERNEL32/USER32...)签名恒定，命中缓存即跳过，
                    // 既避免无意义的进程内存 dump/磁盘拷贝，也省去后续 IsUntrusted 二次验签。
                    if (MsSignedCache.IsMicrosoftSigned(m))
                        continue;
                    _moduleDumper.DumpProcessModule(evt.RequestorPid, m);
                    if (DriverClassifier.IsUntrusted(m))
                        _moduleDumper.DumpProcessMiniDump(evt.RequestorPid, m);
                }
            }

            // 对端驱动 sys，按 AttachId 去重
            _driverDumper.DumpTargetDriver((uint)evt.AttachId);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[IO] dump 分发异常: {ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine(LogUtil.Detail(ex));
        }
    }

    /// <summary>返回当前 IOCTL 累计统计快照，即码 → 次数，不修改内部状态。</summary>
    public IReadOnlyDictionary<uint, ulong> GetCounts() => new Dictionary<uint, ulong>(_counts);

    /// <summary>返回参与交互的模块路径集合快照，用于本地取证统计。</summary>
    public IReadOnlyCollection<string> GetInteractionModules()
    {
        lock (_modLock) return new List<string>(_interactionModules);
    }

    public void Dispose() => Stop();
}
