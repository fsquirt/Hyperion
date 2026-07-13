// HyperionNativeService — 核心业务编排层
//
// 取代原 Program.cs 中直接调用 P/Invoke + 打印 int 的做法:
// 本类通过 NativeBridge 间接调用 HyperionNative, 对每次调用进行
// 计时、异常捕获、日志记录, 并返回结构化的 NativeResult 实例。
// Program 仅负责参数解析与最终输出格式化。

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace UserService.Native;

/// <summary>
/// 核心业务编排服务。
/// 通过 <see cref="NativeBridge"/> 间接调用 HyperionNative,
/// 对外暴露按命令划分的高级方法, 返回 <see cref="NativeResult"/>。
/// </summary>
public sealed class HyperionNativeService
{
    private readonly NativeBridge _bridge;
    private readonly ServiceLogger _logger;

    public HyperionNativeService(NativeBridge bridge, ServiceLogger logger)
    {
        _bridge = bridge ?? throw new ArgumentNullException(nameof(bridge));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ═══════════════════════════════════════════════════════════════
    //  初始化
    // ═══════════════════════════════════════════════════════════════

    /// <summary>初始化 ntdll API (幂等)。</summary>
    public NativeResult Initialize()
    {
        _logger.Info("初始化 ntdll API...");
        var (code, elapsed) = Timed(() => _bridge.Initialize());
        NativeResult result = code == 0
            ? NativeResult.Ok("init", elapsed)
            : NativeResult.Fail("init", code, elapsed, $"InitNtdll 返回 {code}, 部分功能可能不可用");
        LogResult(result);
        return result;
    }

    /// <summary>若尚未初始化则执行初始化; 已初始化则直接返回成功。</summary>
    public NativeResult EnsureInitialized()
    {
        if (_bridge.IsInitialized) return NativeResult.Ok("init", TimeSpan.Zero);
        return Initialize();
    }

    /// <summary>
    /// 设置危险函数列表 (注入服务端下发的 policy.DangerousFunctions)。
    /// 在扫描驱动 IAT 之前调用, 否则 Native 端用硬编码的默认 4 个危险函数。
    /// </summary>
    public void SetDangerousApiList(IEnumerable<string> funcNames)
    {
        _bridge.SetDangerousApiList(funcNames);
    }

    // ═══════════════════════════════════════════════════════════════
    //  数据导出 API (Fetch* 系列方法, 返回结构化数据而非纯返回码)
    //
    //  这些方法调用 HyperionNative.dll 的 CombNative_Get* 函数,
    //  获取扁平化 C 结构体缓冲区, 通过 NativeDataResult<T> 包装为
    //  强类型托管对象。调用方应在 using 块中使用以释放非托管内存。
    // ═══════════════════════════════════════════════════════════════

    /// <summary>获取驱动扫描+分类数据 (CbnClassifyEntry 列表)。</summary>
    public NativeDataResult<CbnClassifyEntry> FetchScanAndClassify()
        => InvokeData("scan-classify", null, _bridge.GetScanAndClassifyData);

    /// <summary>获取单驱动设备列表 (DeviceEntry 列表)。</summary>
    public NativeDataResult<DeviceEntry> FetchEnumDevices(string driverName)
        => InvokeData("enum-devices", $"driver=\"{driverName}\"",
                      () => _bridge.GetEnumDevicesData(driverName));

    /// <summary>获取 IAT 扫描结果 (CbnIatResult 单条)。</summary>
    public NativeDataResult<CbnIatResult> FetchScanIat(string filePath)
        => InvokeData("scan-iat", $"file=\"{filePath}\"",
                      () => _bridge.GetScanIatData(filePath));

    /// <summary>附着设备并获取结果 (CbnAttachResult 单条)。</summary>
    public NativeDataResult<CbnAttachResult> FetchAttach(string devicePath)
        => InvokeData("attach", $"device=\"{devicePath}\"",
                      () => _bridge.GetAttachData(devicePath));

    /// <summary>解绑附着并获取结果 (CbnDetachResult 单条)。</summary>
    public NativeDataResult<CbnDetachResult> FetchUnattach(string arg)
        => InvokeData("unattach", $"arg=\"{arg}\"",
                      () => _bridge.GetUnattachData(arg));

    /// <summary>获取当前附着列表 (AttachEntry 列表)。</summary>
    public NativeDataResult<AttachEntry> FetchListAttachments()
        => InvokeData("list-attach", null, _bridge.GetListAttachmentsData);

    /// <summary>获取通信监控数据 (CbnCommsSummary 单条)。</summary>
    public NativeDataResult<CbnCommsSummary> FetchComms(CommsParameters parameters)
        => InvokeData("comms", parameters?.ToString(),
                      () => _bridge.GetCommsData(parameters!.DurationSec, parameters.EnableJson,
                                                  (int)parameters.DumpMode));

    /// <summary>
    /// 通信监控实时订阅: 通过回调实时输出每个 IOCTL 通信事件, 而非等待结束后一次性返回。
    /// 每个 CbnCommsEvent 通过 onEvent 回调实时传入 C# 类, 由调用方处理。
    /// </summary>
    public int FetchCommsLive(CommsParameters parameters, Action<CbnCommsEvent> onEvent)
    {
        _logger.Info($"[comms-live] 开始实时订阅 {parameters}...");

        // 用 GCHandle 保持委托不被 GC 回收
        var collector = new CommsLiveCollector(onEvent);
        GCHandle gch = GCHandle.Alloc(collector);
        try
        {
            var sw = Stopwatch.StartNew();
            IntPtr callbackPtr = collector.CallbackPtr;
            int ret = _bridge.RunCommsLive(parameters!.DurationSec,
                                            parameters.EnableJson,
                                            (int)parameters.DumpMode,
                                            callbackPtr,
                                            GCHandle.ToIntPtr(gch));
            sw.Stop();
            _logger.Info($"[comms-live] 结束, 共 {collector.Count} 个通信事件, " +
                         $"耗时 {sw.Elapsed.TotalMilliseconds:F0}ms, ret={ret}");
            return ret;
        }
        finally
        {
            // S3: 加 200ms grace period 防 use-after-free。
            Thread.Sleep(200);
            gch.Free();
        }
    }

    /// <summary>
    /// 获取已收集的驱动内存 dump 元数据 (CommsMonitor 期间 DumpTargetDriver 收集)。
    /// 在 FetchComms / FetchCommsLive 运行结束后调用, 返回 CbnDriverDumpInfo 列表。
    /// </summary>
    public NativeDataResult<CbnDriverDumpInfo> FetchDriverDumpInfo()
        => InvokeData("driver-dump", null, _bridge.GetDriverDumpInfo);

    /// <summary>获取句柄扫描数据 (CbnHandleEntry 列表)。</summary>
    public NativeDataResult<CbnHandleEntry> FetchScanHandles(uint targetPid)
        => InvokeData("scan-handles", $"pid={targetPid}",
                      () => _bridge.GetScanHandlesData(targetPid));

    /// <summary>获取进程树数据 (CbnProcBrief 列表)。</summary>
    public NativeDataResult<CbnProcBrief> FetchTree(TreeParameters parameters)
        => InvokeData("tree", parameters?.ToString(),
                      () => _bridge.GetTreeData(parameters!.Pid, parameters.MaxDepth, parameters.JsonOutput));

    /// <summary>获取进程安全详情 (CbnProcDetail 列表)。</summary>
    public NativeDataResult<CbnProcDetail> FetchSecurity(SecurityParameters parameters)
        => InvokeData("security", parameters?.ToString(),
                      () => _bridge.GetSecurityData(parameters!.Pid, parameters.Flags));

    // ═══════════════════════════════════════════════════════════════
    //  停止接口 (供宿主程序主动停止长时运行的 Comms 线程)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>主动停止通信监控 (非阻塞, ~200ms 内退出)。</summary>
    public void StopComms()
    {
        _logger.Info("[comms-stop] 请求停止通信监控...");
        try { _bridge.StopComms(); }
        catch (Exception ex) { _logger.Error("[comms-stop] 调用失败", ex); }
    }

    // ═══════════════════════════════════════════════════════════════
    //  内部辅助
    // ═══════════════════════════════════════════════════════════════

    /// <summary>执行指定动作并返回 (返回码, 耗时)。</summary>
    private static (int code, TimeSpan elapsed) Timed(Func<int> action)
    {
        var sw = Stopwatch.StartNew();
        int code = action();
        sw.Stop();
        return (code, sw.Elapsed);
    }

    private void LogResult(NativeResult result)
    {
        if (result.Success)
            _logger.Info(result.ToString());
        else
            _logger.Warning(result.ToString());
    }

    /// <summary>
    /// 数据导出调用的统一包装器: 计时、异常捕获、日志记录。
    /// 与 Invoke 不同, 返回 NativeDataResult<T> 而非 NativeResult,
    /// 调用方可在 using 块中访问 Entries / SingleEntry。
    /// </summary>
    private NativeDataResult<T> InvokeData<T>(string command, string? arguments,
                                              Func<NativeDataResult<T>> nativeCall)
                                               where T : struct
    {
        _logger.Info($"[{command}] 开始执行 (数据模式){(arguments != null ? $" ({arguments})" : "")}...");

        var sw = Stopwatch.StartNew();
        try
        {
            NativeDataResult<T> result = nativeCall();
            sw.Stop();

            if (result.Success)
            {
                _logger.Info($"[{command}] 成功, 返回 {result.Count} 条记录, 耗时 {sw.Elapsed.TotalMilliseconds:F0}ms");
            }
            else
            {
                _logger.Warning($"[{command}] 失败: ErrorCode={result.Header.ErrorCode}, " +
                                $"Message={result.ErrorMessage}, 耗时 {sw.Elapsed.TotalMilliseconds:F0}ms");
            }
            return result;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            sw.Stop();
            _logger.Error($"[{command}] 调用过程中抛出异常", ex);
            throw;
        }
    }
}

/// <summary>
/// 通信监控实时事件收集器: 作为 C# 端的"数据接收类"。
/// C++ 通过回调将每个 CbnCommsEvent 传入此类, 再由调用方从类中读取输出。
/// </summary>
public sealed class CommsLiveCollector
{
    private readonly Action<CbnCommsEvent> _onEvent;
    private int _count;

    // 委托实例必须显式保持, 防止 GC 回收
    internal readonly CommsEventCallbackDelegate Callback;

    public CommsLiveCollector(Action<CbnCommsEvent> onEvent)
    {
        _onEvent = onEvent;
        Callback = NativeCallback;
    }

    public int Count => Volatile.Read(ref _count);

    /// <summary>
    /// C++ 回调入口 (cdecl)。context 是 GCHandle 的 IntPtr。
    /// 数据先进入此方法 → 存入 C# 对象 → 调用 onEvent 从类中输出。
    /// </summary>
    /// <remarks>
    /// S4: native 回调线程上抛异常会损坏 C++ 线程状态,
    ///     用 try/catch 包住所有用户代码, 仅记日志不传播。
    /// H8: 通信事件可能从多个 native 线程并发投递, _count 用 Interlocked 保证原子。
    /// </remarks>
    private void NativeCallback(IntPtr evtPtr, IntPtr context)
    {
        if (evtPtr == IntPtr.Zero || context == IntPtr.Zero) return;

        var gch = GCHandle.FromIntPtr(context);
        if (gch.Target is not CommsLiveCollector collector) return;

        try
        {
            // 数据进入 C# 类 (Marshal.PtrToStructure 创建托管副本)
            CbnCommsEvent evt = Marshal.PtrToStructure<CbnCommsEvent>(evtPtr);
            Interlocked.Increment(ref collector._count);

            // 从类中输出 (通过 onEvent 委托)
            collector._onEvent(evt);
        }
        catch (Exception ex)
        {
            // S4: 用户代码 (onEvent + JsonSerializer.Serialize + HTTP 投递) 抛异常
            //     不能让异常传播到 C++ 回调线程, 否则 C++ 线程状态未定义。
            Console.Error.WriteLine($"[CommsLiveCollector] 回调异常: {ex.Message}");
        }
    }

    /// <summary>获取回调函数指针, 用于传递给 C++。</summary>
    public IntPtr CallbackPtr => Marshal.GetFunctionPointerForDelegate(Callback);
}

/// <summary>C++ 通信事件回调委托 (cdecl), 签名与 CBN_COMMS_EVENT_CALLBACK 一致。</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void CommsEventCallbackDelegate(IntPtr evtPtr, IntPtr context);
