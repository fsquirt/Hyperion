// CombinationNativeService — 核心业务编排层
//
// 取代原 Program.cs 中直接调用 P/Invoke + 打印 int 的做法:
// 本类通过 NativeBridge 间接调用 CombinationNative, 对每次调用进行
// 计时、异常捕获、日志记录, 并返回结构化的 NativeResult 实例。
// Program 仅负责参数解析与最终输出格式化。

using System.Diagnostics;
using System.Runtime.InteropServices;

using SuperUserService.Logging;
using SuperUserService.Models;
using SuperUserService.NativeInterop;

namespace SuperUserService.Services;

/// <summary>
/// 核心业务编排服务。
/// 通过 <see cref="NativeBridge"/> 间接调用 CombinationNative,
/// 对外暴露按命令划分的高级方法, 返回 <see cref="NativeResult"/>。
/// </summary>
public sealed class CombinationNativeService
{
    private readonly NativeBridge _bridge;
    private readonly ServiceLogger _logger;

    public CombinationNativeService(NativeBridge bridge, ServiceLogger logger)
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

    // ═══════════════════════════════════════════════════════════════
    //  DriverAttachSelector 命令
    // ═══════════════════════════════════════════════════════════════

    public NativeResult RunKernelScan()
        => Invoke("kernel-scan", null, _bridge.RunKernelScan);

    public NativeResult RunScanAndClassify()
        => Invoke("scan-classify", null, _bridge.RunScanAndClassify);

    public NativeResult RunScanAndEnumDevices()
        => Invoke("scan-enum-devices", null, _bridge.RunScanAndEnumDevices);

    public NativeResult RunEnumDevices(string driverName)
        => Invoke("enum-devices", $"driver=\"{driverName}\"", () => _bridge.RunEnumDevices(driverName));

    public NativeResult RunScanIAT(string filePath)
        => Invoke("scan-iat", $"file=\"{filePath}\"", () => _bridge.RunScanIAT(filePath));

    public NativeResult RunAttachDevice(string devicePath)
        => Invoke("attach", $"device=\"{devicePath}\"", () => _bridge.RunAttachDevice(devicePath));

    public NativeResult RunUnattachDevice(string arg)
        => Invoke("unattach", $"arg=\"{arg}\"", () => _bridge.RunUnattachDevice(arg));

    public NativeResult RunListAttachments()
        => Invoke("list-attach", null, _bridge.RunListAttachments);

    public NativeResult RunEnumAndClassify()
        => Invoke("enum-classify", null, _bridge.RunEnumAndClassify);

    public NativeResult RunScanObjects(ScanObjectsParameters parameters)
        => Invoke("scan-objects", parameters?.ToString(),
                  () => _bridge.ScanObjectNamespaces(parameters!.ToNativeString()));

    public NativeResult RunEtwConsumer(EtwParameters parameters)
        => Invoke("etw", parameters?.ToString(),
                  () => _bridge.RunEtwConsumer(parameters!.DurationSec, parameters.EtlPath));

    // ═══════════════════════════════════════════════════════════════
    //  HeuristicDumper 命令
    // ═══════════════════════════════════════════════════════════════

    public NativeResult RunCommsMonitor(CommsParameters parameters)
        => Invoke("comms", parameters?.ToString(),
                  () => _bridge.RunCommsMonitor(parameters!.DurationSec, parameters.EnableJson));

    public NativeResult RunScanHandlesForPid(uint targetPid)
        => Invoke("scan-handles", $"pid={targetPid}", () => _bridge.ScanHandlesForPid(targetPid));

    // ═══════════════════════════════════════════════════════════════
    //  ProcessTreeSnapshot 命令
    // ═══════════════════════════════════════════════════════════════

    public NativeResult RunTreeMode(TreeParameters parameters)
        => Invoke("tree", parameters?.ToString(),
                  () => _bridge.RunTreeMode(parameters!.Pid, parameters.MaxDepth, parameters.JsonOutput));

    public NativeResult RunSecurityMode(SecurityParameters parameters)
        => Invoke("security", parameters?.ToString(),
                  () => _bridge.RunSecurityMode(parameters!.Pid, parameters.Flags));

    // ═══════════════════════════════════════════════════════════════
    //  数据导出 API (Fetch* 系列方法, 返回结构化数据而非纯返回码)
    //
    //  这些方法调用 CombinationNative.dll 的 CombNative_Get* 函数,
    //  获取扁平化 C 结构体缓冲区, 通过 NativeDataResult<T> 包装为
    //  强类型托管对象。调用方应在 using 块中使用以释放非托管内存。
    // ═══════════════════════════════════════════════════════════════

    /// <summary>获取内核扫描数据 (LoadedDriverEntry 列表)。</summary>
    public NativeDataResult<LoadedDriverEntry> FetchKernelScan()
        => InvokeData("kernel-scan", null, _bridge.GetKernelScanData);

    /// <summary>获取驱动扫描+分类数据 (CbnClassifyEntry 列表)。</summary>
    public NativeDataResult<CbnClassifyEntry> FetchScanAndClassify()
        => InvokeData("scan-classify", null, _bridge.GetScanAndClassifyData);

    /// <summary>获取扫描+分类+设备列表数据 (CbnClassifyEntry 列表)。</summary>
    public NativeDataResult<CbnClassifyEntry> FetchScanAndEnumDevices()
        => InvokeData("scan-enum-devices", null, _bridge.GetScanAndEnumDevicesData);

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

    /// <summary>获取 PSAPI 枚举+分类数据 (CbnClassifyEntry 列表)。</summary>
    public NativeDataResult<CbnClassifyEntry> FetchEnumAndClassify()
        => InvokeData("enum-classify", null, _bridge.GetEnumAndClassifyData);

    /// <summary>获取对象管理器命名空间扫描结果 (CbnNtDirEntry 列表)。</summary>
    public NativeDataResult<CbnNtDirEntry> FetchScanObjects(ScanObjectsParameters parameters)
        => InvokeData("scan-objects", parameters?.ToString(),
                      () => _bridge.GetScanObjectsData(parameters!.ToNativeString()));

    /// <summary>获取 ETW 订阅事件数据 (CbnEtwEvent 列表)。</summary>
    public NativeDataResult<CbnEtwEvent> FetchEtw(EtwParameters parameters)
        => InvokeData("etw", parameters?.ToString(),
                      () => _bridge.GetEtwData(parameters!.DurationSec, parameters.EtlPath));

    /// <summary>
    /// ETW 实时订阅: 通过回调实时输出事件, 而非等待结束后一次性返回。
    /// 每个 ETW 事件通过 onEvent 回调实时传入 C# 类, 由调用方处理。
    /// </summary>
    public int FetchEtwLive(EtwParameters parameters, Action<CbnEtwEvent> onEvent)
    {
        _logger.Info($"[etw-live] 开始实时订阅 {parameters}...");

        // 用 GCHandle 保持委托不被 GC 回收
        var collector = new EtwLiveCollector(onEvent);
        GCHandle gch = GCHandle.Alloc(collector);
        try
        {
            var sw = Stopwatch.StartNew();
            // 取得回调函数指针 (委托实例由 collector 保持, 不会被 GC 回收)
            IntPtr callbackPtr = collector.CallbackPtr;
            int ret = _bridge.RunEtwLive(parameters.DurationSec, parameters.EtlPath,
                                         callbackPtr,
                                         GCHandle.ToIntPtr(gch));
            sw.Stop();
            _logger.Info($"[etw-live] 结束, 共 {collector.Count} 个事件, 耗时 {sw.Elapsed.TotalMilliseconds:F0}ms, ret={ret}");
            return ret;
        }
        finally
        {
            gch.Free();
        }
    }

    /// <summary>获取通信监控数据 (CbnCommsSummary 单条)。</summary>
    public NativeDataResult<CbnCommsSummary> FetchComms(CommsParameters parameters)
        => InvokeData("comms", parameters?.ToString(),
                      () => _bridge.GetCommsData(parameters!.DurationSec, parameters.EnableJson,
                                                  (int)parameters.DumpMode));

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
    //  停止接口 (供宿主程序主动停止长时运行的 ETW/Comms 线程)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>主动停止 ETW 实时订阅 (非阻塞, ~200ms 内退出)。</summary>
    public void StopEtwLive()
    {
        _logger.Info("[etw-stop] 请求停止 ETW 实时订阅...");
        try { _bridge.StopEtwLive(); }
        catch (Exception ex) { _logger.Error("[etw-stop] 调用失败", ex); }
    }

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

    /// <summary>
    /// 统一的调用包装器: 计时、异常捕获、日志记录, 返回结构化结果。
    /// 所有命令方法均通过此辅助方法间接调用 NativeBridge。
    /// </summary>
    private NativeResult Invoke(string command, string? arguments, Func<int> nativeCall)
    {
        _logger.Info($"[{command}] 开始执行{(arguments != null ? $" ({arguments})" : "")}...");

        var sw = Stopwatch.StartNew();
        try
        {
            int code = nativeCall();
            sw.Stop();

            NativeResult result = code == 0
                ? NativeResult.Ok(command, sw.Elapsed, arguments)
                : NativeResult.Fail(command, code, sw.Elapsed,
                                    $"CombinationNative 返回非零退出码 {code}", arguments);
            LogResult(result);
            return result;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            sw.Stop();
            _logger.Error($"[{command}] 调用过程中抛出异常", ex);
            return NativeResult.Fail(command, -1, sw.Elapsed, ex.Message, arguments);
        }
    }

    private void LogResult(NativeResult result)
    {
        if (result.Success)
            _logger.Info(result.ToString());
        else
            _logger.Warning(result.ToString());
    }

    /// <summary>执行指定动作并返回 (返回码, 耗时)。</summary>
    private static (int code, TimeSpan elapsed) Timed(Func<int> action)
    {
        var sw = Stopwatch.StartNew();
        int code = action();
        sw.Stop();
        return (code, sw.Elapsed);
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
/// ETW 实时事件收集器: 作为 C# 端的"数据接收类"。
/// C++ 通过回调将每个 CbnEtwEvent 传入此类, 再由调用方从类中读取输出。
/// 符合"数据先入类, 再从类出"原则。
/// </summary>
public sealed class EtwLiveCollector
{
    private readonly Action<CbnEtwEvent> _onEvent;
    private int _count;

    // 委托实例必须显式保持, 防止 GC 回收
    internal readonly EtwCallbackDelegate Callback;

    public EtwLiveCollector(Action<CbnEtwEvent> onEvent)
    {
        _onEvent = onEvent;
        Callback = NativeCallback;
    }

    public int Count => _count;

    /// <summary>
    /// C++ 回调入口 (cdecl)。context 是 GCHandle 的 IntPtr。
    /// 数据先进入此方法 → 存入 C# 对象 → 调用 onEvent 从类中输出。
    /// </summary>
    private void NativeCallback(IntPtr evtPtr, IntPtr context)
    {
        if (evtPtr == IntPtr.Zero || context == IntPtr.Zero) return;

        // 从 GCHandle 恢复 collector 对象
        var gch = GCHandle.FromIntPtr(context);
        if (gch.Target is not EtwLiveCollector collector) return;

        // 数据进入 C# 类 (Marshal.PtrToStructure 创建托管副本)
        CbnEtwEvent evt = Marshal.PtrToStructure<CbnEtwEvent>(evtPtr);
        collector._count++;

        // 从类中输出 (通过 onEvent 委托)
        collector._onEvent(evt);
    }

    /// <summary>获取回调函数指针, 用于传递给 C++。</summary>
    public IntPtr CallbackPtr => Marshal.GetFunctionPointerForDelegate(Callback);
}

/// <summary>C++ ETW 回调委托 (cdecl)。</summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void EtwCallbackDelegate(IntPtr evtPtr, IntPtr context);
