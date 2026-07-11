// NativeBridge — CombinationNative.dll 的唯一托管入口
//
// 整个 SuperUserService 中只有此处直接声明并调用 P/Invoke。
// 所有上层服务必须通过 NativeBridge 的公共方法间接访问原生函数,
// 从而把互操作边界集中在一处, 便于审计与维护。

using System.Runtime.InteropServices;
using SuperUserService.Models;

namespace SuperUserService.NativeInterop;

/// <summary>
/// CombinationNative.dll 的托管包装器。
/// 持有全部 16 个导出函数的 P/Invoke 声明, 对外暴露强类型方法;
/// 同时跟踪 ntdll 初始化状态, 避免重复初始化。
/// </summary>
public sealed class NativeBridge
{
    private const string Dll = "CombinationNative.dll";

    // ─── P/Invoke 声明 (对应 CombinationNative.h 的 16 个导出函数) ───

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_InitNtdll();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunKernelScan();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunScanAndClassify();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunScanAndEnumDevices();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunEnumDevices(string driverName);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunScanIAT(string filePath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunAttachDevice(string devicePath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunUnattachDevice(string arg);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunListAttachments();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunEnumAndClassify();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_ScanObjectNamespaces(string dirs);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunEtwConsumer(uint durationSec, string? etlPath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunCommsMonitor(uint durationSec, int enableJson);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_ScanHandlesForPid(uint targetPid);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunTreeMode(ulong pid, int maxDepth, int jsonOut);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunSecurityMode(ulong pid, uint flags);

    // ─── 状态 ──────────────────────────────────────────────────────

    /// <summary>ntdll 是否已成功初始化。</summary>
    public bool IsInitialized { get; private set; }

    // ─── 公共 API: 初始化 ──────────────────────────────────────────

    /// <summary>初始化 ntdll API; 重复调用是安全的 (幂等)。</summary>
    /// <returns>0 表示成功, 非 0 为原生返回码。</returns>
    public int Initialize()
    {
        if (IsInitialized) return 0;
        int r = CombNative_InitNtdll();
        IsInitialized = (r == 0);
        return r;
    }

    // ─── 公共 API: DriverAttachSelector ────────────────────────────

    public int RunKernelScan() => CombNative_RunKernelScan();

    public int RunScanAndClassify() => CombNative_RunScanAndClassify();

    public int RunScanAndEnumDevices() => CombNative_RunScanAndEnumDevices();

    public int RunEnumDevices(string driverName) => CombNative_RunEnumDevices(driverName);

    public int RunScanIAT(string filePath) => CombNative_RunScanIAT(filePath);

    public int RunAttachDevice(string devicePath) => CombNative_RunAttachDevice(devicePath);

    public int RunUnattachDevice(string arg) => CombNative_RunUnattachDevice(arg);

    public int RunListAttachments() => CombNative_RunListAttachments();

    public int RunEnumAndClassify() => CombNative_RunEnumAndClassify();

    public int ScanObjectNamespaces(string dirs) => CombNative_ScanObjectNamespaces(dirs);

    public int RunEtwConsumer(uint durationSec, string? etlPath)
        => CombNative_RunEtwConsumer(durationSec, etlPath);

    // ─── 公共 API: HeuristicDumper ─────────────────────────────────

    public int RunCommsMonitor(uint durationSec, bool enableJson)
        => CombNative_RunCommsMonitor(durationSec, enableJson ? 1 : 0);

    public int ScanHandlesForPid(uint targetPid) => CombNative_ScanHandlesForPid(targetPid);

    // ─── 公共 API: ProcessTreeSnapshot ─────────────────────────────

    public int RunTreeMode(ulong pid, int maxDepth, bool jsonOutput)
        => CombNative_RunTreeMode(pid, maxDepth, jsonOutput ? 1 : 0);

    public int RunSecurityMode(ulong pid, uint flags) => CombNative_RunSecurityMode(pid, flags);

    // ═══════════════════════════════════════════════════════════════
    //  数据导出 P/Invoke (对应 CombinationNativeData.h 的 Get* 函数)
    //  返回 malloc 分配的缓冲区, 调用方通过 NativeDataResult<T> 释放
    //  (CombNative_FreeBuffer 声明在 NativeBufferHelper 中, 避免泛型类限制)
    // ═══════════════════════════════════════════════════════════════

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetKernelScanData(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetScanAndClassifyData(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetScanAndEnumDevicesData(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern IntPtr CombNative_GetEnumDevicesData(string driverName, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern IntPtr CombNative_GetScanIatData(string filePath, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern IntPtr CombNative_GetAttachData(string devicePath, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern IntPtr CombNative_GetUnattachData(string arg, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetListAttachmentsData(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetEnumAndClassifyData(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern IntPtr CombNative_GetScanObjectsData(string dirs, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetEtwData(uint durationSec, string? etlPath, out uint outSize);

    // ETW 实时回调
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CombNative_SetEtwCallback(IntPtr callback, IntPtr context);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunEtwLive(uint durationSec, string? etlPath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetCommsData(uint durationSec, int enableJson, int dumpMode, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetScanHandlesData(uint targetPid, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetTreeData(ulong pid, int maxDepth, int jsonOut, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetSecurityData(ulong pid, uint flags, out uint outSize);

    // 停止接口 (供宿主程序主动停止长时运行的 ETW/Comms 线程)
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CombNative_StopEtwLive();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CombNative_StopComms();

    // ─── 数据导出公共 API ──────────────────────────────────────────
    //  返回 NativeDataResult<T>, 调用方应在 using 块中使用

    public NativeDataResult<LoadedDriverEntry> GetKernelScanData()
        => new(CombNative_GetKernelScanData(out _));

    public NativeDataResult<CbnClassifyEntry> GetScanAndClassifyData()
        => new(CombNative_GetScanAndClassifyData(out _));

    public NativeDataResult<CbnClassifyEntry> GetScanAndEnumDevicesData()
        => new(CombNative_GetScanAndEnumDevicesData(out _));

    public NativeDataResult<DeviceEntry> GetEnumDevicesData(string driverName)
        => new(CombNative_GetEnumDevicesData(driverName, out _));

    public NativeDataResult<CbnIatResult> GetScanIatData(string filePath)
        => new(CombNative_GetScanIatData(filePath, out _));

    public NativeDataResult<CbnAttachResult> GetAttachData(string devicePath)
        => new(CombNative_GetAttachData(devicePath, out _));

    public NativeDataResult<CbnDetachResult> GetUnattachData(string arg)
        => new(CombNative_GetUnattachData(arg, out _));

    public NativeDataResult<AttachEntry> GetListAttachmentsData()
        => new(CombNative_GetListAttachmentsData(out _));

    public NativeDataResult<CbnClassifyEntry> GetEnumAndClassifyData()
        => new(CombNative_GetEnumAndClassifyData(out _));

    public NativeDataResult<CbnNtDirEntry> GetScanObjectsData(string dirs)
        => new(CombNative_GetScanObjectsData(dirs, out _));

    public NativeDataResult<CbnEtwEvent> GetEtwData(uint durationSec, string? etlPath)
        => new(CombNative_GetEtwData(durationSec, etlPath, out _));

    /// <summary>
    /// ETW 实时订阅: 注册回调后运行, 每收到一个事件通过回调实时通知。
    /// 回调中接收 CbnEtwEvent 结构体指针, 调用方在回调中将数据加入 C# 类。
    /// </summary>
    public int RunEtwLive(uint durationSec, string? etlPath, IntPtr callback, IntPtr context)
    {
        CombNative_SetEtwCallback(callback, context);
        int ret = CombNative_RunEtwLive(durationSec, etlPath);
        CombNative_SetEtwCallback(IntPtr.Zero, IntPtr.Zero);
        return ret;
    }

    public NativeDataResult<CbnCommsSummary> GetCommsData(uint durationSec, bool enableJson, int dumpMode)
        => new(CombNative_GetCommsData(durationSec, enableJson ? 1 : 0, dumpMode, out _));

    public NativeDataResult<CbnHandleEntry> GetScanHandlesData(uint targetPid)
        => new(CombNative_GetScanHandlesData(targetPid, out _));

    public NativeDataResult<CbnProcBrief> GetTreeData(ulong pid, int maxDepth, bool jsonOut)
        => new(CombNative_GetTreeData(pid, maxDepth, jsonOut ? 1 : 0, out _));

    public NativeDataResult<CbnProcDetail> GetSecurityData(ulong pid, uint flags)
        => new(CombNative_GetSecurityData(pid, flags, out _));

    // ─── 停止接口 ──────────────────────────────────────────────────
    // 主动停止 ETW 实时订阅 (非阻塞, 实际线程 ~200ms 内退出)
    public void StopEtwLive() => CombNative_StopEtwLive();

    // 主动停止通信监控 (非阻塞, 实际线程 ~200ms 内退出)
    public void StopComms() => CombNative_StopComms();
}
