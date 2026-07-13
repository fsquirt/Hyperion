// NativeBridge — CombinationNative.dll 的唯一托管入口
//
// 整个 UserService 中只有此处直接声明并调用 P/Invoke。
// 所有上层服务必须通过 NativeBridge 的公共方法间接访问原生函数,
// 从而把互操作边界集中在一处, 便于审计与维护。

using System.Runtime.InteropServices;

namespace UserService.Native;

/// <summary>
/// CombinationNative.dll 的托管包装器。
/// 持有全部导出函数的 P/Invoke 声明, 对外暴露强类型方法;
/// 同时跟踪 ntdll 初始化状态, 避免重复初始化。
/// </summary>
public sealed class NativeBridge
{
    private const string Dll = "CombinationNative.dll";

    // ─── P/Invoke 声明 ───

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_InitNtdll();

    // 配置接口: 注入服务端下发的危险函数列表 (const char* pipeSeparated, ANSI)
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern void CombNative_SetDangerousApiList(string? pipeSeparated);

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

    /// <summary>
    /// 设置危险函数列表 (注入服务端下发的 policy.DangerousFunctions)。
    /// 把函数名列表用 '|' 拼接成单个字符串传给 Native。
    /// 传入空列表则回退到 Native 硬编码的 4 个默认危险函数。
    /// </summary>
    public void SetDangerousApiList(IEnumerable<string> funcNames)
    {
        var list = funcNames?.Where(n => !string.IsNullOrEmpty(n)).ToList();
        if (list == null || list.Count == 0)
        {
            CombNative_SetDangerousApiList(null);
            return;
        }
        string joined = string.Join("|", list);
        CombNative_SetDangerousApiList(joined);
    }

    // ═══════════════════════════════════════════════════════════════
    //  数据导出 P/Invoke (对应 CombinationNativeData.h 的 Get* 函数)
    //  返回 malloc 分配的缓冲区, 调用方通过 NativeDataResult<T> 释放
    //  (CombNative_FreeBuffer 声明在 NativeBufferHelper 中, 避免泛型类限制)
    // ═══════════════════════════════════════════════════════════════

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetScanAndClassifyData(out uint outSize);

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
    private static extern IntPtr CombNative_GetCommsData(uint durationSec, int enableJson, int dumpMode, out uint outSize);

    // 通信监控实时回调 (注册回调 → 运行 → 投递每事件数据)
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CombNative_SetCommsEventCallback(IntPtr callback, IntPtr context);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunCommsLive(uint durationSec, int enableJson, int dumpMode);

    // 驱动内存 dump 元数据导出 (CommsMonitor 期间 DumpTargetDriver 收集的元数据)
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetDriverDumpInfo(out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetScanHandlesData(uint targetPid, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetTreeData(ulong pid, int maxDepth, int jsonOut, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CombNative_GetSecurityData(ulong pid, uint flags, out uint outSize);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void CombNative_StopComms();

    // ─── 数据导出公共 API ──────────────────────────────────────────
    //  返回 NativeDataResult<T>, 调用方应在 using 块中使用

    public NativeDataResult<CbnClassifyEntry> GetScanAndClassifyData()
        => new(CombNative_GetScanAndClassifyData(out _));

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

    public NativeDataResult<CbnCommsSummary> GetCommsData(uint durationSec, bool enableJson, int dumpMode)
        => new(CombNative_GetCommsData(durationSec, enableJson ? 1 : 0, dumpMode, out _));

    /// <summary>
    /// 通信监控实时订阅: 注册回调后运行, 每收到一个 IOCTL 通信事件通过回调实时通知。
    /// 回调中接收 CbnCommsEvent 结构体指针, 调用方在回调中将数据加入 C# 类。
    /// 运行结束后回调自动清零。
    /// </summary>
    public int RunCommsLive(uint durationSec, bool enableJson, int dumpMode,
                            IntPtr callback, IntPtr context)
    {
        CombNative_SetCommsEventCallback(callback, context);
        int ret = CombNative_RunCommsLive(durationSec, enableJson ? 1 : 0, dumpMode);
        CombNative_SetCommsEventCallback(IntPtr.Zero, IntPtr.Zero);
        return ret;
    }

    /// <summary>
    /// 获取已收集的驱动内存 dump 元数据 (CommsMonitor 期间 DumpTargetDriver 收集)。
    /// 返回 CbnDriverDumpInfo 列表, 由 NativeDataResult 包装并负责释放原生缓冲区。
    /// </summary>
    public NativeDataResult<CbnDriverDumpInfo> GetDriverDumpInfo()
        => new(CombNative_GetDriverDumpInfo(out _));

    public NativeDataResult<CbnHandleEntry> GetScanHandlesData(uint targetPid)
        => new(CombNative_GetScanHandlesData(targetPid, out _));

    public NativeDataResult<CbnProcBrief> GetTreeData(ulong pid, int maxDepth, bool jsonOut)
        => new(CombNative_GetTreeData(pid, maxDepth, jsonOut ? 1 : 0, out _));

    public NativeDataResult<CbnProcDetail> GetSecurityData(ulong pid, uint flags)
        => new(CombNative_GetSecurityData(pid, flags, out _));

    // ─── 停止接口 ──────────────────────────────────────────────────
    // 主动停止通信监控 (非阻塞, 实际线程 ~200ms 内退出)
    public void StopComms() => CombNative_StopComms();
}
