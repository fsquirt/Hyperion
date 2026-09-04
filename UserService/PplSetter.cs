using System.Runtime.InteropServices;

namespace Hyperion.UserService;

/// <summary>
/// 通过 DeviceIoControl 调用 KernelService 驱动设置进程 PPL
/// </summary>
public static class PplSetter
{
    private const uint IOCTL_SET_PPL = 0x00222000;
    private const uint IOCTL_TERMINATE_PROCESS = 0x00222004;
    private const uint IOCTL_WAIT_LOADIMAGE = 0x00222008;  // Method=0,Func=0x802,Access=0
    private const uint IOCTL_CANCEL_LOADIMAGE = 0x0022200C; // Func=0x803 同上编码

    // GameProtect 系列 (Driver.c): CTL_CODE(FILE_DEVICE_UNKNOWN, func, METHOD_BUFFERED, FILE_ANY_ACCESS)
    // 编码公式 = (0x22<<16) | (func<<2)。func: 0x80A~0x810
    private const uint IOCTL_GAMEPROTECT_START = 0x00222028; // func 0x80A  句柄降级保护
    private const uint IOCTL_GAMEPROTECT_STOP = 0x0022202C;  // func 0x80B  停止句柄降级保护
    private const uint IOCTL_GAMEPROTECT_DROPHANDLES = 0x00222030; // func 0x80C 丢弃高危句柄
    private const uint IOCTL_GAMEPROTECT_MONITOR_IMAGELOAD = 0x00222034; // func 0x80D 设置 ImageLoad 监控
    private const uint IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG = 0x00222038; // func 0x80E 新线程反调试
    private const uint IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG_STOP = 0x0022203C; // func 0x80F 停止新线程反调试
    private const uint IOCTL_GAMEPROTECT_ALREADY_THREAD_ANTIDEBUG = 0x00222040; // func 0x810 已有线程反调试
    private const string DEVICE_PATH = @"\\.\KernelService";

    // LOADIMAGE_NOTIFY 结构,须与驱动 DriverMonitor.h 一致
    // ULONG_PTR ImageBase (8) + ULONG ImageSize (4) + 2字节对齐 + WCHAR[260] (520)
    // 注意:不能用 Pack=1! 驱动端 C 结构体默认对齐,ULONG_PTR(8) + ULONG(4) + 2字节padding + WCHAR[260](520) = 536
    // C# Pack=1 会算成 532,导致 DeviceIoControl 报 ERROR_INSUFFICIENT_BUFFER (122)
    [StructLayout(LayoutKind.Sequential)]
    public struct LoadImageNotify
    {
        public ulong ImageBase;
        public uint ImageSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ImageName;
    }

    // 异步版 DeviceIoControl,用于反向调用 IOCTL_WAIT_LOADIMAGE
    // 与上面 byte[] 版本用不同签名,通过 EntryPoint 别名避免冲突
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
    private static extern bool DeviceIoControlPtr(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(
        IntPtr hFile,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(
        IntPtr hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds);

    [StructLayout(LayoutKind.Sequential)]
    public struct OverlappedStruct
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint OffsetLow;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    // PPL Signer types (must match ProcessProtect.h)
    public const byte PsProtectedSignerNone = 0;
    public const byte PsProtectedSignerAuthenticode = 1;
    public const byte PsProtectedSignerCodeGen = 2;
    public const byte PsProtectedSignerAntimalware = 3;
    public const byte PsProtectedSignerLsa = 4;
    public const byte PsProtectedSignerWindows = 5;
    public const byte PsProtectedSignerWinTcb = 6;
    public const byte PsProtectedSignerWinSystem = 7;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        byte[] lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForMultipleObjects(
        uint nCount, IntPtr[] lpHandles, bool bWaitAll, uint dwMilliseconds);

    private const uint WAIT_FAILED = 0xFFFFFFFF;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint INFINITE = 0xFFFFFFFF;

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    /// <summary>
    /// 验证指定 PID 是否仍存在且进程名与预期匹配
    /// 用于防止 PID 复用攻击:游戏退出后 PID 可能被分配给任何进程,包括杀软等 PPL 进程
    /// 使用 System.Diagnostics.Process 查询,内部用 ToolHelp32 快照,不需要 OpenProcess
    /// 任务管理器也是用此 API 显示进程列表,PPL 进程也可查询
    /// </summary>
    /// <param name="pid">目标 PID</param>
    /// <param name="expectedExeName">预期的可执行文件名,例如 "osu!.exe",不区分大小写</param>
    /// <returns>true 表示 PID 存在且 exe 名匹配</returns>
    public static bool VerifyProcessExeName(uint pid, string expectedExeName)
    {
        // Process.ProcessName 不含 .exe 后缀,去掉后缀比较
        string expectedNameNoExt = Path.GetFileNameWithoutExtension(expectedExeName);

        try
        {
            // GetProcessById 找不到 PID 会抛 ArgumentException,即进程已退出
            var proc = System.Diagnostics.Process.GetProcessById((int)pid);
            // ProcessName 对 PPL 进程也可获取,.NET 内部用 ToolHelp32,有 OpenProcess 失败的回退
            string actualName = proc.ProcessName;
            bool match = string.Equals(actualName, expectedNameNoExt,
                StringComparison.OrdinalIgnoreCase);
            Console.Error.WriteLine($"[PPL] VerifyProcess: PID {pid} = '{actualName}', expected '{expectedNameNoExt}', match={match}");
            return match;
        }
        catch (ArgumentException)
        {
            // PID 不在进程列表中,说明进程已退出
            Console.Error.WriteLine($"[PPL] VerifyProcess: PID {pid} not found (process exited)");
            return false;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[PPL] VerifyProcess: PID {pid} query failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 设置指定进程为 PPL (Protected Process Light)
    /// </summary>
    /// <param name="pid">目标进程 ID</param>
    /// <param name="signerType">签名者类型，默认 Antimalware (3)</param>
    /// <returns>true 表示成功</returns>
    public static bool SetPpl(uint pid, byte signerType = PsProtectedSignerAntimalware)
    {
        IntPtr handle = OpenDevice();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;

        try
        {
            // PPL_REQUEST struct: ULONG_PTR Pid (8 bytes on x64) + UCHAR SignerType (1 byte)
            // On x64 this is 16 bytes due to alignment
            byte[] request = new byte[16];
            BitConverter.GetBytes((ulong)pid).CopyTo(request, 0);
            request[8] = signerType;

            bool ok = DeviceIoControl(
                handle,
                IOCTL_SET_PPL,
                request,
                (uint)request.Length,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);

            if (!ok)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[PPL] DeviceIoControl(SET_PPL) failed: error {err}");
                return false;
            }

            Console.Error.WriteLine($"[PPL] PPL set on PID {pid} (signer={signerType})");
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// 通过驱动结束指定进程,也可结束 PPL 进程
    /// </summary>
    /// <param name="pid">目标进程 ID</param>
    /// <returns>true 表示成功</returns>
    public static bool KillProcess(uint pid)
    {
        IntPtr handle = OpenDevice();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;

        try
        {
            // TERMINATE_REQUEST struct: ULONG_PTR Pid (8 bytes on x64)
            byte[] request = new byte[8];
            BitConverter.GetBytes((ulong)pid).CopyTo(request, 0);

            bool ok = DeviceIoControl(
                handle,
                IOCTL_TERMINATE_PROCESS,
                request,
                (uint)request.Length,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);

            if (!ok)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[PPL] DeviceIoControl(TERMINATE) failed: error {err}");
                return false;
            }

            Console.Error.WriteLine($"[PPL] Terminate request sent for PID {pid}");
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  GameProtect 系列:句柄降级、ImageLoad 监控、线程反调试、高危句柄丢弃
    //  输入结构 GAMEPROTECT_REQUEST = ULONG_PTR Pid,x64 上占 8 字节,与 TERMINATE_REQUEST 同构
    // ══════════════════════════════════════════════════════════════════

    /// <summary>同步发送带 PID 的 GAMEPROTECT 请求,使用短生命周期句柄。</summary>
    private static bool SendGameProtectPid(uint ioctl, uint pid)
    {
        IntPtr handle = OpenDevice();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;

        try
        {
            byte[] request = new byte[8];
            BitConverter.GetBytes((ulong)pid).CopyTo(request, 0);

            bool ok = DeviceIoControl(handle, ioctl, request, (uint)request.Length,
                IntPtr.Zero, 0, out _, IntPtr.Zero);
            if (!ok)
                Console.Error.WriteLine($"[PPL] DeviceIoControl(0x{ioctl:X8}, pid={pid}) failed: error {Marshal.GetLastWin32Error()}");
            return ok;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>同步发送无输入的 GAMEPROTECT 请求,使用短生命周期句柄。</summary>
    private static bool SendGameProtectVoid(uint ioctl)
    {
        IntPtr handle = OpenDevice();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;

        try
        {
            bool ok = DeviceIoControl(handle, ioctl, Array.Empty<byte>(), 0,
                IntPtr.Zero, 0, out _, IntPtr.Zero);
            if (!ok)
                Console.Error.WriteLine($"[PPL] DeviceIoControl(0x{ioctl:X8}) failed: error {Marshal.GetLastWin32Error()}");
            return ok;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// 对目标进程启用句柄降级保护:通过 Ob 回调剥夺外部进程持有的高危进程与线程句柄权限。
    /// 内核 add 语义:加入保护列表,上限 16 个,与已有受保护进程共存,幂等;进程退出自动摘槽。
    /// </summary>
    public static bool GameProtectStart(uint pid)
    {
        bool ok = SendGameProtectPid(IOCTL_GAMEPROTECT_START, pid);
        Console.Error.WriteLine($"[PPL] GameProtectStart(pid={pid}) = {ok}");
        return ok;
    }

    /// <summary>停止句柄降级保护,清空全部受保护进程。</summary>
    public static bool GameProtectStop()
    {
        bool ok = SendGameProtectVoid(IOCTL_GAMEPROTECT_STOP);
        Console.Error.WriteLine($"[PPL] GameProtectStop() = {ok}");
        return ok;
    }

    /// <summary>丢弃其他进程握有的指向目标游戏进程的高危句柄,权限为 VM_READ/WRITE/OPERATION。</summary>
    public static bool GameProtectDropHandles(uint pid)
    {
        bool ok = SendGameProtectPid(IOCTL_GAMEPROTECT_DROPHANDLES, pid);
        Console.Error.WriteLine($"[PPL] GameProtectDropHandles(pid={pid}) = {ok}");
        return ok;
    }

    /// <summary>
    /// 设置 ImageLoad 监控目标 PID,用户态 DLL 加载事件经 ETW ID2 回传。
    /// 内核 add 语义:加入监控列表,与已有目标共存,幂等;pid=0 清空全部并关闭监控。
    /// </summary>
    public static bool SetImageLoadMonitor(uint pid)
    {
        bool ok = SendGameProtectPid(IOCTL_GAMEPROTECT_MONITOR_IMAGELOAD, pid);
        Console.Error.WriteLine($"[PPL] SetImageLoadMonitor(pid={pid}) = {ok}");
        return ok;
    }

    /// <summary>
    /// 开启新线程反调试:目标进程新建线程时执行 ThreadHideFromDebugger,事件经 ETW ID3 回传。
    /// 内核 add 语义:加入反调试列表,与已有目标共存,幂等。
    /// </summary>
    public static bool SetThreadAntiDebug(uint pid)
    {
        bool ok = SendGameProtectPid(IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG, pid);
        Console.Error.WriteLine($"[PPL] SetThreadAntiDebug(pid={pid}) = {ok}");
        return ok;
    }

    /// <summary>停止新线程反调试,卸载线程创建回调。</summary>
    public static bool StopThreadAntiDebug()
    {
        bool ok = SendGameProtectVoid(IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG_STOP);
        Console.Error.WriteLine($"[PPL] StopThreadAntiDebug() = {ok}");
        return ok;
    }

    /// <summary>对目标进程已有的全部线程执行反调试,即设置 ThreadHideFromDebugger。</summary>
    public static bool HideExistingThreads(uint pid)
    {
        bool ok = SendGameProtectPid(IOCTL_GAMEPROTECT_ALREADY_THREAD_ANTIDEBUG, pid);
        Console.Error.WriteLine($"[PPL] HideExistingThreads(pid={pid}) = {ok}");
        return ok;
    }

    /// <summary>
    /// 打开 KernelService 设备句柄的公开版,供 WaitLoadImage 等长生命周期操作使用
    /// 调用方负责 CloseHandle
    /// </summary>
    public static IntPtr OpenDeviceHandle()
    {
        return OpenDevice();
    }

    /// <summary>
    /// 通知驱动立即完成所有挂起的 IOCTL_WAIT_LOADIMAGE IRP,完成状态为 STATUS_CANCELLED。
    /// 在 Cleanup 早期调用,让监控线程的 WaitForMultipleObjects 立即返回,
    /// 避免依赖 WDF cancel 机制,因为 CancelIoEx → EvtRequestCancel 路径不可靠。
    ///
    /// 调用约定: 用独立的短生命周期设备句柄同步调用,不传 OVERLAPPED。
    //            不能复用主监控句柄:同一句柄上有挂起的 overlapped IRP 时,
    //            同步 IO 会被 IO Manager 阻塞。必须新开一个句柄。
    /// 驱动端 EvtIoDeviceControl 收到后调 DriverMonitorCancelAllPendingRequests,
    /// 同步完成所有挂起的 WDFREQUEST。本调用返回时,挂起的 IRP 已被驱动完成,
    /// 监控线程的 hEvent 已信号,此时调用 CloseHandle 关闭主设备句柄不会阻塞。
    /// </summary>
    /// <returns>true 表示已通知驱动</returns>
    public static bool CancelLoadImage()
    {
        IntPtr handle = OpenDevice();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.Error.WriteLine("[PPL] CancelLoadImage: failed to open device");
            return false;
        }

        try
        {
            Console.Error.WriteLine("[PPL] CancelLoadImage: sending IOCTL_CANCEL_LOADIMAGE");
            bool ok = DeviceIoControlPtr(
                handle,
                IOCTL_CANCEL_LOADIMAGE,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _,
                IntPtr.Zero);

            if (!ok)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[PPL] CancelLoadImage: DeviceIoControl failed: error {err}");
                return false;
            }

            Console.Error.WriteLine("[PPL] CancelLoadImage: IOCTL completed, pending IRPs should be done");
            return true;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    /// <summary>
    /// 反向调用: 提交 IOCTL_WAIT_LOADIMAGE 挂起,等待内核回调触发完成
    /// 阻塞直到以下三种情况之一: 有新 .sys 加载则返回 true; 取消事件被信号则返回 false; 出错则返回 false
    /// </summary>
    /// <param name="deviceHandle">已打开的设备句柄</param>
    /// <param name="cancelEvent">取消事件,手动复位类型;外部信号后立即返回 false</param>
    /// <param name="notify">输出: 收到的映像信息,仅返回 true 时有效</param>
    /// <returns>true 表示收到新驱动加载通知</returns>
    public static bool WaitLoadImageOnce(IntPtr deviceHandle, IntPtr cancelEvent, out LoadImageNotify notify)
    {
        notify = default;
        // 不依赖 Marshal.SizeOf<LoadImageNotify>(),因为 C#/C 结构体对齐可能不一致
        // 用 1024 字节固定缓冲区,远大于驱动端 sizeof(LOADIMAGE_NOTIFY)=536,驱动端检查必通过
        // 字段解析用手动偏移读取,完全不依赖结构体 SizeOf
        const int BUF_SIZE = 1024;
        const int MIN_TRANSFER = 532;  // 8 + 4 + 520,驱动至少要填这么多
        IntPtr outBuf = Marshal.AllocHGlobal(BUF_SIZE);
        // leakOverlapped=true 时跳过 FreeHGlobal(ovPtr/outBuf),防 use-after-free
        // 场景: cancelEvent 信号后等驱动完成 IRP 超时,IRP 仍处于 pending 状态,驱动后续
        //       完成时会写已释放内存 → 蓝屏。泄漏交 OS 进程退出回收。
        bool leakOverlapped = false;
        try
        {
            IntPtr hEvent = CreateEvent(IntPtr.Zero, true, false, null);
            if (hEvent == IntPtr.Zero) return false;

            try
            {
                OverlappedStruct ov = default;
                ov.hEvent = hEvent;
                IntPtr ovPtr = Marshal.AllocHGlobal(Marshal.SizeOf<OverlappedStruct>());
                Marshal.StructureToPtr(ov, ovPtr, false);

                try
                {
                    // 提交 IOCTL,异步返回 ERROR_IO_PENDING
                    bool ok = DeviceIoControlPtr(
                        deviceHandle,
                        IOCTL_WAIT_LOADIMAGE,
                        IntPtr.Zero, 0,
                        outBuf, (uint)BUF_SIZE,
                        out _,
                        ovPtr);

                    if (ok)
                    {
                        // 同步完成,不应发生,但处理一下
                        notify = ParseLoadImageNotify(outBuf);
                        return true;
                    }

                    int err = Marshal.GetLastWin32Error();
                    if (err != 997) // ERROR_IO_PENDING
                    {
                        Console.Error.WriteLine($"[PPL] WaitLoadImage: DeviceIoControl failed: error {err}");
                        return false;
                    }

                    // 等待对象: IRP 完成对应 hEvent,取消对应 cancelEvent
                    IntPtr[] handles = new IntPtr[] { hEvent, cancelEvent };
                    uint waitResult = WaitForMultipleObjects(2, handles, false, INFINITE);

                    if (waitResult == 1)
                    {
                        // cancelEvent 信号: 上层 StopLoadImageMonitor 会同步调
                        // PplSetter.CancelLoadImage() 发 IOCTL_CANCEL_LOADIMAGE,
                        // 驱动收到后调 DriverMonitorCancelAllPendingRequests 直接
                        // WdfRequestCompleteWithInformation(STATUS_CANCELLED) 完成本 IRP,
                        // hEvent 会被信号。这里有限等待 hEvent 即可。
                        //
                        // 不调 CancelIoEx: 请求被 driver 持有而处于 in-flight 状态,IO Manager 无法取消,
                        //                   CancelIoEx 对这种情况无效,这正是之前的死锁根因。
                        //
                        // 不调 GetOverlappedResult(true): 会无限阻塞,若 CancelLoadImage 失败
                        //                                  则永久死锁。改用有限等待。
                        Console.Error.WriteLine("[PPL] WaitLoadImage: cancelEvent signaled, waiting for driver to complete IRP");
                        uint cancelWait = WaitForSingleObject(hEvent, 5000);
                        if (cancelWait == WAIT_OBJECT_0)
                        {
                            // IRP 已以 STATUS_CANCELLED 完成,取最终状态,不会阻塞
                            GetOverlappedResult(deviceHandle, ovPtr, out _, false);
                            Console.Error.WriteLine("[PPL] WaitLoadImage: IRP completed by driver, exiting cleanly");
                        }
                        else
                        {
                            // 超时: 驱动未完成 IRP(CancelLoadImage 失败或驱动异常)。
                            // 不能释放 ovPtr/outBuf(IRP 完成时 IO Manager 会写),标记泄漏,
                            // 交给进程退出时 OS 回收。避免 use-after-free 蓝屏。
                            Console.Error.WriteLine(
                                $"[PPL] WaitLoadImage: cancel wait timeout ({cancelWait}), IRP still pending, leaking overlapped");
                            leakOverlapped = true;
                        }
                        return false;
                    }

                    if (waitResult != 0)
                    {
                        Console.Error.WriteLine($"[PPL] WaitLoadImage: WaitForMultipleObjects failed: {waitResult}");
                        return false;
                    }

                    // 取结果
                    if (!GetOverlappedResult(deviceHandle, ovPtr, out uint transferred, true))
                    {
                        int e = Marshal.GetLastWin32Error();
                        Console.Error.WriteLine($"[PPL] WaitLoadImage: GetOverlappedResult failed: error {e}");
                        return false;
                    }

                    if (transferred < MIN_TRANSFER)
                    {
                        Console.Error.WriteLine($"[PPL] WaitLoadImage: short transfer {transferred}");
                        return false;
                    }

                    notify = ParseLoadImageNotify(outBuf);
                    return true;
                }
                finally
                {
                    if (!leakOverlapped) Marshal.FreeHGlobal(ovPtr);
                }
            }
            finally
            {
                CloseHandle(hEvent);
            }
        }
        finally
        {
            if (!leakOverlapped) Marshal.FreeHGlobal(outBuf);
        }
    }

    /// <summary>
    /// 从原始内存缓冲区解析 LOADIMAGE_NOTIFY,手动偏移读取,不依赖结构体对齐
    /// 布局: offset 0 = ULONG_PTR ImageBase (8), offset 8 = ULONG ImageSize (4), offset 12 = WCHAR[260] ImageName (520)
    /// </summary>
    private static LoadImageNotify ParseLoadImageNotify(IntPtr buf)
    {
        var result = new LoadImageNotify
        {
            ImageBase = (ulong)Marshal.ReadInt64(buf, 0),
            ImageSize = (uint)Marshal.ReadInt32(buf, 8)
        };
        // 从 offset 12 读取 WCHAR[260],最多 260 个字符
        // 注意:PtrToStringUni(buf+12,260) 会读取固定 260 字符,包括 \0 之后的填充,
        // 必须在首个 \0 处截断,否则 ImageName 携带尾随空格/空字符 —— 既污染日志,
        // 打印出一大段空白,又会让上层 Path.GetFileName 取到的"文件名"带脏后缀,
        // 与 DriverScanner 返回的干净 ModuleName 比对失败,报"未在已加载列表匹配到"。
        string rawName = Marshal.PtrToStringUni(buf + 12, 260) ?? "";
        int nul = rawName.IndexOf('\0');
        result.ImageName = (nul >= 0 ? rawName.Substring(0, nul) : rawName).Trim();
        return result;
    }

    /// <summary>
    /// 打开 KernelService 设备句柄
    /// </summary>
    private static IntPtr OpenDevice()
    {
        IntPtr handle = CreateFile(
            DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            IntPtr.Zero,
            OPEN_EXISTING,
            0x40000000,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[PPL] Failed to open device: error {err}");
        }
        return handle;
    }
}
