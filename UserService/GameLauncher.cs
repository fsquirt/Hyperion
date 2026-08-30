using System.Runtime.InteropServices;

namespace Hyperion.UserService;

/// <summary>
/// 游戏进程启动器 — 用 CREATE_SUSPENDED 启动,便于在恢复执行前设置 PPL
/// </summary>
public static class GameLauncher
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    // explorer 权限启动所需:打开 explorer 进程做父进程欺骗 + 取其令牌构造环境块
    private const uint PROCESS_CREATE_PROCESS = 0x0080;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = new(0x00020000);

    // CharSet.Unicode 必须显式声明:CreateProcess P/Invoke 是 Unicode 版(CreateProcessW),
    // 结构体不声明 CharSet 时其内 string 字段默认按 ANSI(LPSTR)封送,会导致布局错位/字符串解释错误
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    /// <summary>扩展启动信息(带属性列表),用于父进程欺骗。</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")]
    private static extern bool CreateProcessEx(
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList, uint dwFlags, IntPtr attribute,
        IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// 以 CREATE_SUSPENDED 方式启动游戏,返回挂起的进程信息(调用方需调用 Resume 后进程才执行)
    /// </summary>
    /// <param name="exePath">可执行文件完整路径</param>
    /// <param name="workingDir">工作目录(传 null 用 exe 所在目录)</param>
    /// <returns>(成功?, PID, hProcess, hThread);失败时句柄为 IntPtr.Zero</returns>
    public static (bool Success, uint Pid, IntPtr hProcess, IntPtr hThread) StartSuspended(
        string exePath, string? workingDir = null)
    {
        if (!File.Exists(exePath))
        {
            Console.Error.WriteLine($"[Launcher] File not found: {exePath}");
            return (false, 0, IntPtr.Zero, IntPtr.Zero);
        }

        var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        var dir = workingDir ?? Path.GetDirectoryName(exePath);

        // lpCommandLine 需要可写缓冲,且首参数通常用引号包裹 exe 路径
        string cmdLine = $"\"{exePath}\"";

        bool ok = CreateProcess(
            null,
            cmdLine,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            IntPtr.Zero,
            dir,
            ref si,
            out PROCESS_INFORMATION pi);

        if (!ok)
        {
            var err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[Launcher] CreateProcess failed: error {err}");
            return (false, 0, IntPtr.Zero, IntPtr.Zero);
        }

        Console.Error.WriteLine($"[Launcher] Process created suspended: PID={pi.dwProcessId}");
        return (true, pi.dwProcessId, pi.hProcess, pi.hThread);
    }

    /// <summary>
    /// 以 explorer 权限启动游戏(同样 CREATE_SUSPENDED 挂起)。
    ///
    /// 做法:把当前会话的 explorer.exe 设为新进程的父进程(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
    /// 系统按父进程令牌创建游戏进程 —— 得到的是标准用户令牌(不继承 UserService 的管理员/提升令牌),
    /// 环境变量也从 explorer 令牌重建,游戏就像用户自己双击启动的一样。
    ///
    /// 之所以不用 CreateProcessWithTokenW / CreateProcessAsUser:
    /// 前者在 PPL 进程里无法调用,后者要求 SYSTEM 权限,UserService 两者都不满足。
    ///
    /// 注意:这里<b>不</b>设置 PROC_THREAD_ATTRIBUTE_JOB_LIST —— 作业对象由调用方在挂起期间
    /// 通过 AssignProcessToJobObject 接入 GameJobMonitor(见 GameJobMonitor.Create),
    /// 若创建时就塞进匿名 Job,后续再 Assign 会因进程已归属 Job 而失败。
    /// </summary>
    /// <param name="exePath">可执行文件完整路径</param>
    /// <param name="workingDir">工作目录(传 null 用 exe 所在目录)</param>
    /// <returns>(成功?, PID, hProcess, hThread);失败时句柄为 IntPtr.Zero</returns>
    public static (bool Success, uint Pid, IntPtr hProcess, IntPtr hThread) StartSuspendedAsExplorer(
        string exePath, string? workingDir = null)
    {
        if (!File.Exists(exePath))
        {
            Console.Error.WriteLine($"[Launcher] File not found: {exePath}");
            return (false, 0, IntPtr.Zero, IntPtr.Zero);
        }

        // 1. 定位当前会话的 explorer.exe
        uint explorerPid = FindExplorerPid();
        if (explorerPid == 0)
        {
            Console.Error.WriteLine("[Launcher] No explorer.exe in current session, cannot launch as explorer");
            return (false, 0, IntPtr.Zero, IntPtr.Zero);
        }

        IntPtr hExplorer = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr pEnvBlock = IntPtr.Zero;
        IntPtr pAttrList = IntPtr.Zero;
        IntPtr pParentMem = IntPtr.Zero;

        try
        {
            // 2. 打开 explorer:PROCESS_CREATE_PROCESS 用于父进程欺骗,TOKEN_QUERY|TOKEN_DUPLICATE 用于取环境块
            hExplorer = OpenProcess(PROCESS_CREATE_PROCESS | TOKEN_QUERY | TOKEN_DUPLICATE, false, explorerPid);
            if (hExplorer == IntPtr.Zero)
            {
                Console.Error.WriteLine($"[Launcher] OpenProcess(explorer PID={explorerPid}) failed: error {Marshal.GetLastWin32Error()}");
                return (false, 0, IntPtr.Zero, IntPtr.Zero);
            }

            // 3. 用 explorer 令牌重建环境块(USERPROFILE / APPDATA 等必须是用户的,不是管理员的)
            if (OpenProcessToken(hExplorer, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken))
            {
                if (!CreateEnvironmentBlock(out pEnvBlock, hToken, false))
                {
                    Console.Error.WriteLine($"[Launcher] CreateEnvironmentBlock failed: error {Marshal.GetLastWin32Error()}, fallback to inherited env");
                    pEnvBlock = IntPtr.Zero;
                }
            }
            else
            {
                Console.Error.WriteLine($"[Launcher] OpenProcessToken(explorer) failed: error {Marshal.GetLastWin32Error()}, fallback to inherited env");
            }

            // 4. 初始化属性列表(仅 1 个属性:父进程)
            IntPtr listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
            if (listSize == IntPtr.Zero)
            {
                Console.Error.WriteLine($"[Launcher] InitializeProcThreadAttributeList sizing failed: error {Marshal.GetLastWin32Error()}");
                return (false, 0, IntPtr.Zero, IntPtr.Zero);
            }
            pAttrList = Marshal.AllocHGlobal(listSize);
            if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, ref listSize))
            {
                Console.Error.WriteLine($"[Launcher] InitializeProcThreadAttributeList failed: error {Marshal.GetLastWin32Error()}");
                return (false, 0, IntPtr.Zero, IntPtr.Zero);
            }

            pParentMem = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pParentMem, hExplorer);
            if (!UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    pParentMem, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
            {
                Console.Error.WriteLine($"[Launcher] UpdateProcThreadAttribute(ParentProcess) failed: error {Marshal.GetLastWin32Error()}");
                return (false, 0, IntPtr.Zero, IntPtr.Zero);
            }

            // 5. 创建挂起进程
            var siex = new STARTUPINFOEX
            {
                StartupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFOEX>(),
                    lpDesktop = @"winsta0\default",   // 落在交互式桌面,保证游戏窗口可见
                },
                lpAttributeList = pAttrList,
            };

            string cmdLine = $"\"{exePath}\"";
            string? dir = workingDir ?? Path.GetDirectoryName(exePath);

            bool ok = CreateProcessEx(
                null,
                cmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                pEnvBlock,
                dir,
                ref siex,
                out PROCESS_INFORMATION pi);

            if (!ok)
            {
                Console.Error.WriteLine($"[Launcher] CreateProcess(explorer) failed: error {Marshal.GetLastWin32Error()}");
                return (false, 0, IntPtr.Zero, IntPtr.Zero);
            }

            Console.Error.WriteLine($"[Launcher] Process created suspended as explorer: PID={pi.dwProcessId} (parent=explorer {explorerPid})");
            return (true, pi.dwProcessId, pi.hProcess, pi.hThread);
        }
        finally
        {
            if (pAttrList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(pAttrList);
                Marshal.FreeHGlobal(pAttrList);
            }
            if (pParentMem != IntPtr.Zero) Marshal.FreeHGlobal(pParentMem);
            if (pEnvBlock != IntPtr.Zero) DestroyEnvironmentBlock(pEnvBlock);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hExplorer != IntPtr.Zero) CloseHandle(hExplorer);
        }
    }

    /// <summary>
    /// 查找当前会话中 explorer.exe 的 PID,找不到返回 0。
    /// 必须限定同一会话,否则 RDP / 多用户场景下会拿到别人的 explorer。
    /// </summary>
    private static uint FindExplorerPid()
    {
        try
        {
            int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
            foreach (var p in System.Diagnostics.Process.GetProcessesByName("explorer"))
            {
                try
                {
                    if (p.SessionId == sessionId)
                    {
                        uint pid = (uint)p.Id;
                        p.Dispose();
                        return pid;
                    }
                }
                catch
                {
                    // 进程已退出等,跳过
                }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Launcher] Enumerate explorer failed: {ex.Message}");
        }
        return 0;
    }

    /// <summary>
    /// 恢复挂起的主线程,让进程开始执行
    /// </summary>
    /// <param name="hThread">StartSuspended 返回的 hThread</param>
    /// <returns>之前的挂起计数(0 表示本来未挂起,1 表示正常恢复)</returns>
    public static uint Resume(IntPtr hThread)
    {
        uint prev = ResumeThread(hThread);
        if (prev == uint.MaxValue)
        {
            var err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[Launcher] ResumeThread failed: error {err}");
            return uint.MaxValue;
        }
        else
        {
            Console.Error.WriteLine($"[Launcher] Thread resumed (prev suspend count={prev})");
        }
        return prev;
    }

    /// <summary>
    /// 关闭进程/线程句柄
    /// </summary>
    public static void CloseHandles(IntPtr hProcess, IntPtr hThread)
    {
        if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        if (hThread != IntPtr.Zero) CloseHandle(hThread);
    }
}

/// <summary>
/// 游戏作业对象(Job Object)监控器。
///
/// 游戏主进程放入 Job 后,其创建的所有后代进程(孙进程)被自动限制在同一 Job 中
/// (如旧版 CS 挂在 HL 启动器进程下的多进程场景),并通过绑定的 I/O 完成端口收到通知:
///   - JOB_OBJECT_MSG_NEW_PROCESS(6)      → 新进程加入 Job(overlapped 参数即 PID),供上层自动施加保护链
///   - JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO(4) → Job 内活动进程清零 = 游戏整体退出
///
/// 游戏退出判定以此为准,不再盯主进程句柄(主进程先退、后代继续跑时仍保持保护与监控)。
/// 设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 保持"同生共死":UserService 异常退出时
/// 句柄关闭,整个 Job(含全部后代)被系统终止。
/// </summary>
public sealed class GameJobMonitor : IDisposable
{
    private const int JobObjectAssociateCompletionPortInformation = 7;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
    private const uint JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4;

    private readonly IntPtr _hJob;
    private readonly IntPtr _hIOCP;
    private readonly uint _mainPid;
    private readonly Thread _listenerThread;
    private bool _disposed;

    /// <summary>新后代进程加入 Job(Job 监听线程触发,回调须快速返回)。</summary>
    public event Action<uint>? DescendantProcessCreated;

    /// <summary>Job 内活动进程清零(游戏整体退出)。</summary>
    public event Action? AllProcessesExited;

    private GameJobMonitor(IntPtr hJob, IntPtr hIOCP, uint mainPid)
    {
        _hJob = hJob;
        _hIOCP = hIOCP;
        _mainPid = mainPid;
        _listenerThread = new Thread(ListenLoop)
        {
            IsBackground = true,
            Name = "GameJobMonitor",
        };
    }

    /// <summary>
    /// 创建 Job 并把主进程放入。失败返回 null(调用方决定是否致命)。
    /// 必须在主进程 Resume 之前调用(挂起时 Assign,无窗口期)。
    /// </summary>
    public static GameJobMonitor? Create(IntPtr hGameProcess, uint mainPid)
    {
        // 1. 创建 Job Object
        IntPtr hJob = CreateJobObject(IntPtr.Zero, null);
        if (hJob == IntPtr.Zero)
        {
            Console.Error.WriteLine($"[Job] CreateJobObject failed: error {Marshal.GetLastWin32Error()}");
            return null;
        }

        // 2. 创建 I/O 完成端口
        IntPtr hIOCP = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, IntPtr.Zero, 1);
        if (hIOCP == IntPtr.Zero)
        {
            Console.Error.WriteLine($"[Job] CreateIoCompletionPort failed: error {Marshal.GetLastWin32Error()}");
            CloseHandle(hJob);
            return null;
        }

        // 3. Job 绑定完成端口(后续 NEW_PROCESS / ACTIVE_PROCESS_ZERO 都投递到这里)
        var port = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT
        {
            CompletionKey = hJob,
            CompletionPort = hIOCP,
        };
        if (!SetInformationJobObject(hJob, JobObjectAssociateCompletionPortInformation,
                ref port, (uint)Marshal.SizeOf<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>()))
        {
            Console.Error.WriteLine($"[Job] SetInformationJobObject(AssociateCompletionPort) failed: error {Marshal.GetLastWin32Error()}");
            CloseHandle(hIOCP);
            CloseHandle(hJob);
            return null;
        }

        // 4. KILL_ON_JOB_CLOSE:UserService 异常退出时句柄关闭 → 整个 Job 被终止(同生共死兜底)
        var limit = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                ref limit, (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
        {
            Console.Error.WriteLine($"[Job] SetInformationJobObject(KillOnJobClose) failed: error {Marshal.GetLastWin32Error()} (non-fatal)");
        }

        // 5. 主进程加入 Job(后代进程继承,自动被限制在同一 Job 内)
        if (!AssignProcessToJobObject(hJob, hGameProcess))
        {
            Console.Error.WriteLine($"[Job] AssignProcessToJobObject failed: error {Marshal.GetLastWin32Error()}");
            CloseHandle(hIOCP);
            CloseHandle(hJob);
            return null;
        }

        Console.Error.WriteLine($"[Job] Game job created, main PID={mainPid} assigned (descendants auto-confined)");

        var job = new GameJobMonitor(hJob, hIOCP, mainPid);
        job._listenerThread.Start();
        return job;
    }

    /// <summary>终止 Job 内全部进程(用户主动退出时清理用)。</summary>
    public void Terminate()
    {
        Console.Error.WriteLine("[Job] Terminating all processes in job");
        TerminateJobObject(_hJob, 0);
    }

    // ─────────────────────────────────────────────────────────────
    //  完成端口监听线程
    // ─────────────────────────────────────────────────────────────

    private void ListenLoop()
    {
        while (true)
        {
            if (!GetQueuedCompletionStatus(_hIOCP,
                    out uint bytesTransferred, out IntPtr completionKey,
                    out IntPtr overlapped, uint.MaxValue))
            {
                // Dispose 投递的退出标记(overlapped = -1)
                if (overlapped == new IntPtr(-1)) break;
                // 其他错误(句柄被关闭等),一并退出
                Console.Error.WriteLine($"[Job] GetQueuedCompletionStatus failed: error {Marshal.GetLastWin32Error()}");
                break;
            }

            if (bytesTransferred == JOB_OBJECT_MSG_NEW_PROCESS)
            {
                // 新进程加入 Job,overlapped 字段即其 PID
                uint newPid = (uint)overlapped.ToInt64();
                if (newPid != 0 && newPid != _mainPid)
                {
                    Console.Error.WriteLine($"[Job] Descendant process created: PID={newPid}");
                    try { DescendantProcessCreated?.Invoke(newPid); }
                    catch (Exception ex) { Console.Error.WriteLine($"[Job] Descendant callback exception: {ex.Message}"); }
                }
            }
            else if (bytesTransferred == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO)
            {
                Console.Error.WriteLine("[Job] Active process count is zero, game fully exited");
                try { AllProcessesExited?.Invoke(); }
                catch (Exception ex) { Console.Error.WriteLine($"[Job] Exit callback exception: {ex.Message}"); }
                break;
            }
            // 其他消息(EXIT_PROCESS / ABNORMAL_EXIT_PROCESS 等)只关注上面两个,忽略
        }

        Console.Error.WriteLine("[Job] Listener thread exiting");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // 投递退出标记(overlapped = -1),监听线程收到后退出
        PostQueuedCompletionStatus(_hIOCP, 0, IntPtr.Zero, new IntPtr(-1));
        try { _listenerThread.Join(3000); } catch { }

        CloseHandle(_hIOCP);
        CloseHandle(_hJob);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Win32
    // ═══════════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob, int jobObjectInfoClass,
        ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT lpJobObjectInformation, uint cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob, int jobObjectInfoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation, uint cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateIoCompletionPort(IntPtr fileHandle, IntPtr existingCompletionPort, IntPtr completionKey, uint numberOfConcurrentThreads);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetQueuedCompletionStatus(
        IntPtr completionPort, out uint lpNumberOfBytesTransferred,
        out IntPtr lpCompletionKey, out IntPtr lpOverlapped, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool PostQueuedCompletionStatus(
        IntPtr completionPort, uint dwNumberOfBytesTransferred, IntPtr dwCompletionKey, IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
}
