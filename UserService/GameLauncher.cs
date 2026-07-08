using System.Runtime.InteropServices;

namespace Hyperion.UserService;

/// <summary>
/// 游戏进程启动器 — 用 CREATE_SUSPENDED 启动,便于在恢复执行前设置 PPL
/// </summary>
public static class GameLauncher
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
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
