using System.Runtime.InteropServices;

namespace SEWindows.UserService;

/// <summary>
/// 通过 DeviceIoControl 调用 KernelService 驱动设置进程 PPL
/// </summary>
public static class PplSetter
{
    private const uint IOCTL_SET_PPL = 0x00222000;
    private const uint IOCTL_TERMINATE_PROCESS = 0x00222004;
    private const string DEVICE_PATH = @"\\.\KernelService";

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
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    private const uint TH32CS_SNAPPROCESS = 0x00000002;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public IntPtr th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    /// <summary>
    /// 验证指定 PID 是否仍存在且进程名与预期匹配
    /// 用于防止 PID 复用攻击:游戏退出后 PID 可能被分配给任何进程(包括杀软等 PPL 进程)
    /// 使用 ToolHelp32 快照枚举进程,不需要 OpenProcess,可查询 PPL 进程
    /// (任务管理器也是用此 API 显示进程列表)
    /// </summary>
    /// <param name="pid">目标 PID</param>
    /// <param name="expectedExeName">预期的可执行文件名(如 "osu!.exe"),不区分大小写</param>
    /// <returns>true 表示 PID 存在且 exe 名匹配</returns>
    public static bool VerifyProcessExeName(uint pid, string expectedExeName)
    {
        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == IntPtr.Zero || hSnapshot == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[PPL] VerifyProcess: CreateToolhelp32Snapshot failed: error {err}");
            return false;
        }

        try
        {
            var entry = new PROCESSENTRY32W();
            entry.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>();

            if (!Process32FirstW(hSnapshot, ref entry))
            {
                Console.Error.WriteLine("[PPL] VerifyProcess: Process32FirstW failed");
                return false;
            }

            do
            {
                if (entry.th32ProcessID == pid)
                {
                    bool match = string.Equals(entry.szExeFile, expectedExeName,
                        StringComparison.OrdinalIgnoreCase);
                    Console.Error.WriteLine($"[PPL] VerifyProcess: PID {pid} = '{entry.szExeFile}', expected '{expectedExeName}', match={match}");
                    return match;
                }
            }
            while (Process32NextW(hSnapshot, ref entry));

            // PID 不在进程列表中,说明进程已退出
            Console.Error.WriteLine($"[PPL] VerifyProcess: PID {pid} not found in process list (process exited)");
            return false;
        }
        finally
        {
            CloseHandle(hSnapshot);
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
    /// 通过驱动结束指定进程(可结束 PPL 进程)
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
            0,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[PPL] Failed to open device: error {err}");
        }
        return handle;
    }
}
