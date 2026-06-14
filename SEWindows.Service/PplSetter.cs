using System.Runtime.InteropServices;

namespace SEWindows.Service;

/// <summary>
/// 通过 DeviceIoControl 调用 KernelService 驱动设置进程 PPL
/// </summary>
public static class PplSetter
{
    private const uint IOCTL_SET_PPL = 0x00222000;
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

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    /// <summary>
    /// 设置指定进程为 PPL (Protected Process Light)
    /// </summary>
    /// <param name="pid">目标进程 ID</param>
    /// <param name="signerType">签名者类型，默认 Antimalware (3)</param>
    /// <returns>true 表示成功</returns>
    public static bool SetPpl(uint pid, byte signerType = PsProtectedSignerAntimalware)
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
            return false;
        }

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
                Console.Error.WriteLine($"[PPL] DeviceIoControl failed: error {err}");
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
}
