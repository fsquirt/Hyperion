using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 与 KernelService 驱动通信的集中式 P/Invoke 层。
/// 所有内核结构体布局严格对齐 KernelService/*.h，默认 8 字节自然对齐，
/// IOCTL 码由 CTL_CODE(FILE_DEVICE_UNKNOWN, func, METHOD_BUFFERED, FILE_ANY_ACCESS) 推算:
///   (0x22 &lt;&lt; 16) | (0 &lt;&lt; 14) | (func &lt;&lt; 2) | 0
/// </summary>
public static class KernelServiceIo
{
    public const uint IOCTL_SCAN_LOADED_DRIVERS = 0x222010; // func 0x804
    public const uint IOCTL_ENUM_DRIVER_DEVICES = 0x222014; // func 0x805
    public const uint IOCTL_ATTACH_DEVICE       = 0x222018; // func 0x806
    public const uint IOCTL_DETACH_DEVICE       = 0x22201C; // func 0x807
    public const uint IOCTL_QUERY_ATTACHMENTS   = 0x222020; // func 0x808
    public const uint IOCTL_DUMP_DRIVER_MEMORY   = 0x222024; // func 0x809

    public const string DevicePath = @"\\.\KernelService";

    // ETW IOCTL 拦截 Provider，与 KernelService/EtwLogger.h 一致
    public static readonly Guid EtwIoctlProviderGuid =
        new(0xA7B3C9D2, 0x4E5F, 0x4A1B, 0x9C, 0x8E, 0x7D, 0x6F, 0x5E, 0x4A, 0x3B, 0x2C);

    // 事件 Id，与 KernelService/EtwLogger.h 一致
    public const ushort EtwEventIoctlIntercept = 1;   // IOCTL 拦截
    public const ushort EtwEventImageLoad = 2;        // 游戏进程 DLL/映像加载
    public const ushort EtwEventThreadAntiDebug = 3;  // 新线程反调试,即远程线程注入预警

    //  设备打开 / 关闭
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize,
        IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;

    public static IntPtr OpenDevice()
    {
        IntPtr h = CreateFile(DevicePath, GENERIC_READ | GENERIC_WRITE, 0,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == IntPtr.Zero || h == new IntPtr(-1))
        {
            Console.Error.WriteLine($"[KS] OpenDevice failed: {Marshal.GetLastWin32Error()}");
            return IntPtr.Zero;
        }
        return h;
    }

    /// <summary>
    /// 通用同步 DeviceIoControl。返回 true 表示成功，bytesReturned 为实际返回字节数。
    /// 失败时调用方用 Marshal.GetLastWin32Error() 取错误码。
    /// </summary>
    public static unsafe bool IoControl(IntPtr hDevice, uint ioctl,
        byte[]? inBuffer, byte[] outBuffer, out uint bytesReturned)
    {
        bytesReturned = 0;
        IntPtr inPtr = IntPtr.Zero;
        try
        {
            if (inBuffer != null)
            {
                inPtr = Marshal.AllocHGlobal(inBuffer.Length);
                Marshal.Copy(inBuffer, 0, inPtr, inBuffer.Length);
            }

            if (outBuffer == null)
            {
                return DeviceIoControl(hDevice, ioctl,
                    inPtr, inBuffer == null ? 0u : (uint)inBuffer.Length,
                    IntPtr.Zero, 0, out bytesReturned, IntPtr.Zero);
            }

            // 用 fixed 钉住输出缓冲: P/Invoke 形参为 IntPtr,编组器不会固定数组,
            // 阻塞的 DeviceIoControl 期间 GC 移动数组会让内核写入陈旧地址 → 堆损坏
            fixed (byte* pOut = outBuffer)
            {
                return DeviceIoControl(hDevice, ioctl,
                    inPtr, inBuffer == null ? 0u : (uint)inBuffer.Length,
                    (IntPtr)pOut, (uint)outBuffer.Length,
                    out bytesReturned, IntPtr.Zero);
            }
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
        }
    }

    //  内核对齐结构体，与 KernelService/*.h 一致
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class LoadedDriverEntry
    {
        public ulong ImageBase;
        public uint ImageSize;
        public ushort LoadOrderIndex;
        public ushort Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ModuleName = "";
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FullPath = "";
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string DriverObjectName = "";
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class ScanDriversResponse
    {
        public uint EntryCount;
        public uint TotalCount;
        public uint NeededOutputBytes;
        public int ScanStatus; // NTSTATUS
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class EnumDevicesRequest
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string DriverName = "";
        public uint MaxEntries;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class DeviceEntry
    {
        public ulong DeviceObject;
        public uint DeviceType;
        public uint Characteristics;
        public uint Flags;
        public ushort AttachedCount;
        public ushort StackSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DeviceName = "";
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class EnumDevicesResponse
    {
        public uint EntryCount;
        public uint TotalCount;
        public uint NeededOutputBytes;
        public int Status; // NTSTATUS
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 96)] public string FoundPath = "";
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class AttachDeviceRequest
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DevicePath = "";
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class AttachDeviceResponse
    {
        public int Status; // NTSTATUS
        public uint AttachId;
        public ulong FilterDeviceAddr;
        public ulong LowerDeviceAddr;
        public ushort NewStackSize;
        public ushort TargetStackSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class DetachDeviceRequest
    {
        public uint AttachId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string DevicePath = "";
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class DetachDeviceResponse
    {
        public int Status; // NTSTATUS
        public uint DetachedId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class AttachEntry
    {
        public ulong FilterDeviceAddr;
        public ulong LowerDeviceAddr;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string TargetPath = "";
        public uint AttachId;
        public ushort StackSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class QueryAttachmentsResponse
    {
        public uint Count;
        public uint NeededOutputBytes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class DumpDriverMemoryRequest
    {
        public uint AttachId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public sealed class DumpDriverMemoryResponse
    {
        public int Status; // NTSTATUS
        public ulong DriverObjectAddr;
        public ulong ImageBase;
        public uint ImageSize;
        public uint BytesDumped;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FullPath = "";
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string BaseName = "";
    }

    //  结构化解析辅助：对齐 C++ memcpy 字段拷贝，避免数组打包歧义
    public static T ReadStruct<T>(byte[] buf, int offset) where T : class, new()
    {
        int size = Marshal.SizeOf<T>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(buf, offset, ptr, size);
            return Marshal.PtrToStructure<T>(ptr)!;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    public static T ReadStruct<T>(IntPtr ptr) where T : class, new()
        => Marshal.PtrToStructure<T>(ptr)!;

    /// <summary>将结构体序列化为字节数组，用于 IOCTL 输入缓冲区。</summary>
    public static byte[] StructToBytes<T>(T obj) where T : class
    {
        int size = Marshal.SizeOf<T>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(obj, ptr, false);
            byte[] buf = new byte[size];
            Marshal.Copy(ptr, buf, 0, size);
            return buf;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }
}
