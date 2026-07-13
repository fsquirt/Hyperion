using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules.DriverAttach;

/// <summary>
/// 调用 IOCTL_ENUM_DRIVER_DEVICES 枚举指定驱动创建的设备列表（对齐 KernelComms.cpp::EnumDriverDevices）。
/// </summary>
public static class DeviceEnumerator
{
    public static (List<KernelServiceIo.DeviceEntry> Devices, string FoundPath) Enum(
        IntPtr hDevice, string driverName, uint maxEntries = 0)
    {
        var devices = new List<KernelServiceIo.DeviceEntry>();
        string foundPath = "";

        Console.WriteLine($"  [ENUM] 查询设备: DriverName='{driverName}'");

        var req = new KernelServiceIo.EnumDevicesRequest
        {
            DriverName = driverName.Length >= 64 ? driverName.Substring(0, 63) : driverName,
            MaxEntries = maxEntries
        };
        byte[] reqBytes = KernelServiceIo.StructToBytes(req);

        int headerSize = Marshal.SizeOf<KernelServiceIo.EnumDevicesResponse>();
        int entrySize = Marshal.SizeOf<KernelServiceIo.DeviceEntry>();
        byte[] outBuf = new byte[headerSize + 16 * entrySize];

        for (int retry = 0; retry < 3; retry++)
        {
            if (KernelServiceIo.IoControl(hDevice, KernelServiceIo.IOCTL_ENUM_DRIVER_DEVICES,
                    reqBytes, outBuf, out uint bytesReturned))
            {
                if (bytesReturned < headerSize)
                {
                    Console.WriteLine($"  [ENUM] '{driverName}' 返回字节不足: {bytesReturned} < {headerSize}");
                    return (devices, foundPath);
                }
                var resp = KernelServiceIo.ReadStruct<KernelServiceIo.EnumDevicesResponse>(outBuf, 0);
                foundPath = resp.FoundPath;
                if (resp.Status != 0)
                {
                    Console.WriteLine($"  [ENUM] '{driverName}' 内核状态=0x{resp.Status & 0xFFFFFFFF:X8} " +
                                      $"({DecodeNtStatus(resp.Status)}) FoundPath='{foundPath}' (返回 {bytesReturned}B)");
                    return (devices, foundPath); // 驱动不存在等
                }
                int need = headerSize + (int)resp.EntryCount * entrySize;
                if (bytesReturned < need)
                {
                    Console.WriteLine($"  [ENUM] '{driverName}' 缓冲区偏小: {bytesReturned} < {need} (需 {resp.NeededOutputBytes}B)");
                    return (devices, foundPath);
                }
                int off = headerSize;
                for (int i = 0; i < resp.EntryCount; i++)
                {
                    devices.Add(KernelServiceIo.ReadStruct<KernelServiceIo.DeviceEntry>(outBuf, off));
                    off += entrySize;
                }
                Console.WriteLine($"  [ENUM] '{driverName}' 找到设备 {resp.EntryCount}/{resp.TotalCount} " +
                                  $"FoundPath='{foundPath}'");
                return (devices, foundPath);
            }

            int err = Marshal.GetLastWin32Error();
            Console.WriteLine($"  [ENUM] '{driverName}' IoControl 失败 err={err} (0x{err:X8})");
            if (err == 122 || err == 234)
            {
                if (bytesReturned >= headerSize)
                {
                    var resp = KernelServiceIo.ReadStruct<KernelServiceIo.EnumDevicesResponse>(outBuf, 0);
                    if (resp.NeededOutputBytes > outBuf.Length && resp.NeededOutputBytes < 4 * 1024 * 1024)
                    {
                        outBuf = new byte[resp.NeededOutputBytes];
                        continue;
                    }
                }
                if (outBuf.Length * 2 > 4 * 1024 * 1024) return (devices, foundPath);
                outBuf = new byte[outBuf.Length * 2];
                continue;
            }
            return (devices, foundPath);
        }
        return (devices, foundPath);
    }

    /// <summary>
    /// 把内核返回的常见 NTSTATUS 翻译成可读文本（仅覆盖本项目关心的几个）。
    /// </summary>
    private static string DecodeNtStatus(int status)
    {
        uint s = (uint)status;
        return s switch
        {
            0x00000000 => "STATUS_SUCCESS",
            0xC0000034 => "STATUS_OBJECT_NAME_NOT_FOUND",
            0xC0000022 => "STATUS_ACCESS_DENIED",
            0xC0000023 => "STATUS_BUFFER_TOO_SMALL",
            0xC000000D => "STATUS_INVALID_PARAMETER",
            0xC00000BB => "STATUS_NOT_SUPPORTED",
            _ => "NTSTATUS(0x" + s.ToString("X8") + ")"
        };
    }
}
