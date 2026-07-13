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
                if (bytesReturned < headerSize) return (devices, foundPath);
                var resp = KernelServiceIo.ReadStruct<KernelServiceIo.EnumDevicesResponse>(outBuf, 0);
                foundPath = resp.FoundPath;
                if (resp.Status != 0) return (devices, foundPath); // 驱动不存在等
                int need = headerSize + (int)resp.EntryCount * entrySize;
                if (bytesReturned < need) return (devices, foundPath);
                int off = headerSize;
                for (int i = 0; i < resp.EntryCount; i++)
                {
                    devices.Add(KernelServiceIo.ReadStruct<KernelServiceIo.DeviceEntry>(outBuf, off));
                    off += entrySize;
                }
                return (devices, foundPath);
            }

            int err = Marshal.GetLastWin32Error();
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
}
