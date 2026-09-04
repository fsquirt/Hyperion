using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules.DriverAttach;

/// <summary>
/// 调用 IOCTL_SCAN_LOADED_DRIVERS 枚举已加载内核模块，对齐 KernelComms.cpp::ScanLoadedDriversViaKernel。
/// 缓冲区不足时按驱动返回的 NeededOutputBytes 自动扩容重试。
/// </summary>
public static class DriverScanner
{
    public static List<KernelServiceIo.LoadedDriverEntry> Scan(IntPtr hDevice, uint maxEntries = 0)
    {
        var list = new List<KernelServiceIo.LoadedDriverEntry>();
        if (hDevice == IntPtr.Zero) { Marshal.GetLastWin32Error(); return list; }

        byte[] req = BitConverter.GetBytes(maxEntries);
        int headerSize = Marshal.SizeOf<KernelServiceIo.ScanDriversResponse>();
        int entrySize = Marshal.SizeOf<KernelServiceIo.LoadedDriverEntry>();
        byte[] outBuf = new byte[headerSize + 256 * entrySize];

        for (int retry = 0; retry < 3; retry++)
        {
            if (KernelServiceIo.IoControl(hDevice, KernelServiceIo.IOCTL_SCAN_LOADED_DRIVERS,
                    req, outBuf, out uint bytesReturned))
            {
                if (bytesReturned < headerSize) return list;
                var resp = KernelServiceIo.ReadStruct<KernelServiceIo.ScanDriversResponse>(outBuf, 0);
                int need = headerSize + (int)resp.EntryCount * entrySize;
                if (bytesReturned < need) return list;
                int off = headerSize;
                for (int i = 0; i < resp.EntryCount; i++)
                {
                    list.Add(KernelServiceIo.ReadStruct<KernelServiceIo.LoadedDriverEntry>(outBuf, off));
                    off += entrySize;
                }
                return list;
            }

            int err = Marshal.GetLastWin32Error();
            if (err == 122 /*ERROR_INSUFFICIENT_BUFFER*/ || err == 234 /*ERROR_MORE_DATA*/)
            {
                if (bytesReturned >= headerSize)
                {
                    var resp = KernelServiceIo.ReadStruct<KernelServiceIo.ScanDriversResponse>(outBuf, 0);
                    if (resp.NeededOutputBytes > outBuf.Length && resp.NeededOutputBytes < 16 * 1024 * 1024)
                    {
                        outBuf = new byte[resp.NeededOutputBytes];
                        continue;
                    }
                }
                if (outBuf.Length * 2 > 16 * 1024 * 1024) return list;
                outBuf = new byte[outBuf.Length * 2];
                continue;
            }
            return list;
        }
        return list;
    }
}
