using System.Runtime.InteropServices;
using System.Text;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 内核驱动内存 dump（移植自 HeuristicDumper/DriverDumper.cpp）。
/// 按 AttachId 通过 KernelService 的 IOCTL_DUMP_DRIVER_MEMORY 取对端 sys 映像：
/// 磁盘有文件 → 拷贝到 FileCopy（RHS 加前缀）；磁盘缺失 → 从内存 dump 到 DebugDump（MISSING_ 前缀）。
/// 同一 AttachId 只处理一次（对端驱动不变）。
/// </summary>
public sealed class DriverDumper
{
    private readonly IntPtr _hKernelService;
    private readonly string _dumpDir;
    private readonly string _fileCopyDir;
    private readonly object _lock = new();
    private readonly HashSet<uint> _driverDumped = new();

    public DriverDumper(IntPtr hKernelService, string dumpDir, string fileCopyDir)
    {
        _hKernelService = hKernelService;
        _dumpDir = dumpDir;
        _fileCopyDir = fileCopyDir;
    }

    public void DumpTargetDriver(uint attachId)
    {
        if (attachId == 0 || _hKernelService == IntPtr.Zero) return;

        lock (_lock)
        {
            if (_driverDumped.Contains(attachId)) return;
            _driverDumped.Add(attachId);
        }

        // 第一次：探测响应头拿 ImageSize + 路径
        var req = new KernelServiceIo.DumpDriverMemoryRequest { AttachId = attachId };
        byte[] reqBytes = KernelServiceIo.StructToBytes(req);
        byte[] outBuf = new byte[Marshal.SizeOf<KernelServiceIo.DumpDriverMemoryResponse>()];
        if (!KernelServiceIo.IoControl(_hKernelService, KernelServiceIo.IOCTL_DUMP_DRIVER_MEMORY,
                reqBytes, outBuf, out uint _))
        {
            Console.Error.WriteLine($"  [dd] dump 失败: DeviceIoControl 探测失败 {Marshal.GetLastWin32Error()}");
            return;
        }

        var resp = KernelServiceIo.ReadStruct<KernelServiceIo.DumpDriverMemoryResponse>(outBuf, 0);
        if (resp.Status != 0)
        {
            Console.Error.WriteLine($"  [dd] dump 失败: 内核返回 Status=0x{unchecked((uint)resp.Status):X8}");
            return;
        }

        string fullPath = resp.FullPath ?? "";
        string baseName = string.IsNullOrEmpty(resp.BaseName) ? $"driver_{attachId}.sys" : resp.BaseName;

        string physPath = TranslatePath(fullPath);

        uint attr = GetFileAttributesW(physPath);
        bool diskHas = attr != INVALID_FILE_ATTRIBUTES;

        Console.WriteLine($"  [dd] 对端 sys: {(string.IsNullOrEmpty(physPath) ? baseName : physPath)} " +
                          $"(ImageBase=0x{resp.ImageBase:X} Size={resp.ImageSize})");

        // 磁盘有 → 拷贝到 FileCopy
        if (diskHas)
        {
            string copyName = baseName;
            if ((attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0)
                copyName = "RHS_" + baseName;
            string copyPath = Path.Combine(_fileCopyDir, copyName);
            if (CopyFileExW(physPath, copyPath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0))
                Console.WriteLine($"  [dd] 已拷贝驱动: FileCopy\\{copyName}");
            else
                Console.Error.WriteLine($"  [dd] 驱动拷贝失败: {copyName} err={Marshal.GetLastWin32Error()}");
        }

        // 无论磁盘有没有，都从内存 dump 一份到 DebugDump
        if (resp.ImageSize > 0)
        {
            outBuf = new byte[Marshal.SizeOf<KernelServiceIo.DumpDriverMemoryResponse>() + (int)resp.ImageSize];
            if (!KernelServiceIo.IoControl(_hKernelService, KernelServiceIo.IOCTL_DUMP_DRIVER_MEMORY,
                    reqBytes, outBuf, out uint _))
            {
                Console.Error.WriteLine($"  [dd] 驱动内存 dump 失败: {Marshal.GetLastWin32Error()}");
                return;
            }
            var resp2 = KernelServiceIo.ReadStruct<KernelServiceIo.DumpDriverMemoryResponse>(outBuf, 0);
            if (resp2.BytesDumped == 0)
            {
                Console.Error.WriteLine("  [dd] 驱动内存 dump: BytesDumped=0");
                return;
            }

            string dumpName = baseName;
            if (!diskHas) dumpName = "MISSING_" + baseName;
            string dumpPath = Path.Combine(_dumpDir, dumpName);

            try
            {
                byte[] img = new byte[resp2.BytesDumped];
                Array.Copy(outBuf, Marshal.SizeOf<KernelServiceIo.DumpDriverMemoryResponse>(),
                    img, 0, (int)resp2.BytesDumped);
                File.WriteAllBytes(dumpPath, img);
                Console.WriteLine($"  [dd] 驱动内存已保存: DebugDump\\{dumpName} ({resp2.BytesDumped} 字节)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"  [dd] 驱动写文件失败: {ex.Message}");
            }
        }
    }

    private static string TranslatePath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return fullPath;
        if (fullPath.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase))
        {
            var sb = new StringBuilder(MAX_PATH);
            if (GetWindowsDirectoryW(sb, MAX_PATH) > 0)
                return Path.Combine(sb.ToString(), fullPath.Substring(12).TrimStart('\\'));
        }
        else if (fullPath.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
        {
            return fullPath.Substring(4);
        }
        return fullPath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CopyFileExW(string lpExistingFileName, string lpNewFileName,
        IntPtr lpProgressRoutine, IntPtr lpData, IntPtr pbCancel, uint dwCopyFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowsDirectoryW(StringBuilder lpBuffer, int uSize);

    private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
    private const uint FILE_ATTRIBUTE_READONLY = 0x1;
    private const uint FILE_ATTRIBUTE_HIDDEN = 0x2;
    private const uint FILE_ATTRIBUTE_SYSTEM = 0x4;
    private const int MAX_PATH = 260;
}
