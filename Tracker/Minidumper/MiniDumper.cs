using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SEWindows.Tracker.SysmonEventTracker;

namespace SEWindows.Tracker.Minidumper;

/// <summary>
/// 注入模块内存导出器。
///
/// 精准导出策略：
///   ProcessAccess/CreateRemoteThread → 标记"该进程可能被注入"
///   ImageLoad（紧跟其后）           → 精准导出这个被加载的 DLL
///   反射式注入（无 ImageLoad）      → 回退扫描 MEM_PRIVATE + 可执行内存页
/// </summary>
public static class MiniDumper
{
    // 导出目录
    private static readonly string DumpRoot = Path.Combine(AppContext.BaseDirectory, "dumps");

    // 去重：{pid}:{modulePath} → 上次 dump 时间
    private static readonly ConcurrentDictionary<string, DateTime> _recentDumps = new();
    private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(60);

    // Tracker 自身 PID
    private static readonly int _selfPid = Environment.ProcessId;

    // 受保护的游戏进程路径
    private static readonly string ProtectedGamePath =
        @"E:\PVZ\PlantsVsZombies.exe";

    // ── 事件关联：ProcessAccess/CreateRemoteThread 标记待处理，ImageLoad 精准导出 ──
    private static readonly ConcurrentDictionary<int, PendingInjection> _pendingInjections = new();
    private static readonly TimeSpan PendingWindow = TimeSpan.FromSeconds(5);

    // 反射式注入回退定时器：每 2 秒检查一次过期的 pending 信号
    private static readonly Timer _pendingTimer = new(CheckExpiredPending, null,
        TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));

    private sealed class PendingInjection
    {
        public required DateTime Timestamp { get; init; }
        public required string Trigger { get; init; }      // "ProcessAccess" / "CreateRemoteThread"
        public required string SourceImage { get; init; }   // 注入源进程
        public required string TargetImage { get; init; }   // 目标进程路径
    }

    // ═══════════════════════════════════════════════════════════════
    //  入口方法
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// ProcessAccess 事件：标记待注入，不直接 dump。
    /// </summary>
    public static void SignalProcessAccess(int targetPid, string? targetImage, string? sourceImage)
    {
        if (targetPid <= 0 || targetPid == _selfPid) return;
        if (!ShouldDump(targetPid, targetImage)) return;

        _pendingInjections[targetPid] = new PendingInjection
        {
            Timestamp = DateTime.UtcNow,
            Trigger = "ProcessAccess",
            SourceImage = sourceImage ?? "",
            TargetImage = targetImage ?? "",
        };
    }

    /// <summary>
    /// CreateRemoteThread 事件：标记待注入，不直接 dump。
    /// </summary>
    public static void SignalRemoteThread(int targetPid, string? targetImage, string? sourceImage)
    {
        if (targetPid <= 0 || targetPid == _selfPid) return;
        if (!ShouldDump(targetPid, targetImage)) return;

        _pendingInjections[targetPid] = new PendingInjection
        {
            Timestamp = DateTime.UtcNow,
            Trigger = "CreateRemoteThread",
            SourceImage = sourceImage ?? "",
            TargetImage = targetImage ?? "",
        };
    }

    /// <summary>
    /// ImageLoad 事件：检查是否有待处理的注入信号，精准导出这个 DLL。
    /// </summary>
    public static void OnImageLoad(int pid, string modulePath, string? processImage)
    {
        if (pid <= 0 || string.IsNullOrEmpty(modulePath)) return;
        if (pid == _selfPid) return;

        // 检查是否有待处理的注入信号
        if (!_pendingInjections.TryRemove(pid, out var pending))
            return;

        // 检查信号是否过期
        if (DateTime.UtcNow - pending.Timestamp > PendingWindow)
            return;

        // 检查模块是否是 Microsoft 签名的（是的话跳过）
        if (SysmonEventClassifier.CachedIsMicrosoftSignedPublic(modulePath))
            return;

        var processName = GetProcessName(pid);
        Log($"精准导出 [{pending.Trigger}]: {Path.GetFileName(modulePath)}");
        Log($"  注入源: {Path.GetFileName(pending.SourceImage)} → 目标: {processName} (PID={pid})");

        DumpModuleFromProcess(pid, modulePath, processName, pending.Trigger);
    }

    /// <summary>
    /// 反射式注入回退：扫描目标进程中 MEM_PRIVATE + 可执行内存页。
    /// 当 ProcessAccess/CreateRemoteThread 触发但 5 秒内没有 ImageLoad 时调用。
    /// </summary>
    public static void DumpExecutableMemory(int targetPid, string? targetImage, string? trigger)
    {
        if (targetPid <= 0 || targetPid == _selfPid) return;
        if (!ShouldDump(targetPid, targetImage)) return;

        var processName = GetProcessName(targetPid);
        Log($"扫描可执行内存 [{trigger}]: {processName} (PID={targetPid})");

        SafeProcessHandle hProc;
        try
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, targetPid);
            if (hProc.IsInvalid)
            {
                Log($"  OpenProcess 失败: {Marshal.GetLastWin32Error()}");
                return;
            }
        }
        catch { return; }

        using (hProc)
        {
            // 先获取已加载模块的地址范围，用于排除
            var moduleRanges = new List<(IntPtr Start, IntPtr End)>();
            foreach (var mod in EnumerateModulesInternal(targetPid))
            {
                var size = ReadImageSize(hProc, mod.BaseAddress);
                if (size > 0)
                    moduleRanges.Add((mod.BaseAddress, new IntPtr((long)mod.BaseAddress + size)));
            }

            // 枚举内存区域
            var regions = VirtualQueryExEnum(hProc);
            int dumped = 0;

            foreach (var region in regions)
            {
                // 只看 MEM_PRIVATE + 可执行
                if (region.State != MEM_COMMIT) continue;
                if (region.Type != MEM_PRIVATE) continue;
                if ((region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) continue;

                // 排除已加载模块范围内的区域
                var regionStart = region.BaseAddress;
                var regionEnd = (long)region.BaseAddress + (long)region.RegionSize;
                if (moduleRanges.Any(r => regionStart >= (long)r.Start && regionStart < (long)r.End))
                    continue;

                // 太小的跳过（可能是跳板/trampoline）
                if (region.RegionSize < 4096) continue;

                // 读取并导出
                var size = (int)Math.Min(region.RegionSize, 16 * 1024 * 1024); // 最大 16MB
                var buffer = new byte[size];

                if (!ReadProcessMemory(hProc, region.BaseAddress, buffer, size, out var bytesRead) || bytesRead == 0)
                    continue;

                // 检查是否有 MZ 头（PE 文件）或有效代码
                bool hasPE = bytesRead >= 2 && buffer[0] == 'M' && buffer[1] == 'Z';
                bool looksLikeCode = bytesRead >= 4 && (buffer[0] == 0xE9 || buffer[0] == 0xCC ||
                    (buffer[0] == 0x48 && buffer[1] == 0x89) || // mov [rsp+...], ...
                    (buffer[0] == 0x55)); // push rbp

                if (!hasPE && !looksLikeCode) continue;

                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
                var dumpDir = Path.Combine(DumpRoot, $"{processName}_{targetPid}");
                Directory.CreateDirectory(dumpDir);

                var label = hasPE ? "shellcode_pe" : "shellcode";
                var dumpPath = Path.Combine(dumpDir, $"{timestamp}_{label}_0x{(long)region.BaseAddress:X}.bin");
                File.WriteAllBytes(dumpPath, buffer[..(int)bytesRead]);

                var meta = new DumpMetadata
                {
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    Trigger = $"{trigger}_MemoryScan",
                    ProcessName = processName,
                    ProcessId = targetPid,
                    ModulePath = $"0x{(long)region.BaseAddress:X}",
                    ModuleName = label,
                    BaseAddress = $"0x{(long)region.BaseAddress:X}",
                    ImageSize = (int)bytesRead,
                    DumpFile = dumpPath,
                    IsMicrosoftSigned = false,
                    IsCatalogSigned = false,
                };
                var metaPath = Path.Combine(dumpDir, $"{timestamp}_{label}_0x{(long)region.BaseAddress:X}.meta.json");
                File.WriteAllText(metaPath, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));

                Log($"  [✓] 可执行内存: {dumpPath} ({bytesRead / 1024} KB, {(hasPE ? "PE" : "code")})");
                dumped++;
            }

            if (dumped == 0)
                Log($"  未发现可疑可执行内存区域");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  检查过期的 pending 注入信号（反射式注入回退）
    // ═══════════════════════════════════════════════════════════════

    private static void CheckExpiredPending(object? state)
    {
        var now = DateTime.UtcNow;
        foreach (var (pid, pending) in _pendingInjections)
        {
            if (now - pending.Timestamp <= PendingWindow) continue;

            // 信号过期且没有被 ImageLoad 消费 → 可能是反射式注入
            _pendingInjections.TryRemove(pid, out _);

            // 回退：扫描目标进程的可执行内存页
            try
            {
                DumpExecutableMemory(pid, pending.TargetImage, pending.Trigger);
            }
            catch (Exception ex)
            {
                Log($"反射式注入扫描异常: {ex.Message}");
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  核心：从进程内存中导出单个模块
    // ═══════════════════════════════════════════════════════════════

    private static bool DumpModuleFromProcess(int pid, string modulePath, string processName, string trigger)
    {
        var dedupKey = $"{pid}:{modulePath}";
        var now = DateTime.UtcNow;
        if (_recentDumps.TryGetValue(dedupKey, out var lastDump) && now - lastDump < DedupWindow)
        {
            Log($"  跳过（{DedupWindow.TotalSeconds}s 内已导出）: {Path.GetFileName(modulePath)}");
            return false;
        }

        SafeProcessHandle hProc;
        try
        {
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProc.IsInvalid)
            {
                Log($"  OpenProcess 失败 (PID={pid}): {Marshal.GetLastWin32Error()}");
                return false;
            }
        }
        catch { return false; }

        using (hProc)
        {
            try
            {
                var modules = EnumerateModulesInternal(pid);
                var mod = modules.FirstOrDefault(m =>
                    string.Equals(m.ModulePath, modulePath, StringComparison.OrdinalIgnoreCase));

                if (mod.BaseAddress == IntPtr.Zero)
                {
                    Log($"  模块未找到: {Path.GetFileName(modulePath)}");
                    return false;
                }

                var imageSize = ReadImageSize(hProc, mod.BaseAddress);
                if (imageSize == 0)
                {
                    imageSize = 1024 * 1024;
                    Log($"  无法读取 PE 头，使用默认大小: {imageSize} bytes");
                }

                if (imageSize > 256 * 1024 * 1024)
                {
                    Log($"  模块过大 ({imageSize / 1024 / 1024}MB)，跳过");
                    return false;
                }

                var buffer = new byte[imageSize];
                var success = ReadProcessMemory(hProc, mod.BaseAddress, buffer, imageSize, out var bytesRead);

                if (!success || bytesRead == 0)
                {
                    Log($"  ReadProcessMemory 失败: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                var timestamp = now.ToString("yyyyMMdd_HHmmss_fff");
                var moduleFileName = Path.GetFileNameWithoutExtension(modulePath);
                var moduleExt = Path.GetExtension(modulePath);
                var dumpDir = Path.Combine(DumpRoot, $"{processName}_{pid}");
                Directory.CreateDirectory(dumpDir);

                var dumpPath = Path.Combine(dumpDir, $"{timestamp}_{moduleFileName}{moduleExt}");
                File.WriteAllBytes(dumpPath, buffer[..(int)bytesRead]);

                var meta = new DumpMetadata
                {
                    Timestamp = now.ToString("o"),
                    Trigger = trigger,
                    ProcessName = processName,
                    ProcessId = pid,
                    ModulePath = modulePath,
                    ModuleName = Path.GetFileName(modulePath),
                    BaseAddress = $"0x{mod.BaseAddress:X}",
                    ImageSize = (int)bytesRead,
                    DumpFile = dumpPath,
                    IsMicrosoftSigned = false,
                    IsCatalogSigned = false,
                };
                var metaPath = Path.Combine(dumpDir, $"{timestamp}_{moduleFileName}.meta.json");
                File.WriteAllText(metaPath, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));

                _recentDumps[dedupKey] = now;

                Log($"  [✓] 已导出: {dumpPath} ({bytesRead / 1024} KB)");
                return true;
            }
            catch (Exception ex)
            {
                Log($"  导出异常: {ex.Message}");
                return false;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  PE 头解析
    // ═══════════════════════════════════════════════════════════════

    private static int ReadImageSize(SafeProcessHandle hProc, IntPtr baseAddress)
    {
        try
        {
            var dosBuf = new byte[64];
            if (!ReadProcessMemory(hProc, baseAddress, dosBuf, dosBuf.Length, out _) || dosBuf.Length < 64)
                return 0;

            var e_lfanew = BitConverter.ToInt32(dosBuf, 60);
            if (e_lfanew <= 0 || e_lfanew > 1024)
                return 0;

            var ntBuf = new byte[e_lfanew + 4 + 20 + 68];
            if (!ReadProcessMemory(hProc, baseAddress + e_lfanew, ntBuf, ntBuf.Length, out _))
                return 0;

            if (ntBuf[0] != 'P' || ntBuf[1] != 'E' || ntBuf[2] != 0 || ntBuf[3] != 0)
                return 0;

            int optHeaderOffset = 4 + 20;
            if (ntBuf.Length < optHeaderOffset + 60)
                return 0;

            var magic = BitConverter.ToUInt16(ntBuf, optHeaderOffset);
            int sizeOfImageOffset;
            if (magic == 0x20B)
                sizeOfImageOffset = optHeaderOffset + 56;
            else if (magic == 0x10B)
                sizeOfImageOffset = optHeaderOffset + 56;
            else
                return 0;

            if (ntBuf.Length < sizeOfImageOffset + 4)
                return 0;

            return BitConverter.ToInt32(ntBuf, sizeOfImageOffset);
        }
        catch { return 0; }
    }

    // ═══════════════════════════════════════════════════════════════
    //  内存区域枚举（用于反射式注入扫描）
    // ═══════════════════════════════════════════════════════════════

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private static List<MEMORY_BASIC_INFORMATION> VirtualQueryExEnum(SafeProcessHandle hProc)
    {
        var result = new List<MEMORY_BASIC_INFORMATION>();
        IntPtr address = IntPtr.Zero;
        var mbi = new MEMORY_BASIC_INFORMATION();
        uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

        while (true)
        {
            IntPtr ret;
            unsafe
            {
                ret = VirtualQueryEx(hProc, address, &mbi, mbiSize);
            }
            if (ret == IntPtr.Zero) break;
            if ((long)mbi.RegionSize <= 0) break;

            result.Add(mbi);
            address = new IntPtr((long)mbi.BaseAddress + (long)mbi.RegionSize);
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  模块枚举
    // ═══════════════════════════════════════════════════════════════

    private static List<ModuleInfo> EnumerateModulesInternal(int pid)
    {
        var result = new List<ModuleInfo>();

        try
        {
            var snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
            if (snap == INVALID_HANDLE_VALUE) return result;

            using var safeHandle = new SafeFileHandle(snap, true);
            var entry = new MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32W>() };

            if (Module32FirstW(snap, ref entry))
            {
                do
                {
                    result.Add(new ModuleInfo
                    {
                        BaseAddress = entry.modBaseAddr,
                        ModuleSize = entry.modBaseSize,
                        ModulePath = entry.szExePath,
                        ModuleName = entry.szModule,
                    });
                } while (Module32NextW(snap, ref entry));
            }
        }
        catch { }

        return result;
    }

    private static bool ShouldDump(int pid, string? targetImage)
    {
        if (!string.IsNullOrEmpty(targetImage) &&
            targetImage.Equals(ProtectedGamePath, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            using var proc = Process.GetProcessById(pid);
            var exePath = proc.MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath) &&
                SysmonEventClassifier.CachedIsMicrosoftSignedPublic(exePath))
                return true;
        }
        catch { }

        Log($"跳过（非游戏/非系统进程）: {GetProcessName(pid)} (PID={pid})");
        return false;
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch { return $"pid_{pid}"; }
    }

    // ═══════════════════════════════════════════════════════════════
    //  日志
    // ═══════════════════════════════════════════════════════════════

    private static void Log(string message)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.Write("[MINIDUMP] ");
        Console.ResetColor();
        Console.WriteLine(message);
    }

    // ═══════════════════════════════════════════════════════════════
    //  数据结构
    // ═══════════════════════════════════════════════════════════════

    private struct ModuleInfo
    {
        public IntPtr BaseAddress;
        public uint ModuleSize;
        public string ModulePath;
        public string ModuleName;
    }

    private sealed class DumpMetadata
    {
        public string Timestamp { get; set; } = "";
        public string Trigger { get; set; } = "";
        public string ProcessName { get; set; } = "";
        public int ProcessId { get; set; }
        public string ModulePath { get; set; } = "";
        public string ModuleName { get; set; } = "";
        public string BaseAddress { get; set; } = "";
        public int ImageSize { get; set; }
        public string DumpFile { get; set; } = "";
        public bool IsMicrosoftSigned { get; set; }
        public bool IsCatalogSigned { get; set; }
    }

    // ═══════════════════════════════════════════════════════════════
    //  P/Invoke
    // ═══════════════════════════════════════════════════════════════

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint TH32CS_SNAPMODULE = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        SafeProcessHandle hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Module32FirstW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Module32NextW(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern unsafe IntPtr VirtualQueryEx(
        SafeProcessHandle hProcess, IntPtr lpAddress,
        MEMORY_BASIC_INFORMATION* lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MODULEENTRY32W
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }
}
