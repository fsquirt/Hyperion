using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SEWindows.Tracker.SysmonEventTracker;

namespace SEWindows.Tracker.Minidumper;

/// <summary>
/// 注入模块内存导出器。
/// 检测到 HIGH 级别注入事件后，自动从目标进程内存中导出可疑模块。
/// </summary>
public static class MiniDumper
{
    // 导出目录：进程运行目录下的 dumps/
    private static readonly string DumpRoot = Path.Combine(AppContext.BaseDirectory, "dumps");

    // 去重：{pid}:{modulePath} → 上次 dump 时间，同模块 60 秒内不重复导出
    private static readonly ConcurrentDictionary<string, DateTime> _recentDumps = new();
    private static readonly TimeSpan DedupWindow = TimeSpan.FromSeconds(60);

    // Tracker 自身 PID，防止读内存时触发自己的 ProcessAccess 造成死循环
    private static readonly int _selfPid = Environment.ProcessId;

    // 受保护的游戏进程路径（与 Sysmon.xml 配置一致）
    private static readonly string ProtectedGamePath =
        @"E:\PVZ\PlantsVsZombies.exe";

    // 签名验证复用 SysmonEventClassifier 的缓存
    // 通过 CachedIsMicrosoftSigned 访问

    // ═══════════════════════════════════════════════════════════════
    //  入口方法
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// ProcessAccess 事件触发：从目标进程中导出可疑模块。
    /// </summary>
    /// <param name="targetPid">目标进程 PID。</param>
    /// <param name="targetImage">目标进程路径（来自 Sysmon TargetImage 字段）。</param>
    /// <param name="callTrace">Sysmon CallTrace。</param>
    public static void DumpFromProcessAccess(int targetPid, string? targetImage, string? callTrace)
    {
        if (targetPid <= 0) return;

        // 防止 Tracker 自己读内存触发的 ProcessAccess 造成死循环
        if (targetPid == _selfPid) return;

        if (!ShouldDump(targetPid, targetImage))
            return;

        var processName = GetProcessName(targetPid);
        Log($"ProcessAccess → 导出目标进程可疑模块: {processName} (PID={targetPid})");

        var count = DumpSuspiciousModules(targetPid, processName, "ProcessAccess");
        if (count == 0)
            Log($"  未发现非 Microsoft 签名模块");
    }

    /// <summary>
    /// CreateRemoteThread 事件触发：从目标进程中导出可疑模块。
    /// </summary>
    /// <param name="targetPid">目标进程 PID。</param>
    /// <param name="targetImage">目标进程路径（来自 Sysmon TargetImage 字段）。</param>
    public static void DumpFromRemoteThread(int targetPid, string? targetImage)
    {
        if (targetPid <= 0) return;

        // 防止 Tracker 自身操作触发的死循环
        if (targetPid == _selfPid) return;

        if (!ShouldDump(targetPid, targetImage))
            return;

        var processName = GetProcessName(targetPid);
        Log($"CreateRemoteThread → 导出目标进程可疑模块: {processName} (PID={targetPid})");

        var count = DumpSuspiciousModules(targetPid, processName, "CreateRemoteThread");
        if (count == 0)
            Log($"  未发现非 Microsoft 签名模块");
    }

    /// <summary>
    /// ImageLoad 事件触发：直接导出指定模块。
    /// </summary>
    /// <param name="pid">加载模块的进程 PID。</param>
    /// <param name="modulePath">模块完整路径。</param>
    public static void DumpModule(int pid, string modulePath)
    {
        if (pid <= 0 || string.IsNullOrEmpty(modulePath)) return;

        var processName = GetProcessName(pid);
        Log($"ImageLoad → 导出模块: {Path.GetFileName(modulePath)} (PID={pid})");

        var ok = DumpModuleFromProcess(pid, modulePath, processName, "ImageLoad");
        if (!ok)
            Log($"  导出失败");
    }

    // ═══════════════════════════════════════════════════════════════
    //  核心：导出目标进程中的可疑（非 Microsoft 签名）模块
    // ═══════════════════════════════════════════════════════════════

    private static int DumpSuspiciousModules(int pid, string processName, string trigger)
    {
        var modules = EnumerateModules(pid);
        if (modules.Count == 0) return 0;

        int dumped = 0;
        foreach (var mod in modules)
        {
            // 只导出非 Microsoft 签名的模块
            if (SysmonEventClassifier.CachedIsMicrosoftSignedPublic(mod.ModulePath))
                continue;

            if (DumpModuleFromProcess(pid, mod.ModulePath, processName, trigger))
                dumped++;
        }

        return dumped;
    }

    // ═══════════════════════════════════════════════════════════════
    //  核心：从进程内存中导出单个模块
    // ═══════════════════════════════════════════════════════════════

    private static bool DumpModuleFromProcess(int pid, string modulePath, string processName, string trigger)
    {
        // 去重检查
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
        catch
        {
            return false;
        }

        using (hProc)
        {
            try
            {
                // 1. 找到模块基址
                var modules = EnumerateModulesInternal(pid);
                var mod = modules.FirstOrDefault(m =>
                    string.Equals(m.ModulePath, modulePath, StringComparison.OrdinalIgnoreCase));

                if (mod.BaseAddress == IntPtr.Zero)
                {
                    Log($"  模块未找到: {Path.GetFileName(modulePath)}");
                    return false;
                }

                // 2. 读取 PE 头获取 SizeOfImage
                var imageSize = ReadImageSize(hProc, mod.BaseAddress);
                if (imageSize == 0)
                {
                    // 无法读取 PE 头，使用默认大小
                    imageSize = 1024 * 1024; // 1MB fallback
                    Log($"  无法读取 PE 头，使用默认大小: {imageSize} bytes");
                }

                if (imageSize > 256 * 1024 * 1024)
                {
                    Log($"  模块过大 ({imageSize / 1024 / 1024}MB)，跳过");
                    return false;
                }

                // 3. 读取模块内存
                var buffer = new byte[imageSize];
                var success = ReadProcessMemory(hProc, mod.BaseAddress, buffer, imageSize, out var bytesRead);

                if (!success || bytesRead == 0)
                {
                    Log($"  ReadProcessMemory 失败: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // 4. 写入文件
                var timestamp = now.ToString("yyyyMMdd_HHmmss_fff");
                var moduleFileName = Path.GetFileNameWithoutExtension(modulePath);
                var moduleExt = Path.GetExtension(modulePath);
                var dumpDir = Path.Combine(DumpRoot, $"{processName}_{pid}");
                Directory.CreateDirectory(dumpDir);

                var dumpPath = Path.Combine(dumpDir, $"{timestamp}_{moduleFileName}{moduleExt}");
                File.WriteAllBytes(dumpPath, buffer[..(int)bytesRead]);

                // 5. 写入元数据
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

                // 更新去重
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
    //  PE 头解析：从内存中读取 SizeOfImage
    // ═══════════════════════════════════════════════════════════════

    private static int ReadImageSize(SafeProcessHandle hProc, IntPtr baseAddress)
    {
        try
        {
            // 读取 DOS 头
            var dosBuf = new byte[64];
            if (!ReadProcessMemory(hProc, baseAddress, dosBuf, dosBuf.Length, out _) || dosBuf.Length < 64)
                return 0;

            // IMAGE_DOS_HEADER.e_lfanew = offset 60
            var e_lfanew = BitConverter.ToInt32(dosBuf, 60);
            if (e_lfanew <= 0 || e_lfanew > 1024)
                return 0;

            // 读取 NT 签名 + FileHeader + OptionalHeader 前 68 字节
            // OptionalHeader.SizeOfImage 在 OptionalHeader 偏移 56 处
            var ntBuf = new byte[e_lfanew + 4 + 20 + 68]; // signature + fileheader + partial optheader
            if (!ReadProcessMemory(hProc, baseAddress + e_lfanew, ntBuf, ntBuf.Length, out _))
                return 0;

            // 检查 NT 签名 "PE\0\0"
            if (ntBuf[0] != 'P' || ntBuf[1] != 'E' || ntBuf[2] != 0 || ntBuf[3] != 0)
                return 0;

            // OptionalHeader 从 ntBuf[4+20=24] 开始
            // SizeOfImage 在 OptionalHeader 偏移 56，即 ntBuf[24+56=80]
            int optHeaderOffset = 4 + 20;
            if (ntBuf.Length < optHeaderOffset + 60)
                return 0;

            // 检查 Magic: 0x10B=PE32, 0x20B=PE32+
            var magic = BitConverter.ToUInt16(ntBuf, optHeaderOffset);
            int sizeOfImageOffset;
            if (magic == 0x20B) // PE32+
                sizeOfImageOffset = optHeaderOffset + 56;
            else if (magic == 0x10B) // PE32
                sizeOfImageOffset = optHeaderOffset + 56;
            else
                return 0;

            if (ntBuf.Length < sizeOfImageOffset + 4)
                return 0;

            return BitConverter.ToInt32(ntBuf, sizeOfImageOffset);
        }
        catch
        {
            return 0;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  模块枚举
    // ═══════════════════════════════════════════════════════════════

    private static List<ModuleInfo> EnumerateModules(int pid)
    {
        return EnumerateModulesInternal(pid);
    }

    private static List<ModuleInfo> EnumerateModulesInternal(int pid)
    {
        var result = new List<ModuleInfo>();

        try
        {
            var snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
            if (snap == INVALID_HANDLE_VALUE)
                return result;

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
        catch
        {
            // 枚举失败，返回已收集的结果
        }

        return result;
    }

    /// <summary>
    /// 判断是否应该 dump：
    /// - 目标是受保护的游戏进程 → dump
    /// - 目标是 Microsoft 签名的系统进程 → dump
    /// - 两者都不是 → 跳过（开发工具噪音）
    /// </summary>
    private static bool ShouldDump(int pid, string? targetImage)
    {
        // 受保护的游戏进程 → dump
        if (!string.IsNullOrEmpty(targetImage) &&
            targetImage.Equals(ProtectedGamePath, StringComparison.OrdinalIgnoreCase))
            return true;

        // Microsoft 签名的系统进程 → dump
        try
        {
            using var proc = Process.GetProcessById(pid);
            var exePath = proc.MainModule?.FileName;
            if (!string.IsNullOrEmpty(exePath) &&
                SysmonEventClassifier.CachedIsMicrosoftSignedPublic(exePath))
                return true;
        }
        catch { /* 进程已退出等 */ }

        // 两者都不是 → 跳过
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
        catch
        {
            return $"pid_{pid}";
        }
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
