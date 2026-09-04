using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 跨态调用栈解析，对齐 EtwConsumer.cpp::PrintStackTrace + StackResolver.cpp。
/// 从 ETW 事件的 ExtendedData 取出原生栈帧地址，对地址小于 0x800000000000 的 Ring3 帧
/// 在 RequestorPid 进程模块表里查归属模块，返回调用方磁盘模块路径列表。
/// </summary>
public static class StackResolver
{
    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule,
        int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
        [Out] StringBuilder lpBaseName, int nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, int cb);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, int dwFlags,
        StringBuilder lpExeName, ref int lpdwSize);

    /// <summary>取进程主 exe 路径，用于区分通信发起方。</summary>
    public static string? GetProcessImageName(ulong pid)
    {
        if (pid == 0) return null;
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, (int)pid);
        if (hProc == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int len = sb.Capacity;
            if (QueryFullProcessImageNameW(hProc, 0, sb, ref len))
                return sb.ToString();
            return null;
        }
        finally { CloseHandle(hProc); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    private const uint PROCESS_QUERY_INFORMATION = 0x400;
    private const uint PROCESS_VM_READ = 0x10;
    private const uint LIST_MODULES_ALL = 0x03;

    public sealed class ModuleRange
    {
        public ulong Base;
        public uint Size;
        public string Path = "";
    }

    // 进程模块表缓存：枚举整个进程模块表是热路径最贵的一步。高频 IOCTL 下同一进程反复通信，
    // 模块表在通信窗口内基本不变，按 PID 缓存、无过期、FIFO 2000 上限，命中即直接复用。
    private static readonly ConcurrentDictionary<ulong, List<ModuleRange>> _tableCache = new();
    private static readonly ConcurrentQueue<ulong> _tableKeys = new();
    private const int TableCacheMax = 2000;

    public static List<ModuleRange> BuildModuleTable(ulong pid)
    {
        if (pid != 0 && _tableCache.TryGetValue(pid, out var cached))
            return cached;

        var list = BuildModuleTableUncached(pid);
        if (pid != 0)
        {
            _tableCache[pid] = list;
            _tableKeys.Enqueue(pid);
            while (_tableCache.Count > TableCacheMax)
            {
                if (_tableKeys.TryDequeue(out var old) && old != pid)
                    _tableCache.TryRemove(old, out _);
                else
                    break;
            }
        }
        return list;
    }

    private static List<ModuleRange> BuildModuleTableUncached(ulong pid)
    {
        var list = new List<ModuleRange>();
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (int)pid);
        if (hProc == IntPtr.Zero) return list;
        try
        {
            IntPtr[] mods = new IntPtr[1024];
            if (EnumProcessModulesEx(hProc, mods, mods.Length * IntPtr.Size, out int cb, LIST_MODULES_ALL))
            {
                int count = Math.Min(cb / IntPtr.Size, mods.Length);
                var sb = new StringBuilder(1024);
                for (int i = 0; i < count; i++)
                {
                    var mi = new MODULEINFO();
                    if (GetModuleInformation(hProc, mods[i], out mi, Marshal.SizeOf<MODULEINFO>()))
                    {
                        sb.Clear();
                        GetModuleFileNameExW(hProc, mods[i], sb, sb.Capacity);
                        list.Add(new ModuleRange
                        {
                            Base = (ulong)mods[i],
                            Size = mi.SizeOfImage,
                            Path = sb.ToString()
                        });
                    }
                }
            }
        }
        finally { CloseHandle(hProc); }
        return list;
    }

    /// <summary>把原始栈帧解析为调用方模块路径，去重并排除系统目录与内核态帧。</summary>
    public static List<string> ResolveCallerModules(ulong pid, ulong[] frames)
    {
        var table = BuildModuleTable(pid);
        var result = new List<string>();
        foreach (var addr in frames)
        {
            if (addr == 0 || addr >= 0x800000000000UL) continue; // 内核态跳过
            foreach (var m in table)
            {
                if (addr >= m.Base && addr < m.Base + m.Size)
                {
                    if (!result.Contains(m.Path, StringComparer.OrdinalIgnoreCase))
                        result.Add(m.Path);
                    break;
                }
            }
        }
        return result;
    }
}
