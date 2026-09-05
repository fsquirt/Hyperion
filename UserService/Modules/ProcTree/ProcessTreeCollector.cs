using System.Runtime.InteropServices;
using System.Text;
using Hyperion.UserService.Modules.Heuristic;

namespace Hyperion.UserService.Modules.ProcTree;

/// <summary>进程概要，来自 NtQuerySystemInformation 的轻量结构。</summary>
internal sealed class ProcBrief
{
    public ulong Pid;
    public ulong Ppid;
    public string Name = "";
    public uint Session;
    public ulong WorkingSet;
    public int HandleCount;
    public int ThreadCount;
}

/// <summary>
/// 进程树快照采集，移植自 ProcessTreeSnapshot/Collector。
/// 5 维采集：进程概要 / 线程 / 模块 / 可疑内存 / 句柄 + 网络连接，网络连接用 GetExtendedTcpTable。
/// 支持全量快照与单进程快照两种模式，单进程快照含其子树。输出可直接序列化为 JSON 上报。
/// </summary>
public sealed class ProcessTreeCollector
{
    /// <summary>全系统快照，覆盖所有进程与网络连接。事件触发式，期待低频调用。</summary>
    public ProcessTreeSnapshot SnapshotFull()
    {
        var snap = new ProcessTreeSnapshot { CaptureTime = DateTime.UtcNow };
        var procs = CollectBriefs();
        foreach (var b in procs)
            snap.Processes.Add(SnapshotProcess(b.Pid) ?? BuildBriefOnly(b));
        snap.Connections = CollectTcpConnections();
        return snap;
    }

    /// <summary>单进程快照，含其子树，即本进程与所有后代进程。</summary>
    public ProcessTreeSnapshot SnapshotProcessTree(ulong rootPid)
    {
        var snap = new ProcessTreeSnapshot { CaptureTime = DateTime.UtcNow };
        var briefs = CollectBriefs();
        var inTree = new HashSet<ulong>();
        CollectDescendants(rootPid, briefs, inTree);

        foreach (var pid in inTree)
            snap.Processes.Add(SnapshotProcess(pid) ?? BuildBriefOnly(briefs.First(b => b.Pid == pid)));
        // 仅包含树内进程的网络连接
        snap.Connections = CollectTcpConnections().FindAll(c => inTree.Contains(c.Pid));
        return snap;
    }

    /// <summary>仅单个进程的快照。</summary>
    public ProcessSnapshot? SnapshotProcess(ulong pid)
    {
        try
        {
            IntPtr hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (int)pid);
            if (hProc == IntPtr.Zero) return null;
            try
            {
                var d = new ProcessSnapshot { Pid = pid, CaptureTime = DateTime.UtcNow };
                CollectBrief(pid, d);
                CollectModules(hProc, d);
                CollectThreads(pid, hProc, d);
                CollectSuspiciousMemory(hProc, d);
                CollectOwnedHandles(pid, d);
                return d;
            }
            finally { CloseHandle(hProc); }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[PT] SnapshotProcess({pid}) 异常: {ex.Message}");
            return null;
        }
    }

    //  进程枚举：NtQuerySystemInformation
    private List<ProcBrief> CollectBriefs()
    {
        var list = new List<ProcBrief>();
        uint outLen = 0;
        NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, out outLen);
        if (outLen == 0) outLen = 0x10000;
        outLen = Math.Max(outLen, (uint)0x10000) * 2;

        IntPtr buf = Marshal.AllocHGlobal((int)outLen);
        try
        {
            int status = NtQuerySystemInformation(SystemProcessInformation, buf, outLen, out uint _);
            if (status != 0) return list;

            IntPtr p = buf;
            while (true)
            {
                var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(p)!;
                var b = new ProcBrief
                {
                    Pid = (ulong)spi.UniqueProcessId,
                    Ppid = (ulong)spi.InheritedFromUniqueProcessId,
                    Name = spi.ImageName.Length > 0
                        ? spi.ImageName.Buffer == IntPtr.Zero ? ""
                        : Marshal.PtrToStringUni(spi.ImageName.Buffer, (int)(spi.ImageName.Length / 2))
                        : "",
                    Session = spi.SessionId,
                    WorkingSet = (ulong)spi.WorkingSetSize,
                    HandleCount = (int)spi.HandleCount,
                    ThreadCount = (int)spi.NumberOfThreads
                };
                list.Add(b);

                if (spi.NextEntryOffset == 0) break;
                p = IntPtr.Add(p, (int)spi.NextEntryOffset);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }

    private void CollectDescendants(ulong pid, List<ProcBrief> briefs, HashSet<ulong> outTree)
    {
        if (!outTree.Add(pid)) return;
        foreach (var b in briefs)
        {
            if (b.Ppid == pid)
                CollectDescendants(b.Pid, briefs, outTree);
        }
    }

    private ProcessSnapshot BuildBriefOnly(ProcBrief b)
    {
        return new ProcessSnapshot
        {
            Pid = b.Pid,
            Ppid = b.Ppid,
            Name = b.Name,
            Session = b.Session,
            WorkingSet = b.WorkingSet,
            ThreadCount = b.ThreadCount,
            HandleCount = b.HandleCount,
            CaptureTime = DateTime.UtcNow
        };
    }

    private void CollectBrief(ulong pid, ProcessSnapshot d)
    {
        // 概要已由调用方部分提供；这里补命令行 + 映像路径 + ppid
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (int)pid);
        if (hProc == IntPtr.Zero) return;
        try
        {
            d.Ppid = GetParentPid(hProc);
            d.ImagePath = StackResolver.GetProcessImageName(pid) ?? "";
            d.CommandLine = GetCommandLine(hProc) ?? "";
        }
        finally { CloseHandle(hProc); }
    }

    private ulong GetParentPid(IntPtr hProc)
    {
        var pbi = new PROCESS_BASIC_INFORMATION();
        int len;
        if (NtQueryInformationProcess(hProc, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out len) == 0)
            return (ulong)pbi.InheritedFromUniqueProcessId;
        return 0;
    }

    private string? GetCommandLine(IntPtr hProc)
    {
        // ProcessCommandLineInformation = 60
        const int ProcessCommandLineInformation = 60;
        int size = 1024;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            int len;
            if (NtQueryInformationProcess(hProc, ProcessCommandLineInformation, buf, size, out len) != 0)
            {
                if (len > size)
                {
                    Marshal.FreeHGlobal(buf);
                    size = len;
                    buf = Marshal.AllocHGlobal(size);
                    if (NtQueryInformationProcess(hProc, ProcessCommandLineInformation, buf, size, out len) != 0)
                        return null;
                }
                else return null;
            }
            var us = Marshal.PtrToStructure<UNICODE_STRING>(buf)!;
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        }
        catch { return null; }
        finally { Marshal.FreeHGlobal(buf); }
    }

    //  模块采集：EnumProcessModulesEx
    private void CollectModules(IntPtr hProc, ProcessSnapshot d)
    {
        const int max = 4096;
        var mods = new IntPtr[max];
        if (!EnumProcessModulesEx(hProc, mods, mods.Length * IntPtr.Size, out int cb, LIST_MODULES_ALL))
            return;
        int count = Math.Min(cb / IntPtr.Size, max);
        var sb = new StringBuilder(1024);
        for (int i = 0; i < count; i++)
        {
            var mi = new MODULEINFO();
            if (!GetModuleInformation(hProc, mods[i], out mi, Marshal.SizeOf<MODULEINFO>()))
                continue;
            sb.Clear();
            if (GetModuleFileNameExW(hProc, mods[i], sb, sb.Capacity) == 0)
                continue;
            d.Modules.Add(new ModuleInfo
            {
                Base = (ulong)mods[i],
                Size = mi.SizeOfImage,
                Path = sb.ToString(),
                Name = Path.GetFileName(sb.ToString())
            });
        }
    }

    //  线程采集：Process.Threads
    private void CollectThreads(ulong pid, IntPtr hProc, ProcessSnapshot d)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById((int)pid);
            foreach (System.Diagnostics.ProcessThread t in p.Threads)
            {
                d.Threads.Add(new ThreadInfo
                {
                    Tid = (ulong)t.Id,
                    StartAddress = (ulong)t.StartAddress.ToInt64(),
                    Win32StartAddress = (ulong)t.StartAddress.ToInt64(),
                    Suspended = t.ThreadState == System.Diagnostics.ThreadState.Wait
                                && t.WaitReason == System.Diagnostics.ThreadWaitReason.Suspended
                });
            }
        }
        catch { /* 进程可能已退出 */ }
    }

    //  可疑内存扫描：VirtualQueryEx
    private void CollectSuspiciousMemory(IntPtr hProc, ProcessSnapshot d)
    {
        ulong addr = 0x10000;
        const ulong userLimit = 0x00007FFFFFFFFFFFUL;
        while (addr < userLimit)
        {
            var mbi = new MEMORY_BASIC_INFORMATION();
            IntPtr res = VirtualQueryEx(hProc, (IntPtr)addr, ref mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            if (res == IntPtr.Zero) break;
            uint protect = mbi.Protect;
            uint state = mbi.State;
            uint type = mbi.Type;

            bool exec = (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool writable = (protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool rwX = exec && writable;
            bool rxUnbacked = exec && state == MEM_COMMIT && type == MEM_PRIVATE;

            if (rwX || rxUnbacked)
            {
                d.SuspiciousMemory.Add(new MemRegion
                {
                    Base = (ulong)mbi.BaseAddress,
                    Size = (ulong)mbi.RegionSize,
                    Protect = ProtectToString(protect),
                    Type = TypeToString(type),
                    Reason = rwX ? "RWX" : "RX-unbacked"
                });
            }

            ulong regionEnd = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
            if (regionEnd <= addr) break; // 防御
            addr = regionEnd;
        }
    }

    //  句柄采集：NtQuerySystemInformation 扩展句柄表 + DuplicateHandle
    private void CollectOwnedHandles(ulong pid, ProcessSnapshot d)
    {
        int maxEntries = 2000; // 单进程句柄上限保护
        uint outLen = (uint)(Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>() + maxEntries * Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>());
        IntPtr buf = Marshal.AllocHGlobal((int)outLen);
        try
        {
            int status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, outLen, out uint ret);
            if (status != 0)
            {
                if (ret > outLen)
                {
                    Marshal.FreeHGlobal(buf);
                    outLen = ret + 4096;
                    buf = Marshal.AllocHGlobal((int)outLen);
                    status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, outLen, out uint _);
                }
                if (status != 0) return;
            }

            int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            int hdrSize = Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>();
            int count = Marshal.ReadInt32(buf, 0);
            int collected = 0;
            for (int i = 0; i < count && collected < maxEntries; i++)
            {
                IntPtr p = IntPtr.Add(buf, hdrSize + i * entrySize);
                var e = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(p)!;
                if ((ulong)e.UniqueProcessId != pid) continue;
                collected++;

                var info = new HandleInfo
                {
                    OwnerPid = pid,
                    HandleValue = (ulong)e.HandleValue,
                    GrantedAccess = e.GrantedAccess
                };
                ResolveHandleTypeAndTarget(pid, (IntPtr)e.HandleValue, info);
                d.Handles.Add(info);
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private void ResolveHandleTypeAndTarget(ulong ownerPid, IntPtr handle, HandleInfo info)
    {
        IntPtr hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, (int)ownerPid);
        if (hOwner == IntPtr.Zero) return;
        try
        {
            if (!DuplicateHandle(hOwner, handle, GetCurrentProcess(), out IntPtr dup,
                    0, false, DUPLICATE_SAME_ACCESS))
                return;
            try
            {
                info.TypeName = GetObjectType(dup);
                if (info.TypeName.Equals("Process", StringComparison.OrdinalIgnoreCase))
                {
                    uint target = GetProcessId(dup);
                    info.TargetPid = target;
                    info.HighRisk = (info.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) != 0;
                }
                else if (info.TypeName.Equals("Thread", StringComparison.OrdinalIgnoreCase))
                {
                    info.HighRisk = (info.GrantedAccess & (THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_TERMINATE)) != 0;
                }
            }
            finally { CloseHandle(dup); }
        }
        finally { CloseHandle(hOwner); }
    }

    private string GetObjectType(IntPtr handle)
    {
        int size = 256;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            int len;
            if (NtQueryObject(handle, 2 /*ObjectTypeInformation*/, buf, size, out len) != 0)
            {
                if (len > size)
                {
                    Marshal.FreeHGlobal(buf);
                    size = len;
                    buf = Marshal.AllocHGlobal(size);
                    if (NtQueryObject(handle, 2, buf, size, out len) != 0) return "";
                }
                else return "";
            }
            // PUBLIC_OBJECT_TYPE_INFORMATION: ULONG Length; UNICODE_STRING TypeName;
            var us = Marshal.PtrToStructure<UNICODE_STRING>(buf + IntPtr.Size)!;
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        }
        catch { return ""; }
        finally { Marshal.FreeHGlobal(buf); }
    }

    //  网络连接：GetExtendedTcpTable
    private List<NetConnection> CollectTcpConnections()
    {
        var conns = new List<NetConnection>();
        const int TCP_TABLE_OWNER_PID_ALL = 0x5;
        const uint AF_INET = 2;

        int size = 8192;
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            uint ret = GetExtendedTcpTable(buf, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret == ERROR_INSUFFICIENT_BUFFER)
            {
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(size);
                ret = GetExtendedTcpTable(buf, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            }
            if (ret != 0) return conns;

            int numEntries = Marshal.ReadInt32(buf, 0);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < numEntries; i++)
            {
                IntPtr p = IntPtr.Add(buf, 4 + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(p)!;
                conns.Add(new NetConnection
                {
                    LocalAddr = row.dwLocalAddr,
                    LocalPort = ntohs((ushort)row.dwLocalPort),
                    RemoteAddr = row.dwRemoteAddr,
                    RemotePort = ntohs((ushort)row.dwRemotePort),
                    State = TcpStateToString(row.dwState),
                    Pid = row.dwOwningPid,
                    Proto = "TCP"
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return conns;
    }

    private static ushort ntohs(ushort n) => (ushort)(((n << 8) & 0xFF00) | ((n >> 8) & 0x00FF));

    private static string ProtectToString(uint p)
    {
        return p switch
        {
            PAGE_EXECUTE => "EXECUTE",
            PAGE_EXECUTE_READ => "EXECUTE_READ",
            PAGE_EXECUTE_READWRITE => "EXECUTE_READWRITE",
            PAGE_EXECUTE_WRITECOPY => "EXECUTE_WRITECOPY",
            PAGE_NOACCESS => "NOACCESS",
            PAGE_READONLY => "READONLY",
            PAGE_READWRITE => "READWRITE",
            PAGE_WRITECOPY => "WRITECOPY",
            _ => $"0x{p:X}"
        };
    }

    private static string TypeToString(uint t)
    {
        return t switch
        {
            MEM_IMAGE => "IMAGE",
            MEM_MAPPED => "MAPPED",
            MEM_PRIVATE => "PRIVATE",
            _ => $"0x{t:X}"
        };
    }

    private static string TcpStateToString(uint s)
    {
        return s switch
        {
            1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD",
            5 => "ESTABLISHED", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT", 9 => "LAST_ACK", 10 => "TIME_WAIT",
            11 => "DELETE_TCB", _ => $"{s}"
        };
    }

    
    //  原生声明
    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public ulong UniqueProcessKey;
        public ulong PeakVirtualSize;
        public ulong VirtualSize;
        public uint PageFaultCount;
        public uint PeakWorkingSetSize;
        public ulong WorkingSetSize;
        public ulong QuotaPagedPoolUsage;
        public ulong QuotaNonPagedPoolUsage;
        public ulong PagefileUsage;
        public ulong PeakPagefileUsage;
        public ulong PrivatePageCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_INFORMATION_EX
    {
        public int NumberOfHandles;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(uint infoClass, IntPtr buffer, uint length, out uint returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        IntPtr processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(IntPtr handle, int objectInformationClass,
        IntPtr objectInformation, int objectInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess,
        bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(IntPtr hProcess);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule,
        int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, int cb);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
        [Out] StringBuilder lpBaseName, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
        bool bOrder, uint ulAf, int TableClass, uint ulReserved);

    private const uint SystemProcessInformation = 0x5;
    private const uint SystemExtendedHandleInformation = 0x40;
    private const uint PROCESS_QUERY_INFORMATION = 0x400;
    private const uint PROCESS_VM_READ = 0x10;
    private const uint PROCESS_DUP_HANDLE = 0x40;
    private const uint PROCESS_VM_WRITE = 0x20;
    private const uint PROCESS_CREATE_THREAD = 0x2;
    private const uint PROCESS_VM_READ_ = 0x10;
    private const uint THREAD_SUSPEND_RESUME = 0x2;
    private const uint THREAD_SET_CONTEXT = 0x10;
    private const uint THREAD_TERMINATE = 0x1;
    private const uint DUPLICATE_SAME_ACCESS = 0x2;
    private const uint LIST_MODULES_ALL = 0x03;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;
    private const uint MEM_PRIVATE = 0x20000;
}

//  快照数据模型
public sealed class ProcessSnapshot
{
    public ulong Pid { get; set; }
    public ulong Ppid { get; set; }
    public string Name { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public uint Session { get; set; }
    public ulong WorkingSet { get; set; }
    public int ThreadCount { get; set; }
    public int HandleCount { get; set; }
    public DateTime CaptureTime { get; set; }
    public List<ModuleInfo> Modules { get; set; } = new();
    public List<ThreadInfo> Threads { get; set; } = new();
    public List<MemRegion> SuspiciousMemory { get; set; } = new();
    public List<HandleInfo> Handles { get; set; } = new();
}

public sealed class ModuleInfo
{
    public ulong Base { get; set; }
    public uint Size { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
}

public sealed class ThreadInfo
{
    public ulong Tid { get; set; }
    public ulong StartAddress { get; set; }
    public ulong Win32StartAddress { get; set; }
    public bool Suspended { get; set; }
}

public sealed class MemRegion
{
    public ulong Base { get; set; }
    public ulong Size { get; set; }
    public string Protect { get; set; } = "";
    public string Type { get; set; } = "";
    public string Reason { get; set; } = "";
}

public sealed class HandleInfo
{
    public ulong OwnerPid { get; set; }
    public ulong HandleValue { get; set; }
    public uint GrantedAccess { get; set; }
    public string TypeName { get; set; } = "";
    public ulong TargetPid { get; set; }
    public bool HighRisk { get; set; }
}

public sealed class NetConnection
{
    public uint LocalAddr { get; set; }
    public uint LocalPort { get; set; }
    public uint RemoteAddr { get; set; }
    public uint RemotePort { get; set; }
    public string State { get; set; } = "";
    public ulong Pid { get; set; }
    public string Proto { get; set; } = "";
}

public sealed class ProcessTreeSnapshot
{
    public DateTime CaptureTime { get; set; }
    public string Trigger { get; set; } = "";
    public List<ProcessSnapshot> Processes { get; set; } = new();
    public List<NetConnection> Connections { get; set; } = new();
}
