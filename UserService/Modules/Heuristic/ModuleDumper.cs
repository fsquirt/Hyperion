using System.Runtime.InteropServices;
using System.Text;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 用户态模块 dump + 磁盘文件拷贝（移植自 HeuristicDumper/ModuleDumper.cpp）。
/// 默认 Raw 模式：从进程内存 ReadProcessMemory 原始映像，按模块路径去重；
/// 磁盘上存在则拷贝到 FileDump\（RHS 文件加前缀）。
/// </summary>
public sealed class ModuleDumper
{
    private readonly string _dumpDir;
    private readonly string _fileDumpDir;
    private readonly object _lock = new();
    private readonly HashSet<string> _dumpedRaw = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _fileCopied = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<ulong> _miniDumpedPid = new(); // 每进程只产一份 minidump（按 PID 去重）

    public string DumpDir => _dumpDir;
    public string FileDumpDir => _fileDumpDir;

    public ModuleDumper(string baseDir)
    {
        _dumpDir = Path.Combine(baseDir, "dumpfile");
        _fileDumpDir = Path.Combine(baseDir, "FileDump");
        try
        {
            Directory.CreateDirectory(_dumpDir);
            Directory.CreateDirectory(_fileDumpDir);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[MD] 创建 dump 目录失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 对一个进程模块做完整取证：内存原始映像 dump + 磁盘副本拷贝。
    /// 通过进程模块表查找 base/size。去重基于路径。
    /// </summary>
    public void DumpProcessModule(ulong pid, string modulePath)
    {
        if (string.IsNullOrEmpty(modulePath)) return;

        var table = StackResolver.BuildModuleTable(pid);
        var m = table.FirstOrDefault(x =>
            x.Path.Equals(modulePath, StringComparison.OrdinalIgnoreCase));

        ulong baseAddr = m?.Base ?? 0;
        uint size = m?.Size ?? 0;

        bool diskMissing = GetFileAttributesW(modulePath) == INVALID_FILE_ATTRIBUTES;
        bool rhs = !diskMissing && (GetFileAttributesW(modulePath) &
            (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;

        string note = diskMissing ? "[磁盘上不存在!]" : (rhs ? "[RHS]" : "");

        // 内存映像（Raw 模式，需要 base+size；缺失时跳过）
        if (baseAddr != 0 && size != 0)
        {
            string? dumpFile = DumpModuleRaw(pid, modulePath, baseAddr, size, diskMissing || rhs, note);
            if (dumpFile != null)
                Console.WriteLine($"    [md] 内存映像已保存: dumpfile\\{dumpFile}");
        }
        else if (!diskMissing)
        {
            Console.WriteLine($"    [md] 内存模块基址无效，仅拷贝磁盘文件: {modulePath}");
        }

        // 磁盘副本
        if (!diskMissing)
        {
            string? copyName = CopyFileFromDisk(modulePath, rhs);
            if (copyName != null)
                Console.WriteLine($"    [md] 已拷贝磁盘文件: FileDump\\{copyName}");
        }
    }

    private string? DumpModuleRaw(ulong pid, string modulePath, ulong baseAddr, uint size,
        bool abnormal, string note)
    {
        lock (_lock)
        {
            if (_dumpedRaw.Contains(modulePath)) return null;
            _dumpedRaw.Add(modulePath);
        }

        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (int)pid);
        if (hProc == IntPtr.Zero) return null;
        try
        {
            var buf = new byte[size];
            if (!ReadProcessMemory(hProc, (IntPtr)baseAddr, buf, (IntPtr)size, out IntPtr read)
                || read == IntPtr.Zero)
            {
                Console.Error.WriteLine($"    [md] ReadProcessMemory 失败: {modulePath}");
                return null;
            }

            string dumpName = MakeDumpName(modulePath, abnormal, note);
            string dumpPath = Path.Combine(_dumpDir, dumpName);
            try
            {
                File.WriteAllBytes(dumpPath, buf);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"    [md] 写 dump 失败 {dumpPath}: {ex.Message}");
                return null;
            }
            return dumpName;
        }
        finally { CloseHandle(hProc); }
    }

    private string? CopyFileFromDisk(string modulePath, bool rhs)
    {
        lock (_lock)
        {
            if (_fileCopied.Contains(modulePath)) return null;
            _fileCopied.Add(modulePath);
        }

        string baseName = Path.GetFileName(modulePath);
        string copyName = baseName;
        if (rhs) copyName = "RHS_" + baseName;
        string copyPath = Path.Combine(_fileDumpDir, copyName);

        if (CopyFileExW(modulePath, copyPath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0))
            return copyName;
        return null;
    }

    /// <summary>
    /// 针对"未签名模块 ↔ 被附着驱动"交互场景，额外生成一份进程 minidump（含线程上下文/句柄表/模块列表），
    /// 供服务端在进程上下文中逆向分析该未签名模块。按 PID 去重，避免同进程多模块重复 dump。
    /// 文件名带触发模块名，便于与 raw 映像/磁盘副本对应。
    /// </summary>
    public void DumpProcessMiniDump(ulong pid, string modulePath)
    {
        if (pid == 0 || string.IsNullOrEmpty(modulePath)) return;

        lock (_lock)
        {
            if (_miniDumpedPid.Contains(pid)) return; // 同进程已产过，跳过
            _miniDumpedPid.Add(pid);
        }

        string baseName = Path.GetFileName(modulePath);
        string dumpName = $"MiniDump_{Path.GetFileNameWithoutExtension(baseName)}_{pid}.dmp";
        string dumpPath = Path.Combine(_dumpDir, dumpName);
        if (File.Exists(dumpPath)) return;

        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
            false, (int)pid);
        if (hProc == IntPtr.Zero)
        {
            Console.Error.WriteLine($"    [md] minidump OpenProcess 失败 PID={pid}: {Marshal.GetLastWin32Error()}");
            return;
        }
        try
        {
            IntPtr hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, IntPtr.Zero,
                CREATE_ALWAYS, 0, IntPtr.Zero);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                Console.Error.WriteLine($"    [md] minidump 创建文件失败 {dumpPath}: {Marshal.GetLastWin32Error()}");
                return;
            }
            try
            {
                // MiniDumpNormal | WithHandleData | WithUnloadedModules | WithProcessThreadData
                // 提供线程上下文/句柄表/模块列表；模块原始字节已由 DumpProcessModule 单独取走
                int dumpType = (int)(MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithProcessThreadData);
                if (MiniDumpWriteDump(hProc, (int)pid, hFile, dumpType,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                {
                    Console.WriteLine($"    [md] minidump 已保存: dumpfile\\{dumpName}");
                }
                else
                {
                    Console.Error.WriteLine($"    [md] MiniDumpWriteDump 失败 PID={pid}: {Marshal.GetLastWin32Error()}");
                }
            }
            finally { CloseHandle(hFile); }
        }
        finally { CloseHandle(hProc); }
    }

    private static string MakeDumpName(string modulePath, bool abnormal, string note)
    {
        string baseName = Path.GetFileName(modulePath);
        if (!abnormal) return baseName;
        string prefix = note.Contains("不存在") ? "MISSING_"
                      : note.Contains("RHS") ? "RHS_"
                      : "ABNORMAL_";
        return prefix + baseName;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CopyFileExW(string lpExistingFileName, string lpNewFileName,
        IntPtr lpProgressRoutine, IntPtr lpData, IntPtr pbCancel, uint dwCopyFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("dbghelp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile,
        int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

    private const uint PROCESS_QUERY_INFORMATION = 0x400;
    private const uint PROCESS_VM_READ = 0x10;
    private const uint PROCESS_DUP_HANDLE = 0x40;
    private const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
    private const uint FILE_ATTRIBUTE_READONLY = 0x1;
    private const uint FILE_ATTRIBUTE_HIDDEN = 0x2;
    private const uint FILE_ATTRIBUTE_SYSTEM = 0x4;

    private const uint GENERIC_WRITE = 0x40000000;
    private const uint CREATE_ALWAYS = 2;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // MiniDumpWriteDump DumpType 标志
    private const uint MiniDumpWithHandleData = 0x00000004;
    private const uint MiniDumpWithUnloadedModules = 0x00000020;
    private const uint MiniDumpWithProcessThreadData = 0x00000100;
}
