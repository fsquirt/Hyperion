using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 用户态模块取证（移植自 HeuristicDumper/ModuleDumper.cpp）。
/// - 磁盘文件拷贝到 FileCopy\（RHS 文件加前缀），按路径去重；
/// - 对"未签名模块 ↔ 被附着驱动"交互场景，额外生成一份进程 minidump（DebugDump\）。
/// 说明：原先的"进程模块裸内存镜像 dump"已移除（minidump 已足够，裸内存镜像无额外价值）。
/// 每产生一个取证文件，通过 <see cref="OnFileCaptured"/> 通知上报器实时上传。
/// </summary>
public sealed class ModuleDumper
{
    private readonly string _dumpDir;
    private readonly string _fileCopyDir;
    private readonly object _lock = new();
    private readonly HashSet<string> _fileCopied = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<ulong> _miniDumpedPid = new(); // 每进程只产一份 minidump（按 PID 去重）

    /// <summary>取证文件落盘后回调（路径, 类别: "FileCopy" | "DebugDump"）。</summary>
    public event Action<string, string>? OnFileCaptured;

    public string DumpDir => _dumpDir;
    public string FileCopyDir => _fileCopyDir;

    public ModuleDumper(string baseDir)
    {
        _dumpDir = Path.Combine(baseDir, "DebugDump");
        _fileCopyDir = Path.Combine(baseDir, "FileCopy");
        try
        {
            Directory.CreateDirectory(_dumpDir);
            Directory.CreateDirectory(_fileCopyDir);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[MD] 创建 dump 目录失败: {ex.Message}");
        }
    }

    /// <summary>
    /// 对一个进程模块做取证：仅拷贝磁盘副本到 FileCopy\（按路径去重）。
    /// （进程模块的裸内存镜像 dump 已移除，minidump 由 <see cref="DumpProcessMiniDump"/> 提供。）
    /// </summary>
    /// <summary>
    /// 对一个进程模块做取证：拷贝磁盘副本到 FileCopy\（按路径去重，每个模块仅处理一次）。
    /// 优先字节级拷贝（共享读 + 备份语义打开，可绕过 CopyFileExW 被安全产品拦截 / 独占锁定的场景），
    /// 失败再回退 CopyFileExW；两者都失败且源确实不存在时才报"磁盘不存在"。
    /// </summary>
    public void DumpProcessModule(ulong pid, string modulePath)
    {
        if (string.IsNullOrEmpty(modulePath)) return;

        // 同一模块路径只处理一次：避免重复拷贝与重复上传
        lock (_lock)
        {
            if (_fileCopied.Contains(modulePath)) return;
            _fileCopied.Add(modulePath);
        }

        if (TryReadCopy(modulePath, out var copyName) || TryCopyViaCopyFile(modulePath, out copyName))
        {
            Console.WriteLine($"    [md] 已拷贝磁盘文件: FileCopy\\{copyName}");
            OnFileCaptured?.Invoke(Path.Combine(_fileCopyDir, copyName!), "FileCopy");
            return;
        }

        int err = Marshal.GetLastWin32Error();
        if (GetFileAttributesW(modulePath) == INVALID_FILE_ATTRIBUTES)
            Console.WriteLine($"    [md] 模块磁盘不存在，无文件可拷贝: {modulePath}");
        else
            Console.Error.WriteLine($"    [md] 磁盘文件无法拷贝: {modulePath} (err={err})");
    }

    /// <summary>RHS（只读/隐藏/系统）文件加前缀，避免与同名普通文件冲突。</summary>
    private static string ComputeCopyName(string modulePath)
    {
        uint attr = GetFileAttributesW(modulePath);
        bool rhs = (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
        string baseName = Path.GetFileName(modulePath);
        return rhs ? "RHS_" + baseName : baseName;
    }

    /// <summary>
    /// 字节级拷贝（主路径）：以共享读 + 备份语义打开源文件，逐字节复制到 FileCopy\，
    /// 可绕过 CopyFileExW 被安全产品拦截或文件被独占锁定的场景。
    /// </summary>
    private bool TryReadCopy(string modulePath, out string? copyName)
    {
        copyName = null;
        string name = ComputeCopyName(modulePath);
        string copyPath = Path.Combine(_fileCopyDir, name);

        IntPtr hSrcRaw = CreateFileW(modulePath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (hSrcRaw == INVALID_HANDLE_VALUE) return false;
        using var safeSrc = new SafeFileHandle(hSrcRaw, ownsHandle: true);
        try
        {
            IntPtr hDstRaw = CreateFileW(copyPath, GENERIC_WRITE, 0, IntPtr.Zero,
                CREATE_ALWAYS, 0, IntPtr.Zero);
            if (hDstRaw == INVALID_HANDLE_VALUE) return false;
            using var safeDst = new SafeFileHandle(hDstRaw, ownsHandle: true);
            using var src = new FileStream(safeSrc, FileAccess.Read, 81920, false);
            using var dst = new FileStream(safeDst, FileAccess.Write, 81920, false);
            src.CopyTo(dst);
            copyName = name;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>CopyFileExW 拷贝（回退路径）。</summary>
    private bool TryCopyViaCopyFile(string modulePath, out string? copyName)
    {
        copyName = null;
        string name = ComputeCopyName(modulePath);
        string copyPath = Path.Combine(_fileCopyDir, name);
        if (CopyFileExW(modulePath, copyPath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0))
        {
            copyName = name;
            return true;
        }
        return false;
    }

    /// <summary>
    /// 针对"未签名模块 ↔ 被附着驱动"交互场景，额外生成一份进程 minidump（含线程上下文/句柄表/模块列表），
    /// 供服务端在进程上下文中逆向分析该未签名模块。按 PID 去重，避免同进程多模块重复 dump。
    /// 文件名带触发模块名，便于与磁盘副本对应。
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
                    Console.WriteLine($"    [md] minidump 已保存: DebugDump\\{dumpName}");
                    OnFileCaptured?.Invoke(dumpPath, "DebugDump");
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

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

    // 字节级回退拷贝所需标志与错误码
    private const uint GENERIC_READ = 0x80000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    private const uint GENERIC_WRITE = 0x40000000;
    private const uint CREATE_ALWAYS = 2;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    // MiniDumpWriteDump DumpType 标志
    private const uint MiniDumpWithHandleData = 0x00000004;
    private const uint MiniDumpWithUnloadedModules = 0x00000020;
    private const uint MiniDumpWithProcessThreadData = 0x00000100;
}
