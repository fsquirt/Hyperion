using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

public class ProcessLauncher
{
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_QUERY = 0x0008;

    const uint CREATE_SUSPENDED = 0x00000004;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    const int PROCESS_CREATE_PROCESS = 0x0080;

    // 两个核心属性
    const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
    const int PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    // 使用最基础的 CreateProcess，支持 STARTUPINFOEX
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    public static bool CreateSuspendedUserProcessInJob(string commandLine)
    {
        IntPtr hExplorer = IntPtr.Zero;
        IntPtr hToken = IntPtr.Zero;
        IntPtr pEnvBlock = IntPtr.Zero;
        IntPtr hJob = IntPtr.Zero;
        IntPtr pAttributeList = IntPtr.Zero;
        IntPtr pParentHandleMem = IntPtr.Zero;
        IntPtr pJobArrayMem = IntPtr.Zero;

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFOEX siex = new STARTUPINFOEX();

        try
        {
            // 1. 获取 explorer 进程 PID
            int currentSessionId = Process.GetCurrentProcess().SessionId;
            var explorerProcess = Process.GetProcessesByName("explorer")
                                         .FirstOrDefault(p => p.SessionId == currentSessionId);
            if (explorerProcess == null) return false;

            // 2. 获取 explorer 句柄（必须拥有 PROCESS_CREATE_PROCESS 权限以进行 PPID 欺骗）
            hExplorer = OpenProcess(PROCESS_CREATE_PROCESS | TOKEN_QUERY, false, explorerProcess.Id);
            if (hExplorer == IntPtr.Zero)
            {
                Console.WriteLine($"OpenProcess (Explorer) 失败: {Marshal.GetLastWin32Error()}");
                return false;
            }

            // 3. 打开 explorer 的 token 用于提取环境变量
            if (OpenProcessToken(hExplorer, TOKEN_QUERY | TOKEN_DUPLICATE, out hToken))
            {
                CreateEnvironmentBlock(out pEnvBlock, hToken, false);
            }

            // 4. 创建 Job 对象
            hJob = CreateJobObject(IntPtr.Zero, null);

            // 5. 初始化属性列表，注意这里需要 2 个属性（Parent Process 和 Job）
            IntPtr listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref listSize);
            pAttributeList = Marshal.AllocHGlobal(listSize);
            InitializeProcThreadAttributeList(pAttributeList, 2, 0, ref listSize);

            // 6. 配置属性 1: Parent Process
            pParentHandleMem = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pParentHandleMem, hExplorer);
            UpdateProcThreadAttribute(pAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                pParentHandleMem, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            // 7. 配置属性 2: Job Object
            pJobArrayMem = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pJobArrayMem, hJob);
            UpdateProcThreadAttribute(pAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_JOB_LIST,
                pJobArrayMem, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            // 8. 设置 STARTUPINFOEX
            siex.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            siex.StartupInfo.lpDesktop = "winsta0\\default";
            siex.lpAttributeList = pAttributeList;

            uint creationFlags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
            StringBuilder cmdBuf = new StringBuilder(commandLine);

            // 9. 调用基础 CreateProcess。系统看到 ParentProcess 属性，会自动复制 explorer 的 token 并降权
            bool success = CreateProcess(
                null,
                cmdBuf,
                IntPtr.Zero,
                IntPtr.Zero,
                false, // 注意：即便是否继承句柄设为 false，父进程欺骗依然有效
                creationFlags,
                pEnvBlock,
                null,
                ref siex,
                out pi);

            if (success)
            {
                Console.WriteLine("进程创建成功 (普通用户权限)，已在内核层挂入 Job 并处于挂起状态。");

                // 此处可以安全地操作挂起的进程

                ResumeThread(pi.hThread);
                return true;
            }
            else
            {
                Console.WriteLine($"CreateProcess 失败，错误码: {Marshal.GetLastWin32Error()}");
                return false;
            }
        }
        finally
        {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pAttributeList != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(pAttributeList);
                Marshal.FreeHGlobal(pAttributeList);
            }
            if (pParentHandleMem != IntPtr.Zero) Marshal.FreeHGlobal(pParentHandleMem);
            if (pJobArrayMem != IntPtr.Zero) Marshal.FreeHGlobal(pJobArrayMem);
            if (pEnvBlock != IntPtr.Zero) DestroyEnvironmentBlock(pEnvBlock);
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hExplorer != IntPtr.Zero) CloseHandle(hExplorer);
            // hJob 根据需求决定何时 Close
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine("请输入要启动的完整程序路径:");
        string input = Console.ReadLine();
        bool result = CreateSuspendedUserProcessInJob(input);
        Console.ReadLine();
    }
}