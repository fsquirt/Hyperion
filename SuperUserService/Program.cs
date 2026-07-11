// SuperUserService — CombinationNative DLL 测试入口
//
// 通过 P/Invoke 调用 CombinationNative.dll, 测试三个子项目的核心功能。
//
// 用法:
//   SuperUserService.exe <命令> [参数]
//
// 命令列表:
//   init                    初始化 ntdll API
//   kernel-scan             通过 KernelService 驱动扫描已加载内核模块
//   scan-classify           驱动扫描 + 签名分类
//   scan-enum-devices       扫描 + 分类 + 设备列表 + IAT
//   enum-devices <名称>     对单个驱动名扫设备列表
//   scan-iat <sys路径>      扫描单个 .sys 的 IAT
//   attach <设备路径>       附着到设备 (如 \Device\Tcp)
//   unattach <ID|路径>      解绑附着
//   list-attach             查询当前附着列表
//   enum-classify           PSAPI 本地枚举 + 分类
//   scan-objects [目录]     扫描对象管理器命名空间
//   etw [秒数] [etl路径]    ETW 实时订阅
//   comms [秒数] [json]     ETW 通信监控
//   scan-handles <PID>      扫描持有目标 PID 的句柄
//   tree [PID] [深度] [json] 进程树打印
//   security [PID] [flags]  安全采集模式
//   help                    显示帮助

using System.Runtime.InteropServices;

namespace SuperUserService;

internal static class Program
{
    // ═══════════════════════════════════════════════════════════════════
    //  P/Invoke 声明 — 对应 CombinationNative.h 的 16 个导出函数
    // ═══════════════════════════════════════════════════════════════════

    private const string Dll = "CombinationNative.dll";

    // 初始化
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_InitNtdll();

    // DriverAttachSelector
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunKernelScan();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunScanAndClassify();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunScanAndEnumDevices();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunEnumDevices(string driverName);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunScanIAT(string filePath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunAttachDevice(string devicePath);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunUnattachDevice(string arg);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunListAttachments();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunEnumAndClassify();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_ScanObjectNamespaces(string dirs);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int CombNative_RunEtwConsumer(uint durationSec, string? etlPath);

    // HeuristicDumper
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunCommsMonitor(uint durationSec, int enableJson);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_ScanHandlesForPid(uint targetPid);

    // ProcessTreeSnapshot
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunTreeMode(ulong pid, int maxDepth, int jsonOut);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int CombNative_RunSecurityMode(ulong pid, uint flags);

    // ═══════════════════════════════════════════════════════════════════
    //  Main
    // ═══════════════════════════════════════════════════════════════════

    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0)
        {
            PrintHelp();
            return 0;
        }

        // 大部分功能需要先初始化 ntdll
        string cmd = args[0].ToLowerInvariant();

        // init 之外的所有命令先自动初始化 ntdll
        if (cmd != "help" && cmd != "init")
        {
            int r = CombNative_InitNtdll();
            if (r != 0)
                Console.WriteLine($"[警告] InitNtdll 返回 {r} (部分功能可能不可用)");
        }

        return cmd switch
        {
            "help"               => PrintHelp(),
            "init"               => RunInit(),
            "kernel-scan"        => RunKernelScan(),
            "scan-classify"      => RunScanClassify(),
            "scan-enum-devices"  => RunScanEnumDevices(),
            "enum-devices"       => RunEnumDevices(args),
            "scan-iat"           => RunScanIAT(args),
            "attach"             => RunAttach(args),
            "unattach"           => RunUnattach(args),
            "list-attach"        => RunListAttach(),
            "enum-classify"      => RunEnumClassify(),
            "scan-objects"       => RunScanObjects(args),
            "etw"                => RunEtw(args),
            "comms"              => RunComms(args),
            "scan-handles"       => RunScanHandles(args),
            "tree"               => RunTree(args),
            "security"           => RunSecurity(args),
            _                    => UnknownCommand(cmd),
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    //  命令实现
    // ═══════════════════════════════════════════════════════════════════

    private static int PrintHelp()
    {
        Console.WriteLine("""
            SuperUserService — CombinationNative DLL 测试工具

            用法: SuperUserService.exe <命令> [参数]

            命令:
              init                    初始化 ntdll API
              kernel-scan             通过 KernelService 驱动扫描已加载内核模块
              scan-classify           驱动扫描 + 签名分类, 给出附着清单
              scan-enum-devices       扫描 + 分类 + 设备列表 + IAT (整合模式)
              enum-devices <名称>     对单个驱动名扫设备列表 (如 enum-devices tcpip)
              scan-iat <sys路径>      扫描单个 .sys 的 IAT (如 scan-iat C:\...\tcpip.sys)
              attach <设备路径>       附着到设备 (如 attach \Device\Tcp)
              unattach <ID|路径>      解绑附着 (如 unattach 1 或 unattach \Device\Tcp)
              list-attach             查询当前所有附着列表
              enum-classify           PSAPI 本地枚举 + 签名分类 (不需要驱动)
              scan-objects [目录]     扫描对象管理器命名空间 (默认 \GLOBAL??,\Device)
              etw [秒数] [etl路径]    ETW 实时订阅 (默认 30 秒)
              comms [秒数] [json]     ETW 通信监控 (如 comms 60 1)
              scan-handles <PID>      扫描持有目标 PID 的 VM_READ 句柄
              tree [PID] [深度] [json] 进程树打印 (如 tree 0 0 1)
              security [PID] [flags]  安全采集模式 (如 security 0 0)

            注意:
              - 大部分命令需要管理员权限
              - kernel-scan / scan-classify / scan-enum-devices / attach 等需要 KernelService 驱动已加载
              - etw / comms 需要管理员权限 + 驱动已加载
              - scan-iat / enum-classify / tree 不需要驱动
            """);
        return 0;
    }

    private static int RunInit()
    {
        int r = CombNative_InitNtdll();
        Console.WriteLine($"InitNtdll 返回: {r} (0=成功)");
        return r;
    }

    private static int RunKernelScan()
    {
        Console.WriteLine("[*] 调用 CombNative_RunKernelScan...");
        int r = CombNative_RunKernelScan();
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunScanClassify()
    {
        Console.WriteLine("[*] 调用 CombNative_RunScanAndClassify...");
        int r = CombNative_RunScanAndClassify();
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunScanEnumDevices()
    {
        Console.WriteLine("[*] 调用 CombNative_RunScanAndEnumDevices...");
        int r = CombNative_RunScanAndEnumDevices();
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunEnumDevices(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: enum-devices <驱动名>  (如 enum-devices tcpip)");
            return 1;
        }
        Console.WriteLine($"[*] 调用 CombNative_RunEnumDevices(\"{args[1]}\")...");
        int r = CombNative_RunEnumDevices(args[1]);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunScanIAT(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: scan-iat <sys文件路径>  (如 scan-iat C:\\Windows\\System32\\drivers\\tcpip.sys)");
            return 1;
        }
        Console.WriteLine($"[*] 调用 CombNative_RunScanIAT(\"{args[1]}\")...");
        int r = CombNative_RunScanIAT(args[1]);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunAttach(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: attach <设备路径>  (如 attach \\Device\\Tcp)");
            return 1;
        }
        Console.WriteLine($"[*] 调用 CombNative_RunAttachDevice(\"{args[1]}\")...");
        int r = CombNative_RunAttachDevice(args[1]);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunUnattach(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: unattach <ID|设备路径>  (如 unattach 1 或 unattach \\Device\\Tcp)");
            return 1;
        }
        Console.WriteLine($"[*] 调用 CombNative_RunUnattachDevice(\"{args[1]}\")...");
        int r = CombNative_RunUnattachDevice(args[1]);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunListAttach()
    {
        Console.WriteLine("[*] 调用 CombNative_RunListAttachments...");
        int r = CombNative_RunListAttachments();
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunEnumClassify()
    {
        Console.WriteLine("[*] 调用 CombNative_RunEnumAndClassify (PSAPI 模式)...");
        int r = CombNative_RunEnumAndClassify();
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunScanObjects(string[] args)
    {
        string dirs = args.Length >= 2 ? args[1] : @"\GLOBAL??,\Device";
        Console.WriteLine($"[*] 调用 CombNative_ScanObjectNamespaces(\"{dirs}\")...");
        int r = CombNative_ScanObjectNamespaces(dirs);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunEtw(string[] args)
    {
        uint duration = args.Length >= 2 ? uint.Parse(args[1]) : 30;
        string? etlPath = args.Length >= 3 ? args[2] : null;
        Console.WriteLine($"[*] 调用 CombNative_RunEtwConsumer(duration={duration}, etl=\"{etlPath}\")...");
        int r = CombNative_RunEtwConsumer(duration, etlPath);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunComms(string[] args)
    {
        uint duration = args.Length >= 2 ? uint.Parse(args[1]) : 0;
        int enableJson = args.Length >= 3 ? int.Parse(args[2]) : 0;
        Console.WriteLine($"[*] 调用 CombNative_RunCommsMonitor(duration={duration}, json={enableJson})...");
        int r = CombNative_RunCommsMonitor(duration, enableJson);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunScanHandles(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: scan-handles <PID>  (如 scan-handles 1234)");
            return 1;
        }
        uint pid = uint.Parse(args[1]);
        Console.WriteLine($"[*] 调用 CombNative_ScanHandlesForPid(pid={pid})...");
        int r = CombNative_ScanHandlesForPid(pid);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunTree(string[] args)
    {
        ulong pid = args.Length >= 2 ? ulong.Parse(args[1]) : 0;
        int maxDepth = args.Length >= 3 ? int.Parse(args[2]) : 0;
        int json = args.Length >= 4 ? int.Parse(args[3]) : 0;
        Console.WriteLine($"[*] 调用 CombNative_RunTreeMode(pid={pid}, depth={maxDepth}, json={json})...");
        int r = CombNative_RunTreeMode(pid, maxDepth, json);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int RunSecurity(string[] args)
    {
        ulong pid = args.Length >= 2 ? ulong.Parse(args[1]) : 0;
        uint flags = args.Length >= 3 ? uint.Parse(args[2]) : 0;
        Console.WriteLine($"[*] 调用 CombNative_RunSecurityMode(pid={pid}, flags=0x{flags:X})...");
        int r = CombNative_RunSecurityMode(pid, flags);
        Console.WriteLine($"[*] 返回: {r}");
        return r;
    }

    private static int UnknownCommand(string cmd)
    {
        Console.WriteLine($"未知命令: {cmd}");
        Console.WriteLine("输入 'help' 查看可用命令");
        return 1;
    }
}