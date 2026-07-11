// SuperUserService — CombinationNative DLL 测试入口
//
// 重构原则: "数据先入类, 再从类出"
//   1. 所有命令通过 CombinationNativeService.Fetch* 方法调用 C++ 数据导出函数
//   2. 数据进入 NativeDataResult<T> (C# 类) 中, 作为唯一数据源
//   3. 由 DataFormatter 从类中读取并格式化输出
//   4. 不再调用任何 CombNative_Run* 直接打印函数
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

using SuperUserService.Logging;
using SuperUserService.Models;
using SuperUserService.NativeInterop;
using SuperUserService.Services;

namespace SuperUserService;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0)
        {
            PrintHelp();
            return 0;
        }

        // 实例化依赖链: Logger -> NativeBridge -> CombinationNativeService
        var logger = new ServiceLogger();
        var bridge = new NativeBridge();
        var service = new CombinationNativeService(bridge, logger);

        string cmd = args[0].ToLowerInvariant();

        // help 之外的所有命令先自动初始化 ntdll
        if (cmd != "help" && cmd != "init")
        {
            NativeResult initResult = service.EnsureInitialized();
            if (!initResult.Success)
            {
                logger.Warning($"InitNtdll 未成功 (退出码 {initResult.ExitCode}), 部分功能可能不可用");
            }
        }

        // ─── 命令分发 ─────────────────────────────────────────────
        // 所有命令均通过 Fetch* 方法 (数据导出), 而非 Run* 方法 (直接打印)
        // Fetch* 返回 NativeDataResult<T>, 数据进入 C# 类后由 DataFormatter 输出

        int exitCode = cmd switch
        {
            "help"              => PrintHelp(),
            "init"              => DoInit(service),
            "kernel-scan"       => DoKernelScan(service),
            "scan-classify"     => DoScanAndClassify(service),
            "scan-enum-devices" => DoScanAndEnumDevices(service),
            "enum-devices"      => DoEnumDevices(service, args),
            "scan-iat"          => DoScanIat(service, args),
            "attach"            => DoAttach(service, args),
            "unattach"          => DoUnattach(service, args),
            "list-attach"       => DoListAttachments(service),
            "enum-classify"     => DoEnumAndClassify(service),
            "scan-objects"      => DoScanObjects(service, args),
            "etw"               => DoEtw(service, args),
            "comms"             => DoComms(service, args),
            "scan-handles"      => DoScanHandles(service, args),
            "tree"              => DoTree(service, args),
            "security"          => DoSecurity(service, args),
            _                   => UnknownCommand(cmd),
        };

        return exitCode;
    }

    // ═══════════════════════════════════════════════════════════════
    //  命令实现: 每个 Do* 方法都遵循"数据先入类, 再从类出"流程
    //  1. 调用 service.Fetch* 获取 NativeDataResult<T> (数据进入 C# 类)
    //  2. 在 using 块中确保非托管缓冲区被释放
    //  3. 调用 DataFormatter.Format* 从类中读取并输出
    // ═══════════════════════════════════════════════════════════════

    private static int DoInit(CombinationNativeService service)
    {
        NativeResult r = service.Initialize();
        Console.WriteLine(r.Success
            ? $"[init] 成功 ({r.Duration.TotalMilliseconds:F0}ms)"
            : $"[init] 失败: {r.Message}");
        return r.ExitCode;
    }

    private static int DoKernelScan(CombinationNativeService service)
    {
        using var data = service.FetchKernelScan();
        return DataFormatter.FormatKernelScan(data);
    }

    private static int DoScanAndClassify(CombinationNativeService service)
    {
        using var data = service.FetchScanAndClassify();
        return DataFormatter.FormatClassify(data, "驱动扫描 + 签名分类");
    }

    private static int DoScanAndEnumDevices(CombinationNativeService service)
    {
        using var data = service.FetchScanAndEnumDevices();
        return DataFormatter.FormatClassify(data, "扫描 + 分类 + 设备列表 + IAT (整合模式)");
    }

    private static int DoEnumDevices(CombinationNativeService service, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: enum-devices <驱动名>  (如 enum-devices tcpip)");
            return 1;
        }
        using var data = service.FetchEnumDevices(args[1]);
        return DataFormatter.FormatEnumDevices(data, args[1]);
    }

    private static int DoScanIat(CombinationNativeService service, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: scan-iat <sys文件路径>  (如 scan-iat C:\\Windows\\System32\\drivers\\tcpip.sys)");
            return 1;
        }
        using var data = service.FetchScanIat(args[1]);
        return DataFormatter.FormatIat(data);
    }

    private static int DoAttach(CombinationNativeService service, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: attach <设备路径>  (如 attach \\Device\\Tcp)");
            return 1;
        }
        using var data = service.FetchAttach(args[1]);
        return DataFormatter.FormatAttach(data, args[1]);
    }

    private static int DoUnattach(CombinationNativeService service, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: unattach <ID|设备路径>  (如 unattach 1 或 unattach \\Device\\Tcp)");
            return 1;
        }
        using var data = service.FetchUnattach(args[1]);
        return DataFormatter.FormatUnattach(data, args[1]);
    }

    private static int DoListAttachments(CombinationNativeService service)
    {
        using var data = service.FetchListAttachments();
        return DataFormatter.FormatListAttachments(data);
    }

    private static int DoEnumAndClassify(CombinationNativeService service)
    {
        using var data = service.FetchEnumAndClassify();
        return DataFormatter.FormatClassify(data, "PSAPI 本地枚举 + 签名分类");
    }

    private static int DoScanObjects(CombinationNativeService service, string[] args)
    {
        string dirs = args.Length >= 2 ? args[1] : @"\GLOBAL??,\Device";
        var parameters = new ScanObjectsParameters(dirs.Split(',', StringSplitOptions.RemoveEmptyEntries));
        using var data = service.FetchScanObjects(parameters);
        return DataFormatter.FormatScanObjects(data, dirs);
    }

    private static int DoEtw(CombinationNativeService service, string[] args)
    {
        uint duration = args.Length >= 2 ? uint.Parse(args[1]) : 30;
        string? etlPath = args.Length >= 3 ? args[2] : null;
        var parameters = new EtwParameters(duration, etlPath);
        using var data = service.FetchEtw(parameters);
        return DataFormatter.FormatEtw(data, duration);
    }

    private static int DoComms(CombinationNativeService service, string[] args)
    {
        uint duration = args.Length >= 2 ? uint.Parse(args[1]) : 0;
        bool enableJson = args.Length >= 3 && int.Parse(args[2]) != 0;
        var parameters = new CommsParameters(duration, enableJson);
        using var data = service.FetchComms(parameters);
        return DataFormatter.FormatComms(data, duration);
    }

    private static int DoScanHandles(CombinationNativeService service, string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("用法: scan-handles <PID>  (如 scan-handles 1234)");
            return 1;
        }
        uint pid = uint.Parse(args[1]);
        using var data = service.FetchScanHandles(pid);
        return DataFormatter.FormatScanHandles(data, pid);
    }

    private static int DoTree(CombinationNativeService service, string[] args)
    {
        ulong pid = args.Length >= 2 ? ulong.Parse(args[1]) : 0;
        int maxDepth = args.Length >= 3 ? int.Parse(args[2]) : 0;
        bool json = args.Length >= 4 && int.Parse(args[3]) != 0;
        var parameters = new TreeParameters(pid, maxDepth, json);
        using var data = service.FetchTree(parameters);
        return DataFormatter.FormatTree(data);
    }

    private static int DoSecurity(CombinationNativeService service, string[] args)
    {
        ulong pid = args.Length >= 2 ? ulong.Parse(args[1]) : 0;
        uint flags = args.Length >= 3 ? uint.Parse(args[2]) : 0;
        var parameters = new SecurityParameters(pid, flags);
        using var data = service.FetchSecurity(parameters);
        return DataFormatter.FormatSecurity(data, pid);
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private static int UnknownCommand(string cmd)
    {
        Console.WriteLine($"未知命令: {cmd}");
        Console.WriteLine("输入 'help' 查看可用命令");
        return 1;
    }

    private static int PrintHelp()
    {
        Console.WriteLine("""
            SuperUserService — CombinationNative DLL 测试工具

            用法: SuperUserService.exe <命令> [参数]

            命令 (所有命令通过数据导出接口 Fetch* 执行, 数据先入类再输出):
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

            数据流:
              C++ (CombNative_Get*) → NativeDataResult<T> (C# 类) → DataFormatter (输出)

            注意:
              - 大部分命令需要管理员权限
              - kernel-scan / scan-classify / scan-enum-devices / attach 等需要 KernelService 驱动已加载
              - etw / comms 需要管理员权限 + 驱动已加载
              - scan-iat / enum-classify / tree 不需要驱动
            """);
        return 0;
    }
}
