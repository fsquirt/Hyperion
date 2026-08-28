using System.IO;
using System.Text.Json;
using System.Threading;
using Hyperion.UserService.Comm;
using Hyperion.UserService.Modules.DriverAttach;
using Hyperion.UserService.Modules.Heuristic;
using Hyperion.UserService.Modules.ProcTree;
using Hyperion.UserService.Modules.Upload;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 运行时检测引擎编排器（集成三个 C++ 反制能力）。
/// 由 AntiCheatService 在驱动加载成功且自保护后构造启动；Cleanup 时 Stop 并关闭内核句柄。
/// 负责：内核驱动枚举/验签分类/IAT/设备枚举/附着 → ETW 通信监控 + 调用栈回溯 + 模块/驱动 dump
/// → 事件触发式进程树快照 → HTTP 多部分上报（含脱机缓冲重试）。
/// </summary>
public sealed class RuntimeDetectionEngine : IDisposable
{
    private const string EtwSessionName = "HyperionRuntimeIoctlTrace";

    private readonly string _baseDir;
    private readonly string? _serverUrl;
    private readonly object _gate = new();
    private IntPtr _hKernelService = IntPtr.Zero;

    private AttachWhitelist? _attachWhitelist; // 来自服务端策略;null 表示未拉取/跳过白名单

    private readonly AttachManager _attach = new();
    private ModuleDumper? _moduleDumper;
    private DriverDumper? _driverDumper;
    private EtwSession? _etw;
    private IoctlCommsMonitor? _comms;
    private ForensicJsonLogger? _forensic;
    private ProcessTreeCollector? _collector;
    private EventTrigger? _trigger;
    private TrackerReporter? _reporter;
    private PolicyBundle? _policyBundle;
    private MockInputMonitor? _mockInput; // 模拟键鼠检测(全局低级钩子,按服务端策略启动)

    private System.Threading.Timer? _flushTimer;

    // 受保护的游戏进程 PID(由 AntiCheatService 启动游戏后设置),用于 ETW ID3 线程反调试事件判定
    private volatile uint _protectedGamePid;

    public EngineStatus Status { get; private set; } = EngineStatus.Stopped;
    public string StatusMessage { get; private set; } = "";
    public IReadOnlyDictionary<uint, KernelServiceIo.AttachEntry> Attachments => _attach.Attachments;

    /// <summary>
    /// 服务端策略是否要求在游戏启动前更新 SiPolicy.p7b(免重启刷新驱动阻止策略)。
    /// 由 AntiCheatService 在启动游戏前读取;策略未拉取到时为 false。
    /// </summary>
    public bool SiPolicyUpdateRequired => _policyBundle?.SiPolicyEnabled ?? false;

    /// <summary>
    /// 设置受保护的游戏进程 PID。由 AntiCheatService 在启动游戏(拿到 PID)后调用,
    /// 供 ETW ID3 线程反调试事件判定 CreatorPid/ProcessId 是否属于游戏进程。
    /// </summary>
    public void SetProtectedGamePid(uint pid) => _protectedGamePid = pid;

    public RuntimeDetectionEngine(string? baseDir = null, string? serverUrl = null)
    {
        _baseDir = baseDir ?? AppContext.BaseDirectory;
        _serverUrl = serverUrl;
    }

    /// <summary>
    /// 运行前清空上一轮的取证产物，保证每次启动都是干净基线：
    /// 清空 DebugDump / FileCopy / snapshots 三个目录，并删除 ioctl_stats.json
    /// 与上一轮未上传的取证文件归档（pending_uploads.json，其本地路径已随目录清空而失效）。
    /// 清空只删内容、不删目录本身；目录创建仍由各 dumper / EventTrigger 负责。
    /// </summary>
    private static void PrepareOutputDirectories(string baseDir)
    {
        void ClearDirectory(string dir)
        {
            if (!Directory.Exists(dir)) return;
            foreach (var f in Directory.GetFiles(dir)) { try { File.Delete(f); } catch { } }
            foreach (var d in Directory.GetDirectories(dir)) { try { Directory.Delete(d, true); } catch { } }
        }

        ClearDirectory(Path.Combine(baseDir, "DebugDump"));
        ClearDirectory(Path.Combine(baseDir, "FileCopy"));
        ClearDirectory(Path.Combine(baseDir, "snapshots"));
        string stats = Path.Combine(baseDir, "ioctl_stats.json");
        if (File.Exists(stats)) { try { File.Delete(stats); } catch { } }
        // 上一轮异常退出遗留的未上传归档：本地文件已随目录清空，条目全部失效，一并清掉避免无限增长
        string pendingUploads = Path.Combine(AppContext.BaseDirectory, "pending_uploads.json");
        if (File.Exists(pendingUploads)) { try { File.Delete(pendingUploads); } catch { } }
    }

    /// <summary>
    /// 从服务端拉取并应用策略:
    ///   1) 危险内核函数列表 → 覆盖 IatScanner 的内置默认(用于 IAT 命中判定)
    ///   2) 附着白名单 → 存入 _attachWhitelist,在附着决策时跳过白名单驱动
    ///   3) 模拟键鼠 / SiPolicy 开关
    /// 拉取失败为致命错误:抛出异常由 Start 外层 catch 收尾,不执行后续流程(游戏不启动)。
    /// </summary>
    private void ApplyServerPolicies()
    {
        PolicyBundle? bundle;
        try
        {
            bundle = PolicySync.FetchAsync(_serverUrl).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"拉取服务端策略异常: {ex.Message}", ex);
        }

        if (bundle == null)
            throw new InvalidOperationException("服务端策略拉取失败(服务端不可达或返回无效)");

        _policyBundle = bundle;

        // 1) 危险内核函数列表
        if (bundle.KernelFuncs.Count > 0)
        {
            IatScanner.SetDangerousApis(bundle.KernelFuncs);
            Console.WriteLine($"[ENGINE] 已应用服务端危险函数列表: {bundle.KernelFuncs.Count} 个");
        }
        else
        {
            Console.WriteLine("[ENGINE] 服务端危险函数列表为空,保留内置默认");
        }

        // 2) 附着白名单
        _attachWhitelist = bundle.Whitelist;
        int wlCount = bundle.Whitelist.CertSubjects.Count
            + bundle.Whitelist.HashMd5.Count + bundle.Whitelist.HashSha1.Count
            + bundle.Whitelist.HashSha256.Count;
        Console.WriteLine($"[ENGINE] 已应用服务端附着白名单: {wlCount} 条(hash+cert)");
    }

    /// <summary>把引擎采用的服务端策略整理为上报 DTO（内核危险函数 + 白名单），用于会话建立事件展示。</summary>
    private ServerConnection.PolicyInfoDto? BuildPolicyDto()
    {
        if (_policyBundle == null) return null;
        var wl = _policyBundle.Whitelist;
        var hashes = new List<string>(wl.HashMd5.Count + wl.HashSha1.Count + wl.HashSha256.Count);
        hashes.AddRange(wl.HashMd5);
        hashes.AddRange(wl.HashSha1);
        hashes.AddRange(wl.HashSha256);
        return new ServerConnection.PolicyInfoDto
        {
            kernelFuncs = new List<string>(_policyBundle.KernelFuncs),
            whitelistCertSubjects = new List<string>(wl.CertSubjects),
            whitelistHashes = hashes,
        };
    }

    public bool Start()
    {
        lock (_gate)
        {
            if (Status == EngineStatus.Running) return true;
            try
            {
                _hKernelService = KernelServiceIo.OpenDevice();
                if (_hKernelService == IntPtr.Zero)
                {
                    Status = EngineStatus.Error;
                    StatusMessage = "无法打开 \\\\.\\KernelService（内核驱动未就绪？）";
                    Console.Error.WriteLine("[ENGINE] " + StatusMessage);
                    return false;
                }

                // 运行前清空上一轮遗留的取证产物，保证每次启动都是干净基线
                PrepareOutputDirectories(_baseDir);

                _moduleDumper = new ModuleDumper(_baseDir);
                _driverDumper = new DriverDumper(_hKernelService, _moduleDumper.DumpDir, _moduleDumper.FileCopyDir);
                _etw = new EtwSession(EtwSessionName, KernelServiceIo.EtwIoctlProviderGuid);
                _comms = new IoctlCommsMonitor(_etw, _attach, _moduleDumper, _driverDumper);
                _forensic = new ForensicJsonLogger();
                _collector = new ProcessTreeCollector();
                _trigger = new EventTrigger(_collector, _comms, _baseDir);

                // 订阅 ETW ID2(游戏进程 ImageLoad) / ID3(新线程反调试)
                // ImageLoad 未签名 → 异步验签 + FileCopy + 上报 HIGH(见 OnGameImageLoad)
                // ThreadAntiDebug → 远程线程注入预警上报(见 OnGameThreadAntiDebug)
                _etw.ImageLoad += OnGameImageLoad;
                _etw.ThreadAntiDebug += OnGameThreadAntiDebug;

                // 拉取服务端策略(危险内核函数列表 + 附着白名单)并应用。
                // 失败不致命:回退到 IatScanner 内置默认危险函数,且白名单为空(只按分类决策)。
                ApplyServerPolicies();

                // 建立 Tracker 会话并订阅 Windows/ETW 事件实时上报。服务端不可达时降级，不致命。
                if (!string.IsNullOrWhiteSpace(_serverUrl))
                {
                    try
                    {
                        _reporter = new TrackerReporter(_serverUrl);
                        var policyDto = BuildPolicyDto();
                        if (_reporter.Start(policyDto))
                        {
                            Console.WriteLine($"[ENGINE] 已连接 Tracker 服务端，会话 {_reporter.SessionId}");
                            if (policyDto != null) _reporter.ReportPolicy(policyDto);
                            _moduleDumper.OnFileCaptured += (p, k) => _reporter?.ReportFile(p, k);
                            _driverDumper.OnFileCaptured += (p, k) => _reporter?.ReportFile(p, k);
                            _trigger.OnSnapshot += json => _reporter?.ReportSnapshot(json);
                        }
                        else
                        {
                            Console.Error.WriteLine("[ENGINE] Tracker 会话建立失败（服务端不可达？），事件/产物上报停用");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[ENGINE] 创建 Tracker 上报器异常: {ex.Message}");
                    }
                }

                // 模拟键鼠检测:上报/拦截任一启用才安装全局低级钩子(均关闭则零开销)。
                // 放在 Tracker 会话建立之后,检测到的事件经会话事件通道(mock_input)上报。
                // 钩子启动失败为致命错误:异常直接抛出,由 Start 外层 catch 统一收尾(终止引擎,游戏不启动)。
                bool mockReport = _policyBundle?.MockInputReport ?? false;
                bool mockBlock = _policyBundle?.MockInputBlock ?? false;
                if (mockReport || mockBlock)
                {
                    _mockInput = new MockInputMonitor();
                    _mockInput.Start(mockBlock, mockReport, info =>
                    {
                        if (mockReport)
                            _reporter?.ReportMockInput(info.Source, info.Action, info.Detail);
                        else
                            Console.WriteLine($"[MockInput] {info.Source}: {info.Action} ({info.Detail}) [已拦截]");
                    });
                }

                RunAttachPipeline();
                _reporter?.ReportDevices(_attach.Attachments);

                _comms.Start();
                _trigger.Start();

                _flushTimer = new System.Threading.Timer(_ => FlushStats(), null,
                    TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

                Status = EngineStatus.Running;
                StatusMessage = $"运行中（已附着 {_attach.Attachments.Count} 个驱动，dump 目录 {_moduleDumper.DumpDir}）";
                Console.WriteLine("[ENGINE] 运行时检测引擎已启动");
                return true;
            }
            catch (Exception ex)
            {
                Status = EngineStatus.Error;
                StatusMessage = $"启动异常: {ex.GetType().Name}: {ex.Message}";
                Console.Error.WriteLine("[ENGINE] " + StatusMessage);
                Console.Error.WriteLine(LogUtil.Detail(ex));
                CleanupHandles();
                return false;
            }
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (Status == EngineStatus.Stopped) return;
            try
            {
                FlushStats();
            }
            catch { }

            try { _flushTimer?.Dispose(); } catch { }
            _flushTimer = null;
            try { _trigger?.Stop(); } catch { }
            try { _comms?.Stop(); } catch { }
            try { _mockInput?.Dispose(); } catch { }
            _mockInput = null;
            try { _reporter?.Stop(); } catch { }

            // 退订 ETW ID2/3(与 _comms.Stop() 内的 ID1 退订一并完成订阅清理)
            if (_etw != null)
            {
                try { _etw.ImageLoad -= OnGameImageLoad; } catch { }
                try { _etw.ThreadAntiDebug -= OnGameThreadAntiDebug; } catch { }
            }

            CleanupHandles();
            Status = EngineStatus.Stopped;
            StatusMessage = "已停止";
            Console.WriteLine("[ENGINE] 运行时检测引擎已停止");
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  附着决策流水线（DriverAttach 集成）
    // ─────────────────────────────────────────────────────────────

    private void RunAttachPipeline()
    {
        if (_hKernelService == IntPtr.Zero) return;
        var drivers = DriverScanner.Scan(_hKernelService);
        Console.WriteLine($"[ENGINE] 已加载驱动 {drivers.Count} 个，开始附着决策…");

        int considered = 0, attached = 0;
        int idx = 0;
        foreach (var d in drivers)
        {
            idx++;
            // ── 每驱动诊断头：现在在处理哪个驱动 ──
            Console.WriteLine($"────────── [{idx}/{drivers.Count}] 处理驱动 ──────────");
            Console.WriteLine($"  模块名   ModuleName     = '{d.ModuleName}'");
            Console.WriteLine($"  驱动对象 DriverObject   = '{d.DriverObjectName}'");
            Console.WriteLine($"  原始路径 FullPath       = '{d.FullPath}'");
            EvaluateAndAttachDriver(d, ref considered, ref attached);
        }

        // 刷新托管附着表（与内核保持一致）
        _attach.Refresh(_hKernelService);
        Console.WriteLine($"[ENGINE] 附着决策完成：候选 {considered}，成功附着 {attached}");
    }

    // ─────────────────────────────────────────────────────────────
    //  单驱动候选判定 + 附着（被启动全量扫描与"新驱动加载"增量重扫共用）
    // ─────────────────────────────────────────────────────────────
    private void EvaluateAndAttachDriver(KernelServiceIo.LoadedDriverEntry d, ref int considered, ref int attached)
    {
        // 排除自身（KernelService）：附着自己会让内核 IOCTL 拦截自递归，无意义且危险
        if (string.Equals(d.ModuleName, "KernelService.sys", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(d.DriverObjectName, "KernelService", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"  [跳过自身] {d.ModuleName} 为本服务驱动，不附着");
            return;
        }

        // 解析驱动对象名：内核 EnumDriverDevices 需要裸对象名（如 OpenArkDrv64），
        // 优先用内核反查的 DriverObjectName，缺失时回退到去 .sys 的文件名。
        string objName = ResolveDriverObjectName(d);

        string path = DriverClassifier.NormalizeDriverPath(d.FullPath);
        bool pathExists = !string.IsNullOrEmpty(path) && File.Exists(path);
        Console.WriteLine($"  解析对象 objName       = '{objName}'");
        Console.WriteLine($"  归一路径 path          = '{path}'");
        Console.WriteLine($"  文件存在 File.Exists   = {pathExists}");

        // 内核已加载但磁盘无文件：无法验签/读 IAT（不落盘的 BYOVD/ARK 也属此类）。
        // 按可疑处理；一般也不会暴露 \Device，但若暴露则直接附着监听。
        bool diskMissing = !pathExists;
        if (diskMissing)
        {
            Console.WriteLine($"  [内存驻留] {d.ModuleName} 磁盘无文件，按可疑处理（跳过验签/IAT）");
            considered++;
            var (memDevices, _) = DeviceEnumerator.Enum(_hKernelService, objName);
            DumpDevices(memDevices);
            if (memDevices.Count == 0)
            {
                Console.WriteLine($"  [无设备] 内存驻留驱动 {d.ModuleName} 未暴露 \\Device，跳过");
                return;
            }
            foreach (var dev in memDevices)
            {
                Console.WriteLine($"  → 尝试附着(内存驻留) {dev.DeviceName} ...");
                if (_attach.Attach(_hKernelService, dev.DeviceName, out uint id, out string err))
                {
                    attached++;
                    Console.WriteLine($"  ← 附着成功 {d.ModuleName} → {dev.DeviceName} (AttachId={id})");
                }
                else
                {
                    Console.WriteLine($"  ← 附着失败 {d.ModuleName} → {dev.DeviceName}: {err}");
                }
            }
            return;
        }

        // 验签分类（打印分类结果 + 签名者，便于确认微软/Inbox 是否被误判为候选）
        var cls = DriverClassifier.ClassifyDriver(path);
        Console.WriteLine($"  验签分类 Class         = {cls.Class}  (内嵌签名={cls.HasEmbedded}, 目录签名={cls.HasCatalog})");
        Console.WriteLine($"    WinVerifyTrust hr     = 0x{cls.VerifyHr & 0xFFFFFFFF:X8} ({DriverClassifier.HrName((uint)cls.VerifyHr)})  目录签名验证={cls.CatalogVerified}");
        if (cls.Signers.Count > 0)
            foreach (var s in cls.Signers)
                Console.WriteLine($"    签名者: {s.Subject}  [{SigTag(s)}]");
        if (!string.IsNullOrEmpty(cls.ErrorReason))
            Console.WriteLine($"    分类原因: {cls.ErrorReason}");

        // 附着白名单(来自服务端策略):命中则跳过该驱动,不附着监听
        if (_attachWhitelist != null && _attachWhitelist.IsWhitelisted(path, cls.Signers))
        {
            Console.WriteLine($"  [白名单] {d.ModuleName} 命中附着白名单,跳过附着");
            return;
        }

        if (cls.Class != DriverClass.ThirdPartyWhql && cls.Class != DriverClass.Untrusted)
        {
            Console.WriteLine($"  [跳过] {d.ModuleName} 分类为 {cls.Class}，非待附着类别，跳过");
            return;
        }

        // IAT 表（仅候选驱动打印，避免 187 个驱动刷屏）
        IatScanner.ScanIat(path, out var iat, out var iatErr);
        Console.WriteLine($"  IAT 表 ({iat.Count} 个导入模块" +
                          (string.IsNullOrEmpty(iatErr) ? "" : $", 备注: {iatErr}") + "):");
        DumpIat(iat);

        bool empty = iat.Count == 0;
        bool danger = IatScanner.HasDangerousImports(iat, out var foundApis);
        if (!empty && !danger)
        {
            Console.WriteLine($"  [跳过] {d.ModuleName} IAT 良性（非可疑）");
            return;
        }
        considered++;

        var (devices, foundPath) = DeviceEnumerator.Enum(_hKernelService, objName);
        DumpDevices(devices, foundPath);
        if (devices.Count == 0)
        {
            Console.WriteLine($"  [无设备] {d.ModuleName} 未暴露 \\Device，仅记录");
            return;
        }

        foreach (var dev in devices)
        {
            Console.WriteLine($"  → 尝试附着 {dev.DeviceName} ... (若此后无 ← 行，说明卡在内核 AttachDevice)");
            if (_attach.Attach(_hKernelService, dev.DeviceName, out uint id, out string err))
            {
                attached++;
                Console.WriteLine($"  ← 附着成功 {d.ModuleName} → {dev.DeviceName} (AttachId={id})" +
                                  (danger ? $" 高危导入: {string.Join(",", foundApis)}" : " (IAT 空)"));
            }
            else
            {
                Console.WriteLine($"  ← 附着失败 {d.ModuleName} → {dev.DeviceName}: {err}");
            }
        }
    }

    /// <summary>
    /// 新驱动加载增量重扫（方案X）：内核 LoadImage 通知触发。
    /// 由 AntiCheatService.LoadImageMonitorProc 在后台线程调用。
    /// 只针对通知到的那一个驱动，跑与启动全量扫描相同的
    /// "候选判定 + IAT/签名/设备扫描 + 附着"，不重扫全部（避免 IO 抖动）。
    ///
    /// 注意：LoadImage 通知在映像映射之后、DriverEntry 执行之前触发，
    /// 驱动此时多半还没创建设备对象，故先 Sleep 一小段再扫，避免误判"无设备"跳过附着。
    /// 即使仍查不到设备，ETW 通信监控会在该驱动实际 IOCTL 通信时被动触发 dump。
    /// </summary>
    public void RescanDriverByImage(string imageName)
    {
        if (string.IsNullOrEmpty(imageName)) return;

        // DriverEntry 可能尚未完成，等约 2s 让驱动创建设备对象（不在锁内 sleep，避免阻塞 Stop）
        Thread.Sleep(2000);

        lock (_gate)
        {
            if (Status != EngineStatus.Running || _hKernelService == IntPtr.Zero) return;

            var drivers = DriverScanner.Scan(_hKernelService);
            string fileName = Path.GetFileName(imageName);

            KernelServiceIo.LoadedDriverEntry? target = null;
            foreach (var d in drivers)
            {
                if (string.Equals(d.ModuleName, fileName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(Path.GetFileName(d.FullPath), fileName, StringComparison.OrdinalIgnoreCase))
                {
                    target = d;
                    break;
                }
            }

            if (target == null)
            {
                Console.WriteLine($"[ENGINE] Rescan: 通知驱动未在已加载列表匹配到: '{imageName}'");
                return;
            }

            Console.WriteLine($"════════ 新驱动增量重扫: {target.ModuleName} ══════");
            Console.WriteLine($"  模块名   ModuleName     = '{target.ModuleName}'");
            Console.WriteLine($"  驱动对象 DriverObject   = '{target.DriverObjectName}'");
            Console.WriteLine($"  原始路径 FullPath       = '{target.FullPath}'");
            int considered = 0, attached = 0;
            EvaluateAndAttachDriver(target, ref considered, ref attached);
            _attach.Refresh(_hKernelService);
            _reporter?.ReportDevices(_attach.Attachments);
            Console.WriteLine($"[ENGINE] Rescan 完成: {target.ModuleName} 候选 {considered}, 附着 {attached}");
        }
    }

    /// <summary>
    /// 解析传给内核 EnumDriverDevices 的驱动对象名。EnlistDriverDevices 期望裸对象名
    /// （如 "OpenArkDrv64"，不含路径/.sys），与 \Driver\&lt;Name&gt; 对应。
    /// 优先用内核反查的 DriverObjectName；缺失（如极少数找不到 DriverObject 的模块）时
    /// 回退到 ModuleName 去路径并去 .sys 后缀。
    /// </summary>
    private static string ResolveDriverObjectName(KernelServiceIo.LoadedDriverEntry d)
    {
        if (!string.IsNullOrEmpty(d.DriverObjectName))
            return d.DriverObjectName;
        string baseName = Path.GetFileName(d.ModuleName);
        if (baseName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            baseName = baseName.Substring(0, baseName.Length - 4);
        return baseName;
    }

    /// <summary>签名者标签：Microsoft / WHQL / Vendor / Other。</summary>
    private static string SigTag(SignerInfo s)
        => s.IsMicrosoft ? "Microsoft" : s.IsWhql ? "WHQL" : s.IsVendor ? "Vendor" : "Other";

    /// <summary>打印驱动 IAT 表（每个导入 DLL 及其导入函数）。</summary>
    private static void DumpIat(List<IatScanner.IatEntry> iat)
    {
        if (iat.Count == 0) { Console.WriteLine("    (空 IAT)"); return; }
        foreach (var e in iat)
        {
            if (e.Apis.Count == 0) { Console.WriteLine($"    {e.DllName} : (无导入函数)"); continue; }
            Console.WriteLine($"    {e.DllName} :");
            foreach (var api in e.Apis)
                Console.WriteLine($"        - {api}");
        }
    }

    /// <summary>打印驱动暴露的设备列表。</summary>
    private static void DumpDevices(List<KernelServiceIo.DeviceEntry> devices, string foundPath = "")
    {
        if (!string.IsNullOrEmpty(foundPath))
            Console.WriteLine($"    枚举 FoundPath = '{foundPath}'");
        if (devices.Count == 0)
        {
            Console.WriteLine($"    设备: (无)  FoundPath='{foundPath}'");
            return;
        }
        foreach (var dev in devices)
            Console.WriteLine($"    设备: {dev.DeviceName}  Type=0x{dev.DeviceType:X8} " +
                              $"Flags=0x{dev.Flags:X8} Attached={dev.AttachedCount} StackSize={dev.StackSize}");
    }

    // ─────────────────────────────────────────────────────────────
    //  快照回调 → 暂存后随取证包一起上报
    // ─────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────
    //  ETW ID2: 游戏进程 ImageLoad — 异步验签,未签名则 FileCopy + 上报 HIGH
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// 游戏进程内 DLL/映像加载(ETW ID2)。在 ETW 线程上触发,只做轻量投递,重 IO(验签/拷贝)异步执行。
    /// 未签名(Untrusted)→ 拷贝磁盘副本到 FileCopy + 上报 HIGH 事件。
    /// 已签名 → 仅本地日志,不上报(按需求)。失败按"未签名"保守处理(宁可多取)。
    /// </summary>
    private void OnGameImageLoad(ImageLoadEvent evt)
    {
        if (string.IsNullOrEmpty(evt.ImageName)) return;

        // 重 IO 投递线程池,避免阻塞 ETW 会话丢事件
        ImageLoadEvent captured = evt;
        _ = Task.Run(() => ProcessUnsignedImageLoad(captured));
    }

    /// <summary>
    /// 后台处理一次 ImageLoad:验签 → 未签名则取证并上报 HIGH。
    /// 内核 ImageLoad 回调给的是 NT 设备路径(如 \Device\HarddiskVolume3\...),需先转成
    /// Win32 路径(如 C:\...)才能 File.Exists / 验签 / 拷贝。
    /// </summary>
    private void ProcessUnsignedImageLoad(ImageLoadEvent evt)
    {
        try
        {
            string path = NtToDosPath(evt.ImageName);
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                Console.Error.WriteLine($"[ENGINE] ImageLoad 文件不可访问(内存瞬态/已删/NT路径转换失败),按可疑处理: {evt.ImageName} -> {path}");
                // 文件无法读取时仍尝试转换失败的上报(用原始 NT 路径),便于服务端核对
                ReportUnsignedImageLoad(evt, path);
                return;
            }

            // 验签(复用驱动分类缓存)。Untrusted = 无签名或验签失败。
            bool hasSignature;
            try
            {
                hasSignature = DriverClassifier.ClassifyDriver(path).Class != DriverClass.Untrusted;
            }
            catch
            {
                hasSignature = false; // 验签异常按可疑处理
            }

            if (hasSignature)
            {
                Console.WriteLine($"[ENGINE] ImageLoad 已签名(仅记录): {path}");
                return; // 不上报已签名日志
            }

            Console.WriteLine($"[ENGINE] ImageLoad 未签名 DLL 加载: {path} (InitiatorPid={evt.InitiatorPid}, ProcessId={evt.ProcessId})");

            // 拷磁盘副本到 FileCopy\(路径去重;OnFileCaptured 会触发 _reporter.ReportFile 自动上传)
            _moduleDumper?.DumpProcessModule(evt.ProcessId, path);

            ReportUnsignedImageLoad(evt, path);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ENGINE] ProcessUnsignedImageLoad 异常: {ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine(LogUtil.Detail(ex));
        }
    }

    /// <summary>上报一条未签名 ImageLoad HIGH 事件(统一含 NT 原路径与转换后路径)。</summary>
    private void ReportUnsignedImageLoad(ImageLoadEvent evt, string dosPath)
    {
        _reporter?.ReportImageLoadUnsigned(new
        {
            imagePath = dosPath,
            imagePathNt = evt.ImageName,
            processId = evt.ProcessId,
            initiatorPid = evt.InitiatorPid,
            imageBase = evt.ImageBase,
            imageSize = evt.ImageSize,
            time = evt.TimeStamp.ToString("o")
        });
    }

    // ─────────────────────────────────────────────────────────────
    //  NT 设备路径 → Win32 路径转换
    //  \Device\HarddiskVolumeN\... → 盘符:\...
    //  用 QueryDosDevice 枚举每个盘符映射到其 NT 设备路径,再最长前缀替换。
    // ─────────────────────────────────────────────────────────────

    /// <summary>把 NT 设备路径(如 \Device\HarddiskVolume3\a\b.dll)转成 Win32 路径(如 C:\a\b.dll)。</summary>
    internal static string NtToDosPath(string ntPath)
    {
        if (string.IsNullOrEmpty(ntPath)) return "";

        // 已是 Win32 绝对路径
        if (ntPath.Length >= 3 && ntPath[1] == ':' && (ntPath[2] == '\\' || ntPath[2] == '/'))
            return ntPath;
        // \??\ 前缀去掉
        if (ntPath.StartsWith(@"\??\", StringComparison.Ordinal))
            ntPath = ntPath.Substring(4);

        // 最长前缀匹配:遍历所有盘符,找到匹配的 NT 设备前缀并替换
        string? best = null;
        string? bestDos = null;
        uint mask = GetLogicalDrives();
        for (char c = 'A'; c <= 'Z'; c++)
        {
            if ((mask & (1u << (c - 'A'))) == 0) continue;
            string dosName = c + ":";
            string ntDev = QueryDosDeviceName(dosName);
            if (string.IsNullOrEmpty(ntDev)) continue;

            // 匹配 \Device\HarddiskVolumeN 形式,且尽量匹配最长前缀
            if (ntPath.StartsWith(ntDev + @"\", StringComparison.OrdinalIgnoreCase) ||
                ntPath.Equals(ntDev, StringComparison.OrdinalIgnoreCase))
            {
                if (best == null || ntDev.Length > best.Length)
                {
                    best = ntDev;
                    bestDos = dosName;
                }
            }
        }

        if (best == null || bestDos == null) return ntPath; // 无法转换,原样返回

        if (ntPath.Equals(best, StringComparison.OrdinalIgnoreCase))
            return bestDos + @"\";
        return bestDos + ntPath.Substring(best.Length);
    }

    /// <summary>通过 QueryDosDevice 获取一个 Dos 设备名(如 "C:")对应的 NT 设备路径(如 "\Device\HarddiskVolume3")。</summary>
    private static string QueryDosDeviceName(string dosDeviceName)
    {
        var sb = new System.Text.StringBuilder(260);
        if (!QueryDosDevice(dosDeviceName, sb, sb.Capacity))
            return "";
        return sb.ToString();
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint GetLogicalDrives();

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);


    // ─────────────────────────────────────────────────────────────
    //  ETW ID3: 新线程反调试 — 远程线程注入预警上报 HIGH
    // ─────────────────────────────────────────────────────────────

    /// <summary>
    /// 新线程反调试事件(ETW ID3)。
    /// 判定规则: CreatorPid 或 ProcessId 任一不是游戏进程(_protectedGamePid) → HIGH 上报服务器。
    /// 不做取证逻辑(创建的远程线程会被驱动用 PspTerminateThreadByPointer 直接掐死)。
    /// </summary>
    private void OnGameThreadAntiDebug(ThreadAntiDebugEvent evt)
    {
        try
        {
            uint gamePid = _protectedGamePid;
            bool creatorIsGame = evt.CreatorPid == gamePid;
            bool processIsGame = evt.ProcessId == gamePid;

            // 任一 PID 不是游戏进程(且该 PID 非 0/空)即视为可疑
            bool suspicious = (!creatorIsGame && evt.CreatorPid != 0) ||
                              (!processIsGame && evt.ProcessId != 0);

            Console.WriteLine($"[ENGINE] ThreadAntiDebug: CreatorPid={evt.CreatorPid} ProcessId={evt.ProcessId} ThreadId={evt.ThreadId} gamePid={gamePid} {(suspicious ? "SUSPICIOUS" : "normal")}");

            if (suspicious)
            {
                _reporter?.ReportRemoteThreadInjection(new
                {
                    creatorPid = evt.CreatorPid,
                    processId = evt.ProcessId,
                    threadId = evt.ThreadId,
                    gamePid = gamePid,
                    // 远程线程由驱动直接强杀,此处仅上报留痕,不做本地取证
                    note = "remote_thread_killed_by_driver",
                    time = evt.TimeStamp.ToString("o")
                });
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ENGINE] OnGameThreadAntiDebug 异常: {ex.Message}");
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  本地统计落盘：IOCTL 码→次数 + 交互模块集合（不上报，服务端未就绪）
    // ─────────────────────────────────────────────────────────────

    private void FlushStats()
    {
        if (_forensic == null || _comms == null) return;

        var counts = _comms.GetCounts();
        var modules = _comms.GetInteractionModules();
        _forensic.WriteStats(_baseDir, counts, modules);
        Console.WriteLine($"[ENGINE] 已写本地统计 ioctl_stats.json（IOCTL 码 {counts.Count} 种，" +
                          $"交互模块 {modules.Count} 个）");

        // 实时上报最新 IOCTL 统计快照到服务端（每 30 秒一次，覆盖式更新）
        if (_reporter != null)
        {
            var stats = new Dictionary<string, ulong>(counts.Count);
            foreach (var kv in counts) stats[$"0x{kv.Key:X8}"] = kv.Value;
            _reporter.ReportIoctlStats(stats, new List<string>(modules));
        }
    }

    private void CleanupHandles()
    {
        if (_hKernelService != IntPtr.Zero)
        {
            KernelServiceIo.CloseHandle(_hKernelService);
            _hKernelService = IntPtr.Zero;
        }

        // 引擎启动中途失败时回收已安装的模拟键鼠钩子(正常路径由 Stop 清理)
        try { _mockInput?.Dispose(); } catch { }
        _mockInput = null;
    }

    public void Dispose() => Stop();
}

public enum EngineStatus
{
    Stopped,
    Running,
    Error
}
