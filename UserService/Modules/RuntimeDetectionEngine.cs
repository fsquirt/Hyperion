using System.Text.Json;
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
    private const string UploadEndpoint = "/api/forensics/upload";

    private readonly string _baseDir;
    private readonly object _gate = new();
    private IntPtr _hKernelService = IntPtr.Zero;

    private readonly AttachManager _attach = new();
    private ModuleDumper? _moduleDumper;
    private DriverDumper? _driverDumper;
    private EtwSession? _etw;
    private IoctlCommsMonitor? _comms;
    private ForensicJsonLogger? _forensic;
    private ProcessTreeCollector? _collector;
    private EventTrigger? _trigger;
    private HttpForensicUploader? _uploader;

    private System.Threading.Timer? _flushTimer;
    private readonly HashSet<string> _uploaded = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _pendingSnapshots = new();
    private readonly object _uploadLock = new();

    public EngineStatus Status { get; private set; } = EngineStatus.Stopped;
    public string StatusMessage { get; private set; } = "";
    public IReadOnlyDictionary<uint, KernelServiceIo.AttachEntry> Attachments => _attach.Attachments;

    public RuntimeDetectionEngine(string? baseDir = null)
    {
        _baseDir = baseDir ?? AppContext.BaseDirectory;
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

                _moduleDumper = new ModuleDumper(_baseDir);
                _driverDumper = new DriverDumper(_hKernelService, _moduleDumper.DumpDir, _moduleDumper.FileDumpDir);
                _etw = new EtwSession(EtwSessionName, KernelServiceIo.EtwIoctlProviderGuid);
                _comms = new IoctlCommsMonitor(_etw, _attach, _moduleDumper, _driverDumper);
                _forensic = new ForensicJsonLogger();
                _collector = new ProcessTreeCollector();
                _trigger = new EventTrigger(_collector, _comms, OnSnapshot);
                _uploader = new HttpForensicUploader(UploadEndpoint, _baseDir);

                RunAttachPipeline();

                _comms.Start();
                _trigger.Start();

                _flushTimer = new System.Threading.Timer(_ => FlushUpload("periodic"), null,
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
                FlushUpload("shutdown");
            }
            catch { }

            try { _flushTimer?.Dispose(); } catch { }
            _flushTimer = null;
            try { _trigger?.Stop(); } catch { }
            try { _comms?.Stop(); } catch { }
            try { _uploader?.Dispose(); } catch { }

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

            // 排除自身（KernelService）：附着自己会让内核 IOCTL 拦截自递归，无意义且危险
            if (string.Equals(d.ModuleName, "KernelService.sys", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(d.DriverObjectName, "KernelService", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  [跳过自身] {d.ModuleName} 为本服务驱动，不附着");
                continue;
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
                    continue;
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
                continue;
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

            if (cls.Class != DriverClass.ThirdPartyWhql && cls.Class != DriverClass.Untrusted)
            {
                Console.WriteLine($"  [跳过] {d.ModuleName} 分类为 {cls.Class}，非待附着类别，跳过");
                continue;
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
                continue;
            }
            considered++;

            var (devices, foundPath) = DeviceEnumerator.Enum(_hKernelService, objName);
            DumpDevices(devices, foundPath);
            if (devices.Count == 0)
            {
                Console.WriteLine($"  [无设备] {d.ModuleName} 未暴露 \\Device，仅记录");
                continue;
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

        // 刷新托管附着表（与内核保持一致）
        _attach.Refresh(_hKernelService);
        Console.WriteLine($"[ENGINE] 附着决策完成：候选 {considered}，成功附着 {attached}");
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

    private void OnSnapshot(ProcessTreeSnapshot snap)
    {
        try
        {
            string snapDir = Path.Combine(_baseDir, "snapshots");
            Directory.CreateDirectory(snapDir);
            string jsonPath = Path.Combine(snapDir,
                $"snap_{DateTime.UtcNow:yyyyMMddHHmmssfff}_{snap.Trigger}.json");
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(snap,
                new JsonSerializerOptions { WriteIndented = true }));

            lock (_uploadLock) _pendingSnapshots.Add(jsonPath);
            FlushUpload(snap.Trigger);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ENGINE] OnSnapshot 异常: {ex.GetType().Name}: {ex.Message}");
            Console.Error.WriteLine(LogUtil.Detail(ex));
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  取证上报：IOCTL 统计 JSON + 新增 dump 文件 + 待上报快照
    // ─────────────────────────────────────────────────────────────

    private void FlushUpload(string tag)
    {
        if (_uploader == null || _forensic == null || _comms == null || _moduleDumper == null) return;

        var counts = _comms.DrainCounts();
        if (counts.Count == 0 && _pendingSnapshots.Count == 0 && _uploaded.Count == 0)
            return;

        _forensic.RecordCounts(counts);
        string jsonPath = _forensic.Flush(_baseDir);
        string metadata = File.Exists(jsonPath) ? File.ReadAllText(jsonPath) : "{}";

        var files = new List<string> { jsonPath };

        // 收集新增 dump 文件（去重，避免重复上传）
        foreach (var dir in new[] { _moduleDumper.DumpDir, _moduleDumper.FileDumpDir })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                lock (_uploadLock)
                {
                    if (_uploaded.Add(f)) files.Add(f);
                }
            }
        }

        // 待上报快照
        List<string> snaps;
        lock (_uploadLock)
        {
            snaps = new List<string>(_pendingSnapshots);
            _pendingSnapshots.Clear();
        }
        files.AddRange(snaps);

        _ = _uploader.UploadAsync(files, metadata, tag);
    }

    private void CleanupHandles()
    {
        if (_hKernelService != IntPtr.Zero)
        {
            KernelServiceIo.CloseHandle(_hKernelService);
            _hKernelService = IntPtr.Zero;
        }
    }

    public void Dispose() => Stop();
}

public enum EngineStatus
{
    Stopped,
    Running,
    Error
}
