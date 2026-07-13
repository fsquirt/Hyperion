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
                StatusMessage = $"启动异常: {ex.Message}";
                Console.Error.WriteLine("[ENGINE] " + StatusMessage);
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
        foreach (var d in drivers)
        {
            string path = DriverClassifier.NormalizeDriverPath(d.FullPath);
            if (string.IsNullOrEmpty(path)) continue;
            var cls = DriverClassifier.ClassifyDriver(path);
            if (cls.Class != DriverClass.ThirdPartyWhql && cls.Class != DriverClass.Untrusted)
                continue; // 仅 THIRD_PARTY_WHQL + UNTRUSTED 进入待附着清单

            IatScanner.ScanIat(path, out var iat, out _);
            bool empty = iat.Count == 0;
            bool danger = IatScanner.HasDangerousImports(iat, out var foundApis);
            if (!empty && !danger)
            {
                Console.WriteLine($"  [跳过] {d.ModuleName} IAT 良性（非可疑）");
                continue;
            }
            considered++;

            var (devices, foundPath) = DeviceEnumerator.Enum(_hKernelService, d.ModuleName);
            if (devices.Count == 0)
            {
                Console.WriteLine($"  [无设备] {d.ModuleName} 未暴露 \\Device，仅记录");
                continue;
            }

            foreach (var dev in devices)
            {
                if (_attach.Attach(_hKernelService, dev.DeviceName, out uint id, out string err))
                {
                    attached++;
                    Console.WriteLine($"  [附着] {d.ModuleName} → {dev.DeviceName} (AttachId={id})" +
                                      (danger ? $" 高危导入: {string.Join(",", foundApis)}" : " (IAT 空)"));
                }
                else
                {
                    Console.Error.WriteLine($"  [附着失败] {d.ModuleName} → {dev.DeviceName}: {err}");
                }
            }
        }

        // 刷新托管附着表（与内核保持一致）
        _attach.Refresh(_hKernelService);
        Console.WriteLine($"[ENGINE] 附着决策完成：候选 {considered}，成功附着 {attached}");
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
            Console.Error.WriteLine($"[ENGINE] OnSnapshot 异常: {ex.Message}");
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
