using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Hyperion.Tracker.EtwTracker;

/// <summary>
/// ETW 实时事件追踪管理器。
/// - KernelTraceEventParser.ImageLoad: 监听 .sys 驱动加载 (PID 0/4)
/// - UserPnP: 监听驱动安装事件 (20001/20003)
/// </summary>
public sealed class EtwTrackerManager : IDisposable
{
    // ── UserPnP (驱动安装) ────────────────────────────────────────────────
    private static readonly Guid UserPnPProvider = new("96f4a050-7e31-453c-88be-9634f4e02139");
    private const int DriverInstallStart = 20001;
    private const int DriverInstallComplete = 20003;

    private TraceEventSession? _session;
    private Thread? _thread;

    public event Action<EtwEvent>? OnEvent;

    public void Start()
    {
        _session = new TraceEventSession("Hyperion_Tracker_Etw");

        // Kernel — ImageLoad 捕获所有模块加载 (含驱动 .sys)
        var flags = KernelTraceEventParser.Keywords.ImageLoad;
        _session.EnableKernelProvider(flags);

        // UserPnP — 驱动安装事件
        _session.EnableProvider(UserPnPProvider);

        // 强类型解析
        _session.Source.Kernel.ImageLoad += OnImageLoad;
        _session.Source.Dynamic.All += OnDynamicEvent;

        _thread = new Thread(() =>
        {
            try { _session.Source.Process(); }
            catch (Exception ex) { Console.Error.WriteLine($"[EtwTracker] 异常: {ex.Message}"); }
        })
        { IsBackground = true, Name = "EtwTracker" };
        _thread.Start();

        Console.WriteLine("  ├─ ETW Kernel (ImageLoad)  [.sys 驱动加载]");
        Console.WriteLine($"  ├─ ETW UserPnP ({UserPnPProvider})  [20001, 20003]");
    }

    public void Dispose()
    {
        try { _session?.Stop(); _session?.Dispose(); }
        catch { }
        _session = null;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  驱动加载 — KernelTraceEventParser.ImageLoad → 过滤 .sys
    // ══════════════════════════════════════════════════════════════════════

    private void OnImageLoad(ImageLoadTraceData data)
    {
        // 只要 System 进程 (PID 0/4) 加载的 .sys 文件
        if (data.ProcessID != 0 && data.ProcessID != 4) return;
        var fileName = data.FileName ?? "";
        if (!fileName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) return;

        OnEvent?.Invoke(new EtwEvent
        {
            TimeCreated = data.TimeStamp.ToUniversalTime(),
            ProviderName = "Kernel",
            EventId = (int)data.ID,
            EventName = "DriverLoad",
            ProcessName = data.ProcessName ?? "System",
            ProcessId = data.ProcessID,
            Details = new()
            {
                ["FileName"] = fileName,
                ["ImageBase"] = $"0x{data.ImageBase:X}",
                ["ImageSize"] = data.ImageSize.ToString(),
                ["DefaultBase"] = $"0x{data.DefaultBase:X}",
            },
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    //  驱动安装 — UserPnP 20001/20003
    // ══════════════════════════════════════════════════════════════════════

    private void OnDynamicEvent(TraceEvent data)
    {
        if (data.ProviderGuid != UserPnPProvider) return;
        if (data.ID != (TraceEventID)DriverInstallStart &&
            data.ID != (TraceEventID)DriverInstallComplete) return;

        var eventName = (int)data.ID switch
        {
            DriverInstallStart => "DriverInstall",
            DriverInstallComplete => "DriverInstallComplete",
            _ => $"Unknown({(int)data.ID})",
        };

        var details = new Dictionary<string, string>();
        foreach (var name in data.PayloadNames)
        {
            try { details[name] = data.PayloadByName(name)?.ToString() ?? "(null)"; }
            catch { }
        }

        OnEvent?.Invoke(new EtwEvent
        {
            TimeCreated = data.TimeStamp.ToUniversalTime(),
            ProviderName = "UserPnP",
            EventId = (int)data.ID,
            EventName = eventName,
            ProcessName = data.ProcessName ?? "N/A",
            ProcessId = data.ProcessID,
            Details = details,
        });
    }
}
