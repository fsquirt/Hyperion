using Hyperion.Tracker.EtwTracker;
using Hyperion.Tracker.WinEventTracker;

namespace Hyperion.UserService;

/// <summary>
/// 把 Hyperion.Tracker 的 ETW + Windows Event 订阅能力集成到 UserService。
/// 
/// 事件分级逻辑对齐 Hyperion.Tracker/Program.cs:
///   - Windows 事件: CodeIntegrity / Defender → HIGH;其他按 Level (1=CRIT 2=ERR 3=WARN 4=INFO)
///   - ETW 事件:    DriverLoad / DriverInstall / DriverInstallComplete → HIGH;其他 INFO
///   - INFO 默认不投递 (--debug 才投递,避免噪声)
/// 
/// 事件经分级后投递到 <see cref="ITrackerSink"/>。当前用 <see cref="LocalLogTrackerSink"/>
/// 仅写本地 Console.Error 日志;未来可换 ServerTrackerSink 走 HTTP 批量上报到 Hyperion.Server。
/// </summary>
public sealed class TrackerIntegration : IDisposable
{
    private readonly ITrackerSink _sink;
    private readonly bool _debug;
    private readonly WinEventTrackerManager _winEvt = new();
    private readonly EtwTrackerManager _etw = new();
    private bool _started;

    public TrackerIntegration(ITrackerSink sink, bool debug = false)
    {
        _sink = sink;
        _debug = debug;
    }

    /// <summary>
    /// 启动 ETW + Windows Event 实时订阅。
    /// 幂等: 重复调用不会重复订阅。
    /// </summary>
    public void Start()
    {
        if (_started) return;
        _started = true;

        Console.Error.WriteLine("[Tracker] 启动事件订阅...");
        Console.Error.WriteLine("[*] Windows 事件日志订阅:");

        // Windows 事件: 回调里做分级,高危直接投递,其他按 Level
        _winEvt.OnEvent += OnWinEvent;
        _winEvt.Start();

        Console.Error.WriteLine();
        Console.Error.WriteLine("[*] ETW 实时事件订阅:");

        // ETW: 驱动加载/安装 → HIGH (BYOVD 检测核心);其他 INFO
        _etw.OnEvent += OnEtwEvent;
        _etw.Start();

        Console.Error.WriteLine();
        Console.Error.WriteLine("[Tracker] 订阅已启动 (Windows Event + ETW,本地日志 sink)");
        if (_debug)
            Console.Error.WriteLine("[Tracker] DEBUG 模式: INFO 事件也会投递");
    }

    // ═══════════════════════════════════════════════════════════════
    //  Windows 事件分级处理
    //  逻辑对齐 Hyperion.Tracker/Program.cs 的 winTracker.OnEvent
    // ═══════════════════════════════════════════════════════════════

    private void OnWinEvent(MonitoredEvent evt)
    {
        // CodeIntegrity: 未签名驱动被阻止 → 直接算高危
        if (evt.Channel.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase))
        {
            PostHigh("winevent", evt.Channel, "代码完整性违规", evt.Description, evt.RawXml);
            return;
        }

        // Defender: 检测到恶意软件 → 高危
        if (evt.Channel.Contains("Defender", StringComparison.OrdinalIgnoreCase))
        {
            PostHigh("winevent", evt.Channel, "Defender 告警", evt.Description, evt.RawXml);
            return;
        }

        // 其他事件: 按 Windows Event Level 分级
        var level = evt.Level switch
        {
            1 => "CRIT",
            2 => "ERR",
            3 => "WARN",
            _ => "INFO",
        };

        // 默认不投递 INFO, --debug 才投递
        if (level == "INFO" && !_debug) return;

        _sink.Post(new TrackedEvent
        {
            Type = "winevent",
            Timestamp = evt.TimeCreated,
            Level = level,
            Source = evt.Channel,
            Title = $"ID={evt.EventId} ({evt.Provider})",
            Detail = evt.Description,
            Xml = evt.RawXml,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  ETW 事件分级处理
    //  逻辑对齐 Hyperion.Tracker/Program.cs 的 etwTracker.OnEvent
    // ═══════════════════════════════════════════════════════════════

    private void OnEtwEvent(EtwEvent evt)
    {
        // 驱动加载 / 驱动安装 → 高危 (BYOVD 检测核心)
        if (evt.EventName is "DriverLoad" or "DriverInstall" or "DriverInstallComplete")
        {
            var detail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                         string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}"));
            PostHigh("etw", evt.ProviderName, $"⚠ {evt.EventName}", detail, null);
            return;
        }

        // 其他 ETW 事件 → INFO, 仅 --debug
        if (!_debug) return;

        var infoDetail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                         string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}"));

        _sink.Post(new TrackedEvent
        {
            Type = "etw",
            Timestamp = evt.TimeCreated,
            Level = "INFO",
            Source = evt.ProviderName,
            Title = evt.EventName,
            Detail = infoDetail,
            Xml = null,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private void PostHigh(string type, string source, string title, string? detail, string? xml)
    {
        _sink.Post(new TrackedEvent
        {
            Type = type,
            Timestamp = DateTime.UtcNow,
            Level = "HIGH",
            Source = source,
            Title = title,
            Detail = detail,
            Xml = xml,
        });
    }

    /// <summary>
    /// 停止所有订阅并刷新 sink 缓冲。
    /// 顺序: 先停 ETW (不再产生事件) → 再停 WinEvent → 最后 FlushAsync。
    /// </summary>
    public void Dispose()
    {
        if (!_started) return;
        _started = false;

        Console.Error.WriteLine("[Tracker] 正在停止订阅...");

        // 1. 先停订阅 (不再产生新事件)
        try { _etw.Dispose(); }   catch { Console.Error.WriteLine("[Tracker] ETW 停止异常"); }
        try { _winEvt.Dispose(); } catch { Console.Error.WriteLine("[Tracker] WinEvent 停止异常"); }
        Console.Error.WriteLine("[Tracker] 事件订阅已释放");

        // 2. 刷掉 sink 里缓冲的事件 (本地 sink 立即返回;未来 Server sink 阻塞到落网)
        try { _sink.FlushAsync().GetAwaiter().GetResult(); }
        catch (Exception ex) { Console.Error.WriteLine($"[Tracker] Flush 异常: {ex.Message}"); }

        Console.Error.WriteLine("[Tracker] 已停止");
    }
}
