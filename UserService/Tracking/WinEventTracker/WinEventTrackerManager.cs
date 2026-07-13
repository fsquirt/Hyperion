using System.Diagnostics.Eventing.Reader;
using System.Text;

namespace Hyperion.UserService.Tracking.WinEventTracker;

/// <summary>
/// Windows 事件日志订阅管理器。
/// 负责为每个 Windows 事件通道创建 EventLogWatcher，统一输出 MonitoredEvent。
/// </summary>
public sealed class WinEventTrackerManager : IDisposable
{
    // ── 监控的事件定义 ─────────────────────────────────────────────────────

    /// <summary>安全日志</summary>
    private static readonly (int Id, string Name)[] SecurityEvents =
    [
        (4688, "进程创建"),
        (4656, "句柄请求"),
        (4663, "对象访问"),
        (4657, "注册表修改"),
        (4697, "服务安装"),
        (5038, "代码完整性校验失败"),
    ];

    /// <summary>系统日志</summary>
    private static readonly (int Id, string Name)[] SystemEvents =
    [
        (7045, "新服务安装"),
    ];

    /// <summary>CodeIntegrity 日志</summary>
    private static readonly (int Id, string Name)[] CodeIntegrityEvents =
    [
        (3004, "未签名驱动被阻止"),
        (3033, "未签名驱动被阻止(变体)"),
    ];

    /// <summary>Windows Defender 日志</summary>
    private static readonly (int Id, string Name)[] DefenderEvents =
    [
        (1116, "检测到恶意软件"),
        (1117, "恶意软件处理操作"),
        (1006, "Defender 警报"),
    ];

    private readonly List<EventLogWatcher> _watchers = [];

    /// <summary>
    /// 收到监控事件时触发。在 EventLogWatcher 回调线程上调用，不要做耗时操作。
    /// </summary>
    public event Action<MonitoredEvent>? OnEvent;

    /// <summary>
    /// 启动所有订阅。
    /// </summary>
    public void Start()
    {
        Subscribe("Security", SecurityEvents);
        Subscribe("System", SystemEvents);
        Subscribe("Microsoft-Windows-CodeIntegrity/Operational", CodeIntegrityEvents);
        Subscribe("Microsoft-Windows-Windows Defender/Operational", DefenderEvents);

        Console.WriteLine($"[WinEventTracker] 已启动 {_watchers.Count} 个事件通道订阅");
    }

    /// <summary>
    /// 停止所有订阅并释放资源。
    /// </summary>
    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try
            {
                w.Enabled = false;
                w.Dispose();
            }
            catch { /* 清理时不抛异常 */ }
        }
        _watchers.Clear();
    }

    // ── 内部实现 ──────────────────────────────────────────────────────────

    private void Subscribe(string channel, (int Id, string Name)[]? events)
    {
        var xpath = BuildXPath(channel, events);
        var query = new EventLogQuery(channel, PathType.LogName, xpath);

        var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += OnEventRecordWritten;
        watcher.Enabled = true;

        _watchers.Add(watcher);

        var label = events is { Length: > 0 }
            ? string.Join(", ", events.Select(e => e.Id))
            : "ALL";
        Console.WriteLine($"  ├─ {channel}  [{label}]");
    }

    private static string BuildXPath(string channel, (int Id, string Name)[]? events)
    {
        var sb = new StringBuilder();
        sb.Append("<QueryList><Query Id='0' Path='");
        sb.Append(EscapeXml(channel));
        sb.Append("'><Select Path='");
        sb.Append(EscapeXml(channel));
        sb.Append("'>");

        if (events is { Length: > 0 })
        {
            sb.Append("*[System[");
            for (int i = 0; i < events.Length; i++)
            {
                if (i > 0) sb.Append(" or ");
                sb.Append($"(EventID={events[i].Id})");
            }
            sb.Append("]]");
        }
        else
        {
            sb.Append("*");
        }

        sb.Append("</Select></Query></QueryList>");
        return sb.ToString();
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is { } ex)
        {
            Console.Error.WriteLine($"[WinEventTracker] 读取事件异常: {ex.Message}");
            return;
        }
        if (e.EventRecord is not { } record) return;

        try
        {
            var evt = new MonitoredEvent
            {
                TimeCreated = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                Channel = record.LogName ?? "N/A",
                EventId = record.Id,
                Level = (byte)(record.Level ?? 0),
                Provider = record.ProviderName ?? "N/A",
                Description = SafeFormatDescription(record),
                RawXml = record.ToXml(),
            };

            OnEvent?.Invoke(evt);
        }
        finally
        {
            record.Dispose();
        }
    }

    private static string SafeFormatDescription(EventRecord record)
    {
        try { return record.FormatDescription() ?? "(无描述)"; }
        catch { return "(FormatDescription 失败)"; }
    }

    private static string EscapeXml(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("'", "&apos;");
}
