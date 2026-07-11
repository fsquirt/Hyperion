namespace Hyperion.UserService;

// ═══════════════════════════════════════════════════════════════
//  Tracker 事件投递抽象
//
//  当前实现: LocalLogTrackerSink (仅本地 Console.Error 日志,不上报)
//  未来实现: ServerTrackerSink   (走 HTTP 上报到 Hyperion.Server
//                                  的 /api/tracker/start /events /heartbeat /end)
//
//  接入新 sink 的步骤:
//    1. 实现 ITrackerSink (Post + FlushAsync)
//    2. 在 AntiCheatService 构造 TrackerIntegration 时传入新 sink
//  例如未来接入 Server:
//    _tracker = new TrackerIntegration(new ServerTrackerSink(serverUrl));
// ═══════════════════════════════════════════════════════════════

/// <summary>
/// Tracker 事件投递接口。
/// 所有监控事件 (ETW / Windows Event) 经分级后通过此接口投递。
/// 实现可以只写本地日志,也可以走 HTTP 批量上报到 Server。
/// </summary>
public interface ITrackerSink
{
    /// <summary>投递一个分级事件 (非阻塞,由事件回调线程调用)。</summary>
    void Post(TrackedEvent evt);

    /// <summary>阻塞刷新所有待发事件 (在 Dispose 前调用,确保缓冲事件落盘/落网)。</summary>
    Task FlushAsync();
}

/// <summary>
/// 统一事件模型。
/// 字段对齐 Hyperion.Tracker.Services.ServerConnection.TrackedEventDto,
/// 未来 ServerTrackerSink 可直接序列化为 JSON 上报到 /api/tracker/events。
/// </summary>
public sealed record TrackedEvent
{
    /// <summary>事件类型: "winevent" / "etw"</summary>
    public required string Type { get; init; }

    /// <summary>事件时间 (UTC)</summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>分级: "HIGH" / "CRIT" / "ERR" / "WARN" / "INFO"</summary>
    public required string Level { get; init; }

    /// <summary>事件来源 (Windows Channel 或 ETW Provider 名)</summary>
    public required string Source { get; init; }

    /// <summary>事件标题 (人类可读)</summary>
    public required string Title { get; init; }

    /// <summary>详细描述 (多行 Payload)</summary>
    public string? Detail { get; init; }

    /// <summary>Windows 事件的原始 XML (仅 winevent 有,供深度解析)</summary>
    public string? Xml { get; init; }
}

/// <summary>
/// 本地日志 Sink: 只打印到 Console.Error,不上报。
/// 这是当前默认实现,用于"未接入 Server 上报"阶段。
/// </summary>
public sealed class LocalLogTrackerSink : ITrackerSink
{
    private readonly object _lock = new();

    public void Post(TrackedEvent evt)
    {
        // Console.Error 本身线程安全,但"标签颜色 + 多行正文"要保证原子性,加锁
        lock (_lock)
        {
            var oldColor = Console.ForegroundColor;
            try
            {
                var (color, tag) = evt.Level switch
                {
                    "HIGH" => (ConsoleColor.Red,     "HIGH"),
                    "CRIT" => (ConsoleColor.Red,     "CRIT"),
                    "ERR"  => (ConsoleColor.Red,     "ERR "),
                    "WARN" => (ConsoleColor.Yellow,  "WARN"),
                    _      => (ConsoleColor.Cyan,    "INFO"),
                };

                Console.ForegroundColor = color;
                Console.Error.Write($"[{tag}] ");
                Console.ResetColor();
                Console.Error.WriteLine(
                    $"{evt.Timestamp:HH:mm:ss.fff}  {evt.Source}  {evt.Title}");

                if (!string.IsNullOrEmpty(evt.Detail))
                {
                    Console.ForegroundColor = color;
                    // 多行 Detail 每行缩进对齐
                    var detail = evt.Detail.Replace("\n", "\n         ");
                    Console.Error.WriteLine($"         {detail}");
                    Console.ResetColor();
                }
                Console.Error.WriteLine();
            }
            finally
            {
                Console.ForegroundColor = oldColor;
            }
        }
    }

    public Task FlushAsync() => Task.CompletedTask;
}
