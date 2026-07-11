namespace Hyperion.UserService;

// ═══════════════════════════════════════════════════════════════
//  Tracker 事件投递抽象
//
//  现在的架构:
//   - 本地日志: LocalLogTrackerSink (仅 Console.Error 日志)
//   - 服务端上报: ServerDataClient (4 种独立 API: events/snapshots/kernel-comms/dumps)
//     events(winevent+etw) 走 ServerDataClient.PostEvent 批量上报
//     snapshots/kernel-comms/dumps 走各自的独立 POST API
//   - TrackerIntegration 用 LocalLogTrackerSink + ServerDataClient 双投递
// ═══════════════════════════════════════════════════════════════

/// <summary>
/// Tracker 事件投递接口(本地日志)。
/// 服务端上报走 ServerDataClient 的独立 API,不走此接口。
/// </summary>
public interface ITrackerSink
{
    /// <summary>投递一个分级事件 (非阻塞,由事件回调线程调用)。</summary>
    void Post(TrackedEvent evt);

    /// <summary>阻塞刷新所有待发事件。</summary>
    Task FlushAsync();
}

/// <summary>
/// 统一事件模型(winevent + etw)。
/// 通过 ServerDataClient.PostEvent 上报到 /api/tracker/events。
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
/// 本地日志 Sink: 只打印到 Console.Error。
/// 用于本地调试,服务端上报走 ServerDataClient。
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
