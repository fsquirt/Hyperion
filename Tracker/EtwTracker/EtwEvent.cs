namespace Hyperion.Tracker.EtwTracker;

/// <summary>
/// ETW 实时事件模型。
/// </summary>
public sealed record EtwEvent
{
    /// <summary>事件时间 (UTC)</summary>
    public required DateTime TimeCreated { get; init; }

    /// <summary>Provider 名称</summary>
    public required string ProviderName { get; init; }

    /// <summary>事件 ID</summary>
    public required int EventId { get; init; }

    /// <summary>事件名称 (人类可读)</summary>
    public required string EventName { get; init; }

    /// <summary>触发事件的进程名</summary>
    public required string ProcessName { get; init; }

    /// <summary>触发事件的进程 ID</summary>
    public required int ProcessId { get; init; }

    /// <summary>结构化 Payload 字段</summary>
    public required Dictionary<string, string> Details { get; init; }

    /// <summary>格式化输出</summary>
    public string Formatted => Details.Count == 0
        ? "(无 Payload)"
        : string.Join(Environment.NewLine, Details.Select(kv => $"         {kv.Key}: {kv.Value}"));
}
