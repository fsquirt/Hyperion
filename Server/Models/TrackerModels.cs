using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

/// <summary>
/// Tracker 上报的单个事件
/// </summary>
public sealed record TrackedEvent
{
    [JsonPropertyName("type")] public string Type { get; init; } = "";
    [JsonPropertyName("timestamp")] public string Timestamp { get; init; } = "";
    [JsonPropertyName("level")] public string Level { get; init; } = "INFO";
    [JsonPropertyName("source")] public string Source { get; init; } = "";
    [JsonPropertyName("title")] public string Title { get; init; } = "";
    [JsonPropertyName("detail")] public string? Detail { get; init; }
    [JsonPropertyName("xml")] public string? RawXml { get; init; }
}

/// <summary>
/// 会话摘要（列表用）
/// </summary>
public record TrackerSessionSummary
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("machineName")] public string MachineName { get; init; } = "";
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("startedAt")] public string StartedAt { get; init; } = "";
    [JsonPropertyName("lastHeartbeat")] public string LastHeartbeat { get; init; } = "";
    [JsonPropertyName("endedAt")] public string? EndedAt { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = "active";
    [JsonPropertyName("eventCount")] public int EventCount { get; init; }
}

/// <summary>
/// 会话详情（含事件列表）
/// </summary>
public sealed record TrackerSessionDetail : TrackerSessionSummary
{
    [JsonPropertyName("events")] public List<TrackedEvent> Events { get; init; } = [];
}
