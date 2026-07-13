using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
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

/// <summary>
/// 运行时捕获文件元数据(.dmp / .dll / .exe / .sys 上传文件记录)。
/// 客户端 (UserService) 通过 multipart/form-data POST /api/tracker/files 上传。
/// </summary>
[Table("captured_files")]
public sealed class CapturedFile
{
    [Key][Column("id")] public int Id { get; set; }
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("file_name")] public string FileName { get; set; } = "";
    /// <summary>"dump" | "filecopy" | "driver-sys"</summary>
    [Column("file_type")] public string FileType { get; set; } = "";
    [Column("file_size")] public long FileSize { get; set; }
    [Column("sha256")] public string Sha256 { get; set; } = "";
    [Column("stored_path")] public string StoredPath { get; set; } = "";
    [Column("metadata")] public string? Metadata { get; set; }
    [Column("uploaded_at")] public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    /// <summary>"pending" | "analyzing" | "done" | "failed"</summary>
    [Column("analysis_status")] public string AnalysisStatus { get; set; } = "pending";
    /// <summary>MCP 分析结果 JSON blob (Task 7)</summary>
    [Column("analysis_result")] public string? AnalysisResult { get; set; }
}
