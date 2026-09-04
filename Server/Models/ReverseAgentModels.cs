using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

// ═══════════════════════════════════════════════════════════════
//  逆向分析 Agent — 数据库实体
// ═══════════════════════════════════════════════════════════════

[Table("session_analysis_states")]
public sealed class SessionAnalysisStateEntity
{
    [Key][Column("session_id")] public string SessionId { get; set; } = "";
    [Column("analysis_status")] public string AnalysisStatus { get; set; } = "pending"; // pending/analyzing/done/no_files
    [Column("analysis_result")] public string? AnalysisResult { get; set; } // normal/cheat/suspicious
    [Column("assigned_agent_id")] public string? AssignedAgentId { get; set; }
    [Column("analysis_started_at")] public string? AnalysisStartedAt { get; set; }
    [Column("analysis_completed_at")] public string? AnalysisCompletedAt { get; set; }
    [Column("last_heartbeat_at")] public string? LastHeartbeatAt { get; set; }
    [Column("current_file")] public string? CurrentFile { get; set; }
}

[Table("analysis_reports")]
public sealed class AnalysisReportEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("file_name")] public string FileName { get; set; } = "";
    [Column("result")] public string Result { get; set; } = ""; // normal/cheat/suspicious
    [Column("content")] public string Content { get; set; } = ""; // markdown
    [Column("generated_at")] public string GeneratedAt { get; set; } = "";
    [Column("agent_id")] public string AgentId { get; set; } = "";
}

// ═══════════════════════════════════════════════════════════════
//  API 响应模型
// ═══════════════════════════════════════════════════════════════

public sealed record ReverseAgentConnectResponse
{
    [JsonPropertyName("agent_id")] public string AgentId { get; init; } = "";
    [JsonPropertyName("agent_token")] public string AgentToken { get; init; } = "";
    [JsonPropertyName("llm_apis")] public List<ClusterLlmApiEntry> LlmApis { get; init; } = new();
    [JsonPropertyName("connected_at")] public string ConnectedAt { get; init; } = "";
}

public sealed record NextTaskResponse
{
    [JsonPropertyName("has_task")] public bool HasTask { get; init; }
    [JsonPropertyName("session_id")] public string? SessionId { get; init; }
    [JsonPropertyName("machine_name")] public string? MachineName { get; init; }
    [JsonPropertyName("files")] public List<TaskFileInfo> Files { get; init; } = new();
}

public sealed record TaskFileInfo
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("stored_name")] public string StoredName { get; init; } = "";
    [JsonPropertyName("download_url")] public string DownloadUrl { get; init; } = "";
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";
}

public sealed record ActiveAgentEntry
{
    [JsonPropertyName("agent_id")] public string AgentId { get; init; } = "";
    [JsonPropertyName("llm_api_name")] public string LlmApiName { get; init; } = "";
    [JsonPropertyName("connected_at")] public string ConnectedAt { get; init; } = "";
    [JsonPropertyName("completed_tasks")] public int CompletedTasks { get; init; }
    [JsonPropertyName("current_status")] public string CurrentStatus { get; init; } = "";
    [JsonPropertyName("is_online")] public bool IsOnline { get; init; }
}

public sealed record AnalysisQueueEntry
{
    [JsonPropertyName("session_id")] public string SessionId { get; init; } = "";
    [JsonPropertyName("machine_name")] public string MachineName { get; init; } = "";
    [JsonPropertyName("started_at")] public string StartedAt { get; init; } = "";
    [JsonPropertyName("analysis_status")] public string AnalysisStatus { get; init; } = "pending";
    [JsonPropertyName("analysis_result")] public string? AnalysisResult { get; init; }
    [JsonPropertyName("file_count")] public int FileCount { get; init; }
}

public record ReportListEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("session_id")] public string SessionId { get; init; } = "";
    [JsonPropertyName("file_name")] public string FileName { get; init; } = "";
    [JsonPropertyName("result")] public string Result { get; init; } = "";
    [JsonPropertyName("generated_at")] public string GeneratedAt { get; init; } = "";
}

public sealed record ReportDetail : ReportListEntry
{
    [JsonPropertyName("content")] public string Content { get; init; } = "";
    [JsonPropertyName("agent_id")] public string AgentId { get; init; } = "";
}

// ═══════════════════════════════════════════════════════════════
//  请求模型
// ═══════════════════════════════════════════════════════════════

public sealed class ReverseAgentHeartbeatRequest
{
    [JsonPropertyName("agent_id")] public string AgentId { get; set; } = "";
    [JsonPropertyName("current_status")] public string CurrentStatus { get; set; } = "";
}

// 研判终端日志，由 Agent 在执行过程中上报，用于前端可观测/回放
[Table("analysis_logs")]
public sealed class AnalysisLogEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("seq")] public long Seq { get; set; }
    [Column("ts")] public string Ts { get; set; } = "";
    [Column("level")] public string Level { get; set; } = "info"; // info | llm | tool_call | tool_result
    [Column("file")] public string File { get; set; } = "";
    [Column("text")] public string Text { get; set; } = "";
}

public sealed record AnalysisLogDto
{
    [JsonPropertyName("session_id")] public string SessionId { get; init; } = "";
    [JsonPropertyName("seq")] public long Seq { get; init; }
    [JsonPropertyName("ts")] public string Ts { get; init; } = "";
    [JsonPropertyName("level")] public string Level { get; init; } = "info";
    [JsonPropertyName("file")] public string File { get; init; } = "";
    [JsonPropertyName("text")] public string Text { get; init; } = "";
}

public sealed class AgentLogRequest
{
    [JsonPropertyName("agent_id")] public string AgentId { get; set; } = "";
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("file")] public string File { get; set; } = "";
    [JsonPropertyName("level")] public string Level { get; set; } = "info";
    [JsonPropertyName("text")] public string Text { get; set; } = "";
}
