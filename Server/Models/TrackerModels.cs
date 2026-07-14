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
/// 会话建立时客户端采纳的策略快照。
/// </summary>
public sealed record PolicyInfo
{
    [JsonPropertyName("kernelFuncs")] public List<string> KernelFuncs { get; init; } = new();
    [JsonPropertyName("whitelistCertSubjects")] public List<string> WhitelistCertSubjects { get; init; } = new();
    [JsonPropertyName("whitelistHashes")] public List<string> WhitelistHashes { get; init; } = new();
}

/// <summary>
/// IOCTL 通信统计快照（客户端每 30 秒上报一次最新值，覆盖式更新）。
/// 与 ForensicJsonLogger 写出的 ioctl_stats.json 结构一致：
///   IoctlCounts: IOCTL 控制码 → 累计次数
///   Modules:     参与交互的模块路径集合
/// </summary>
public sealed record IoctlStats
{
    [JsonPropertyName("IoctlCounts")] public Dictionary<string, ulong> IoctlCounts { get; init; } = new();
    [JsonPropertyName("Modules")] public List<string> Modules { get; init; } = new();
}

/// <summary>
/// 一个已附着设备（AttachId + 设备名 + 对端驱动路径）。
/// </summary>
public sealed record AttachedDevice
{
    [JsonPropertyName("attachId")] public uint AttachId { get; init; }
    [JsonPropertyName("deviceName")] public string DeviceName { get; init; } = "";
    [JsonPropertyName("targetPath")] public string TargetPath { get; init; } = "";
}

/// <summary>
/// 一个采集到的取证文件（FileCopy / DebugDump）。
/// 文件字节由客户端以 multipart 上传并在服务端落地存储，<see cref="StoredName"/> 为服务端存储名，
/// <see cref="DownloadUrl"/> 为下载地址；仅元数据上报（旧客户端）时二者为空。
/// </summary>
public sealed record FileEntry
{
    [JsonPropertyName("kind")] public string Kind { get; init; } = "";   // "FileCopy" | "DebugDump"
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("path")] public string Path { get; init; } = "";
    [JsonPropertyName("size")] public long Size { get; init; }
    [JsonPropertyName("time")] public string Time { get; init; } = "";
    [JsonPropertyName("storedName")] public string StoredName { get; init; } = "";
    [JsonPropertyName("downloadUrl")] public string DownloadUrl { get; init; } = "";
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

    // ── 新产物计数（列表概览用）─────────────────────────────
    [JsonPropertyName("hasPolicy")] public bool HasPolicy { get; init; }
    [JsonPropertyName("hasIoctlStats")] public bool HasIoctlStats { get; init; }
    [JsonPropertyName("deviceCount")] public int DeviceCount { get; init; }
    [JsonPropertyName("fileCount")] public int FileCount { get; init; }
    [JsonPropertyName("snapshotCount")] public int SnapshotCount { get; init; }
}

/// <summary>
/// 会话详情（含事件列表与所有取证产物）
/// </summary>
public sealed record TrackerSessionDetail : TrackerSessionSummary
{
    [JsonPropertyName("events")] public List<TrackedEvent> Events { get; init; } = new();
    [JsonPropertyName("policy")] public PolicyInfo? Policy { get; init; }
    [JsonPropertyName("ioctlStats")] public IoctlStats? IoctlStats { get; init; }
    [JsonPropertyName("attachedDevices")] public List<AttachedDevice> AttachedDevices { get; init; } = new();
    [JsonPropertyName("fileEntries")] public List<FileEntry> FileEntries { get; init; } = new();
    [JsonPropertyName("snapshots")] public List<string> Snapshots { get; init; } = new();   // 原始 JSON 字符串
}
