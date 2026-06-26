using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SEWindows.Server.Models;

// ═══════════════════════════════════════════════════════════════
//  恶意驱动阻止列表
// ═══════════════════════════════════════════════════════════════

/// <summary>拉黑来源</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum BlocklistSource
{
    /// <summary>LOLDrivers 项目 (loldrivers.io)</summary>
    Loldriver,
    /// <summary>微软易受攻击驱动阻止列表 (WDAC SiPolicy)</summary>
    Msft,
    /// <summary>管理员手动上传 .sys 拉黑</summary>
    Manual,
}

/// <summary>单条拉黑记录（API 响应模型）</summary>
public sealed record BlockedDriverRecord
{
    [JsonPropertyName("id")]         public string Id { get; init; } = "";
    [JsonPropertyName("source")]     public BlocklistSource Source { get; init; }
    [JsonPropertyName("driver_name")] public string DriverName { get; init; } = "";
    [JsonPropertyName("md5")]        public string? Md5 { get; init; }
    [JsonPropertyName("sha1")]       public string? Sha1 { get; init; }
    [JsonPropertyName("sha256")]     public string? Sha256 { get; init; }
    [JsonPropertyName("added_at")]   public string AddedAt { get; init; } = "";
    [JsonPropertyName("notes")]      public string? Notes { get; init; }
}

/// <summary>来源统计</summary>
public sealed record BlocklistStats
{
    [JsonPropertyName("total")]       public int Total { get; init; }
    [JsonPropertyName("loldriver")]   public int Loldriver { get; init; }
    [JsonPropertyName("msft")]        public int Msft { get; init; }
    [JsonPropertyName("manual")]      public int Manual { get; init; }
    [JsonPropertyName("loldriver_updated_at")] public string? LoldriverUpdatedAt { get; init; }
    [JsonPropertyName("msft_updated_at")]      public string? MsftUpdatedAt { get; init; }
}

/// <summary>更新操作结果</summary>
public sealed record BlocklistUpdateResult
{
    [JsonPropertyName("success")]    public bool Success { get; init; }
    [JsonPropertyName("source")]     public string Source { get; init; } = "";
    [JsonPropertyName("added")]      public int Added { get; init; }
    [JsonPropertyName("removed")]    public int Removed { get; init; }
    [JsonPropertyName("total")]      public int Total { get; init; }
    [JsonPropertyName("error")]      public string? Error { get; init; }
}

/// <summary>手动上传拉黑结果</summary>
public sealed record ManualBlockResult
{
    [JsonPropertyName("success")]    public bool Success { get; init; }
    [JsonPropertyName("id")]         public string? Id { get; init; }
    [JsonPropertyName("driver_name")] public string DriverName { get; init; } = "";
    [JsonPropertyName("md5")]        public string? Md5 { get; init; }
    [JsonPropertyName("sha1")]       public string? Sha1 { get; init; }
    [JsonPropertyName("sha256")]     public string? Sha256 { get; init; }
    [JsonPropertyName("error")]      public string? Error { get; init; }
}

/// <summary>手动按哈希添加拉黑记录请求</summary>
public sealed class ManualHashAddRequest
{
    [JsonPropertyName("driver_name")] public string DriverName { get; set; } = "";
    [JsonPropertyName("md5")]         public string? Md5 { get; set; }
    [JsonPropertyName("sha1")]        public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")]      public string? Sha256 { get; set; }
    [JsonPropertyName("notes")]       public string? Notes { get; set; }
}

/// <summary>编辑拉黑记录请求</summary>
public sealed class BlocklistUpdateRequest
{
    [JsonPropertyName("driver_name")] public string? DriverName { get; set; }
    [JsonPropertyName("md5")]         public string? Md5 { get; set; }
    [JsonPropertyName("sha1")]        public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")]      public string? Sha256 { get; set; }
    [JsonPropertyName("notes")]       public string? Notes { get; set; }
}

// ═══════════════════════════════════════════════════════════════
//  数据库实体
// ═══════════════════════════════════════════════════════════════

[Table("blocked_drivers")]
public sealed class BlockedDriverEntity
{
    [Key] [Column("id")]          public string Id { get; set; } = "";
    [Column("source")]            public string Source { get; set; } = "";   // loldriver / msft / manual
    [Column("driver_name")]       public string DriverName { get; set; } = "";
    [Column("md5")]               public string? Md5 { get; set; }
    [Column("sha1")]              public string? Sha1 { get; set; }
    [Column("sha256")]            public string? Sha256 { get; set; }
    [Column("added_at")]          public string AddedAt { get; set; } = "";
    [Column("notes")]             public string? Notes { get; set; }
}
