using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

// ═══════════════════════════════════════════════════════════════
//  附着白名单 (Filter Attach Whitelist)
// ═══════════════════════════════════════════════════════════════
//  场景:KernelService 的 DriverFilter 模块在游戏启动时会枚举所有
//        应用层可达的第三方 WHQL 驱动并附着。某些驱动虽然符合
//        "第三方 WHQL + 暴露符号链接"的条件,但实际是杀毒软件、
//        其他反作弊、合法外设驱动等,不应当被骚扰。
//        管理员可以在该白名单中按 "驱动文件哈希" 或 "签名证书"
//        两种维度排除它们。
//
//  两种条目类型:
//    1) Hash   — 指定 .sys 的 MD5/SHA1/SHA256 之一或多个
//    2) Cert   — 指定签名者证书的 Subject + SHA256 指纹
//
//  典型来源:
//    - 管理员手动按哈希添加
//    - 管理员手动按证书添加(填 Subject 或 上传 .cer)
//    - 管理员上传 .sys 文件,后端提取哈希 + 多签名(多证书),
//      返回给前端,前端弹出对话框让管理员选择"添加哈希"还是
//      "添加其中某个证书"
// ═══════════════════════════════════════════════════════════════

/// <summary>白名单条目类型</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum WhitelistEntryType
{
    /// <summary>按驱动文件哈希排除</summary>
    Hash,
    /// <summary>按签名者证书排除</summary>
    Cert,
}

/// <summary>白名单单条记录(API 响应模型)</summary>
public sealed record WhitelistEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("type")] public WhitelistEntryType Type { get; init; }
    /// <summary>显示名(哈希:驱动文件名;证书:签名者 Subject 简称)</summary>
    [JsonPropertyName("display_name")] public string DisplayName { get; init; } = "";
    /// <summary>哈希条目:SHA256(可空,可能有 MD5/SHA1);证书条目:证书 SHA256 指纹</summary>
    [JsonPropertyName("sha256")] public string? Sha256 { get; init; }
    [JsonPropertyName("md5")] public string? Md5 { get; init; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; init; }
    /// <summary>证书条目:签名者 Subject 全文</summary>
    [JsonPropertyName("cert_subject")] public string? CertSubject { get; init; }
    /// <summary>证书条目:证书颁发者 Issuer</summary>
    [JsonPropertyName("cert_issuer")] public string? CertIssuer { get; init; }
    [JsonPropertyName("added_at")] public string AddedAt { get; init; } = "";
    [JsonPropertyName("notes")] public string? Notes { get; init; }
}

/// <summary>白名单统计</summary>
public sealed record WhitelistStats
{
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("hash_count")] public int HashCount { get; init; }
    [JsonPropertyName("cert_count")] public int CertCount { get; init; }
}

/// <summary>按哈希添加白名单请求</summary>
public sealed class WhitelistAddHashRequest
{
    [JsonPropertyName("driver_name")] public string DriverName { get; set; } = "";
    [JsonPropertyName("md5")] public string? Md5 { get; set; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>按证书添加白名单请求</summary>
public sealed class WhitelistAddCertRequest
{
    /// <summary>签名者 Subject(完整或前缀匹配)</summary>
    [JsonPropertyName("cert_subject")] public string CertSubject { get; set; } = "";
    /// <summary>证书 SHA256 指纹(可选,优先用指纹精确匹配)</summary>
    [JsonPropertyName("cert_thumbprint_sha256")] public string? CertThumbprintSha256 { get; set; }
    /// <summary>证书颁发者 Issuer(可选)</summary>
    [JsonPropertyName("cert_issuer")] public string? CertIssuer { get; set; }
    /// <summary>显示名(可选,默认取 Subject 简称)</summary>
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>编辑白名单条目请求</summary>
public sealed class WhitelistUpdateRequest
{
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>上传 .sys 后返回的解析结果(多签名选择)</summary>
public sealed class SysParseResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("file_name")] public string FileName { get; init; } = "";
    [JsonPropertyName("file_size")] public long FileSize { get; init; }
    [JsonPropertyName("md5")] public string? Md5 { get; init; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; init; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; init; }
    /// <summary>提取到的所有签名者证书(WHQL + 厂商等),供管理员选择添加哪个</summary>
    [JsonPropertyName("signers")] public List<SysSignerInfo> Signers { get; init; } = new();
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>上传 .sys 解析出的单个签名者信息</summary>
public sealed record SysSignerInfo
{
    /// <summary>签名类型标签:"WHQL" / "Microsoft" / "Vendor" / "Other"</summary>
    [JsonPropertyName("tag")] public string Tag { get; init; } = "";
    [JsonPropertyName("subject")] public string Subject { get; init; } = "";
    [JsonPropertyName("issuer")] public string Issuer { get; init; } = "";
    /// <summary>SHA256 指纹(用于精确添加)</summary>
    [JsonPropertyName("thumbprint_sha256")] public string ThumbprintSha256 { get; init; } = "";
}

/// <summary>添加白名单操作结果</summary>
public sealed record WhitelistAddResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

// ═══════════════════════════════════════════════════════════════
//  数据库实体
// ═══════════════════════════════════════════════════════════════

[Table("whitelist_entries")]
public sealed class WhitelistEntryEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    /// <summary>"hash" 或 "cert"</summary>
    [Column("type")] public string Type { get; set; } = "";
    [Column("display_name")] public string DisplayName { get; set; } = "";
    /// <summary>哈希条目:文件 SHA256;证书条目:证书 SHA256 指纹</summary>
    [Column("sha256")] public string? Sha256 { get; set; }
    [Column("md5")] public string? Md5 { get; set; }
    [Column("sha1")] public string? Sha1 { get; set; }
    [Column("cert_subject")] public string? CertSubject { get; set; }
    [Column("cert_issuer")] public string? CertIssuer { get; set; }
    [Column("added_at")] public string AddedAt { get; set; } = "";
    [Column("notes")] public string? Notes { get; set; }
}
