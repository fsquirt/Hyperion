using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

/// <summary>
/// 受信任根证书 CSV 行记录,对应 IncludedCACertificateReportForMSFT.csv 6 列。
/// 列顺序:[0]Microsoft Status,[1]CA Owner,[2]Common Name,[3]Subject,[4]SHA-1,[5]SHA-256
/// </summary>
public sealed class CertRow
{
    [JsonPropertyName("microsoft_status")] public string? MicrosoftStatus { get; set; }
    [JsonPropertyName("ca_owner")] public string? CaOwner { get; set; }
    [JsonPropertyName("common_name")] public string? CommonName { get; set; }
    [JsonPropertyName("subject")] public string? Subject { get; set; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
}

/// <summary>添加 / 编辑证书请求。original_sha256 仅编辑时使用，用于定位原记录。</summary>
public sealed class CertUpsertRequest
{
    [JsonPropertyName("microsoft_status")] public string? MicrosoftStatus { get; set; }
    [JsonPropertyName("ca_owner")] public string? CaOwner { get; set; }
    [JsonPropertyName("common_name")] public string? CommonName { get; set; }
    [JsonPropertyName("subject")] public string? Subject { get; set; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }

    /// <summary>编辑时由 URL 路径传入,这里仅作为补充字段，可不填。</summary>
    [JsonPropertyName("original_sha256")] public string? OriginalSha256 { get; set; }
}

/// <summary>证书 CRUD 通用返回。</summary>
public sealed class CertOpResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
    [JsonPropertyName("row")] public CertRow? Row { get; init; }
}
