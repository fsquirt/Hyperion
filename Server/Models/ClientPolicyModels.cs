using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

/// <summary>
/// 供 UserService 客户端(无需鉴权)拉取的服务端策略。
/// 当前包含两类:危险内核函数列表 + 附着白名单。
/// </summary>
public sealed class ClientPolicyResponse
{
    [JsonPropertyName("kernel_funcs")] public List<ClientKernelFuncDto> KernelFuncs { get; set; } = new();
    [JsonPropertyName("whitelist")] public ClientWhitelistDto Whitelist { get; set; } = new();
    [JsonPropertyName("fetched_at")] public string FetchedAt { get; set; } = "";
}

/// <summary>危险内核函数(只回传启用中的)。</summary>
public sealed class ClientKernelFuncDto
{
    [JsonPropertyName("func_name")] public string FuncName { get; set; } = "";
    [JsonPropertyName("display_name")] public string DisplayName { get; set; } = "";
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "High";
}

/// <summary>附着白名单(hash 维度 + 证书维度)。</summary>
public sealed class ClientWhitelistDto
{
    [JsonPropertyName("hashes")] public ClientHashWhitelistDto Hashes { get; set; } = new();
    [JsonPropertyName("certs")] public ClientCertWhitelistDto Certs { get; set; } = new();
}

public sealed class ClientHashWhitelistDto
{
    [JsonPropertyName("md5")] public List<string> Md5 { get; set; } = new();
    [JsonPropertyName("sha1")] public List<string> Sha1 { get; set; } = new();
    [JsonPropertyName("sha256")] public List<string> Sha256 { get; set; } = new();
}

public sealed class ClientCertWhitelistDto
{
    /// <summary>签名者 Subject 前缀(大小写不敏感)。</summary>
    [JsonPropertyName("subjects")] public List<string> Subjects { get; set; } = new();
    /// <summary>证书 SHA256 指纹(精确匹配)。</summary>
    [JsonPropertyName("thumbprints_sha256")] public List<string> ThumbprintsSha256 { get; set; } = new();
}
