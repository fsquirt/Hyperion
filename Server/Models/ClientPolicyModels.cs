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
    [JsonPropertyName("sipolicy")] public ClientSiPolicyDto SiPolicy { get; set; } = new();
    [JsonPropertyName("mock_input")] public ClientMockInputDto MockInput { get; set; } = new();
    [JsonPropertyName("launch")] public ClientLaunchDto Launch { get; set; } = new();
    [JsonPropertyName("fetched_at")] public string FetchedAt { get; set; } = "";
}

/// <summary>游戏启动权限模式(经 /api/client/policies 的 launch 字段下发)。</summary>
public sealed class ClientLaunchDto
{
    /// <summary>
    /// 启动权限模式:
    ///   "inherit"  — 继承管理员权限(直接 CreateProcess,沿用 UserService 自身令牌)
    ///   "explorer" — 使用 explorer 权限(以 explorer 为父进程创建,令牌为标准用户令牌)
    /// </summary>
    [JsonPropertyName("mode")] public string Mode { get; set; } = "explorer";
}

/// <summary>模拟键鼠检测开关(上报 / 拦截,均关闭则客户端不挂全局低级钩子)。</summary>
public sealed class ClientMockInputDto
{
    /// <summary>通过会话事件上报模拟键鼠事件。</summary>
    [JsonPropertyName("report")] public bool Report { get; set; }

    /// <summary>拦截(吞掉)模拟键鼠事件。</summary>
    [JsonPropertyName("block")] public bool Block { get; set; }
}

/// <summary>SiPolicy.p7b 下发开关(游戏启动前是否免重启刷新驱动阻止策略)。</summary>
public sealed class ClientSiPolicyDto
{
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
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
