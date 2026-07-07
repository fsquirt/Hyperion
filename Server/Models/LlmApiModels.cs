using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace SEWindows.Server.Models;

// ═══════════════════════════════════════════════════════════════
//  大模型 API 配置 + 访问凭据 (LLM API Config + Access Credentials)
// ═══════════════════════════════════════════════════════════════
//  场景:Web 后台管理多个大模型 API(OpenAI / Anthropic / DeepSeek /
//        通义千问等),集群内机器(Tracker / Verifyer / AI Agent)通过
//        "访问凭据"调 /api/cluster/llm-apis 获取可用 API 列表。
//
//  两个表:
//    llm_apis            — 大模型 API 配置(provider/base_url/key/model...)
//    llm_api_credentials — 集群访问凭据(name/token/enabled)
// ═══════════════════════════════════════════════════════════════

// ───────────────────────────────────────────────────────────────
//  LLM API
// ───────────────────────────────────────────────────────────────

/// <summary>大模型 API 单条记录(API 响应模型)</summary>
public sealed record LlmApiEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    /// <summary>显示名,如 "GPT-4o 生产环境"</summary>
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    /// <summary>提供商:openai / anthropic / deepseek / qwen / custom</summary>
    [JsonPropertyName("provider")] public string Provider { get; init; } = "";
    /// <summary>API 端点,如 "https://api.openai.com/v1"</summary>
    [JsonPropertyName("base_url")] public string BaseUrl { get; init; } = "";
    /// <summary>API 密钥(管理端列表展示时脱敏,集群获取时返回完整)</summary>
    [JsonPropertyName("api_key_masked")] public string ApiKeyMasked { get; init; } = "";
    /// <summary>模型名,如 "gpt-4o" / "claude-3-opus"</summary>
    [JsonPropertyName("model_name")] public string ModelName { get; init; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; init; }
    /// <summary>优先级(数字越小越优先,集群获取时按此排序)</summary>
    [JsonPropertyName("priority")] public int Priority { get; init; }
    [JsonPropertyName("max_tokens")] public int MaxTokens { get; init; }
    [JsonPropertyName("temperature")] public double Temperature { get; init; }
    [JsonPropertyName("added_at")] public string AddedAt { get; init; } = "";
    [JsonPropertyName("last_used_at")] public string? LastUsedAt { get; init; }
    [JsonPropertyName("notes")] public string? Notes { get; init; }
}

/// <summary>大模型 API 统计</summary>
public sealed record LlmApiStats
{
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("enabled_count")] public int EnabledCount { get; init; }
    [JsonPropertyName("disabled_count")] public int DisabledCount { get; init; }
    /// <summary>按提供商统计</summary>
    [JsonPropertyName("by_provider")] public Dictionary<string, int> ByProvider { get; init; } = new();
}

/// <summary>添加 LLM API 请求</summary>
public sealed class LlmApiAddRequest
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("provider")] public string Provider { get; set; } = "custom";
    [JsonPropertyName("base_url")] public string BaseUrl { get; set; } = "";
    [JsonPropertyName("api_key")] public string ApiKey { get; set; } = "";
    [JsonPropertyName("model_name")] public string ModelName { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    [JsonPropertyName("priority")] public int Priority { get; set; } = 100;
    [JsonPropertyName("max_tokens")] public int MaxTokens { get; set; } = 4096;
    [JsonPropertyName("temperature")] public double Temperature { get; set; } = 0.7;
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>编辑 LLM API 请求(api_key 为 null 表示不改)</summary>
public sealed class LlmApiUpdateRequest
{
    [JsonPropertyName("name")] public string? Name { get; set; }
    [JsonPropertyName("provider")] public string? Provider { get; set; }
    [JsonPropertyName("base_url")] public string? BaseUrl { get; set; }
    [JsonPropertyName("api_key")] public string? ApiKey { get; set; }
    [JsonPropertyName("model_name")] public string? ModelName { get; set; }
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
    [JsonPropertyName("priority")] public int? Priority { get; set; }
    [JsonPropertyName("max_tokens")] public int? MaxTokens { get; set; }
    [JsonPropertyName("temperature")] public double? Temperature { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

// ───────────────────────────────────────────────────────────────
//  访问凭据
// ───────────────────────────────────────────────────────────────

/// <summary>访问凭据单条记录(API 响应模型,token 脱敏)</summary>
public sealed record LlmCredentialEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    /// <summary>脱敏后的 token(只显示前 8 + 后 4 位)</summary>
    [JsonPropertyName("token_masked")] public string TokenMasked { get; init; } = "";
    /// <summary>完整 token(仅创建时返回一次,之后不再返回)</summary>
    [JsonPropertyName("token_full")] public string? TokenFull { get; init; }
    [JsonPropertyName("enabled")] public bool Enabled { get; init; }
    [JsonPropertyName("created_at")] public string CreatedAt { get; init; } = "";
    [JsonPropertyName("last_used_at")] public string? LastUsedAt { get; init; }
    [JsonPropertyName("notes")] public string? Notes { get; init; }
}

/// <summary>访问凭据统计</summary>
public sealed record LlmCredentialStats
{
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("enabled_count")] public int EnabledCount { get; init; }
    [JsonPropertyName("disabled_count")] public int DisabledCount { get; init; }
}

/// <summary>创建凭据请求</summary>
public sealed class LlmCredentialAddRequest
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>操作结果</summary>
public sealed record LlmApiOpResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
    /// <summary>创建凭据时返回完整 token(仅此一次)</summary>
    [JsonPropertyName("token")] public string? Token { get; init; }
}

/// <summary>集群获取 LLM API 时返回的单条记录(含完整 api_key)</summary>
public sealed record ClusterLlmApiEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("provider")] public string Provider { get; init; } = "";
    [JsonPropertyName("base_url")] public string BaseUrl { get; init; } = "";
    [JsonPropertyName("api_key")] public string ApiKey { get; init; } = "";
    [JsonPropertyName("model_name")] public string ModelName { get; init; } = "";
    [JsonPropertyName("priority")] public int Priority { get; init; }
    [JsonPropertyName("max_tokens")] public int MaxTokens { get; init; }
    [JsonPropertyName("temperature")] public double Temperature { get; init; }
}

// ═══════════════════════════════════════════════════════════════
//  数据库实体
// ═══════════════════════════════════════════════════════════════

[Table("llm_apis")]
public sealed class LlmApiEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("name")] public string Name { get; set; } = "";
    [Column("provider")] public string Provider { get; set; } = "custom";
    [Column("base_url")] public string BaseUrl { get; set; } = "";
    [Column("api_key")] public string ApiKey { get; set; } = "";
    [Column("model_name")] public string ModelName { get; set; } = "";
    [Column("enabled")] public bool Enabled { get; set; } = true;
    [Column("priority")] public int Priority { get; set; } = 100;
    [Column("max_tokens")] public int MaxTokens { get; set; } = 4096;
    [Column("temperature")] public double Temperature { get; set; } = 0.7;
    [Column("added_at")] public string AddedAt { get; set; } = "";
    [Column("last_used_at")] public string? LastUsedAt { get; set; }
    [Column("notes")] public string? Notes { get; set; }
}

[Table("llm_api_credentials")]
public sealed class LlmCredentialEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("name")] public string Name { get; set; } = "";
    /// <summary>凭据 token(唯一,集群用 Bearer 认证)</summary>
    [Column("token")] public string Token { get; set; } = "";
    [Column("enabled")] public bool Enabled { get; set; } = true;
    [Column("created_at")] public string CreatedAt { get; set; } = "";
    [Column("last_used_at")] public string? LastUsedAt { get; set; }
    [Column("notes")] public string? Notes { get; set; }
}
