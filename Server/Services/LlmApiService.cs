using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using System.Security.Cryptography;

namespace Hyperion.Server.Services;

/// <summary>
/// 大模型 API 配置 + 访问凭据服务。
///
/// 两部分:
///   1. LLM API CRUD — 管理多个大模型 API(OpenAI/Anthropic/DeepSeek/Qwen/custom)
///   2. 访问凭据 CRUD — 集群机器用 Bearer token 认证,调 GetClusterLlmApis 获取可用 API
///
/// 集群 API 路径:/api/cluster/llm-apis
/// 认证方式:Authorization: Bearer <token>
/// </summary>
public sealed class LlmApiService
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<LlmApiService> _logger;

    // 内存索引:启用中的凭据 token → credential id(集群认证用,O(1) 查找)
    private readonly Dictionary<string, string> _enabledTokens = new(); // token → id
    private readonly object _lock = new();

    public LlmApiService(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<LlmApiService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    // ═══════════════════════════════════════════════════════════════
    //  启动加载
    // ═══════════════════════════════════════════════════════════════

    public async Task LoadAsync()
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var rows = await db.LlmCredentials.Where(c => c.Enabled).ToListAsync();

            lock (_lock)
            {
                _enabledTokens.Clear();
                foreach (var r in rows)
                {
                    if (!string.IsNullOrEmpty(r.Token))
                        _enabledTokens[r.Token] = r.Id;
                }
            }

            _logger.LogInformation(
                "[LlmApi] 已加载 {Count} 个有效访问凭据, {ApiCount} 个 LLM API 配置",
                rows.Count, await db.LlmApis.CountAsync());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[LlmApi] 加载失败");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  LLM API CRUD
    // ═══════════════════════════════════════════════════════════════

    public async Task<(List<LlmApiEntry> rows, int total)> QueryApisAsync(
        string? search = null,
        string? provider = null,
        bool? enabled = null,
        int page = 1,
        int pageSize = 100)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var q = db.LlmApis.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search.Trim().ToLowerInvariant();
            q = q.Where(r =>
                (r.Name != null && r.Name.ToLower().Contains(kw)) ||
                (r.ModelName != null && r.ModelName.ToLower().Contains(kw)) ||
                (r.BaseUrl != null && r.BaseUrl.ToLower().Contains(kw)) ||
                (r.Notes != null && r.Notes.ToLower().Contains(kw)));
        }
        if (!string.IsNullOrWhiteSpace(provider))
        {
            var p = provider.Trim().ToLowerInvariant();
            q = q.Where(r => r.Provider != null && r.Provider.ToLower() == p);
        }
        if (enabled.HasValue)
        {
            q = q.Where(r => r.Enabled == enabled.Value);
        }

        var total = await q.CountAsync();
        var rows = await q
            .OrderBy(r => r.Priority)
            .ThenByDescending(r => r.AddedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (rows.Select(ToApiEntry).ToList(), total);
    }

    public async Task<LlmApiStats> GetApiStatsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.LlmApis.ToListAsync();
        return new LlmApiStats
        {
            Total = all.Count,
            EnabledCount = all.Count(r => r.Enabled),
            DisabledCount = all.Count(r => !r.Enabled),
            ByProvider = all.GroupBy(r => r.Provider ?? "unknown")
                            .ToDictionary(g => g.Key, g => g.Count()),
        };
    }

    public async Task<LlmApiOpResult> AddApiAsync(LlmApiAddRequest req)
    {
        var name = req.Name?.Trim() ?? "";
        if (string.IsNullOrEmpty(name))
            return new LlmApiOpResult { Error = "名称不能为空" };
        if (string.IsNullOrWhiteSpace(req.BaseUrl))
            return new LlmApiOpResult { Error = "Base URL 不能为空" };
        if (string.IsNullOrWhiteSpace(req.ApiKey))
            return new LlmApiOpResult { Error = "API Key 不能为空" };
        if (string.IsNullOrWhiteSpace(req.ModelName))
            return new LlmApiOpResult { Error = "模型名不能为空" };

        var entity = new LlmApiEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
            Provider = string.IsNullOrWhiteSpace(req.Provider) ? "custom" : req.Provider.Trim().ToLowerInvariant(),
            BaseUrl = req.BaseUrl.Trim(),
            ApiKey = req.ApiKey.Trim(),
            ModelName = req.ModelName.Trim(),
            Enabled = req.Enabled,
            Priority = req.Priority,
            MaxTokens = req.MaxTokens > 0 ? req.MaxTokens : 4096,
            Temperature = req.Temperature >= 0 && req.Temperature <= 2 ? req.Temperature : 0.7,
            AddedAt = DateTime.UtcNow.ToString("o"),
            Notes = req.Notes?.Trim(),
        };

        await using var db = await _dbFactory.CreateDbContextAsync();
        db.LlmApis.Add(entity);
        await db.SaveChangesAsync();

        _logger.LogInformation("[LlmApi] 添加 API: {Name} ({Provider})", name, entity.Provider);
        return new LlmApiOpResult { Success = true, Id = entity.Id };
    }

    public async Task<LlmApiOpResult> UpdateApiAsync(string id, LlmApiUpdateRequest req)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.LlmApis.FindAsync(id);
        if (entity == null)
            return new LlmApiOpResult { Error = "记录不存在" };

        if (req.Name != null) entity.Name = req.Name.Trim();
        if (req.Provider != null) entity.Provider = req.Provider.Trim().ToLowerInvariant();
        if (req.BaseUrl != null) entity.BaseUrl = req.BaseUrl.Trim();
        // api_key 为 null 表示不改,空字符串表示清空(一般不允许清空,至少给个占位)
        if (req.ApiKey != null) entity.ApiKey = req.ApiKey.Trim();
        if (req.ModelName != null) entity.ModelName = req.ModelName.Trim();
        if (req.Enabled.HasValue) entity.Enabled = req.Enabled.Value;
        if (req.Priority.HasValue) entity.Priority = req.Priority.Value;
        if (req.MaxTokens.HasValue) entity.MaxTokens = req.MaxTokens.Value > 0 ? req.MaxTokens.Value : 4096;
        if (req.Temperature.HasValue) entity.Temperature = req.Temperature.Value >= 0 && req.Temperature.Value <= 2 ? req.Temperature.Value : 0.7;
        if (req.Notes != null) entity.Notes = string.IsNullOrWhiteSpace(req.Notes) ? null : req.Notes.Trim();

        await db.SaveChangesAsync();
        return new LlmApiOpResult { Success = true, Id = entity.Id };
    }

    public async Task<bool> DeleteApiAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.LlmApis.FindAsync(id);
        if (entity == null) return false;
        db.LlmApis.Remove(entity);
        await db.SaveChangesAsync();
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  访问凭据 CRUD
    // ═══════════════════════════════════════════════════════════════

    public async Task<(List<LlmCredentialEntry> rows, int total)> QueryCredentialsAsync(
        string? search = null,
        bool? enabled = null,
        int page = 1,
        int pageSize = 100)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var q = db.LlmCredentials.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search.Trim().ToLowerInvariant();
            q = q.Where(r =>
                (r.Name != null && r.Name.ToLower().Contains(kw)) ||
                (r.Notes != null && r.Notes.ToLower().Contains(kw)));
        }
        if (enabled.HasValue)
        {
            q = q.Where(r => r.Enabled == enabled.Value);
        }

        var total = await q.CountAsync();
        var rows = await q
            .OrderByDescending(r => r.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (rows.Select(ToCredEntry).ToList(), total);
    }

    public async Task<LlmCredentialStats> GetCredentialStatsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.LlmCredentials.ToListAsync();
        return new LlmCredentialStats
        {
            Total = all.Count,
            EnabledCount = all.Count(r => r.Enabled),
            DisabledCount = all.Count(r => !r.Enabled),
        };
    }

    /// <summary>创建凭据,返回完整 token(仅此一次)</summary>
    public async Task<LlmApiOpResult> AddCredentialAsync(LlmCredentialAddRequest req)
    {
        var name = req.Name?.Trim() ?? "";
        if (string.IsNullOrEmpty(name))
            return new LlmApiOpResult { Error = "凭据名不能为空" };

        // 生成 48 字节随机 token → Base64Url (64 字符)
        var tokenBytes = RandomNumberGenerator.GetBytes(48);
        var token = Convert.ToBase64String(tokenBytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        var entity = new LlmCredentialEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            Name = name,
            Token = token,
            Enabled = req.Enabled,
            CreatedAt = DateTime.UtcNow.ToString("o"),
            Notes = req.Notes?.Trim(),
        };

        await using var db = await _dbFactory.CreateDbContextAsync();
        db.LlmCredentials.Add(entity);
        await db.SaveChangesAsync();

        // 更新内存索引
        lock (_lock)
        {
            if (entity.Enabled)
                _enabledTokens[token] = entity.Id;
        }

        _logger.LogInformation("[LlmApi] 创建凭据: {Name}", name);
        return new LlmApiOpResult { Success = true, Id = entity.Id, Token = token };
    }

    public async Task<LlmApiOpResult> UpdateCredentialAsync(string id, bool? enabled, string? name, string? notes)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.LlmCredentials.FindAsync(id);
        if (entity == null)
            return new LlmApiOpResult { Error = "凭据不存在" };

        var wasEnabled = entity.Enabled;
        if (name != null) entity.Name = name.Trim();
        if (enabled.HasValue) entity.Enabled = enabled.Value;
        if (notes != null) entity.Notes = string.IsNullOrWhiteSpace(notes) ? null : notes.Trim();

        await db.SaveChangesAsync();

        // 更新内存索引
        if (enabled.HasValue && enabled.Value != wasEnabled)
        {
            lock (_lock)
            {
                if (enabled.Value)
                    _enabledTokens[entity.Token] = entity.Id;
                else
                    _enabledTokens.Remove(entity.Token);
            }
        }

        return new LlmApiOpResult { Success = true, Id = entity.Id };
    }

    public async Task<bool> DeleteCredentialAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.LlmCredentials.FindAsync(id);
        if (entity == null) return false;

        db.LlmCredentials.Remove(entity);
        await db.SaveChangesAsync();

        // 更新内存索引
        lock (_lock)
        {
            _enabledTokens.Remove(entity.Token);
        }

        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  集群 API(凭据认证,返回可用 LLM API 列表)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 验证 Bearer token,返回是否有效。有效则更新 last_used_at。
    /// </summary>
    public async Task<bool> ValidateCredentialAsync(string? bearerToken)
    {
        if (string.IsNullOrEmpty(bearerToken)) return false;
        var token = bearerToken.Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            token = token[7..].Trim();

        string credId;
        lock (_lock)
        {
            if (!_enabledTokens.TryGetValue(token, out credId!))
                return false;
        }

        // 更新 last_used_at(非阻塞,失败无碍)
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var entity = await db.LlmCredentials.FindAsync(credId);
            if (entity != null)
            {
                entity.LastUsedAt = DateTime.UtcNow.ToString("o");
                await db.SaveChangesAsync();
            }
        }
        catch { /* 更新使用时间失败不影响获取 API */ }

        return true;
    }

    /// <summary>
    /// 获取启用中的 LLM API 列表(按 priority 升序),含完整 api_key。
    /// 供集群机器调用。
    /// </summary>
    public async Task<List<ClusterLlmApiEntry>> GetClusterLlmApisAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.LlmApis
            .Where(r => r.Enabled)
            .OrderBy(r => r.Priority)
            .ThenByDescending(r => r.AddedAt)
            .ToListAsync();

        return rows.Select(r => new ClusterLlmApiEntry
        {
            Id = r.Id,
            Name = r.Name,
            Provider = r.Provider,
            BaseUrl = r.BaseUrl,
            ApiKey = r.ApiKey,
            ModelName = r.ModelName,
            Priority = r.Priority,
            MaxTokens = r.MaxTokens,
            Temperature = r.Temperature,
        }).ToList();
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private static string MaskApiKey(string key)
    {
        if (string.IsNullOrEmpty(key)) return "";
        if (key.Length <= 8) return new string('*', key.Length);
        return string.Concat(key.AsSpan(0, 4), "****", key.AsSpan(key.Length - 4));
    }

    private static string MaskToken(string token)
    {
        if (string.IsNullOrEmpty(token)) return "";
        if (token.Length <= 12) return new string('*', token.Length);
        return string.Concat(token.AsSpan(0, 8), "****", token.AsSpan(token.Length - 4));
    }

    private static LlmApiEntry ToApiEntry(LlmApiEntity e)
    {
        return new LlmApiEntry
        {
            Id = e.Id,
            Name = e.Name,
            Provider = e.Provider,
            BaseUrl = e.BaseUrl,
            ApiKeyMasked = MaskApiKey(e.ApiKey),
            ModelName = e.ModelName,
            Enabled = e.Enabled,
            Priority = e.Priority,
            MaxTokens = e.MaxTokens,
            Temperature = e.Temperature,
            AddedAt = e.AddedAt,
            LastUsedAt = e.LastUsedAt,
            Notes = e.Notes,
        };
    }

    private static LlmCredentialEntry ToCredEntry(LlmCredentialEntity e)
    {
        return new LlmCredentialEntry
        {
            Id = e.Id,
            Name = e.Name,
            TokenMasked = MaskToken(e.Token),
            Enabled = e.Enabled,
            CreatedAt = e.CreatedAt,
            LastUsedAt = e.LastUsedAt,
            Notes = e.Notes,
        };
    }
}
