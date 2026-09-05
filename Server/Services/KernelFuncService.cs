using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;

namespace Hyperion.Server.Services;

/// <summary>
/// 危险内核函数列表服务。
///
/// 用途:DriverAttachSelector 扫驱动 IAT 时,如果导入了这里登记的
/// "危险内核函数",就标记该驱动为高危，即使签名 WHQL 也视为可疑。
///
/// 内存维护 HashSet，键为 func_name 且大小写敏感 — 内核函数名本身大小写敏感，
/// 供后续 KernelService / DriverAttachSelector 查询。
/// 全量记录持久化到 SQLite kernel_dangerous_funcs 表。
///
/// 启动时如果表为空,自动塞入 4 个默认函数:
///   MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory
/// </summary>
public sealed class KernelFuncService
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<KernelFuncService> _logger;

    // 内存索引:启用中的函数名集合，大小写敏感
    // 查询时 O(1),供 DriverAttachSelector / KernelService 用
    private readonly HashSet<string> _enabledFuncs = new();
    private readonly object _lock = new();

    public KernelFuncService(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<KernelFuncService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    
    //  启动加载
    public async Task LoadAsync()
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();

            // 表空时塞入默认 4 个
            if (!await db.KernelDangerousFuncs.AnyAsync())
            {
                await SeedDefaultsAsync(db);
            }

            var rows = await db.KernelDangerousFuncs.ToListAsync();

            lock (_lock)
            {
                _enabledFuncs.Clear();
                foreach (var r in rows)
                {
                    if (r.Enabled && !string.IsNullOrEmpty(r.FuncName))
                        _enabledFuncs.Add(r.FuncName);
                }
            }

            _logger.LogInformation(
                "[KernelFunc] 已加载 {Total} 条危险函数记录，其中启用 {Enabled} 条",
                rows.Count, rows.Count(r => r.Enabled));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[KernelFunc] 加载失败");
        }
    }

    private static async Task SeedDefaultsAsync(AttestationDbContext db)
    {
        var now = DateTime.UtcNow.ToString("o");
        var defaults = new[]
        {
            new KernelDangerousFuncEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                FuncName = "MmCopyMemory",
                DisplayName = "跨进程读内核内存",
                Category = "内存操作",
                Severity = "High",
                Enabled = true,
                AddedAt = now,
                Notes = "默认自带 — BYOVD 经典,可读任意物理/虚拟内存",
            },
            new KernelDangerousFuncEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                FuncName = "MmMapIoSpace",
                DisplayName = "映射物理内存到虚拟地址",
                Category = "内存操作",
                Severity = "High",
                Enabled = true,
                AddedAt = now,
                Notes = "默认自带 — 直接硬件操作,可绕过内存保护",
            },
            new KernelDangerousFuncEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                FuncName = "ZwMapViewOfSection",
                DisplayName = "映射 Section 到进程",
                Category = "内存操作",
                Severity = "High",
                Enabled = true,
                AddedAt = now,
                Notes = "默认自带 — BYOVD 经典,可注入或读写其他进程内存",
            },
            new KernelDangerousFuncEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                FuncName = "MmCopyVirtualMemory",
                DisplayName = "跨进程读写虚拟内存",
                Category = "内存操作",
                Severity = "High",
                Enabled = true,
                AddedAt = now,
                Notes = "默认自带 — 反作弊常用,跨进程读写",
            },
        };

        db.KernelDangerousFuncs.AddRange(defaults);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// 检查给定函数名是否为登记的危险函数，只匹配启用项。
    /// 大小写敏感 — 内核函数名本身大小写敏感，如 MmCopyMemory ≠ mmcopymemory。
    /// </summary>
    public bool IsDangerous(string funcName)
    {
        if (string.IsNullOrEmpty(funcName)) return false;
        lock (_lock)
        {
            return _enabledFuncs.Contains(funcName);
        }
    }

    /// <summary>返回当前启用中的所有危险函数名，供批量匹配用。</summary>
    public List<string> GetEnabledFuncNames()
    {
        lock (_lock)
        {
            return _enabledFuncs.ToList();
        }
    }

    /// <summary>返回所有启用中的危险函数记录，供客户端策略下发用。</summary>
    public async Task<List<KernelFuncEntry>> GetEnabledEntriesAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.KernelDangerousFuncs
            .Where(r => r.Enabled && !string.IsNullOrEmpty(r.FuncName))
            .OrderByDescending(r => r.Severity)
            .ThenBy(r => r.FuncName)
            .ToListAsync();
        return rows.Select(ToRecord).ToList();
    }

    
    //  管理端 API
    public async Task<(List<KernelFuncEntry> rows, int total)> QueryAsync(
        string? search = null,
        string? category = null,
        string? severity = null,
        bool? enabled = null,
        int page = 1,
        int pageSize = 100)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var q = db.KernelDangerousFuncs.AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search.Trim().ToLowerInvariant();
            q = q.Where(r =>
                (r.FuncName != null && r.FuncName.ToLower().Contains(kw)) ||
                (r.DisplayName != null && r.DisplayName.ToLower().Contains(kw)) ||
                (r.Notes != null && r.Notes.ToLower().Contains(kw)));
        }
        if (!string.IsNullOrWhiteSpace(category))
        {
            var c = category.Trim().ToLowerInvariant();
            q = q.Where(r => r.Category != null && r.Category.ToLower() == c);
        }
        if (!string.IsNullOrWhiteSpace(severity))
        {
            var s = severity.Trim();
            q = q.Where(r => r.Severity == s);
        }
        if (enabled.HasValue)
        {
            q = q.Where(r => r.Enabled == enabled.Value);
        }

        var total = await q.CountAsync();
        var rows = await q
            .OrderByDescending(r => r.Severity)   // High 优先
            .ThenBy(r => r.FuncName)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (rows.Select(ToRecord).ToList(), total);
    }

    public async Task<KernelFuncStats> GetStatsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.KernelDangerousFuncs.ToListAsync();
        return new KernelFuncStats
        {
            Total = all.Count,
            EnabledCount = all.Count(r => r.Enabled),
            DisabledCount = all.Count(r => !r.Enabled),
            HighCount = all.Count(r => r.Severity == "High"),
            MediumCount = all.Count(r => r.Severity == "Medium"),
            LowCount = all.Count(r => r.Severity == "Low"),
        };
    }

    public async Task<KernelFuncOpResult> AddAsync(KernelFuncAddRequest req)
    {
        var funcName = req.FuncName?.Trim() ?? "";
        if (string.IsNullOrEmpty(funcName))
            return new KernelFuncOpResult { Error = "函数名不能为空" };

        // 函数名合法性:只允许字母数字下划线，即内核函数名规范
        if (!funcName.All(c => char.IsLetterOrDigit(c) || c == '_'))
            return new KernelFuncOpResult { Error = "函数名只能含字母、数字、下划线" };

        var severity = req.Severity.ToString();

        var entity = new KernelDangerousFuncEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            FuncName = funcName,
            DisplayName = string.IsNullOrWhiteSpace(req.DisplayName) ? "" : req.DisplayName.Trim(),
            Category = string.IsNullOrWhiteSpace(req.Category) ? "其他" : req.Category.Trim(),
            Severity = severity,
            Enabled = req.Enabled,
            AddedAt = DateTime.UtcNow.ToString("o"),
            Notes = req.Notes?.Trim(),
        };

        await using var db = await _dbFactory.CreateDbContextAsync();
        // 去重检查
        if (await db.KernelDangerousFuncs.AnyAsync(r => r.FuncName == funcName))
            return new KernelFuncOpResult { Error = $"函数 '{funcName}' 已存在" };

        db.KernelDangerousFuncs.Add(entity);
        await db.SaveChangesAsync();

        RebuildIndex(db);

        return new KernelFuncOpResult { Success = true, Id = entity.Id };
    }

    public async Task<KernelFuncOpResult> UpdateAsync(string id, KernelFuncUpdateRequest req)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.KernelDangerousFuncs.FindAsync(id);
        if (entity == null)
            return new KernelFuncOpResult { Error = "记录不存在" };

        if (req.DisplayName != null) entity.DisplayName = req.DisplayName.Trim();
        if (req.Category != null) entity.Category = string.IsNullOrWhiteSpace(req.Category) ? "其他" : req.Category.Trim();
        if (req.Severity.HasValue) entity.Severity = req.Severity.Value.ToString();
        if (req.Enabled.HasValue) entity.Enabled = req.Enabled.Value;
        if (req.Notes != null) entity.Notes = string.IsNullOrWhiteSpace(req.Notes) ? null : req.Notes.Trim();

        await db.SaveChangesAsync();
        RebuildIndex(db);

        return new KernelFuncOpResult { Success = true, Id = entity.Id };
    }

    public async Task<bool> DeleteAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.KernelDangerousFuncs.FindAsync(id);
        if (entity == null) return false;

        db.KernelDangerousFuncs.Remove(entity);
        await db.SaveChangesAsync();
        RebuildIndex(db);
        return true;
    }

    /// <summary>
    /// 重置为默认 4 个，即删除所有现有记录后塞入默认。
    /// 供前端"恢复默认"按钮用。
    /// </summary>
    public async Task<KernelFuncOpResult> ResetToDefaultsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        // 清空
        db.KernelDangerousFuncs.RemoveRange(db.KernelDangerousFuncs);
        await db.SaveChangesAsync();

        // 塞默认
        await SeedDefaultsAsync(db);
        RebuildIndex(db);

        return new KernelFuncOpResult { Success = true };
    }

    private void RebuildIndex(AttestationDbContext db)
    {
        // 重新从数据库读取,刷新内存索引
        var rows = db.KernelDangerousFuncs.AsNoTracking().ToList();
        lock (_lock)
        {
            _enabledFuncs.Clear();
            foreach (var r in rows)
            {
                if (r.Enabled && !string.IsNullOrEmpty(r.FuncName))
                    _enabledFuncs.Add(r.FuncName);
            }
        }
    }

    private static KernelFuncEntry ToRecord(KernelDangerousFuncEntity e)
    {
        return new KernelFuncEntry
        {
            Id = e.Id,
            FuncName = e.FuncName,
            DisplayName = e.DisplayName,
            Category = e.Category,
            Severity = Enum.TryParse<KernelFuncSeverity>(e.Severity, true, out var s) ? s : KernelFuncSeverity.High,
            Enabled = e.Enabled,
            AddedAt = e.AddedAt,
            Notes = e.Notes,
        };
    }
}
