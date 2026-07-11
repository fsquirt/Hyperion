using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Cryptography;
using System.Text.Json;

namespace Hyperion.Server.Data;

// ═══════════════════════════════════════════════════════════════
//  实体定义
// ═══════════════════════════════════════════════════════════════

[Table("ek_records")]
public sealed class EkEntity
{
    [Key][Column("fingerprint")] public string Fingerprint { get; set; } = "";
    [Column("subject")] public string Subject { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
}

[Table("ak_records")]
public sealed class AkEntity
{
    [Key][Column("ak_name")] public string AkName { get; set; } = "";
    [Column("ak_pub")] public string AkPub { get; set; } = "";
    [Column("ek_fingerprint")] public string EkFingerprint { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
}

[Table("attestation_history")]
public sealed class HistoryEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    [Column("ek_fingerprint")] public string EkFingerprint { get; set; } = "";
    [Column("ak_name")] public string AkName { get; set; } = "";
    [Column("sig_valid")] public bool SigValid { get; set; }
    [Column("magic_ok")] public bool MagicOk { get; set; }
    [Column("nonce_ok")] public bool NonceOk { get; set; }
    [Column("pcr_match")] public bool PcrMatch { get; set; }
    [Column("security_features_json")] public string SecurityFeaturesJson { get; set; } = "[]";
    [Column("result")] public string Result { get; set; } = "fail";
}

[Table("admin_credentials")]
public sealed class AdminCredentialEntity
{
    [Key][Column("credential_id")] public string CredentialId { get; set; } = "";
    [Column("public_key")] public string PublicKey { get; set; } = "";
    [Column("sign_count")] public uint SignCount { get; set; }
    [Column("created")] public string Created { get; set; } = "";
}

[Table("cert_verify_history")]
public sealed class CertVerifyHistoryEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    [Column("client_cert_count")] public int ClientCertCount { get; set; }
    [Column("trusted_count")] public int TrustedCount { get; set; }
    [Column("suspicious_count")] public int SuspiciousCount { get; set; }
    [Column("suspicious_certs_json")] public string SuspiciousCertsJson { get; set; } = "[]";
    [Column("result")] public string Result { get; set; } = "pass";
}

[Table("tracker_sessions")]
public sealed class TrackerSessionEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("machine_name")] public string MachineName { get; set; } = "";
    [Column("pid")] public int Pid { get; set; }
    [Column("started_at")] public string StartedAt { get; set; } = "";
    [Column("ended_at")] public string EndedAt { get; set; } = "";
    [Column("event_count")] public int EventCount { get; set; }
    [Column("events_json")] public string EventsJson { get; set; } = "[]";
}

[Table("driver_verify_history")]
public sealed class DriverVerifyHistoryEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    [Column("client_driver_count")] public int ClientDriverCount { get; set; }
    [Column("blocked_count")] public int BlockedCount { get; set; }
    [Column("suspicious_drivers_json")] public string SuspiciousDriversJson { get; set; } = "[]";
    [Column("all_drivers_json")] public string AllDriversJson { get; set; } = "[]";
    [Column("result")] public string Result { get; set; } = "pass";
}

// ═══════════════════════════════════════════════════════════════
//  运行时追踪 — 4 种独立数据流
// ═══════════════════════════════════════════════════════════════

/// <summary>进程树快照(全量 baseline + 后续 tree 轮询)。</summary>
[Table("tracker_snapshots")]
public sealed class TrackerSnapshotEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    /// <summary>"security"(初始全量) | "tree"(后续轮询)</summary>
    [Column("kind")] public string Kind { get; set; } = "tree";
    /// <summary>进程数量</summary>
    [Column("process_count")] public int ProcessCount { get; set; }
    /// <summary>完整进程列表 JSON(全量/精简)</summary>
    [Column("processes_json")] public string ProcessesJson { get; set; } = "[]";
}

/// <summary>内核通信记录(驱动扫描 + 附着 + IOCTL 拦截事件)。</summary>
[Table("tracker_kernel_comms")]
public sealed class TrackerKernelCommEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    /// <summary>"driver"(驱动扫描) | "attach"(附着) | "ioctl"(IOCTL 拦截)</summary>
    [Column("kind")] public string Kind { get; set; } = "driver";
    [Column("level")] public string Level { get; set; } = "INFO";
    [Column("source")] public string Source { get; set; } = "";
    [Column("title")] public string Title { get; set; } = "";
    [Column("detail")] public string Detail { get; set; } = "";
}

/// <summary>Dump 触发记录(通信 dump 文件路径 + 汇总)。</summary>
[Table("tracker_dumps")]
public sealed class TrackerDumpEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    [Column("session_id")] public string SessionId { get; set; } = "";
    [Column("timestamp")] public string Timestamp { get; set; } = "";
    [Column("level")] public string Level { get; set; } = "INFO";
    [Column("title")] public string Title { get; set; } = "";
    [Column("detail")] public string Detail { get; set; } = "";
    /// <summary>JSON 数组: [{path, kind, pid, hitCount, abnormal}]</summary>
    [Column("dump_files_json")] public string DumpFilesJson { get; set; } = "[]";
}

/// <summary>Tracker 运行配置(全局单行,id="default")。</summary>
[Table("tracker_config")]
public sealed class TrackerConfigEntity
{
    [Key][Column("id")] public string Id { get; set; } = "default";
    /// <summary>Tree 轮询频率(秒),默认 10</summary>
    [Column("tree_poll_interval_sec")] public int TreePollIntervalSec { get; set; } = 10;
    /// <summary>是否启用 IOCTL 通信监听(默认 0=关闭)</summary>
    [Column("ioctl_enabled")] public int IoctlEnabled { get; set; } = 0;
    /// <summary>Dump 模式: "raw" | "mini" | "full"</summary>
    [Column("dump_mode")] public string DumpMode { get; set; } = "mini";
    /// <summary>是否拷贝磁盘文件(默认 1=开启)</summary>
    [Column("file_copy_enabled")] public int FileCopyEnabled { get; set; } = 1;
    [Column("updated_at")] public string UpdatedAt { get; set; } = "";
}

// ═══════════════════════════════════════════════════════════════
//  DbContext
// ═══════════════════════════════════════════════════════════════

public sealed class AttestationDbContext : DbContext
{
    public DbSet<EkEntity> EkRecords => Set<EkEntity>();
    public DbSet<AkEntity> AkRecords => Set<AkEntity>();
    public DbSet<HistoryEntity> History => Set<HistoryEntity>();
    public DbSet<AdminCredentialEntity> AdminCredentials => Set<AdminCredentialEntity>();
    public DbSet<CertVerifyHistoryEntity> CertVerifyHistory => Set<CertVerifyHistoryEntity>();
    public DbSet<TrackerSessionEntity> TrackerSessions => Set<TrackerSessionEntity>();
    public DbSet<BlockedDriverEntity> BlockedDrivers => Set<BlockedDriverEntity>();
    public DbSet<DriverVerifyHistoryEntity> DriverVerifyHistory => Set<DriverVerifyHistoryEntity>();
    public DbSet<WhitelistEntryEntity> WhitelistEntries => Set<WhitelistEntryEntity>();
    public DbSet<KernelDangerousFuncEntity> KernelDangerousFuncs => Set<KernelDangerousFuncEntity>();
    public DbSet<LlmApiEntity> LlmApis => Set<LlmApiEntity>();
    public DbSet<LlmCredentialEntity> LlmCredentials => Set<LlmCredentialEntity>();
    public DbSet<TrackerSnapshotEntity> TrackerSnapshots => Set<TrackerSnapshotEntity>();
    public DbSet<TrackerKernelCommEntity> TrackerKernelComms => Set<TrackerKernelCommEntity>();
    public DbSet<TrackerDumpEntity> TrackerDumps => Set<TrackerDumpEntity>();
    public DbSet<TrackerConfigEntity> TrackerConfig => Set<TrackerConfigEntity>();

    public AttestationDbContext(DbContextOptions<AttestationDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<EkEntity>().HasKey(e => e.Fingerprint);
        modelBuilder.Entity<AkEntity>().HasKey(e => e.AkName);
        modelBuilder.Entity<HistoryEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<AdminCredentialEntity>().HasKey(e => e.CredentialId);
        modelBuilder.Entity<CertVerifyHistoryEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<TrackerSessionEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<BlockedDriverEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<DriverVerifyHistoryEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<WhitelistEntryEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<KernelDangerousFuncEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<LlmApiEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<LlmCredentialEntity>().HasKey(e => e.Id);

        // 拉黑驱动哈希索引(加速查询)
        modelBuilder.Entity<BlockedDriverEntity>()
            .HasIndex(e => e.Sha256);
        modelBuilder.Entity<BlockedDriverEntity>()
            .HasIndex(e => e.Source);

        // 白名单:按类型 + 哈希/Subject 索引
        modelBuilder.Entity<WhitelistEntryEntity>()
            .HasIndex(e => e.Type);
        modelBuilder.Entity<WhitelistEntryEntity>()
            .HasIndex(e => e.Sha256);
        modelBuilder.Entity<WhitelistEntryEntity>()
            .HasIndex(e => e.CertSubject);

        // 危险内核函数:func_name 唯一(用于去重),enabled + severity 用于筛选
        modelBuilder.Entity<KernelDangerousFuncEntity>()
            .HasIndex(e => e.FuncName).IsUnique();
        modelBuilder.Entity<KernelDangerousFuncEntity>()
            .HasIndex(e => e.Enabled);
        modelBuilder.Entity<KernelDangerousFuncEntity>()
            .HasIndex(e => e.Severity);

        // 大模型 API:provider + enabled 用于筛选,priority 用于排序
        modelBuilder.Entity<LlmApiEntity>()
            .HasIndex(e => e.Provider);
        modelBuilder.Entity<LlmApiEntity>()
            .HasIndex(e => e.Enabled);
        modelBuilder.Entity<LlmApiEntity>()
            .HasIndex(e => e.Priority);

        // 访问凭据:token 唯一(集群认证用),enabled 用于筛选
        modelBuilder.Entity<LlmCredentialEntity>()
            .HasIndex(e => e.Token).IsUnique();
        modelBuilder.Entity<LlmCredentialEntity>()
            .HasIndex(e => e.Enabled);

        // 运行时追踪:按 session_id 索引(查询会话相关数据)
        modelBuilder.Entity<TrackerSnapshotEntity>()
            .HasIndex(e => e.SessionId);
        modelBuilder.Entity<TrackerKernelCommEntity>()
            .HasIndex(e => e.SessionId);
        modelBuilder.Entity<TrackerDumpEntity>()
            .HasIndex(e => e.SessionId);
    }
}

// ═══════════════════════════════════════════════════════════════
//  SqliteStore — 替代 JsonFileStore
// ═══════════════════════════════════════════════════════════════

public sealed class SqliteStore
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<SqliteStore> _logger;

    public SqliteStore(IDbContextFactory<AttestationDbContext> dbFactory, ILogger<SqliteStore> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    // ───────────────────────────────────────────────────────────
    //  计算 EK 指纹
    // ───────────────────────────────────────────────────────────

    public static string EkFingerprint(byte[] spkiDer)
    {
        var hash = SHA256.HashData(spkiDer);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ───────────────────────────────────────────────────────────
    //  EK 注册
    // ───────────────────────────────────────────────────────────

    public async Task StoreEkAsync(string fingerprint, string subject)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.EkRecords.FindAsync(fingerprint);
        if (existing != null)
        {
            existing.Subject = subject;
            existing.Timestamp = DateTime.UtcNow.ToString("o");
        }
        else
        {
            db.EkRecords.Add(new EkEntity
            {
                Fingerprint = fingerprint,
                Subject = subject,
                Timestamp = DateTime.UtcNow.ToString("o")
            });
        }
        await db.SaveChangesAsync();
        _logger.LogInformation("EK stored: {Fingerprint}", fingerprint[..16]);
    }

    public async Task<bool> IsEkRegisteredAsync(string fingerprint)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.EkRecords.FindAsync(fingerprint) != null;
    }

    public async Task<List<EkRecord>> LoadEkRecordsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.EkRecords
            .OrderByDescending(e => e.Timestamp)
            .Select(e => new EkRecord
            {
                Fingerprint = e.Fingerprint,
                Subject = e.Subject,
                Timestamp = e.Timestamp
            })
            .ToListAsync();
    }

    // ───────────────────────────────────────────────────────────
    //  AK 注册
    // ───────────────────────────────────────────────────────────

    public async Task StoreAkAsync(string akNameHex, string akPubB64, string ekFingerprint)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.AkRecords.FindAsync(akNameHex);
        if (existing != null)
        {
            existing.AkPub = akPubB64;
            existing.EkFingerprint = ekFingerprint;
            existing.Timestamp = DateTime.UtcNow.ToString("o");
        }
        else
        {
            db.AkRecords.Add(new AkEntity
            {
                AkName = akNameHex,
                AkPub = akPubB64,
                EkFingerprint = ekFingerprint,
                Timestamp = DateTime.UtcNow.ToString("o")
            });
        }
        await db.SaveChangesAsync();
        _logger.LogInformation("AK stored: {AkName}", akNameHex[..16]);
    }

    public async Task<AkRecord?> GetAkRecordAsync(string akNameHex)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.AkRecords.FindAsync(akNameHex);
        if (entity == null) return null;
        return new AkRecord
        {
            AkName = entity.AkName,
            AkPub = entity.AkPub,
            EkFingerprint = entity.EkFingerprint,
            Timestamp = entity.Timestamp
        };
    }

    public async Task<List<AkRecord>> LoadAkRecordsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AkRecords
            .OrderByDescending(a => a.Timestamp)
            .Select(a => new AkRecord
            {
                AkName = a.AkName,
                AkPub = a.AkPub,
                EkFingerprint = a.EkFingerprint,
                Timestamp = a.Timestamp
            })
            .ToListAsync();
    }

    // ───────────────────────────────────────────────────────────
    //  验证历史
    // ───────────────────────────────────────────────────────────

    public async Task AppendHistoryAsync(AttestationHistoryEntry entry)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.History.Add(new HistoryEntity
        {
            Id = entry.Id,
            Timestamp = entry.Timestamp,
            EkFingerprint = entry.EkFingerprint,
            AkName = entry.AkName,
            SigValid = entry.SigValid,
            MagicOk = entry.MagicOk,
            NonceOk = entry.NonceOk,
            PcrMatch = entry.PcrMatch,
            SecurityFeaturesJson = JsonSerializer.Serialize(entry.SecurityFeatures),
            Result = entry.Result
        });
        await db.SaveChangesAsync();
    }

    public async Task<List<AttestationHistoryEntry>> LoadHistoryAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entities = await db.History
            .OrderByDescending(h => h.Timestamp)
            .ToListAsync();

        return entities.Select(e => new AttestationHistoryEntry
        {
            Id = e.Id,
            Timestamp = e.Timestamp,
            EkFingerprint = e.EkFingerprint,
            AkName = e.AkName,
            SigValid = e.SigValid,
            MagicOk = e.MagicOk,
            NonceOk = e.NonceOk,
            PcrMatch = e.PcrMatch,
            SecurityFeatures = JsonSerializer.Deserialize<List<SecurityFeature>>(e.SecurityFeaturesJson) ?? [],
            Result = e.Result
        }).ToList();
    }

    // ───────────────────────────────────────────────────────────
    //  证书校验历史
    // ───────────────────────────────────────────────────────────

    public async Task AppendCertVerifyHistoryAsync(CertVerifyHistoryEntry entry)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.CertVerifyHistory.Add(new CertVerifyHistoryEntity
        {
            Id = entry.Id,
            Timestamp = entry.Timestamp,
            ClientCertCount = entry.ClientCertCount,
            TrustedCount = entry.TrustedCount,
            SuspiciousCount = entry.SuspiciousCount,
            SuspiciousCertsJson = JsonSerializer.Serialize(entry.SuspiciousCerts),
            Result = entry.Result,
        });
        await db.SaveChangesAsync();
    }

    public async Task<List<CertVerifyHistoryEntry>> LoadCertVerifyHistoryAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entities = await db.CertVerifyHistory
            .OrderByDescending(h => h.Timestamp)
            .ToListAsync();

        return entities.Select(e => new CertVerifyHistoryEntry
        {
            Id = e.Id,
            Timestamp = e.Timestamp,
            ClientCertCount = e.ClientCertCount,
            TrustedCount = e.TrustedCount,
            SuspiciousCount = e.SuspiciousCount,
            SuspiciousCerts = JsonSerializer.Deserialize<List<CertInfo>>(e.SuspiciousCertsJson) ?? [],
            Result = e.Result,
        }).ToList();
    }

    // ───────────────────────────────────────────────────────────
    //  驱动拉黑校验历史
    // ───────────────────────────────────────────────────────────

    public async Task AppendDriverVerifyHistoryAsync(DriverVerifyHistoryEntry entry)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.DriverVerifyHistory.Add(new DriverVerifyHistoryEntity
        {
            Id = entry.Id,
            Timestamp = entry.Timestamp,
            ClientDriverCount = entry.ClientDriverCount,
            BlockedCount = entry.BlockedCount,
            SuspiciousDriversJson = JsonSerializer.Serialize(entry.SuspiciousDrivers),
            AllDriversJson = JsonSerializer.Serialize(entry.AllDrivers),
            Result = entry.Result,
        });
        await db.SaveChangesAsync();
    }

    public async Task<List<DriverVerifyHistoryEntry>> LoadDriverVerifyHistoryAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entities = await db.DriverVerifyHistory
            .OrderByDescending(h => h.Timestamp)
            .ToListAsync();

        return entities.Select(e => new DriverVerifyHistoryEntry
        {
            Id = e.Id,
            Timestamp = e.Timestamp,
            ClientDriverCount = e.ClientDriverCount,
            BlockedCount = e.BlockedCount,
            SuspiciousDrivers = JsonSerializer.Deserialize<List<DriverInfo>>(e.SuspiciousDriversJson) ?? [],
            AllDrivers = JsonSerializer.Deserialize<List<DriverInfo>>(e.AllDriversJson) ?? [],
            Result = e.Result,
        }).ToList();
    }
}
