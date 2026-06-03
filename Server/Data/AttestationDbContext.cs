using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SEWindows.Server.Models;

namespace SEWindows.Server.Data;

// ═══════════════════════════════════════════════════════════════
//  实体定义
// ═══════════════════════════════════════════════════════════════

[Table("ek_records")]
public sealed class EkEntity
{
    [Key] [Column("fingerprint")]  public string Fingerprint { get; set; } = "";
    [Column("subject")]           public string Subject { get; set; } = "";
    [Column("timestamp")]         public string Timestamp { get; set; } = "";
}

[Table("ak_records")]
public sealed class AkEntity
{
    [Key] [Column("ak_name")]        public string AkName { get; set; } = "";
    [Column("ak_pub")]               public string AkPub { get; set; } = "";
    [Column("ek_fingerprint")]       public string EkFingerprint { get; set; } = "";
    [Column("timestamp")]            public string Timestamp { get; set; } = "";
}

[Table("attestation_history")]
public sealed class HistoryEntity
{
    [Key] [Column("id")]                public string Id { get; set; } = "";
    [Column("timestamp")]               public string Timestamp { get; set; } = "";
    [Column("ek_fingerprint")]          public string EkFingerprint { get; set; } = "";
    [Column("ak_name")]                 public string AkName { get; set; } = "";
    [Column("sig_valid")]               public bool SigValid { get; set; }
    [Column("magic_ok")]                public bool MagicOk { get; set; }
    [Column("nonce_ok")]                public bool NonceOk { get; set; }
    [Column("pcr_match")]               public bool PcrMatch { get; set; }
    [Column("security_features_json")]  public string SecurityFeaturesJson { get; set; } = "[]";
    [Column("result")]                  public string Result { get; set; } = "fail";
}

[Table("admin_credentials")]
public sealed class AdminCredentialEntity
{
    [Key] [Column("credential_id")] public string CredentialId { get; set; } = "";
    [Column("public_key")]          public string PublicKey { get; set; } = "";
    [Column("sign_count")]          public uint SignCount { get; set; }
    [Column("created")]             public string Created { get; set; } = "";
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

    public AttestationDbContext(DbContextOptions<AttestationDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<EkEntity>().HasKey(e => e.Fingerprint);
        modelBuilder.Entity<AkEntity>().HasKey(e => e.AkName);
        modelBuilder.Entity<HistoryEntity>().HasKey(e => e.Id);
        modelBuilder.Entity<AdminCredentialEntity>().HasKey(e => e.CredentialId);
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
}
