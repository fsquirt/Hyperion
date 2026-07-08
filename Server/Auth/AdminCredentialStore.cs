using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;

namespace Hyperion.Server.Auth;

/// <summary>
/// 管理员 Passkey 凭据存储（SQLite，通过 DbContextFactory 支持 Singleton 生命周期）
/// </summary>
public sealed class AdminCredentialStore
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;

    public AdminCredentialStore(IDbContextFactory<AttestationDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<bool> HasAdminAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AdminCredentials.AnyAsync();
    }

    public async Task<List<CredentialEntry>> LoadCredentialsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AdminCredentials
            .Select(c => new CredentialEntry
            {
                CredentialId = c.CredentialId,
                PublicKey = c.PublicKey,
                SignCount = c.SignCount,
                Created = c.Created
            })
            .ToListAsync();
    }

    public async Task SaveCredentialAsync(CredentialEntry entry)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.AdminCredentials.FindAsync(entry.CredentialId);
        if (existing != null)
        {
            existing.PublicKey = entry.PublicKey;
            existing.SignCount = entry.SignCount;
            existing.Created = entry.Created;
        }
        else
        {
            db.AdminCredentials.Add(new AdminCredentialEntity
            {
                CredentialId = entry.CredentialId,
                PublicKey = entry.PublicKey,
                SignCount = entry.SignCount,
                Created = entry.Created
            });
        }
        await db.SaveChangesAsync();
    }

    public async Task UpdateSignCountAsync(string credentialId, uint signCount)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.AdminCredentials.FindAsync(credentialId);
        if (entity != null)
        {
            entity.SignCount = signCount;
            await db.SaveChangesAsync();
        }
    }

    public sealed class CredentialEntry
    {
        public string CredentialId { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public uint SignCount { get; set; }
        public string Created { get; set; } = "";
    }
}
