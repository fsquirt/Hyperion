using System.Text.Json;
using System.Text.Json.Serialization;

namespace SEWindows.Server.Auth;

/// <summary>
/// 管理员 Passkey 凭据存储
/// </summary>
public sealed class AdminCredentialStore
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public AdminCredentialStore(IConfiguration config)
    {
        var baseDir = AppContext.BaseDirectory;
        _filePath = Path.Combine(baseDir, "Data", "admin_credentials.json");
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
    }

    public async Task<bool> HasAdminAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (!File.Exists(_filePath)) return false;
            var data = await File.ReadAllTextAsync(_filePath);
            var creds = JsonSerializer.Deserialize<AdminData>(data);
            return creds?.Credentials.Count > 0;
        }
        catch { return false; }
        finally { _lock.Release(); }
    }

    public async Task<AdminData> LoadAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (!File.Exists(_filePath)) return new AdminData();
            var data = await File.ReadAllTextAsync(_filePath);
            return JsonSerializer.Deserialize<AdminData>(data) ?? new AdminData();
        }
        catch { return new AdminData(); }
        finally { _lock.Release(); }
    }

    public async Task SaveAsync(AdminData admin)
    {
        await _lock.WaitAsync();
        try
        {
            var opts = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(admin, opts);
            await File.WriteAllTextAsync(_filePath, json);
        }
        finally { _lock.Release(); }
    }

    public sealed class AdminData
    {
        [JsonPropertyName("username")] public string Username { get; set; } = "admin";
        [JsonPropertyName("credentials")] public List<CredentialEntry> Credentials { get; set; } = [];
    }

    public sealed class CredentialEntry
    {
        [JsonPropertyName("credential_id")] public string CredentialId { get; set; } = "";
        [JsonPropertyName("public_key")]    public string PublicKey { get; set; } = "";
        [JsonPropertyName("sign_count")]    public uint SignCount { get; set; }
        [JsonPropertyName("created")]       public string Created { get; set; } = "";
    }
}
