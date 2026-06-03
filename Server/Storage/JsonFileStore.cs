using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SEWindows.Server.Models;

namespace SEWindows.Server.Storage;

public sealed class JsonFileStore
{
    private readonly string _validEksFile;
    private readonly string _ValidAksFile;
    private readonly string _historyFile;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public JsonFileStore(IConfiguration config)
    {
        var baseDir = AppContext.BaseDirectory;
        _validEksFile = Path.Combine(baseDir, config["Attestation:ValidEksFile"] ?? "Data/valid_eks.txt");
        _ValidAksFile = Path.Combine(baseDir, config["Attestation:ValidAksFile"] ?? "Data/valid_aks.txt");
        _historyFile  = Path.Combine(baseDir, config["Attestation:HistoryFile"]  ?? "Data/attestation_history.json");

        Directory.CreateDirectory(Path.GetDirectoryName(_validEksFile)!);
    }

    // ═══════════════════════════════════════════════════════════
    //  JSON Lines 读写
    // ═══════════════════════════════════════════════════════════

    public async Task<List<EkRecord>> LoadEkRecordsAsync()
    {
        await _lock.WaitAsync();
        try { return LoadJsonLines<EkRecord>(_validEksFile); }
        finally { _lock.Release(); }
    }

    public async Task<List<AkRecord>> LoadAkRecordsAsync()
    {
        await _lock.WaitAsync();
        try { return LoadJsonLines<AkRecord>(_ValidAksFile); }
        finally { _lock.Release(); }
    }

    public async Task<bool> IsEkRegisteredAsync(string fingerprint)
    {
        var records = await LoadEkRecordsAsync();
        return records.Any(r => r.Fingerprint == fingerprint);
    }

    public async Task<AkRecord?> GetAkRecordAsync(string akNameHex)
    {
        var records = await LoadAkRecordsAsync();
        return records.FirstOrDefault(r => r.AkName == akNameHex);
    }

    public async Task StoreEkAsync(string fingerprint, string subject)
    {
        await _lock.WaitAsync();
        try
        {
            var existing = LoadJsonLines<EkRecord>(_validEksFile);
            if (existing.Any(r => r.Fingerprint == fingerprint)) return;
            AppendRecord(_validEksFile, new EkRecord
            {
                Fingerprint = fingerprint,
                Subject = subject,
                Timestamp = DateTime.UtcNow.ToString("o")
            });
        }
        finally { _lock.Release(); }
    }

    public async Task StoreAkAsync(string akNameHex, string akPubB64, string ekFp)
    {
        await _lock.WaitAsync();
        try
        {
            var existing = LoadJsonLines<AkRecord>(_ValidAksFile);
            if (existing.Any(r => r.AkName == akNameHex)) return;
            AppendRecord(_ValidAksFile, new AkRecord
            {
                AkName = akNameHex,
                AkPub = akPubB64,
                EkFingerprint = ekFp,
                Timestamp = DateTime.UtcNow.ToString("o")
            });
        }
        finally { _lock.Release(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  EK 指纹计算
    // ═══════════════════════════════════════════════════════════

    public static string EkFingerprint(byte[] spkiDer)
    {
        var hash = SHA256.HashData(spkiDer);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ═══════════════════════════════════════════════════════════
    //  验证历史
    // ═══════════════════════════════════════════════════════════

    public async Task<List<AttestationHistoryEntry>> LoadHistoryAsync()
    {
        await _lock.WaitAsync();
        try
        {
            if (!File.Exists(_historyFile)) return [];
            var json = await File.ReadAllTextAsync(_historyFile);
            return JsonSerializer.Deserialize<List<AttestationHistoryEntry>>(json) ?? [];
        }
        catch { return []; }
        finally { _lock.Release(); }
    }

    public async Task AppendHistoryAsync(AttestationHistoryEntry entry)
    {
        await _lock.WaitAsync();
        try
        {
            var list = new List<AttestationHistoryEntry>();
            if (File.Exists(_historyFile))
            {
                var json = await File.ReadAllTextAsync(_historyFile);
                list = JsonSerializer.Deserialize<List<AttestationHistoryEntry>>(json) ?? [];
            }
            list.Insert(0, entry);
            if (list.Count > 500) list = list[..500];
            var opts = new JsonSerializerOptions { WriteIndented = false };
            await File.WriteAllTextAsync(_historyFile, JsonSerializer.Serialize(list, opts));
        }
        finally { _lock.Release(); }
    }

    // ═══════════════════════════════════════════════════════════
    //  内部方法
    // ═══════════════════════════════════════════════════════════

    private static List<T> LoadJsonLines<T>(string path) where T : class
    {
        if (!File.Exists(path)) return [];
        var result = new List<T>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { result.Add(JsonSerializer.Deserialize<T>(line)!); }
            catch { /* skip malformed lines */ }
        }
        return result;
    }

    private static void AppendRecord<T>(string path, T record)
    {
        var json = JsonSerializer.Serialize(record);
        File.AppendAllText(path, json + Environment.NewLine);
    }
}
