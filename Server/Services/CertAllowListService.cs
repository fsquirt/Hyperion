using Hyperion.Server.Models;
using System.Text;

namespace Hyperion.Server.Services;

/// <summary>
/// 管理 Microsoft 受信任根证书列表 (IncludedCACertificateReportForMSFT.csv)。
/// 提供 CRUD 操作,所有修改会即时持久化到 CSV 文件并刷新内存白名单。
/// CSV 列顺序:[0]Microsoft Status,[1]CA Owner,[2]Common Name,[3]Subject,[4]SHA-1,[5]SHA-256
/// </summary>
public sealed class CertAllowListService
{
    private readonly ILogger<CertAllowListService> _logger;
    private readonly string _csvPath;
    private readonly object _lock = new();

    // 内存中的白名单，SHA-256 以大写形式存储，另有完整记录列表
    private HashSet<string> _trustedSha256s;
    private List<CertRow> _rows;

    public CertAllowListService(IConfiguration config, ILogger<CertAllowListService> logger)
    {
        _logger = logger;
        _csvPath = config.GetValue<string>("CertAllowList:Path")
            ?? Path.Combine(AppContext.BaseDirectory, "IncludedCACertificateReportForMSFT.csv");

        (_rows, _trustedSha256s) = LoadFromDisk(_csvPath);
        logger.LogInformation("[CertAllowList] 已加载 {Count} 个受信任 SHA-256 指纹 (from {Path})",
            _trustedSha256s.Count, _csvPath);
    }

    public int TrustedCount { get { lock (_lock) return _trustedSha256s.Count; } }
    public string CsvPath => _csvPath;

    /// <summary>找客户端有但白名单中没有的证书。</summary>
    public List<CertInfo> FindSuspicious(List<CertInfo> clientCerts)
    {
        // 快照避免在持锁时返回
        HashSet<string> snapshot;
        lock (_lock) snapshot = new HashSet<string>(_trustedSha256s, StringComparer.OrdinalIgnoreCase);

        return clientCerts
            .Where(c => !snapshot.Contains(c.Sha256))
            .ToList();
    }

    /// <summary>列出当前白名单的全部记录,可选关键字过滤。</summary>
    public List<CertRow> List(string? keyword)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(keyword)) return _rows.ToList();

            var q = keyword.Trim().ToLowerInvariant();
            return _rows
                .Where(r => (r.MicrosoftStatus?.ToLowerInvariant().Contains(q) ?? false)
                         || (r.CaOwner?.ToLowerInvariant().Contains(q) ?? false)
                         || (r.CommonName?.ToLowerInvariant().Contains(q) ?? false)
                         || (r.Subject?.ToLowerInvariant().Contains(q) ?? false)
                         || (r.Sha1?.ToLowerInvariant().Contains(q) ?? false)
                         || (r.Sha256?.ToLowerInvariant().Contains(q) ?? false))
                .ToList();
        }
    }

    public CertRow? FindBySha256(string sha256)
    {
        lock (_lock)
        {
            return _rows.FirstOrDefault(r =>
                string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>添加新证书行。若 SHA-256 已存在则返回错误。</summary>
    public (bool Success, string? Error) Add(CertRow row)
    {
        if (string.IsNullOrWhiteSpace(row.Sha256))
            return (false, "SHA-256 不能为空");
        if (!IsValidHex(row.Sha256, 64))
            return (false, "SHA-256 格式错误，应为 64 位十六进制");
        if (!string.IsNullOrWhiteSpace(row.Sha1) && !IsValidHex(row.Sha1, 40))
            return (false, "SHA-1 格式错误，应为 40 位十六进制");

        lock (_lock)
        {
            if (_rows.Any(r => string.Equals(r.Sha256, row.Sha256, StringComparison.OrdinalIgnoreCase)))
                return (false, "该 SHA-256 已存在");

            _rows.Add(Normalize(row));
            if (!PersistAndRebuildUnsafe())
                return (false, "写入 CSV 失败,请查看日志");

            _logger.LogInformation("[CertAllowList] 添加证书 {Sha256}", row.Sha256);
            return (true, null);
        }
    }

    /// <summary>按原 SHA-256 定位记录并替换字段。新 SHA-256 必须不冲突，与原值相同时除外。</summary>
    public (bool Success, string? Error) Update(string originalSha256, CertRow row)
    {
        if (string.IsNullOrWhiteSpace(row.Sha256))
            return (false, "SHA-256 不能为空");
        if (!IsValidHex(row.Sha256, 64))
            return (false, "SHA-256 格式错误，应为 64 位十六进制");
        if (!string.IsNullOrWhiteSpace(row.Sha1) && !IsValidHex(row.Sha1, 40))
            return (false, "SHA-1 格式错误，应为 40 位十六进制");

        lock (_lock)
        {
            var idx = _rows.FindIndex(r =>
                string.Equals(r.Sha256, originalSha256, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return (false, "原记录不存在");

            // 若改了 SHA-256,检查新值是否与他人冲突
            if (!string.Equals(originalSha256, row.Sha256, StringComparison.OrdinalIgnoreCase)
                && _rows.Any(r => string.Equals(r.Sha256, row.Sha256, StringComparison.OrdinalIgnoreCase)))
                return (false, "新 SHA-256 已被其他记录占用");

            _rows[idx] = Normalize(row);
            if (!PersistAndRebuildUnsafe())
                return (false, "写入 CSV 失败,请查看日志");

            _logger.LogInformation("[CertAllowList] 编辑证书 {Old} -> {New}", originalSha256, row.Sha256);
            return (true, null);
        }
    }

    /// <summary>按 SHA-256 删除记录。</summary>
    public (bool Success, string? Error) Delete(string sha256)
    {
        lock (_lock)
        {
            var idx = _rows.FindIndex(r =>
                string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase));
            if (idx < 0) return (false, "记录不存在");

            _rows.RemoveAt(idx);
            if (!PersistAndRebuildUnsafe())
                return (false, "写入 CSV 失败,请查看日志");

            _logger.LogInformation("[CertAllowList] 删除证书 {Sha256}", sha256);
            return (true, null);
        }
    }

    /// <summary>从 CSV 文件重新加载，供外部直接修改 CSV 后刷新使用。</summary>
    public void Reload()
    {
        lock (_lock)
        {
            (_rows, _trustedSha256s) = LoadFromDisk(_csvPath);
        }
        _logger.LogInformation("[CertAllowList] 已重新加载 {Count} 个证书", _trustedSha256s.Count);
    }

    
    //  持久化与索引重建，调用方需持有 _lock
    private bool PersistAndRebuildUnsafe()
    {
        try
        {
            SaveToDisk(_csvPath, _rows);
            _trustedSha256s = BuildIndex(_rows);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[CertAllowList] 写入 CSV 失败");
            return false;
        }
    }

    private static HashSet<string> BuildIndex(List<CertRow> rows)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            if (!string.IsNullOrWhiteSpace(r.Sha256))
                set.Add(r.Sha256.Trim());
        }
        return set;
    }

    private static (List<CertRow>, HashSet<string>) LoadFromDisk(string csvPath)
    {
        var rows = new List<CertRow>();
        if (!File.Exists(csvPath)) return (rows, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        var lines = File.ReadAllLines(csvPath);
        // 跳过表头
        for (int i = 1; i < lines.Length; i++)
        {
            var fields = ParseCsvLine(lines[i]);
            if (fields.Count >= 6)
            {
                rows.Add(new CertRow
                {
                    MicrosoftStatus = fields[0],
                    CaOwner = fields[1],
                    CommonName = fields[2],
                    Subject = fields[3],
                    Sha1 = fields[4],
                    Sha256 = fields[5],
                });
            }
        }
        return (rows, BuildIndex(rows));
    }

    private static void SaveToDisk(string csvPath, List<CertRow> rows)
    {
        var sb = new StringBuilder();
        // 表头与微软 CSV 保持一致
        sb.AppendLine("Microsoft Status,CA Owner,Common Name,Subject,SHA-1,SHA-256");
        foreach (var r in rows)
        {
            sb.AppendCsvField(r.MicrosoftStatus ?? "").Append(',');
            sb.AppendCsvField(r.CaOwner ?? "").Append(',');
            sb.AppendCsvField(r.CommonName ?? "").Append(',');
            sb.AppendCsvField(r.Subject ?? "").Append(',');
            sb.AppendCsvField(r.Sha1 ?? "").Append(',');
            sb.AppendCsvField(r.Sha256 ?? "");
            sb.AppendLine();
        }

        // 原子写:先写到临时文件再替换
        var tmp = csvPath + ".tmp";
        File.WriteAllText(tmp, sb.ToString());
        if (File.Exists(csvPath)) File.Replace(tmp, csvPath, null);
        else File.Move(tmp, csvPath);
    }

    private static CertRow Normalize(CertRow r) => new()
    {
        MicrosoftStatus = string.IsNullOrWhiteSpace(r.MicrosoftStatus) ? "Manual" : r.MicrosoftStatus.Trim(),
        CaOwner = (r.CaOwner ?? "").Trim(),
        CommonName = (r.CommonName ?? "").Trim(),
        Subject = (r.Subject ?? "").Trim(),
        Sha1 = string.IsNullOrWhiteSpace(r.Sha1) ? null : r.Sha1.Trim().ToLowerInvariant(),
        Sha256 = r.Sha256!.Trim().ToLowerInvariant(),
    };

    private static bool IsValidHex(string? s, int expectedLen)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        var v = s.Trim();
        if (v.Length != expectedLen) return false;
        foreach (var c in v)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    
    /// <summary>解析 CSV 行为字段列表。</summary>
    /// <param name="line">CSV 行文本</param>
    /// <returns>字段列表</returns>
    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                { current.Append('"'); i++; }
                else if (c == '"') inQuotes = false;
                else current.Append(c);
            }
            else
            {
                if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(current.ToString()); current.Clear(); }
                else current.Append(c);
            }
        }
        fields.Add(current.ToString());
        return fields;
    }
}

internal static class CsvBuilderExt
{
    /// <summary>按 RFC 4180 规则写出单个字段:含 ", " 或换行则用双引号包裹,内部 " 转义为 ""。</summary>
    public static StringBuilder AppendCsvField(this StringBuilder sb, string field)
    {
        if (field.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0)
        {
            sb.Append('"').Append(field.Replace("\"", "\"\"")).Append('"');
        }
        else
        {
            sb.Append(field);
        }
        return sb;
    }
}
