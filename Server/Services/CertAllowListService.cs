using SEWindows.Server.Models;

namespace SEWindows.Server.Services;

/// <summary>
/// 读取 Microsoft 受信任根证书项目列表 (IncludedCACertificateReportForMSFT.csv)，
/// 提供本机证书白名单比对。
/// </summary>
public sealed class CertAllowListService
{
    private readonly HashSet<string> _trustedSha256s;
    private readonly ILogger<CertAllowListService> _logger;
    private readonly string _csvPath;

    public CertAllowListService(IConfiguration config, ILogger<CertAllowListService> logger)
    {
        _logger = logger;
        _csvPath = config.GetValue<string>("CertAllowList:Path")
            ?? Path.Combine(AppContext.BaseDirectory, "IncludedCACertificateReportForMSFT.csv");

        _trustedSha256s = LoadTrustedSha256s(_csvPath);
        logger.LogInformation("[CertAllowList] 已加载 {Count} 个受信任 SHA-256 指纹 (from {Path})",
            _trustedSha256s.Count, _csvPath);
    }

    public int TrustedCount => _trustedSha256s.Count;
    public string CsvPath => _csvPath;

    /// <summary>
    /// 找出客户端有但微软列表中没有的证书。
    /// </summary>
    public List<CertInfo> FindSuspicious(List<CertInfo> clientCerts)
    {
        return clientCerts
            .Where(c => !_trustedSha256s.Contains(c.Sha256))
            .ToList();
    }

    private static HashSet<string> LoadTrustedSha256s(string csvPath)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(csvPath)) return set;

        foreach (var line in File.ReadLines(csvPath))
        {
            var fields = ParseCsvLine(line);
            if (fields.Count > 5 && !string.IsNullOrWhiteSpace(fields[5]))
                set.Add(fields[5].Trim());
        }
        return set;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
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
