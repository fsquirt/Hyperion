using Microsoft.EntityFrameworkCore;
using SEWindows.Server.Data;
using SEWindows.Server.Models;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace SEWindows.Server.Services;

/// <summary>
/// 恶意驱动阻止列表服务。
///
/// 数据源:
///   1. LOLDrivers  — https://www.loldrivers.io/api/drivers.json (MD5/SHA1/SHA256)
///   2. MSFT WDAC   — https://aka.ms/VulnerableDriverBlockList (zip → DriverPolicy_Enforced.xml, SHA1/SHA256)
///   3. 手动上传    — 管理员上传 .sys，计算 MD5/SHA1/SHA256
///
/// 内存维护三套哈希索引（MD5/SHA1/SHA256 → 存在），供 O(1) 查询；
/// 全量记录持久化到 SQLite。
/// </summary>
public sealed class BlocklistService
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<BlocklistService> _logger;
    private readonly IHttpClientFactory _httpFactory;

    // ── 内存哈希索引（O(1) 查询，启动时从 DB 加载）──────────────────
    private readonly HashSet<string> _md5Set = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sha1Set = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _sha256Set = new(StringComparer.OrdinalIgnoreCase);

    // ── 来源更新时间 ──────────────────────────────────────────────
    private string? _loldriverUpdatedAt;
    private string? _msftUpdatedAt;

    // ── 文件路径 ──────────────────────────────────────────────────
    private static readonly string BaseDir = AppContext.BaseDirectory;
    private static readonly string LoldriverPath = Path.Combine(BaseDir, "loldrivers.json");
    private static readonly string MsftBlocklistDir = Path.Combine(BaseDir, "VulnerableDriverBlockList");
    private static readonly string MsftXmlPath = Path.Combine(MsftBlocklistDir, "DriverPolicy_Enforced.xml");

    // 开发回退:bin\Debug\net10.0 → 项目根目录(dotnet run 时源码数据文件在此)
    private static readonly string DevSourceDir =
        Path.GetFullPath(Path.Combine(BaseDir, "..", "..", ".."));
    private static readonly string DevLoldriverPath = Path.Combine(DevSourceDir, "loldrivers.json");
    private static readonly string DevMsftBlocklistDir = Path.Combine(DevSourceDir, "VulnerableDriverBlockList");

    // ── 更新 URL ──────────────────────────────────────────────────
    private const string LoldriverUrl = "https://www.loldrivers.io/api/drivers.json";
    private const string MsftUrl = "https://aka.ms/VulnerableDriverBlockList";

    private static readonly XNamespace SiNs = "urn:schemas-microsoft-com:sipolicy";

    public BlocklistService(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<BlocklistService> logger,
        IHttpClientFactory httpFactory)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _httpFactory = httpFactory;
    }

    // ═══════════════════════════════════════════════════════════════
    //  路径查找(支持递归 + 开发回退)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>查找 loldrivers.json:bin 目录 → 开发源码目录。</summary>
    private static string? FindLoldriverJson()
    {
        if (File.Exists(LoldriverPath)) return LoldriverPath;
        if (File.Exists(DevLoldriverPath)) return DevLoldriverPath;
        return null;
    }

    /// <summary>
    /// 查找微软 WDAC XML:递归搜索 bin 与开发源码目录。
    /// 优先 DriverPolicy_Enforced.xml,其次 LegacyFormat。
    /// zip 内部可能有嵌套目录,故用 AllDirectories 递归。
    /// </summary>
    private static string? FindMsftXml()
    {
        foreach (var dir in new[] { MsftBlocklistDir, DevMsftBlocklistDir })
        {
            if (!Directory.Exists(dir)) continue;
            var f = Directory.GetFiles(dir, "DriverPolicy_Enforced.xml", SearchOption.AllDirectories);
            if (f.Length > 0) return f[0];
            var lf = Directory.GetFiles(dir, "DriverPolicy_Enforced_LegacyFormat.xml", SearchOption.AllDirectories);
            if (lf.Length > 0) return lf[0];
        }
        return null;
    }

    /// <summary>启动时从数据库加载全部记录到内存索引。</summary>
    public async Task LoadAsync()
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var rows = await db.BlockedDrivers.ToListAsync();

            foreach (var r in rows)
            {
                if (!string.IsNullOrEmpty(r.Md5)) _md5Set.Add(r.Md5);
                if (!string.IsNullOrEmpty(r.Sha1)) _sha1Set.Add(r.Sha1);
                if (!string.IsNullOrEmpty(r.Sha256)) _sha256Set.Add(r.Sha256);
            }

            // 推断来源更新时间（取该来源最新一条 added_at）
            _loldriverUpdatedAt = rows.Where(r => r.Source == "loldriver")
                .Select(r => r.AddedAt).DefaultIfEmpty("").Max();
            _msftUpdatedAt = rows.Where(r => r.Source == "msft")
                .Select(r => r.AddedAt).DefaultIfEmpty("").Max();

            _logger.LogInformation("[Blocklist] 已加载 {Count} 条拉黑记录到内存索引", rows.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] 加载失败");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  查询 API
    // ═══════════════════════════════════════════════════════════════

    /// <summary>检查给定哈希是否在拉黑列表中。</summary>
    public bool IsBlocked(string? md5, string? sha1, string? sha256)
    {
        if (!string.IsNullOrEmpty(sha256) && _sha256Set.Contains(sha256)) return true;
        if (!string.IsNullOrEmpty(sha1) && _sha1Set.Contains(sha1)) return true;
        if (!string.IsNullOrEmpty(md5) && _md5Set.Contains(md5)) return true;
        return false;
    }

    /// <summary>
    /// 批量检查客户端上传的驱动列表中,哪些被拉黑。
    /// 返回命中的 DriverInfo 列表(保持原顺序)。
    /// </summary>
    public List<DriverInfo> FindBlocked(IEnumerable<DriverInfo> drivers)
    {
        var result = new List<DriverInfo>();
        foreach (var d in drivers)
        {
            if (IsBlocked(d.Md5, d.Sha1, d.Sha256))
                result.Add(d);
        }
        return result;
    }

    /// <summary>分页查询拉黑记录，可按来源/关键词过滤。</summary>
    public async Task<(List<BlockedDriverRecord> rows, int total)> QueryAsync(
        string? source = null, string? search = null, int page = 1, int pageSize = 50)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var q = db.BlockedDrivers.AsQueryable();

        if (!string.IsNullOrEmpty(source) &&
            Enum.TryParse<BlocklistSource>(source, true, out var src))
            q = q.Where(r => r.Source == src.ToString().ToLowerInvariant());

        if (!string.IsNullOrEmpty(search))
        {
            var kw = search.Trim().ToLowerInvariant();
            q = q.Where(r =>
                (r.DriverName != null && r.DriverName.ToLower().Contains(kw)) ||
                (r.Md5 != null && r.Md5.ToLower().Contains(kw)) ||
                (r.Sha1 != null && r.Sha1.ToLower().Contains(kw)) ||
                (r.Sha256 != null && r.Sha256.ToLower().Contains(kw)));
        }

        var total = await q.CountAsync();
        var rows = await q
            .OrderByDescending(r => r.AddedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (rows.Select(ToRecord).ToList(), total);
    }

    public async Task<BlocklistStats> GetStatsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.BlockedDrivers.ToListAsync();
        return new BlocklistStats
        {
            Total = all.Count,
            Loldriver = all.Count(r => r.Source == "loldriver"),
            Msft = all.Count(r => r.Source == "msft"),
            Manual = all.Count(r => r.Source == "manual"),
            LoldriverUpdatedAt = _loldriverUpdatedAt,
            MsftUpdatedAt = _msftUpdatedAt,
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  更新:LOLDrivers
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 从 loldrivers.io 拉取最新 JSON 并解析入库。
    /// 若本地已有 loldrivers.json 则先尝试本地解析，再尝试联网更新。
    /// </summary>
    public async Task<BlocklistUpdateResult> UpdateLoldriversAsync(bool fetchFromUrl = true)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // 1. 联网下载（可选）
            if (fetchFromUrl)
            {
                _logger.LogInformation("[Blocklist] 从 {Url} 下载 LOLDrivers...", LoldriverUrl);
                var http = _httpFactory.CreateClient("Blocklist");
                http.Timeout = TimeSpan.FromMinutes(2);
                var json = await http.GetStringAsync(LoldriverUrl);
                await File.WriteAllTextAsync(LoldriverPath, json);
                _logger.LogInformation("[Blocklist] LOLDrivers 已保存 ({Size} bytes)", json.Length);
            }

            // 2. 查找 JSON(bin 目录 → 开发源码目录回退)
            var jsonPath = FindLoldriverJson();
            if (jsonPath == null)
            {
                return new BlocklistUpdateResult
                {
                    Source = "loldriver",
                    Error = "未找到 loldrivers.json" + (fetchFromUrl ? "(下载可能失败)" : "(本地不存在,需先联网更新)"),
                };
            }

            // 3. 解析 JSON（流式，避免大文件 OOM）
            var entries = ParseLoldrivers(jsonPath);
            _logger.LogInformation("[Blocklist] LOLDrivers 解析 {Count} 条 (from {Path})", entries.Count, jsonPath);

            // 3. 入库（替换该来源全部记录）
            var (added, removed) = await ReplaceSourceAsync(BlocklistSource.Loldriver, entries);
            _loldriverUpdatedAt = DateTime.UtcNow.ToString("o");

            _logger.LogInformation("[Blocklist] LOLDrivers 更新完成: +{Added} -{Removed} 用时 {Ms}ms",
                added, removed, sw.ElapsedMilliseconds);

            await using var db = await _dbFactory.CreateDbContextAsync();
            return new BlocklistUpdateResult
            {
                Success = true,
                Source = "loldriver",
                Added = added,
                Removed = removed,
                Total = await db.BlockedDrivers.CountAsync(),
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] LOLDrivers 更新失败");
            return new BlocklistUpdateResult { Source = "loldriver", Error = ex.Message };
        }
    }

    /// <summary>解析 LOLDrivers JSON 文件，返回统一条目列表。</summary>
    /// <remarks>
    /// LOLDrivers JSON 结构:
    ///   [{ Id, Category, KnownVulnerableSamples: [{ Filename, MD5, SHA1, SHA256, ... }] }, ...]
    /// 一个 driver 可有多个样本，每个样本独立成条。
    /// </remarks>
    private static List<BlockedDriverEntity> ParseLoldrivers(string path)
    {
        var result = new List<BlockedDriverEntity>();
        using var doc = JsonDocument.Parse(File.OpenRead(path));
        var now = DateTime.UtcNow.ToString("o");

        foreach (var driver in doc.RootElement.EnumerateArray())
        {
            var id = driver.TryGetProperty("Id", out var idEl) ? idEl.GetString() ?? "unknown" : "unknown";
            if (!driver.TryGetProperty("KnownVulnerableSamples", out var samples)) continue;

            foreach (var s in samples.EnumerateArray())
            {
                var md5 = s.TryGetProperty("MD5", out var m) ? m.GetString() : null;
                var sha1 = s.TryGetProperty("SHA1", out var s1) ? s1.GetString() : null;
                var sha256 = s.TryGetProperty("SHA256", out var s2) ? s2.GetString() : null;

                if (string.IsNullOrEmpty(md5) && string.IsNullOrEmpty(sha1) && string.IsNullOrEmpty(sha256))
                    continue;

                var fname = s.TryGetProperty("Filename", out var fn) ? fn.GetString() : null;
                if (string.IsNullOrEmpty(fname) && s.TryGetProperty("OriginalFilename", out var ofn))
                    fname = ofn.GetString();
                var name = !string.IsNullOrEmpty(fname) ? $"{id}\\{fname}" : id;

                result.Add(new BlockedDriverEntity
                {
                    Id = Guid.NewGuid().ToString("N")[..16],
                    Source = "loldriver",
                    DriverName = name,
                    Md5 = md5?.ToLowerInvariant(),
                    Sha1 = sha1?.ToLowerInvariant(),
                    Sha256 = sha256?.ToLowerInvariant(),
                    AddedAt = now,
                });
            }
        }
        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  更新:MSFT WDAC
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 从 aka.ms 下载 VulnerableDriverBlockList.zip，解压，解析 DriverPolicy_Enforced.xml。
    /// </summary>
    public async Task<BlocklistUpdateResult> UpdateMsftAsync(bool fetchFromUrl = true)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            // 1. 联网下载 zip
            if (fetchFromUrl)
            {
                _logger.LogInformation("[Blocklist] 从 {Url} 下载 MSFT Blocklist...", MsftUrl);
                var http = _httpFactory.CreateClient("Blocklist");
                http.Timeout = TimeSpan.FromMinutes(2);
                var bytes = await http.GetByteArrayAsync(MsftUrl);

                var zipPath = Path.Combine(BaseDir, "VulnerableDriverBlockList.zip");
                await File.WriteAllBytesAsync(zipPath, bytes);
                _logger.LogInformation("[Blocklist] MSFT zip 已保存 ({Size} bytes)", bytes.Length);

                // 2. 解压(zip 内部可能有嵌套目录,解压后用 FindMsftXml 递归查找)
                if (Directory.Exists(MsftBlocklistDir))
                    Directory.Delete(MsftBlocklistDir, true);
                ZipFile.ExtractToDirectory(zipPath, MsftBlocklistDir, overwriteFiles: true);
                _logger.LogInformation("[Blocklist] MSFT zip 已解压到 {Dir}", MsftBlocklistDir);
            }

            // 3. 查找 XML(递归搜索 bin 与开发源码目录,兼容 zip 嵌套结构)
            var xmlPath = FindMsftXml();
            if (xmlPath == null)
            {
                return new BlocklistUpdateResult
                {
                    Source = "msft",
                    Error = "未找到 DriverPolicy_Enforced.xml" +
                            (fetchFromUrl ? "(解压后未找到,请检查 zip 结构)" : "(本地不存在,需先联网更新)"),
                };
            }

            // 4. 解析 XML
            var entries = ParseMsftXml(xmlPath);
            _logger.LogInformation("[Blocklist] MSFT 解析 {Count} 条 (from {Path})", entries.Count, xmlPath);

            // 4. 入库
            var (added, removed) = await ReplaceSourceAsync(BlocklistSource.Msft, entries);
            _msftUpdatedAt = DateTime.UtcNow.ToString("o");

            _logger.LogInformation("[Blocklist] MSFT 更新完成: +{Added} -{Removed} 用时 {Ms}ms",
                added, removed, sw.ElapsedMilliseconds);

            await using var db = await _dbFactory.CreateDbContextAsync();
            return new BlocklistUpdateResult
            {
                Success = true,
                Source = "msft",
                Added = added,
                Removed = removed,
                Total = await db.BlockedDrivers.CountAsync(),
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] MSFT 更新失败");
            return new BlocklistUpdateResult { Source = "msft", Error = ex.Message };
        }
    }

    /// <summary>解析微软 WDAC SiPolicy XML，返回统一条目列表。</summary>
    /// <remarks>
    /// XML 结构:
    ///   &lt;SiPolicy&gt;&lt;FileRules&gt;
    ///     &lt;Deny ID="ID_DENY_X_SHA1" FriendlyName="X.sys Hash Sha1" Hash="..."/&gt;
    ///     &lt;Deny ID="ID_DENY_X_SHA256" FriendlyName="X.sys Hash Sha256" Hash="..."/&gt;
    ///     &lt;Deny ID="ID_DENY_X_SHA1_PAGE" FriendlyName="... Hash Page Sha1" Hash="..."/&gt;  ← 页哈希,排除
    ///   &lt;/FileRules&gt;&lt;/SiPolicy&gt;
    /// 同一驱动的 SHA1/SHA256 聚合为一条。部分老格式条目 FriendlyName 无 Sha 类型字样，按哈希长度判定。
    /// </remarks>
    private static List<BlockedDriverEntity> ParseMsftXml(string path)
    {
        var doc = XDocument.Load(path);
        var fileRules = doc.Root?.Element(SiNs + "FileRules");
        if (fileRules == null) return [];

        // 按驱动名聚合
        var byDriver = new Dictionary<string, BlockedDriverEntity>(StringComparer.OrdinalIgnoreCase);
        var now = DateTime.UtcNow.ToString("o");

        foreach (var deny in fileRules.Elements(SiNs + "Deny"))
        {
            var denyId = deny.Attribute("ID")?.Value ?? "";
            var friendly = deny.Attribute("FriendlyName")?.Value ?? "";
            var hashHex = deny.Attribute("Hash")?.Value ?? "";
            if (string.IsNullOrEmpty(hashHex)) continue;

            var htype = DetectMsftHashType(friendly, hashHex);
            if (htype == null) continue; // 页哈希或其他,跳过

            var name = ExtractMsftDriverName(friendly, denyId);
            var hashLower = hashHex.ToLowerInvariant();

            if (!byDriver.TryGetValue(name, out var ent))
            {
                ent = new BlockedDriverEntity
                {
                    Id = Guid.NewGuid().ToString("N")[..16],
                    Source = "msft",
                    DriverName = name,
                    AddedAt = now,
                };
                byDriver[name] = ent;
            }

            if (htype == "sha1" && string.IsNullOrEmpty(ent.Sha1))
                ent.Sha1 = hashLower;
            else if (htype == "sha256" && string.IsNullOrEmpty(ent.Sha256))
                ent.Sha256 = hashLower;
        }

        return byDriver.Values.ToList();
    }

    /// <summary>根据 FriendlyName 关键词与哈希长度判定类型，返回 "sha1"/"sha256"/null(页哈希或未知)。</summary>
    private static string? DetectMsftHashType(string friendly, string hashHex)
    {
        var fl = friendly.ToLowerInvariant();
        // 页哈希排除
        if (fl.Contains("page sha1") || fl.Contains("page sha256")) return null;
        if (fl.Contains("sha1")) return "sha1";
        if (fl.Contains("sha256")) return "sha256";
        // 回退:按长度
        return hashHex.Length switch
        {
            40 => "sha1",
            64 => "sha256",
            _ => null,
        };
    }

    /// <summary>从 FriendlyName 提取驱动名；失败回退到 Deny ID。</summary>
    private static string ExtractMsftDriverName(string friendly, string denyId)
    {
        // FriendlyName 形如:
        //   "Agent64\05f052_... Hash Sha1"
        //   "AsrDrv10.sys Hash Sha256"
        // 取第一个 \ 或空格之前的部分
        var idx = friendly.IndexOfAny(['\\', ' ']);
        if (idx > 0) return friendly[..idx];
        if (idx == 0 && friendly.Length > 1)
        {
            // 以 \ 开头,取 \ 后到下一个分隔
            var rest = friendly[1..];
            var idx2 = rest.IndexOfAny(['\\', ' ']);
            return idx2 > 0 ? rest[..idx2] : rest;
        }
        // 回退:ID_DENY_<NAME>_<suffix>
        var parts = denyId.Split('_');
        return parts.Length >= 3 ? parts[2] : denyId;
    }

    // ═══════════════════════════════════════════════════════════════
    //  手动拉黑:上传 .sys
    // ═══════════════════════════════════════════════════════════════

    /// <summary>计算上传文件的 MD5/SHA1/SHA256 并加入拉黑列表。</summary>
    public async Task<ManualBlockResult> AddManualAsync(byte[] fileBytes, string fileName, string? notes = null)
    {
        try
        {
            if (fileBytes.Length == 0)
                return new ManualBlockResult { Error = "文件为空" };

            string md5, sha1, sha256;
            using (var md = MD5.Create()) md5 = BitConverter.ToString(md.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();
            using (var s1 = SHA1.Create()) sha1 = BitConverter.ToString(s1.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();
            using (var s2 = SHA256.Create()) sha256 = BitConverter.ToString(s2.ComputeHash(fileBytes)).Replace("-", "").ToLowerInvariant();

            var id = Guid.NewGuid().ToString("N")[..16];
            var now = DateTime.UtcNow.ToString("o");
            var drvName = Path.GetFileName(fileName);

            var ent = new BlockedDriverEntity
            {
                Id = id,
                Source = "manual",
                DriverName = drvName,
                Md5 = md5,
                Sha1 = sha1,
                Sha256 = sha256,
                AddedAt = now,
                Notes = notes,
            };

            await using var db = await _dbFactory.CreateDbContextAsync();
            db.BlockedDrivers.Add(ent);
            await db.SaveChangesAsync();

            // 更新内存索引
            _md5Set.Add(md5);
            _sha1Set.Add(sha1);
            _sha256Set.Add(sha256);

            _logger.LogInformation("[Blocklist] 手动拉黑: {Name} sha256={Sha256[..16]}...", drvName, sha256);

            return new ManualBlockResult
            {
                Success = true,
                Id = id,
                DriverName = drvName,
                Md5 = md5,
                Sha1 = sha1,
                Sha256 = sha256,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] 手动拉黑失败");
            return new ManualBlockResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  手动按哈希拉黑(不依赖文件)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 直接按用户提供的哈希添加拉黑记录。允许只填部分哈希，但至少一个。
    /// 哈希会被规范化为小写 hex；非法格式返回错误。
    /// </summary>
    public async Task<ManualBlockResult> AddManualByHashAsync(
        string driverName, string? md5, string? sha1, string? sha256, string? notes)
    {
        try
        {
            var nm = NormalizeHash(md5, 32, "MD5");
            var ns1 = NormalizeHash(sha1, 40, "SHA1");
            var ns2 = NormalizeHash(sha256, 64, "SHA256");

            if (nm.Error != null) return new ManualBlockResult { Error = nm.Error };
            if (ns1.Error != null) return new ManualBlockResult { Error = ns1.Error };
            if (ns2.Error != null) return new ManualBlockResult { Error = ns2.Error };

            if (nm.Value == null && ns1.Value == null && ns2.Value == null)
                return new ManualBlockResult { Error = "至少需要填写 MD5 / SHA1 / SHA256 中的一个" };

            var name = string.IsNullOrWhiteSpace(driverName) ? "manual_entry" : driverName.Trim();
            var id = Guid.NewGuid().ToString("N")[..16];
            var now = DateTime.UtcNow.ToString("o");

            var ent = new BlockedDriverEntity
            {
                Id = id,
                Source = "manual",
                DriverName = name,
                Md5 = nm.Value,
                Sha1 = ns1.Value,
                Sha256 = ns2.Value,
                AddedAt = now,
                Notes = notes,
            };

            await using var db = await _dbFactory.CreateDbContextAsync();
            db.BlockedDrivers.Add(ent);
            await db.SaveChangesAsync();

            if (nm.Value != null) _md5Set.Add(nm.Value);
            if (ns1.Value != null) _sha1Set.Add(ns1.Value);
            if (ns2.Value != null) _sha256Set.Add(ns2.Value);

            _logger.LogInformation("[Blocklist] 手动哈希拉黑: {Name} sha256={Sha256}", name, ns2.Value ?? "(无)");

            return new ManualBlockResult
            {
                Success = true,
                Id = id,
                DriverName = name,
                Md5 = nm.Value,
                Sha1 = ns1.Value,
                Sha256 = ns2.Value,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] 手动哈希拉黑失败");
            return new ManualBlockResult { Error = ex.Message };
        }
    }

    /// <summary>
    /// 规范化哈希:去空白、转小写、校验长度与 hex 字符。空值返回 null+无错误。
    /// </summary>
    private static (string? Value, string? Error) NormalizeHash(string? raw, int expectedLen, string label)
    {
        if (string.IsNullOrWhiteSpace(raw)) return (null, null);
        var s = raw.Trim().ToLowerInvariant();
        if (s.Length != expectedLen)
            return (null, $"{label} 长度应为 {expectedLen} 位,当前 {s.Length} 位");
        if (!s.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return (null, $"{label} 含非法字符(需为十六进制)");
        return (s, null);
    }

    // ═══════════════════════════════════════════════════════════════
    //  编辑
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 编辑已有拉黑记录。仅传入的字段会被更新(null 表示不修改)。
    /// 哈希会规范化校验，至少保留一个哈希不为空。
    /// </summary>
    public async Task<ManualBlockResult> UpdateAsync(
        string id, string? driverName, string? md5, string? sha1, string? sha256, string? notes)
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var ent = await db.BlockedDrivers.FindAsync(id);
            if (ent == null) return new ManualBlockResult { Error = "记录不存在" };

            // 哈希校验
            var nm = NormalizeHash(md5, 32, "MD5");
            var ns1 = NormalizeHash(sha1, 40, "SHA1");
            var ns2 = NormalizeHash(sha256, 64, "SHA256");
            if (nm.Error != null) return new ManualBlockResult { Error = nm.Error };
            if (ns1.Error != null) return new ManualBlockResult { Error = ns1.Error };
            if (ns2.Error != null) return new ManualBlockResult { Error = ns2.Error };

            // 应用字段(空字符串视为清空,null 视为不改)
            if (driverName != null) ent.DriverName = driverName.Trim();
            if (md5 != null) ent.Md5 = nm.Value;
            if (sha1 != null) ent.Sha1 = ns1.Value;
            if (sha256 != null) ent.Sha256 = ns2.Value;
            if (notes != null) ent.Notes = string.IsNullOrWhiteSpace(notes) ? null : notes;

            // 校验:至少要有一个哈希
            if (string.IsNullOrEmpty(ent.Md5) && string.IsNullOrEmpty(ent.Sha1) && string.IsNullOrEmpty(ent.Sha256))
                return new ManualBlockResult { Error = "至少需要保留一个哈希 (MD5/SHA1/SHA256)" };

            await db.SaveChangesAsync();
            await RebuildIndexAsync();

            _logger.LogInformation("[Blocklist] 编辑记录 {Id}: {Name}", id, ent.DriverName);

            return new ManualBlockResult
            {
                Success = true,
                Id = ent.Id,
                DriverName = ent.DriverName,
                Md5 = ent.Md5,
                Sha1 = ent.Sha1,
                Sha256 = ent.Sha256,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Blocklist] 编辑记录失败");
            return new ManualBlockResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  删除
    // ═══════════════════════════════════════════════════════════════

    public async Task<bool> DeleteAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var ent = await db.BlockedDrivers.FindAsync(id);
        if (ent == null) return false;

        db.BlockedDrivers.Remove(ent);
        await db.SaveChangesAsync();

        // 更新内存索引(保守:仅当无其他记录引用该哈希时移除)
        await RebuildIndexAsync();
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  内部:替换某来源全部记录
    // ═══════════════════════════════════════════════════════════════

    /// <summary>删除指定来源全部记录，插入新记录，重建内存索引。</summary>
    private async Task<(int added, int removed)> ReplaceSourceAsync(BlocklistSource source, List<BlockedDriverEntity> entries)
    {
        var srcStr = source.ToString().ToLowerInvariant();
        await using var db = await _dbFactory.CreateDbContextAsync();

        var old = db.BlockedDrivers.Where(r => r.Source == srcStr);
        var removed = await old.CountAsync();
        await old.ExecuteDeleteAsync();

        await db.BlockedDrivers.AddRangeAsync(entries);
        await db.SaveChangesAsync();

        await RebuildIndexAsync();
        return (entries.Count, removed);
    }

    /// <summary>从数据库重建内存哈希索引。</summary>
    private async Task RebuildIndexAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.BlockedDrivers.ToListAsync();

        _md5Set.Clear();
        _sha1Set.Clear();
        _sha256Set.Clear();
        foreach (var r in all)
        {
            if (!string.IsNullOrEmpty(r.Md5)) _md5Set.Add(r.Md5);
            if (!string.IsNullOrEmpty(r.Sha1)) _sha1Set.Add(r.Sha1);
            if (!string.IsNullOrEmpty(r.Sha256)) _sha256Set.Add(r.Sha256);
        }
    }

    private static BlockedDriverRecord ToRecord(BlockedDriverEntity e) => new()
    {
        Id = e.Id,
        Source = Enum.TryParse<BlocklistSource>(e.Source, true, out var s) ? s : BlocklistSource.Manual,
        DriverName = e.DriverName,
        Md5 = e.Md5,
        Sha1 = e.Sha1,
        Sha256 = e.Sha256,
        AddedAt = e.AddedAt,
        Notes = e.Notes,
    };
}
