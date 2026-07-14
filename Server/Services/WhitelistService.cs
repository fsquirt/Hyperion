using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Hyperion.Server.Services;

/// <summary>
/// 附着白名单服务。
///
/// 两种条目类型:
///   1) Hash — 按驱动文件哈希(MD5/SHA1/SHA256)排除特定驱动
///   2) Cert — 按签名者证书(Subject + SHA256 指纹)排除一类驱动
///
/// 内存维护哈希索引(供 KernelService 附着决策时 O(1) 查询);
/// 全量记录持久化到 SQLite whitelist_entries 表。
/// </summary>
public sealed class WhitelistService
{
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<WhitelistService> _logger;

    // ── 内存索引 ───────────────────────────────────────────────────
    private readonly HashSet<string> _hashMd5 = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hashSha1 = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hashSha256 = new(StringComparer.OrdinalIgnoreCase);

    // 证书条目:Subject 前缀匹配(大小写不敏感)+ 精确指纹匹配
    private readonly List<string> _certSubjects = new();           // 前缀匹配用
    private readonly HashSet<string> _certThumbprints = new(StringComparer.OrdinalIgnoreCase); // SHA256 指纹

    private readonly object _lock = new();

    public WhitelistService(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<WhitelistService> logger)
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
            var rows = await db.WhitelistEntries.ToListAsync();

            lock (_lock)
            {
                _hashMd5.Clear();
                _hashSha1.Clear();
                _hashSha256.Clear();
                _certSubjects.Clear();
                _certThumbprints.Clear();

                foreach (var r in rows)
                {
                    if (r.Type == "hash")
                    {
                        if (!string.IsNullOrEmpty(r.Md5)) _hashMd5.Add(r.Md5);
                        if (!string.IsNullOrEmpty(r.Sha1)) _hashSha1.Add(r.Sha1);
                        if (!string.IsNullOrEmpty(r.Sha256)) _hashSha256.Add(r.Sha256);
                    }
                    else if (r.Type == "cert")
                    {
                        if (!string.IsNullOrEmpty(r.Sha256))
                            _certThumbprints.Add(r.Sha256);
                        if (!string.IsNullOrEmpty(r.CertSubject))
                            _certSubjects.Add(r.CertSubject);
                    }
                }
            }

            _logger.LogInformation("[Whitelist] 已加载 {Count} 条白名单记录 (hash={H}, cert={C})",
                rows.Count, rows.Count(r => r.Type == "hash"), rows.Count(r => r.Type == "cert"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Whitelist] 加载失败");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  查询 API(供 KernelService 附着决策时调用)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>检查驱动文件哈希是否在白名单中。</summary>
    public bool IsHashWhitelisted(string? md5, string? sha1, string? sha256)
    {
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(sha256) && _hashSha256.Contains(sha256)) return true;
            if (!string.IsNullOrEmpty(sha1) && _hashSha1.Contains(sha1)) return true;
            if (!string.IsNullOrEmpty(md5) && _hashMd5.Contains(md5)) return true;
            return false;
        }
    }

    /// <summary>检查签名者证书是否在白名单中(Subject 前缀或指纹精确匹配)。</summary>
    public bool IsCertWhitelisted(string certSubject, string? certThumbprintSha256)
    {
        lock (_lock)
        {
            if (!string.IsNullOrEmpty(certThumbprintSha256) && _certThumbprints.Contains(certThumbprintSha256))
                return true;
            foreach (var prefix in _certSubjects)
            {
                if (certSubject.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }
    }

    /// <summary>返回白名单全量数据副本(供客户端策略下发:hash + cert 两个维度)。</summary>
    public (List<string> Md5, List<string> Sha1, List<string> Sha256,
            List<string> CertSubjects, List<string> CertThumbprints) GetAll()
    {
        lock (_lock)
        {
            return (
                _hashMd5.ToList(),
                _hashSha1.ToList(),
                _hashSha256.ToList(),
                _certSubjects.ToList(),
                _certThumbprints.ToList()
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  管理端 API
    // ═══════════════════════════════════════════════════════════════

    public async Task<(List<WhitelistEntry> rows, int total)> QueryAsync(
        string? type = null, string? search = null, int page = 1, int pageSize = 50)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var q = db.WhitelistEntries.AsQueryable();

        if (!string.IsNullOrEmpty(type))
        {
            var t = type.ToLowerInvariant();
            q = q.Where(r => r.Type == t);
        }

        if (!string.IsNullOrEmpty(search))
        {
            var kw = search.Trim().ToLowerInvariant();
            q = q.Where(r =>
                (r.DisplayName != null && r.DisplayName.ToLower().Contains(kw)) ||
                (r.Sha256 != null && r.Sha256.ToLower().Contains(kw)) ||
                (r.Md5 != null && r.Md5.ToLower().Contains(kw)) ||
                (r.Sha1 != null && r.Sha1.ToLower().Contains(kw)) ||
                (r.CertSubject != null && r.CertSubject.ToLower().Contains(kw)));
        }

        var total = await q.CountAsync();
        var rows = await q
            .OrderByDescending(r => r.AddedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (rows.Select(ToRecord).ToList(), total);
    }

    public async Task<WhitelistStats> GetStatsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var all = await db.WhitelistEntries.ToListAsync();
        return new WhitelistStats
        {
            Total = all.Count,
            HashCount = all.Count(r => r.Type == "hash"),
            CertCount = all.Count(r => r.Type == "cert"),
        };
    }

    public async Task<WhitelistAddResult> AddHashAsync(WhitelistAddHashRequest req)
    {
        // 规范化哈希
        var md5 = NormalizeHash(req.Md5, 32);
        var sha1 = NormalizeHash(req.Sha1, 40);
        var sha256 = NormalizeHash(req.Sha256, 64);

        if (md5 == null && sha1 == null && sha256 == null)
            return new WhitelistAddResult { Error = "至少需要提供 MD5 / SHA1 / SHA256 中的一个" };

        var entity = new WhitelistEntryEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            Type = "hash",
            DisplayName = string.IsNullOrWhiteSpace(req.DriverName) ? "(未命名)" : req.DriverName.Trim(),
            Md5 = md5,
            Sha1 = sha1,
            Sha256 = sha256,
            AddedAt = DateTime.UtcNow.ToString("o"),
            Notes = req.Notes?.Trim(),
        };

        await using var db = await _dbFactory.CreateDbContextAsync();
        db.WhitelistEntries.Add(entity);
        await db.SaveChangesAsync();

        RebuildIndex(db);
        return new WhitelistAddResult { Success = true, Id = entity.Id };
    }

    public async Task<WhitelistAddResult> AddCertAsync(WhitelistAddCertRequest req)
    {
        var subject = req.CertSubject?.Trim() ?? "";
        var thumbprint = NormalizeHash(req.CertThumbprintSha256, 64);

        if (string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(thumbprint))
            return new WhitelistAddResult { Error = "需要提供证书 Subject 或 SHA256 指纹" };

        var displayName = string.IsNullOrWhiteSpace(req.DisplayName)
            ? (string.IsNullOrEmpty(subject) ? "(未命名证书)" : ShortSubject(subject))
            : req.DisplayName.Trim();

        var entity = new WhitelistEntryEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            Type = "cert",
            DisplayName = displayName,
            Sha256 = thumbprint,
            CertSubject = string.IsNullOrEmpty(subject) ? null : subject,
            CertIssuer = string.IsNullOrEmpty(req.CertIssuer) ? null : req.CertIssuer.Trim(),
            AddedAt = DateTime.UtcNow.ToString("o"),
            Notes = req.Notes?.Trim(),
        };

        await using var db = await _dbFactory.CreateDbContextAsync();
        db.WhitelistEntries.Add(entity);
        await db.SaveChangesAsync();

        RebuildIndex(db);
        return new WhitelistAddResult { Success = true, Id = entity.Id };
    }

    public async Task<WhitelistAddResult> UpdateAsync(string id, WhitelistUpdateRequest req)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.WhitelistEntries.FindAsync(id);
        if (entity == null)
            return new WhitelistAddResult { Error = "记录不存在" };

        if (req.DisplayName != null) entity.DisplayName = req.DisplayName.Trim();
        if (req.Notes != null) entity.Notes = req.Notes.Trim();
        await db.SaveChangesAsync();
        return new WhitelistAddResult { Success = true, Id = entity.Id };
    }

    public async Task<bool> DeleteAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var entity = await db.WhitelistEntries.FindAsync(id);
        if (entity == null) return false;
        db.WhitelistEntries.Remove(entity);
        await db.SaveChangesAsync();
        RebuildIndex(db);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  上传 .sys 解析多签名(核心:Authenticode + 嵌套签名在 UnauthAttrs)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 上传 .sys 文件,计算 MD5/SHA1/SHA256 + 提取所有签名者证书
    /// (包括嵌套在 UnauthAttrs 里的厂商签名)。
    /// 返回给前端让管理员选择"添加哈希"还是"添加其中某个证书"。
    /// </summary>
    public async Task<SysParseResult> ParseSysAsync(byte[] fileBytes, string fileName)
    {
        await Task.Yield(); // 保持异步签名

        try
        {
            // 计算三个哈希
            var md5 = Convert.ToHexString(MD5.HashData(fileBytes)).ToLowerInvariant();
            var sha1 = Convert.ToHexString(SHA1.HashData(fileBytes)).ToLowerInvariant();
            var sha256 = Convert.ToHexString(SHA256.HashData(fileBytes)).ToLowerInvariant();

            // 提取所有签名者
            var signers = ExtractAllSigners(fileBytes);

            return new SysParseResult
            {
                Success = true,
                FileName = fileName,
                FileSize = fileBytes.Length,
                Md5 = md5,
                Sha1 = sha1,
                Sha256 = sha256,
                Signers = signers,
            };
        }
        catch (Exception ex)
        {
            return new SysParseResult
            {
                FileName = fileName,
                FileSize = fileBytes.Length,
                Error = ex.Message,
            };
        }
    }

    // ───────────────────────────────────────────────────────────────
    //  PE 签名提取(Authenticode + 嵌套签名,纯 C# + P/Invoke)
    // ───────────────────────────────────────────────────────────────

    private List<SysSignerInfo> ExtractAllSigners(byte[] fileBytes)
    {
        var signers = new List<SysSignerInfo>();
        var seenSubjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var tempPath = Path.Combine(Path.GetTempPath(), "sewl_" + Guid.NewGuid().ToString("N") + ".sys");
        try
        {
            File.WriteAllBytes(tempPath, fileBytes);

            // CryptQueryObject 从 PE 文件提取内嵌 PKCS#7 签名
            if (!CryptQueryObjectFromFile(
                    CERT_QUERY_OBJECT_FILE, tempPath,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0, out _, out _, out _,
                    out var hStore, out var hMsg, IntPtr.Zero))
            {
                _logger.LogWarning("[Whitelist] CryptQueryObject 失败,文件可能无内嵌签名: {Path}, 错误码={Err}",
                    tempPath, Marshal.GetLastWin32Error());
                return signers;
            }

            _logger.LogInformation("[Whitelist] CryptQueryObject 成功,开始提取签名者");

            try
            {
                ExtractLeafSignersFromStore(hStore, signers, seenSubjects);
                _logger.LogInformation("[Whitelist] cert store 提取到 {N} 个签名者", signers.Count);

                ExtractNestedSigners(hMsg, signers, seenSubjects);
                _logger.LogInformation("[Whitelist] 嵌套签名提取完毕,总计 {N} 个签名者", signers.Count);
            }
            finally
            {
                CertCloseStore(hStore, 0);
                CryptMsgClose(hMsg);
            }
        }
        finally
        {
            try { File.Delete(tempPath); } catch { }
        }

        return signers;
    }

    private static void ExtractLeafSignersFromStore(IntPtr hStore,
        List<SysSignerInfo> signers, HashSet<string> seen)
    {
        IntPtr pCert = IntPtr.Zero;
        while ((pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                     0, CERT_FIND_ANY, IntPtr.Zero, pCert)) != IntPtr.Zero)
        {
            var cert = new X509Certificate2(pCert);
            if (!IsLeafCertificate(cert)) continue;

            var subject = cert.Subject;
            if (seen.Contains(subject)) continue;
            seen.Add(subject);

            signers.Add(new SysSignerInfo
            {
                Tag = ClassifySignerTag(subject),
                Subject = subject,
                Issuer = cert.Issuer,
                ThumbprintSha256 = cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
            });
        }
    }

    private void ExtractNestedSigners(IntPtr hMsg,
        List<SysSignerInfo> signers, HashSet<string> seen)
    {
        // 从 hMsg 取出完整 PKCS#7 编码字节,改用托管 SignedCms 解析
        // (避免手动 Marshal.PtrToStructure<CMSG_SIGNER_INFO> 在某些签名上 AV)
        //
        // 注意:CryptMsgGetParam 的 pcbData 是 IN/OUT 参数,
        // 必须用 ref 不能用 out —— out 会在调用前清零输入值,
        // 函数认为缓冲区大小=0 就返回 ERROR_MORE_DATA (234)。
        uint cbMessage = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, IntPtr.Zero, ref cbMessage))
        {
            _logger.LogWarning("[Whitelist] CryptMsgGetParam(CMSG_ENCODED_MESSAGE) 取大小失败, 错误码={Err}",
                Marshal.GetLastWin32Error());
            return;
        }

        var messageBytes = new byte[cbMessage];
        IntPtr pMessage = Marshal.AllocHGlobal((int)cbMessage);
        try
        {
            uint cbWritten = cbMessage;
            if (!CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, pMessage, ref cbWritten))
            {
                _logger.LogWarning("[Whitelist] CryptMsgGetParam(CMSG_ENCODED_MESSAGE) 取数据失败, 错误码={Err}",
                    Marshal.GetLastWin32Error());
                return;
            }
            Marshal.Copy(pMessage, messageBytes, 0, (int)cbWritten);
        }
        finally
        {
            Marshal.FreeHGlobal(pMessage);
        }

        try
        {
            var signedCms = new SignedCms();
            signedCms.Decode(messageBytes);
            ExtractNestedFromSignedCms(signedCms, signers, seen, depth: 0);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[Whitelist] SignedCms.Decode 失败: {Ex}", ex.Message);
        }
    }

    private void ExtractNestedFromSignedCms(SignedCms signedCms,
        List<SysSignerInfo> signers, HashSet<string> seen, int depth)
    {
        // 防止恶意递归
        if (depth > 8) return;

        foreach (var signerInfo in signedCms.SignerInfos)
        {
            // 嵌套签名按 RFC 5652 必须作为未认证属性附加,
            // 但微软某些历史签名也见过放在认证属性里,两个都扫
            TryExtractNestedFromAttrs(signerInfo.SignedAttributes, signers, seen, depth);
            TryExtractNestedFromAttrs(signerInfo.UnsignedAttributes, signers, seen, depth);
        }
    }

    private void TryExtractNestedFromAttrs(CryptographicAttributeObjectCollection attrs,
        List<SysSignerInfo> signers, HashSet<string> seen, int depth)
    {
        if (attrs == null) return;
        foreach (var attr in attrs)
        {
            var oid = attr.Oid?.Value;
            if (oid != SZOID_NESTED_SIGNATURE) continue;

            foreach (var value in attr.Values)
            {
                var raw = value.RawData;
                if (raw == null || raw.Length == 0) continue;

                try
                {
                    var nestedCms = new SignedCms();
                    nestedCms.Decode(raw);

                    // 嵌套签名的证书链就在 nestedCms.Certificates 里
                    foreach (var cert in nestedCms.Certificates)
                    {
                        if (!IsLeafCertificate(cert)) continue;
                        var subject = cert.Subject;
                        if (seen.Contains(subject)) continue;
                        seen.Add(subject);

                        signers.Add(new SysSignerInfo
                        {
                            Tag = ClassifySignerTag(subject),
                            Subject = subject,
                            Issuer = cert.Issuer,
                            ThumbprintSha256 = cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
                        });
                    }

                    // 递归处理更深层的嵌套签名
                    ExtractNestedFromSignedCms(nestedCms, signers, seen, depth + 1);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("[Whitelist] 嵌套签名解析失败(深度 {Depth}): {Ex}",
                        depth, ex.Message);
                }
            }
        }
    }

    // ───────────────────────────────────────────────────────────────
    //  辅助
    // ───────────────────────────────────────────────────────────────

    private static bool IsLeafCertificate(X509Certificate2 cert)
    {
        // 有 basicConstraints 且 CA=true → 是 CA 证书,跳过
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509BasicConstraintsExtension bc && bc.CertificateAuthority)
                return false;
        }
        return true;
    }

    private static string ClassifySignerTag(string subject)
    {
        var s = subject;
        if (s.Contains("Microsoft Windows Hardware Compatibility Publisher", StringComparison.OrdinalIgnoreCase))
            return "WHQL";
        if (s.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
            return "Microsoft";
        if (s.Contains("Time Stamp", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("Timestamp", StringComparison.OrdinalIgnoreCase))
            return "Timestamp"; // 会被过滤掉
        return "Vendor";
    }

    private static string? NormalizeHash(string? hash, int expectedLen)
    {
        if (string.IsNullOrWhiteSpace(hash)) return null;
        var h = hash.Trim().ToLowerInvariant();
        if (h.Length != expectedLen) return null;
        foreach (var c in h)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return null;
        return h;
    }

    private static string ShortSubject(string subject)
    {
        // "CN=XXX, O=YYY, ..." → "XXX"
        var parts = subject.Split(',');
        foreach (var p in parts)
        {
            var kv = p.Trim();
            if (kv.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return kv.Substring(3).Trim('"');
        }
        return subject.Length > 40 ? subject.Substring(0, 40) : subject;
    }

    private static WhitelistEntry ToRecord(WhitelistEntryEntity e) => new()
    {
        Id = e.Id,
        Type = e.Type == "cert" ? WhitelistEntryType.Cert : WhitelistEntryType.Hash,
        DisplayName = e.DisplayName,
        Sha256 = e.Sha256,
        Md5 = e.Md5,
        Sha1 = e.Sha1,
        CertSubject = e.CertSubject,
        CertIssuer = e.CertIssuer,
        AddedAt = e.AddedAt,
        Notes = e.Notes,
    };

    private void RebuildIndex(AttestationDbContext db)
    {
        // 重新加载所有记录到内存
        var rows = db.WhitelistEntries.AsNoTracking().ToList();
        lock (_lock)
        {
            _hashMd5.Clear();
            _hashSha1.Clear();
            _hashSha256.Clear();
            _certSubjects.Clear();
            _certThumbprints.Clear();

            foreach (var r in rows)
            {
                if (r.Type == "hash")
                {
                    if (!string.IsNullOrEmpty(r.Md5)) _hashMd5.Add(r.Md5);
                    if (!string.IsNullOrEmpty(r.Sha1)) _hashSha1.Add(r.Sha1);
                    if (!string.IsNullOrEmpty(r.Sha256)) _hashSha256.Add(r.Sha256);
                }
                else if (r.Type == "cert")
                {
                    if (!string.IsNullOrEmpty(r.Sha256))
                        _certThumbprints.Add(r.Sha256);
                    if (!string.IsNullOrEmpty(r.CertSubject))
                        _certSubjects.Add(r.CertSubject);
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  P/Invoke:WinTrust / Crypt32
    // ═══════════════════════════════════════════════════════════════

    private const uint X509_ASN_ENCODING = 0x00000001;
    private const uint PKCS_7_ASN_ENCODING = 0x00010000;
    private const uint CERT_QUERY_OBJECT_FILE = 1;
    private const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x0400;
    private const uint CERT_QUERY_FORMAT_FLAG_BINARY = 0x0002;
    private const uint CERT_FIND_ANY = 0;
    private const uint CMSG_ENCODED_MESSAGE = 29;
    private const string SZOID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";

    // 注意:CryptQueryObject 的 pvObject 参数对于 FILE 传入的是 LPCWSTR,
    // 必须用 [MarshalAs(UnmanagedType.LPWStr)] string,不能用 object。
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CryptQueryObject")]
    private static extern bool CryptQueryObjectFromFile(
        uint dwObjectType,
        [MarshalAs(UnmanagedType.LPWStr)] string pvObject,
        uint dwExpectedContentTypeFlags,
        uint dwExpectedFormatTypeFlags,
        uint dwFlags,
        out uint pdwMsgAndCertEncodingType,
        out uint pdwContentType,
        out uint pdwFormatType,
        out IntPtr phCertStore,
        out IntPtr phMsg,
        IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertFindCertificateInStore(
        IntPtr hCertStore, uint dwCertEncodingType, uint dwFindFlags,
        uint dwFindType, IntPtr pvFindPara, IntPtr pPrevCertContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptMsgGetParam(
        IntPtr hCryptMsg, uint dwParamType, uint dwIndex,
        IntPtr pvData, ref uint pcbData);
}
