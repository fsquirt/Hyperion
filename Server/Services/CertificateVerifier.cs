using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Hyperion.Server.Services;

/// <summary>
/// EK 证书链验证服务，使用 BouncyCastle 解析，兼容 TPM 非标准证书
/// </summary>
public sealed class CertificateVerifier
{
    private readonly string _trustedRootDir;
    private readonly ILogger<CertificateVerifier> _logger;

    public CertificateVerifier(IConfiguration config, ILogger<CertificateVerifier> logger)
    {
        _trustedRootDir = config["Attestation:TrustedRootDir"]
            ?? Path.Combine(AppContext.BaseDirectory, "TrustedRoots");
        _logger = logger;
    }

    
    /// <summary>构建 EK 证书链，基于 BouncyCastle 实现，返回 (success, chainNames, reason)</summary>
    public (bool success, List<string> chain, string reason) BuildChain(
        List<X509Certificate2> certs)
    {
        if (certs.Count == 0)
            return (false, [], "no certificates provided");

        // 用 BouncyCastle 解析所有证书，能正确处理 TPM 非标准 Subject
        var parser = new X509CertificateParser();
        var bcCerts = new List<Org.BouncyCastle.X509.X509Certificate>();
        foreach (var c in certs)
        {
            var bc = parser.ReadCertificate(c.RawData);
            bcCerts.Add(bc);
        }

        var rootPool = LoadRootPoolBc(parser);
        // 信任根未配置必须 fail-closed：空根池时任何链都无法锚定，不能走"自签名即通过"的降级路径
        if (rootPool.Count == 0)
            return (false, [], $"trusted root pool is empty: {_trustedRootDir}");

        var allPool = new List<Org.BouncyCastle.X509.X509Certificate>();
        allPool.AddRange(bcCerts.Skip(1)); // 客户端中间证书
        allPool.AddRange(rootPool);        // 可信根证书

        var chain = new List<string>();
        var current = bcCerts[0]; // leaf = EK cert
        var now = DateTime.UtcNow;

        for (int depth = 0; depth < 20; depth++)
        {
            chain.Add(current.SubjectDN.ToString());

            // 有效期检查: 链上每张证书都必须在有效期内, 叶子证书也不例外
            if (now < current.NotBefore || now > current.NotAfter)
                return (false, chain, $"certificate expired or not yet valid: [{current.SubjectDN}]");

            // 自签名根: 必须是受信根池成员, 否则拒绝, 防止攻击者自造自签名证书直通
            if (current.SubjectDN.Equals(current.IssuerDN))
            {
                if (!rootPool.Any(r => r.SubjectDN.Equals(current.SubjectDN)))
                    return (false, chain, "self-signed cert not in trusted root pool");
                return (true, chain, "ok");
            }

            // 查找 issuer
            var issuer = FindIssuerBc(current, allPool);
            if (issuer == null)
                return (false, chain, $"chain broken: issuer not found for [{current.SubjectDN}]");

            // 逐级验签：issuer 公钥必须能验证当前证书的签名
            try
            {
                if (!current.IsSignatureValid(issuer.GetPublicKey()))
                    return (false, chain, $"signature invalid: [{current.SubjectDN}]");
            }
            catch (Exception ex)
            {
                // TPM 非标准证书可能出现 BouncyCastle 无法处理的签名算法, 验签失败一律拒绝
                return (false, chain, $"signature verification error: [{current.SubjectDN}]: {ex.Message}");
            }

            current = issuer;
        }

        return (false, chain, "chain too deep (>20)");
    }

    
    /// <summary>从证书提取 SPKI DER，用于 EK 指纹计算。</summary>
    public static byte[] GetSpkiDer(X509Certificate2 cert)
    {
        return cert.PublicKey.ExportSubjectPublicKeyInfo();
    }

    
    /// <summary>加载可信根证书池，基于 BouncyCastle 实现。</summary>
    private List<Org.BouncyCastle.X509.X509Certificate> LoadRootPoolBc(X509CertificateParser parser)
    {
        var pool = new List<Org.BouncyCastle.X509.X509Certificate>();
        if (!Directory.Exists(_trustedRootDir))
        {
            _logger.LogWarning("Trusted root directory not found: {Dir}", _trustedRootDir);
            return pool;
        }

        var extensions = new[] { "*.cer", "*.crt", "*.pem", "*.der" };
        foreach (var ext in extensions)
        {
            foreach (var file in Directory.GetFiles(_trustedRootDir, ext))
            {
                try
                {
                    var bytes = File.ReadAllBytes(file);

                    // 检测 PEM 格式
                    var text = Encoding.UTF8.GetString(bytes);
                    if (text.Contains("-----BEGIN CERTIFICATE-----"))
                    {
                        // PEM → 解码 Base64
                        var base64 = string.Join("", text
                            .Split('\n', '\r')
                            .Where(l => !l.StartsWith("-----"))
                            .Select(l => l.Trim()));
                        bytes = Convert.FromBase64String(base64);
                    }

                    var cert = parser.ReadCertificate(bytes);
                    if (cert != null) pool.Add(cert);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug("Failed to load root cert {File}: {Error}", file, ex.Message);
                }
            }
        }

        _logger.LogInformation("Loaded {Count} trusted root certificates", pool.Count);
        return pool;
    }

    /// <summary>
    /// 用 BouncyCastle 比较证书的 Issuer DN 与候选证书的 Subject DN
    /// </summary>
    private static Org.BouncyCastle.X509.X509Certificate? FindIssuerBc(
        Org.BouncyCastle.X509.X509Certificate cert,
        List<Org.BouncyCastle.X509.X509Certificate> pool)
    {
        var issuerDn = cert.IssuerDN;

        foreach (var candidate in pool)
        {
            if (candidate.SubjectDN.Equals(issuerDn))
                return candidate;
        }

        return null;
    }
}
