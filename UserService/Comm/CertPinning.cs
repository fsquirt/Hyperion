using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Hyperion.UserService.Comm;

/// <summary>
/// 证书固定(Certificate Pinning / Public-Key Pinning)。
/// 把服务端证书内置进来,TLS 握手时只接受"公钥(SPKI)与内置证书一致"的服务器证书,
/// 即使系统信任库被篡改 / 存在恶意根证书 / 遭遇中间人,也无法伪造 —— 抵御 MITM。
/// </summary>
public static class CertPinning
{
    /// <summary>内置的服务端 leaf 证书(从 https://hyperion.cloudyou.top 导出)。</summary>
    private const string EmbeddedServerCertPem = @"-----BEGIN CERTIFICATE-----
MIIG2zCCBMOgAwIBAgIQDpfnl3JwhVJDFjmFtA2CDzANBgkqhkiG9w0BAQsFADBb
MQswCQYDVQQGEwJDTjElMCMGA1UEChMcVHJ1c3RBc2lhIFRlY2hub2xvZ2llcywg
SW5jLjElMCMGA1UEAxMcVHJ1c3RBc2lhIERWIFRMUyBSU0EgQ0EgMjAyNTAeFw0y
NjA3MjgwMDAwMDBaFw0yNjEwMjUyMzU5NTlaMCAxHjAcBgNVBAMTFWh5cGVyaW9u
LmNsb3VkeW91LnRvcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKyV
PDiHF+KDtFzVsg6sKwQtAmxHjgdJFawseosyKWFTQbCq5uIIZUyJcPpEvnbj31xO
L4ZJQrauoVvoKurSwnfJYIbtieCjUtt6HfomGWWwbzJK1GqgR2iC7JaJ242WiLEb
HevMOlxuuV/YPO2g0Nvc4i4kAa5VQQTY9H4bSDpRffkKDukW7WT0TwR24gsaovjF
I/S7BEp1xT1NAe0xqJIMrs3gq0B78iGQnUe9NZYWiu0DADkWhh51KmM9Ye65KNxB
QJLPwZuLz0u4oq+PGkAiSZv9letmvbp7XjufFUIsAfi3NNV8DxxnSa50xoco0Sj/
xcINsZXL4+vRTFbngykCAwEAAaOCAtQwggLQMB8GA1UdIwQYMBaAFLQSKKW0wB2f
KXFpPNkRlkp1aVDAMB0GA1UdDgQWBBT3VD4eiI/s3/B1Vgk0zcm/R7tSujAgBgNV
HREEGTAXghVoeXBlcmlvbi5jbG91ZHlvdS50b3AwPgYDVR0gBDcwNTAzBgZngQwB
AgEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATB5BggrBgEFBQcBAQRt
MGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEF
BQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL1RydXN0QXNpYURWVExT
UlNBQ0EyMDI1LmNydDAMBgNVHRMBAf8EAjAAMIIBfAYKKwYBBAHWeQIEAgSCAWwE
ggFoAWYAdQDCMX5XRRmjRe5/ON6ykEHrx8IhWiK/f9W1rXaa2Q5SzQAAAZ+m8UY/
AAAEAwBGMEQCIEw5tw4osqlFHQD5elaYYhXhZySgRjIyfrA0/twqkVhGAiAl3hKP
2fPbbxS12VJXit0rOWxRKwpJ7vq4kjHFlLTeVAB2ANdtfRDRp/V3wsfpX9cAv/mC
yTNaZeHQswFzF8DIxWl3AAABn6bxRhAAAAQDAEcwRQIgYt2PfC1l6f/5Q790AXGp
LZIYxvXc8KkFMC3TsFEavLsCIQCZEPTdyViTej4RY/XS05QBM1kdoSGSnZluvzzp
G3oCnAB1AJROQ4f67MHvgfMZJCaoGGUBx9NfOAIBP3JnfVU3LhnYAAABn6bxRkYA
AAQDAEYwRAIgNd/JHvA094GdzcwwjK4o3aIX3skXTSsfzs5PqTp5hHMCIEfu3/WP
rX0o+eLqshm7Hxi3VKJCoakCLgNiyK9P6B7OMA0GCSqGSIb3DQEBCwUAA4ICAQAs
HR+SO6mzbPk0uK5S5LRieY6QlZD630A40uVoOlL0nTjwDsxl/37b9dC0/4whd7Z4
PyCNiH4aSOORNBB70MnsCqK1NmvP4XuLemnx9usP0aYGpU2tXY5QtFbLURmT/5aW
T3QbVkSyHr6514k2LYrgnppeGpYmxs4fMHe3q0lBxMlNPpcJxIltOApZio/5c/Y+
nzs9fXgDMm8iXUIDVXaK4QuJKsj7SMqsYTMXFeTiZjpwVSqimPu3SIy5hn8mm2tK
aqTKb2xduoNwk26Yd3g8WRyYIVO54FXLHrbpb5wOYirsc2qJA/QntpD+cNLwBywh
c3xMgvXJT3UuWRqkpbw3FgD5aFjpELRA6741scMQsYGD8TtHoweTvfC5OkxFzfOW
UdsduyEdhPbtWHV6lT05LlIfeesNga72HAP/junODOZozBbPpWyUcAsJkBE2/+WS
sgD8iTsRwUJVx/IX3Pnw/AJih+O1IA0V7aws/Zc7X6HmYy/I9X/2qYs6EewYYjZH
HKkoUvqluxtllEAln1wfuwnOUivwAYQy6+kPFU7nZutuZHGmfdYwtIaEkNpyF2HN
OtxY9q2Ict429aYWCG9lStL5wXawsz6Q9aYuKaReLh/6EGh95YZCZ0J9hDSVglMF
IDeSQXpRv4gSGVtgEczdbgGLauqNQHtfUeNk5PyVUA==
-----END CERTIFICATE-----";

    /// <summary>内置证书的公钥(SPKI) SHA256 —— 预计算,握手时用于比对。</summary>
    private static readonly byte[] _expectedSpkiSha256 = ComputeSpkiSha256(EmbeddedServerCertPem);

    /// <summary>供托管 TLS 实现(BouncyCastle 等)复用:服务器证书公钥(SPKI) SHA256 期望值。</summary>
    public static byte[] ExpectedServerSpkiSha256 => _expectedSpkiSha256;

    /// <summary>
    /// 判断给定服务端地址是否为内网开发服务器(仅 192.168.0.0/16)。
    /// 内网开发地址不强制 HTTPS 与证书固定:ManagedTlsHandler 对其放行 http 明文,
    /// https 也跳过 SPKI 固定(开发证书自签/过期均可)。
    /// </summary>
    public static bool IsLanDevServerUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return false;
        if (!IPAddress.TryParse(uri.Host, out var ip)) return false;
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 192 && bytes[1] == 168;
    }

    /// <summary>
    /// 创建带证书固定的 HttpClient。PolicySync 与 ServerConnection 统一走这里。
    /// </summary>
    public static HttpClient CreatePinnedClient(string? baseAddress = null, TimeSpan? timeout = null)
    {
        // 使用纯托管 TLS handler(BouncyCastle),在进程内完成 TLS,不依赖系统 SChannel/LSASS。
        // 即使在 PPL 进程里也能工作;服务端证书由 ManagedTlsHandler 按公钥(SPKI)固定校验。
        var client = new HttpClient(new ManagedTlsHandler());
        if (!string.IsNullOrEmpty(baseAddress))
            client.BaseAddress = new Uri(baseAddress!);
        if (timeout.HasValue)
            client.Timeout = timeout.Value;
        return client;
    }

    private static byte[] ComputeSpkiSha256(string pem)
    {
        using var cert = X509Certificate2.CreateFromPem(pem);
        using var sha = SHA256.Create();
        return sha.ComputeHash(cert.PublicKey.EncodedKeyValue.RawData);
    }
}
