using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Hyperion.UserService.Comm;

/// <summary>
/// 纯托管 TLS 的 HttpMessageHandler:完全用 BouncyCastle 在进程内完成 TLS 握手与加解密,
/// 不经过系统 SChannel / LSASS。因此即使在 PPL(Protected Process Light) 进程里也能正常做 HTTPS。
/// (SChannel 在 PPL 进程里会因无法向 LSASS 申请凭据句柄而失败 SEC_E_INVALID_HANDLE,见之前的排查。)
///
/// 证书校验采用与 CertPinning 一致的"公钥即 SPKI 固定":只接受公钥与内置证书一致的对端,不依赖系统信任库,防 MITM。
/// </summary>
public sealed class ManagedTlsHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is null)
            throw new InvalidOperationException("RequestUri 为空");

        var uri = request.RequestUri;
        var host = uri.Host;
        bool isHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        bool lanDev = CertPinning.IsLanDevServerUrl(uri.ToString());

        // 内网开发服务器,即 192.168.0.0/16 网段,放行 http 明文;其他地址仅支持 https
        if (!isHttps && !lanDev)
            throw new NotSupportedException("ManagedTlsHandler 仅支持 https,内网开发地址 192.168.0.0/16 除外");

        var port = uri.Port == -1 ? (isHttps ? 443 : 80) : uri.Port;
        var pathAndQuery = uri.PathAndQuery;

        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            var netStream = tcp.GetStream();

            // ── BouncyCastle TLS 握手,纯托管,不碰 LSASS ──
            // 内网开发地址跳过 SPKI 固定,开发证书自签或过期均可
            TlsClientProtocol? protocol = null;
            Stream ioStream = netStream;
            if (isHttps)
            {
                var crypto = new BcTlsCrypto();
                var client = new PinnedTlsClient(crypto, host, pinCertificate: !lanDev);
                protocol = new TlsClientProtocol(netStream);
                protocol.Connect(client);
                ioStream = protocol.Stream;
            }

            try
            {
                // ── 构造 HTTP/1.1 请求 ──
                var sb = new StringBuilder();
                sb.Append($"{request.Method.Method} {pathAndQuery} HTTP/1.1\r\n");
                sb.Append($"Host: {host}\r\n");
                sb.Append("Connection: close\r\n");
                sb.Append("Accept: */*\r\n");
                foreach (var h in request.Headers)
                {
                    if (string.Equals(h.Key, "Host", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(h.Key, "Connection", StringComparison.OrdinalIgnoreCase))
                        continue;
                    sb.Append($"{h.Key}: {string.Join(",", h.Value)}\r\n");
                }

                byte[]? body = null;
                if (request.Content is not null)
                {
                    body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                    foreach (var h in request.Content.Headers)
                    {
                        if (string.Equals(h.Key, "Content-Length", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(h.Key, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                            continue;
                        sb.Append($"{h.Key}: {string.Join(",", h.Value)}\r\n");
                    }
                    sb.Append($"Content-Length: {body.Length}\r\n");
                }
                sb.Append("\r\n");

                var headerBytes = Encoding.ASCII.GetBytes(sb.ToString());
                await ioStream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
                if (body is not null)
                    await ioStream.WriteAsync(body, cancellationToken).ConfigureAwait(false);
                await ioStream.FlushAsync(cancellationToken).ConfigureAwait(false);

                // ── 读取 HTTP 响应 ──
                return await ReadResponseAsync(ioStream, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (protocol is not null) { try { protocol.Close(); } catch { } }
            }
        }
        finally
        {
            tcp.Dispose();
        }
    }

    // ═════════════════════════════════════════════════════════════
    //  HTTP 响应解析,极简 HTTP/1.1:状态行 + 头部 + body
    // ═════════════════════════════════════════════════════════════

    private static async Task<HttpResponseMessage> ReadResponseAsync(Stream stream, CancellationToken ct)
    {
        var statusLine = await ReadLineAsync(stream, ct).ConfigureAwait(false);
        var parts = statusLine.Split(' ', 3);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var statusCode))
            throw new HttpRequestException($"无法解析 HTTP 状态行: {statusLine}");

        var resp = new HttpResponseMessage((HttpStatusCode)statusCode);

        int? contentLength = null;
        var chunked = false;
        while (true)
        {
            var line = await ReadLineAsync(stream, ct).ConfigureAwait(false);
            if (line.Length == 0) break;
            var idx = line.IndexOf(':');
            if (idx > 0)
            {
                var name = line.Substring(0, idx).Trim();
                var value = line.Substring(idx + 1).Trim();
                resp.Headers.TryAddWithoutValidation(name, value);
                if (string.Equals(name, "content-length", StringComparison.OrdinalIgnoreCase))
                    contentLength = int.TryParse(value, out var cl) ? cl : null;
                else if (string.Equals(name, "transfer-encoding", StringComparison.OrdinalIgnoreCase) &&
                         value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                    chunked = true;
            }
        }

        byte[] body;
        if (chunked)
            body = await ReadChunkedAsync(stream, ct).ConfigureAwait(false);
        else if (contentLength.HasValue)
            body = await ReadExactAsync(stream, contentLength.Value, ct).ConfigureAwait(false);
        else
            body = await ReadToEndAsync(stream, ct).ConfigureAwait(false);

        resp.Content = new ByteArrayContent(body);
        return resp;
    }

    private static async Task<string> ReadLineAsync(Stream s, CancellationToken ct)
    {
        var ms = new MemoryStream();
        int b;
        while ((b = await ReadByteAsync(s, ct).ConfigureAwait(false)) >= 0)
        {
            if (b == '\n') break;
            if (b == '\r') continue;
            ms.WriteByte((byte)b);
        }
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    private static async Task<int> ReadByteAsync(Stream s, CancellationToken ct)
    {
        var buf = new byte[1];
        var n = await s.ReadAsync(buf, ct).ConfigureAwait(false);
        return n == 1 ? buf[0] : -1;
    }

    private static async Task<byte[]> ReadExactAsync(Stream s, int count, CancellationToken ct)
    {
        var buf = new byte[count];
        var off = 0;
        while (off < count)
        {
            var n = await s.ReadAsync(buf.AsMemory(off, count - off), ct).ConfigureAwait(false);
            if (n == 0) break;
            off += n;
        }
        return buf;
    }

    private static async Task<byte[]> ReadToEndAsync(Stream s, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = await s.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
            ms.Write(buf, 0, n);
        return ms.ToArray();
    }

    private static async Task<byte[]> ReadChunkedAsync(Stream s, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        while (true)
        {
            var sizeLine = await ReadLineAsync(s, ct).ConfigureAwait(false);
            var hex = sizeLine.Split(';')[0].Trim();
            if (hex.Length == 0) continue;
            var size = Convert.ToInt32(hex, 16);
            if (size == 0) break;
            var chunk = await ReadExactAsync(s, size, ct).ConfigureAwait(false);
            ms.Write(chunk, 0, chunk.Length);
            await ReadLineAsync(s, ct).ConfigureAwait(false); // 块后 CRLF
        }
        while (true) // 拖尾头部
        {
            var line = await ReadLineAsync(s, ct).ConfigureAwait(false);
            if (line.Length == 0) break;
        }
        return ms.ToArray();
    }
}

/// <summary>BouncyCastle TlsClient:在 ClientHello 注入 SNI 即 server_name 扩展,并用公钥即 SPKI 固定校验服务端证书。</summary>
file sealed class PinnedTlsClient : DefaultTlsClient
{
    private readonly string _host;
    private readonly bool _pinCertificate;

    /// <param name="pinCertificate">false 时跳过证书校验,适用于内网开发服务器,自签或过期证书均可。</param>
    public PinnedTlsClient(TlsCrypto crypto, string host, bool pinCertificate = true) : base(crypto)
    {
        _host = host;
        _pinCertificate = pinCertificate;
    }

    public override TlsAuthentication GetAuthentication() => new PinnedTlsAuthentication(_pinCertificate);

    // 在 ClientHello 中注入 server_name (SNI) 扩展。BouncyCastle 的客户端通过
    // GetClientExtensions() 发送扩展,而非 GetServerExtensions,后者不存在于 TlsClient 接口。
    // 不注入 SNI 的话,共享 CDN(EdgeOne)会返回默认证书而非 hyperion.cloudyou.top 的证书。
    public override IDictionary<int, byte[]> GetClientExtensions()
    {
        var extensions = base.GetClientExtensions() ?? new Dictionary<int, byte[]>();
        var serverNames = new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(_host)) };
        TlsExtensionsUtilities.AddServerNameExtensionClient(extensions, serverNames);
        return extensions;
    }
}

/// <summary>公钥即 SPKI 固定:只接受与内置证书公钥一致的服务端证书,否则断开,等同于拒绝握手以防 MITM。</summary>
file sealed class PinnedTlsAuthentication : TlsAuthentication
{
    private readonly bool _pinCertificate;
    public PinnedTlsAuthentication(bool pinCertificate) => _pinCertificate = pinCertificate;

    public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
    {
        // 内网开发服务器:接受任意证书,自签或过期均可
        if (!_pinCertificate) return;

        var leaf = serverCertificate.Certificate.GetCertificateAt(0);
        var der = leaf.GetEncoded();
        using var cert2 = X509CertificateLoader.LoadCertificate(der);

        // 有效期检查,避免接受已过期的固定证书
        var now = DateTime.UtcNow;
        if (now < cert2.NotBefore.ToUniversalTime() || now > cert2.NotAfter.ToUniversalTime())
            throw new TlsFatalAlert(AlertDescription.bad_certificate);

        // 公钥即 SPKI 固定
        var spki = cert2.PublicKey.EncodedKeyValue.RawData;
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(spki);
        if (!CryptographicOperations.FixedTimeEquals(hash, CertPinning.ExpectedServerSpkiSha256))
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
    }

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "接口实现")]
    public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null!;
}
