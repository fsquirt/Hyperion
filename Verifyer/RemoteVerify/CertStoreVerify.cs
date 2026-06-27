using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SEWindows.Verifyer.RemoteVerify;

/// <summary>
/// 本机证书存储区验证。
/// 读取 4 个证书存储区的详细信息，发送到服务端与微软受信任列表比对。
/// </summary>
public static class CertStoreVerify
{
    public static async Task<(bool Success, int SuspiciousCount, string Reason, string Id)> RunAsync(HttpClient http)
    {
        try
        {
            // 1. 收集 4 个存储区的证书详细信息
            var certs = CollectAllStoreCerts();
            Console.WriteLine($"  [*] 本机证书存储区共 {certs.Count} 个唯一证书");

            // 2. 发送到服务端（包含详细信息）
            var json = JsonSerializer.Serialize(new { certs });
            var resp = await http.PostAsync("/verify_certs",
                new StringContent(json, Encoding.UTF8, "application/json"));

            if (!resp.IsSuccessStatusCode)
                return (false, 0, $"服务端返回 {resp.StatusCode}", "");

            // 3. 解析响应
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var root = doc.RootElement;

            var certId = root.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";
            var trustedCount = root.GetProperty("trusted_count").GetInt32();
            var clientCount = root.GetProperty("client_count").GetInt32();

            var suspicious = new List<JsonElement>();
            if (root.TryGetProperty("suspicious", out var arr))
            {
                foreach (var item in arr.EnumerateArray())
                    suspicious.Add(item);
            }

            Console.WriteLine($"  [*] 微软信任列表: {trustedCount} 个, 本机: {clientCount} 个, 可疑: {suspicious.Count} 个");

            if (suspicious.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  [!] 发现 {suspicious.Count} 个不在微软信任列表中的证书:");
                Console.ResetColor();
                foreach (var cert in suspicious)
                {
                    var subject = cert.TryGetProperty("subject", out var s) ? s.GetString() : "?";
                    var issuer = cert.TryGetProperty("issuer", out var i) ? i.GetString() : "?";
                    var store = cert.TryGetProperty("store", out var st) ? st.GetString() : "?";
                    var sha256 = cert.TryGetProperty("sha256", out var sh) ? sh.GetString() : "?";
                    Console.WriteLine($"      [{store}] {subject}");
                    Console.WriteLine($"        签发者: {issuer}");
                    Console.WriteLine($"        SHA-256: {sha256?[..16]}...");
                }
            }
            else
            {
                Console.WriteLine("  [✔] 所有证书均在微软受信任根证书列表中");
            }

            return (true, suspicious.Count, suspicious.Count > 0
                ? $"{suspicious.Count} 个可疑证书"
                : "全部受信任", certId);
        }
        catch (Exception ex)
        {
            return (false, 0, $"异常: {ex.Message}", "");
        }
    }

    /// <summary>
    /// 从 4 个存储区收集证书详细信息（按 SHA-256 去重）。
    /// </summary>
    private static List<object> CollectAllStoreCerts()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<object>();

        var stores = new (StoreLocation Location, StoreName Name, string DisplayName)[]
        {
            (StoreLocation.LocalMachine, StoreName.Root, "LocalMachine\\Root"),
            (StoreLocation.LocalMachine, StoreName.CertificateAuthority, "LocalMachine\\CA"),
            (StoreLocation.CurrentUser, StoreName.Root, "CurrentUser\\Root"),
            (StoreLocation.CurrentUser, StoreName.CertificateAuthority, "CurrentUser\\CA"),
        };

        foreach (var (location, name, displayName) in stores)
        {
            try
            {
                using var store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                foreach (var cert in store.Certificates)
                {
                    // 跳过已过期的证书
                    if (cert.NotAfter < DateTime.Now) continue;

                    var sha256 = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
                    if (!seen.Add(sha256)) continue;

                    result.Add(new
                    {
                        sha256,
                        subject = cert.Subject,
                        issuer = cert.Issuer,
                        store = displayName,
                        not_before = cert.NotBefore.ToString("o"),
                        not_after = cert.NotAfter.ToString("o"),
                        serial = cert.SerialNumber,
                        thumbprint = cert.Thumbprint,
                    });
                }
            }
            catch { /* 跳过无法打开的存储区 */ }
        }

        return result;
    }
}
