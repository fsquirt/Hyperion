using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using Hyperion.Tracker;
using System.Text;
using System.Text.Json;
using System.Threading;
using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 附着白名单(来自服务端策略)。两个维度:
///   1) Hash  — 驱动文件 MD5/SHA1/SHA256 任一命中
///   2) Cert  — 驱动签名者证书 Subject 前缀命中(大小写不敏感)
/// 命中即视为"可信、不应被附着监听"。
/// </summary>
public sealed class AttachWhitelist
{
    public HashSet<string> HashMd5 { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> HashSha1 { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> HashSha256 { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>证书 Subject 前缀(大小写不敏感)。</summary>
    public List<string> CertSubjects { get; } = new();

    /// <summary>
    /// 判断给定驱动是否命中白名单。
    /// certs:驱动验签得到的所有签名者;filePath:驱动磁盘路径(用于 hash 判定,内存驻留驱动无文件则跳过 hash)。
    /// </summary>
    public bool IsWhitelisted(string filePath, List<SignerInfo>? certs)
    {
        // 1) 证书维度:任一签名者 Subject 前缀命中
        if (certs != null)
        {
            foreach (var s in certs)
            {
                if (string.IsNullOrEmpty(s.Subject)) continue;
                foreach (var prefix in CertSubjects)
                {
                    if (s.Subject.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }

        // 2) 哈希维度:仅对磁盘存在的文件计算
        if (!string.IsNullOrEmpty(filePath) && File.Exists(filePath))
        {
            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                string md5 = Convert.ToHexString(MD5.HashData(data)).ToLowerInvariant();
                string sha1 = Convert.ToHexString(SHA1.HashData(data)).ToLowerInvariant();
                string sha256 = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
                if (HashMd5.Contains(md5) || HashSha1.Contains(sha1) || HashSha256.Contains(sha256))
                    return true;
            }
            catch
            {
                // 读不到文件不阻断,交给分类逻辑处理
            }
        }

        return false;
    }
}

/// <summary>
/// 服务端下发的策略包:危险内核函数列表(替换内置默认) + 附着白名单。
/// </summary>
public sealed class PolicyBundle
{
    public List<string> KernelFuncs { get; set; } = new();
    public AttachWhitelist Whitelist { get; set; } = new();
}

/// <summary>
/// 从服务端拉取客户端策略(无需鉴权端点 /api/client/policies)。
/// 失败返回 null,调用方应回退到内置默认策略。
/// </summary>
public static class PolicySync
{
    public static async Task<PolicyBundle?> FetchAsync(string serverUrl, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serverUrl)) return null;

        var url = serverUrl.TrimEnd('/') + "/api/client/policies";
        try
        {
            using var http = CertPinning.CreatePinnedClient(timeout: TimeSpan.FromSeconds(15));
            using var resp = await http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[Policy] 拉取服务端策略失败 HTTP {(int)resp.StatusCode}");
                return null;
            }

            var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return Parse(json);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Policy] 拉取服务端策略异常: {ex}");
            return null;
        }
    }

    private static PolicyBundle? Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var bundle = new PolicyBundle();

        // 危险内核函数列表
        if (root.TryGetProperty("kernel_funcs", out var kf) && kf.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in kf.EnumerateArray())
            {
                if (item.TryGetProperty("func_name", out var fn) && fn.ValueKind == JsonValueKind.String)
                {
                    var name = fn.GetString()!.Trim();
                    if (name.Length > 0) bundle.KernelFuncs.Add(name);
                }
            }
        }

        // 附着白名单
        if (root.TryGetProperty("whitelist", out var wl) && wl.ValueKind == JsonValueKind.Object)
        {
            if (wl.TryGetProperty("hashes", out var hashes) && hashes.ValueKind == JsonValueKind.Object)
            {
                ReadStringArray(hashes, "md5", bundle.Whitelist.HashMd5);
                ReadStringArray(hashes, "sha1", bundle.Whitelist.HashSha1);
                ReadStringArray(hashes, "sha256", bundle.Whitelist.HashSha256);
            }
            if (wl.TryGetProperty("certs", out var certs) && certs.ValueKind == JsonValueKind.Object)
            {
                // 证书白名单当前按 Subject 前缀匹配(大小写不敏感)。
                // 服务端同时下发 thumbprints_sha256,但 UserService 验签的 SignerInfo 暂未携带指纹,
                // 故此处仅取 subjects;后续若扩展 SignerInfo 指纹可再加精确匹配。
                ReadStringArray(certs, "subjects", bundle.Whitelist.CertSubjects);
            }
        }

        return bundle;
    }

    private static void ReadStringArray(JsonElement obj, string prop, ICollection<string>? target)
    {
        if (target == null) return;
        if (!obj.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) continue;
            var v = item.GetString()!;
            if (v.Length == 0) continue;
            target.Add(v);
        }
    }
}
