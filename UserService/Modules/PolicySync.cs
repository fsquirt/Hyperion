using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using Hyperion.UserService.Comm;
using System.Text;
using System.Text.Json;
using System.Threading;
using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 附着白名单,来自服务端策略。两个维度:
///   1) Hash  — 驱动文件 MD5/SHA1/SHA256 任一命中
///   2) Cert  — 驱动签名者证书 Subject 前缀命中,大小写不敏感
/// 命中即视为"可信、不应被附着监听"。
/// </summary>
public sealed class AttachWhitelist
{
    public HashSet<string> HashMd5 { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> HashSha1 { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> HashSha256 { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>证书 Subject 前缀,大小写不敏感。</summary>
    public List<string> CertSubjects { get; } = new();

    /// <summary>
    /// 判断给定驱动是否命中白名单。
    /// certs:驱动验签得到的所有签名者;filePath:驱动磁盘路径,用于 hash 判定,内存驻留驱动无文件则跳过 hash。
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
/// 游戏进程保护能力开关。决定对游戏进程施加哪些保护,关闭的项整段跳过。
/// 默认值与服务端默认一致:仅启用句柄降级与丢弃高危句柄。
/// </summary>
public sealed class GameProtectPolicy
{
    /// <summary>句柄降级保护:通过 Ob 回调剥夺外部进程持有的高危进程与线程句柄权限。</summary>
    public bool HandleDowngrade { get; set; } = true;

    /// <summary>ImageLoad 监控:用户态 DLL 加载事件经 ETW 回传做签名校验。</summary>
    public bool ImageLoadMonitor { get; set; }

    /// <summary>新线程反调试:新建线程时设置 ThreadHideFromDebugger,远程注入线程由内核强杀。</summary>
    public bool ThreadAntiDebug { get; set; }

    /// <summary>已有线程反调试:枚举现有全部线程执行 ThreadHideFromDebugger。</summary>
    public bool HideExistingThreads { get; set; }

    /// <summary>丢弃其他进程握有的指向游戏进程的高危句柄,权限为 VM_READ/WRITE/OPERATION。</summary>
    public bool DropHandles { get; set; } = true;
}

/// <summary>
/// 游戏启动权限模式。决定 UserService 用哪个令牌创建游戏进程。
/// </summary>
public enum LaunchMode
{
    /// <summary>继承管理员权限:直接 CreateProcess,沿用 UserService 自身的提升令牌。</summary>
    Inherit,

    /// <summary>使用 explorer 权限:以会话内 explorer.exe 为父进程创建,系统按父进程令牌降权。</summary>
    Explorer,
}

/// <summary>
/// 服务端下发的策略包:危险内核函数列表,用于替换内置默认,外加附着白名单、SiPolicy 开关与启动权限模式。
/// </summary>
public sealed class PolicyBundle
{
    public List<string> KernelFuncs { get; set; } = new();
    public AttachWhitelist Whitelist { get; set; } = new();

    /// <summary>游戏启动前是否需要更新 SiPolicy.p7b,免重启刷新驱动阻止策略。</summary>
    public bool SiPolicyEnabled { get; set; }

    /// <summary>是否通过会话事件上报模拟键鼠事件。</summary>
    public bool MockInputReport { get; set; }

    /// <summary>是否拦截即吞掉模拟键鼠事件。与 Report 均关闭时客户端不挂全局低级钩子。</summary>
    public bool MockInputBlock { get; set; }

    /// <summary>
    /// 游戏启动权限模式。服务端未下发该字段时默认 Explorer,即最小权限。
    /// </summary>
    public LaunchMode Launch { get; set; } = LaunchMode.Explorer;

    /// <summary>
    /// 游戏进程保护能力开关。服务端未下发该字段时按默认值,仅句柄降级加丢弃高危句柄。
    /// </summary>
    public GameProtectPolicy Protect { get; set; } = new();
}

/// <summary>
/// 从服务端拉取客户端策略,使用无需鉴权的端点 /api/client/policies。
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
                // 证书白名单当前按 Subject 前缀匹配,大小写不敏感。
                // 服务端同时下发 thumbprints_sha256,但 UserService 验签的 SignerInfo 暂未携带指纹,
                // 故此处仅取 subjects;后续若扩展 SignerInfo 指纹可再加精确匹配。
                ReadStringArray(certs, "subjects", bundle.Whitelist.CertSubjects);
            }
        }

        // SiPolicy.p7b 更新开关
        if (root.TryGetProperty("sipolicy", out var sip) && sip.ValueKind == JsonValueKind.Object)
        {
            if (sip.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True)
                bundle.SiPolicyEnabled = true;
        }

        // 模拟键鼠检测开关:上报与拦截
        if (root.TryGetProperty("mock_input", out var mi) && mi.ValueKind == JsonValueKind.Object)
        {
            if (mi.TryGetProperty("report", out var mir) && mir.ValueKind == JsonValueKind.True)
                bundle.MockInputReport = true;
            if (mi.TryGetProperty("block", out var mib) && mib.ValueKind == JsonValueKind.True)
                bundle.MockInputBlock = true;
        }

        // 游戏启动权限模式:inherit 或 explorer,缺省或非法值按 explorer 处理
        if (root.TryGetProperty("launch", out var lc) && lc.ValueKind == JsonValueKind.Object)
        {
            if (lc.TryGetProperty("mode", out var lm) && lm.ValueKind == JsonValueKind.String)
            {
                var v = lm.GetString()!.Trim();
                if (string.Equals(v, "inherit", StringComparison.OrdinalIgnoreCase))
                    bundle.Launch = LaunchMode.Inherit;
            }
        }

        // 游戏进程保护能力开关,缺省字段沿用 GameProtectPolicy 的默认值
        if (root.TryGetProperty("protect", out var pt) && pt.ValueKind == JsonValueKind.Object)
        {
            bundle.Protect = new GameProtectPolicy
            {
                HandleDowngrade = ReadBool(pt, "handle_downgrade", true),
                ImageLoadMonitor = ReadBool(pt, "image_load_monitor", false),
                ThreadAntiDebug = ReadBool(pt, "thread_anti_debug", false),
                HideExistingThreads = ReadBool(pt, "hide_existing_threads", false),
                DropHandles = ReadBool(pt, "drop_handles", true),
            };
        }

        return bundle;
    }

    /// <summary>读取布尔开关,字段缺失或类型不对时返回 fallback。</summary>
    private static bool ReadBool(JsonElement obj, string prop, bool fallback)
    {
        if (!obj.TryGetProperty(prop, out var v)) return fallback;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => fallback,
        };
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
