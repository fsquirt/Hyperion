using System.Text.Json;

namespace Hyperion.Server.Services;

/// <summary>
/// SiPolicy.p7b 策略服务。
///
/// 职责:
///   1. 管理"游戏启动前是否更新 SiPolicy.p7b"开关(持久化到 Data/sipolicy_settings.json)
///   2. 定位微软 VulnerableDriverBlockList 压缩包解压出的 SiPolicy_Enforced_LegacyFormat.p7b,
///      供 UserService 下载后放入 %windir%\System32\CodeIntegrity 并 NtSetSystemInformation 免重启刷新。
///
/// p7b 文件本身由 BlocklistService.UpdateMsftAsync 下载 zip 解压产生(bin 目录 → 开发源码目录递归查找),
/// 无需在此重复联网下载。
/// </summary>
public sealed class SiPolicyService
{
    private readonly ILogger<SiPolicyService> _logger;
    private readonly object _lock = new();

    // ── 开关持久化文件 ────────────────────────────────────────────
    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "sipolicy_settings.json");

    private bool _enabled;

    // ── p7b 查找目录(与 BlocklistService 的 MSFT zip 解压目录一致) ──
    private static readonly string MsftBlocklistDir =
        Path.Combine(AppContext.BaseDirectory, "VulnerableDriverBlockList");

    // 开发回退:bin\Debug\net10.0 → 项目根目录(dotnet run 时源码数据文件在此)
    private static readonly string DevMsftBlocklistDir =
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "VulnerableDriverBlockList"));

    public SiPolicyService(ILogger<SiPolicyService> logger)
    {
        _logger = logger;
        _enabled = LoadSetting();
    }

    // ═══════════════════════════════════════════════════════════════
    //  开关
    // ═══════════════════════════════════════════════════════════════

    public bool Enabled { get { lock (_lock) return _enabled; } }

    public void SetEnabled(bool enabled)
    {
        lock (_lock)
        {
            _enabled = enabled;
            PersistSettingUnsafe();
        }
        _logger.LogInformation("[SiPolicy] 更新开关设置为 {Enabled}", enabled);
    }

    private bool LoadSetting()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return false;
            using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            return doc.RootElement.TryGetProperty("enabled", out var e) && e.ValueKind == JsonValueKind.True;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[SiPolicy] 读取设置文件失败,回退默认关闭");
            return false;
        }
    }

    private void PersistSettingUnsafe()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(new
            {
                enabled = _enabled,
                updated_at = DateTime.UtcNow.ToString("o"),
            });
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[SiPolicy] 写入设置文件失败");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  p7b 文件定位与读取
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 查找 SiPolicy_Enforced_LegacyFormat.p7b:递归搜索 bin 解压目录与开发源码目录
    /// (zip 内部有嵌套目录,故用 AllDirectories)。
    /// </summary>
    private static string? FindP7b()
    {
        foreach (var dir in new[] { MsftBlocklistDir, DevMsftBlocklistDir })
        {
            if (!Directory.Exists(dir)) continue;
            var f = Directory.GetFiles(dir, "SiPolicy_Enforced_LegacyFormat.p7b", SearchOption.AllDirectories);
            if (f.Length > 0) return f[0];
        }
        return null;
    }

    /// <summary>读取 p7b 文件内容;文件不存在返回 null。</summary>
    public byte[]? ReadP7b()
    {
        var path = FindP7b();
        if (path == null) return null;
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[SiPolicy] 读取 p7b 失败: {Path}", path);
            return null;
        }
    }

    /// <summary>返回 p7b 文件状态(供管理界面展示)。</summary>
    public object GetFileInfo()
    {
        var path = FindP7b();
        if (path == null)
            return new { exists = false, size = 0L, last_modified = "" };

        var fi = new FileInfo(path);
        return new
        {
            exists = true,
            size = fi.Length,
            last_modified = fi.LastWriteTimeUtc.ToString("o"),
        };
    }
}
