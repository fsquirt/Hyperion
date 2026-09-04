using System.Text.Json;

namespace Hyperion.Server.Services;

/// <summary>
/// 游戏启动权限策略服务。
///
/// 管理 UserService 启动游戏进程时使用的权限模式，设置持久化到 Data/launch_settings.json:
///   Inherit  — 继承管理员权限:直接 CreateProcess,游戏进程沿用 UserService 自身的提升令牌
///   Explorer — 使用 explorer 权限:以会话内 explorer.exe 为父进程创建,
///              系统按父进程令牌降权,游戏以标准用户令牌运行
///
/// 默认 Explorer，即最小权限。经 /api/client/policies 的 launch 字段下发给 UserService。
/// </summary>
public sealed class LaunchPrivilegeService
{
    /// <summary>继承管理员权限。</summary>
    public const string ModeInherit = "inherit";

    /// <summary>使用 explorer 权限，令牌为标准用户令牌。</summary>
    public const string ModeExplorer = "explorer";

    private readonly ILogger<LaunchPrivilegeService> _logger;
    private readonly object _lock = new();

    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "launch_settings.json");

    private string _mode = ModeExplorer;

    public LaunchPrivilegeService(ILogger<LaunchPrivilegeService> logger)
    {
        _logger = logger;
        _mode = LoadSetting();
    }

    // ═══════════════════════════════════════════════════════════════
    //  当前模式
    // ═══════════════════════════════════════════════════════════════

    /// <summary>当前启动权限模式,只会是 Inherit 或 Explorer 之一。</summary>
    public string Mode { get { lock (_lock) return _mode; } }

    /// <summary>判断是否合法模式值。</summary>
    public static bool IsValidMode(string? mode) =>
        string.Equals(mode, ModeInherit, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(mode, ModeExplorer, StringComparison.OrdinalIgnoreCase);

    /// <summary>归一化模式值，非法输入回落到默认 Explorer。</summary>
    public static string NormalizeMode(string? mode)
    {
        if (string.Equals(mode, ModeInherit, StringComparison.OrdinalIgnoreCase)) return ModeInherit;
        return ModeExplorer;
    }

    /// <summary>
    /// 设置启动权限模式。传入非法值时按默认 Explorer 处理。
    /// </summary>
    public void Set(string? mode)
    {
        string normalized = NormalizeMode(mode);
        lock (_lock)
        {
            _mode = normalized;
            PersistSettingUnsafe();
        }
        _logger.LogInformation("[Launch] 策略更新: mode={Mode}", normalized);
    }

    private string LoadSetting()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return ModeExplorer;
            using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = doc.RootElement;
            if (root.TryGetProperty("mode", out var m) && m.ValueKind == JsonValueKind.String)
                return NormalizeMode(m.GetString());
            return ModeExplorer;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Launch] 读取设置文件失败,回退默认 explorer");
            return ModeExplorer;
        }
    }

    private void PersistSettingUnsafe()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(new
            {
                mode = _mode,
                updated_at = DateTime.UtcNow.ToString("o"),
            });
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Launch] 写入设置文件失败");
        }
    }
}
