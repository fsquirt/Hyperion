using System.Text.Json;

namespace Hyperion.Server.Services;

/// <summary>
/// 模拟键鼠策略服务。
///
/// 管理两个开关，设置持久化到 Data/mock_input_settings.json:
///   Report — 客户端是否需要通过会话事件上报模拟键盘鼠标事件，经全局低级钩子检测 SendInput 等注入
///   Block  — 客户端是否需要拦截并吞掉模拟键盘鼠标事件
///
/// 两者均关闭时客户端不安装全局低级钩子。
/// </summary>
public sealed class MockInputService
{
    private readonly ILogger<MockInputService> _logger;
    private readonly object _lock = new();

    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "mock_input_settings.json");

    private bool _report;
    private bool _block;

    public MockInputService(ILogger<MockInputService> logger)
    {
        _logger = logger;
        (_report, _block) = LoadSetting();
    }

    // ═══════════════════════════════════════════════════════════════
    //  开关
    // ═══════════════════════════════════════════════════════════════

    public bool Report { get { lock (_lock) return _report; } }
    public bool Block { get { lock (_lock) return _block; } }

    public void Set(bool report, bool block)
    {
        lock (_lock)
        {
            _report = report;
            _block = block;
            PersistSettingUnsafe();
        }
        _logger.LogInformation("[MockInput] 策略更新: report={Report}, block={Block}", report, block);
    }

    private (bool report, bool block) LoadSetting()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return (false, false);
            using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = doc.RootElement;
            bool report = root.TryGetProperty("report", out var r) && r.ValueKind == JsonValueKind.True;
            bool block = root.TryGetProperty("block", out var b) && b.ValueKind == JsonValueKind.True;
            return (report, block);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[MockInput] 读取设置文件失败,回退默认全关");
            return (false, false);
        }
    }

    private void PersistSettingUnsafe()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(new
            {
                report = _report,
                block = _block,
                updated_at = DateTime.UtcNow.ToString("o"),
            });
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[MockInput] 写入设置文件失败");
        }
    }
}
