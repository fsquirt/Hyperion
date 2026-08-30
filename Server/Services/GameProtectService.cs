using System.Text.Json;

namespace Hyperion.Server.Services;

/// <summary>
/// 游戏进程保护能力策略服务。
///
/// 管理 UserService 对游戏进程施加的五道保护(持久化到 Data/game_protect_settings.json):
///   HandleDowngrade     — 句柄降级保护(Ob 回调,剥夺外部高危进程/线程句柄权限)
///   ImageLoadMonitor    — ImageLoad 监控(用户态 DLL 加载事件经 ETW 回传做签名校验)
///   ThreadAntiDebug     — 新线程反调试(新建线程 ThreadHideFromDebugger,远程注入线程由内核强杀)
///   HideExistingThreads — 已有线程反调试(枚举现有全部线程执行 ThreadHideFromDebugger)
///   DropHandles         — 丢弃其他进程握有的指向游戏进程的高危句柄(VM_READ/WRITE/OPERATION)
///
/// 服务端默认仅启用 句柄降级 与 丢弃高危句柄(其余三项开销/兼容性代价较大,按需开启)。
/// 经 /api/client/policies 的 protect 字段下发给 UserService。
/// </summary>
public sealed class GameProtectService
{
    private readonly ILogger<GameProtectService> _logger;
    private readonly object _lock = new();

    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "game_protect_settings.json");

    private bool _handleDowngrade = true;
    private bool _imageLoadMonitor;
    private bool _threadAntiDebug;
    private bool _hideExistingThreads;
    private bool _dropHandles = true;

    public GameProtectService(ILogger<GameProtectService> logger)
    {
        _logger = logger;
        LoadSetting();
    }

    // ═══════════════════════════════════════════════════════════════
    //  开关
    // ═══════════════════════════════════════════════════════════════

    public bool HandleDowngrade { get { lock (_lock) return _handleDowngrade; } }
    public bool ImageLoadMonitor { get { lock (_lock) return _imageLoadMonitor; } }
    public bool ThreadAntiDebug { get { lock (_lock) return _threadAntiDebug; } }
    public bool HideExistingThreads { get { lock (_lock) return _hideExistingThreads; } }
    public bool DropHandles { get { lock (_lock) return _dropHandles; } }

    public void Set(bool handleDowngrade, bool imageLoadMonitor, bool threadAntiDebug,
                    bool hideExistingThreads, bool dropHandles)
    {
        lock (_lock)
        {
            _handleDowngrade = handleDowngrade;
            _imageLoadMonitor = imageLoadMonitor;
            _threadAntiDebug = threadAntiDebug;
            _hideExistingThreads = hideExistingThreads;
            _dropHandles = dropHandles;
            PersistSettingUnsafe();
        }
        _logger.LogInformation(
            "[Protect] 策略更新: handle_downgrade={HandleDowngrade}, image_load_monitor={ImageLoadMonitor}, " +
            "thread_anti_debug={ThreadAntiDebug}, hide_existing_threads={HideExistingThreads}, drop_handles={DropHandles}",
            handleDowngrade, imageLoadMonitor, threadAntiDebug, hideExistingThreads, dropHandles);
    }

    private void LoadSetting()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return;   // 不存在则保持代码内默认值
            using var doc = JsonDocument.Parse(File.ReadAllText(SettingsPath));
            var root = doc.RootElement;
            _handleDowngrade = ReadBool(root, "handle_downgrade", _handleDowngrade);
            _imageLoadMonitor = ReadBool(root, "image_load_monitor", _imageLoadMonitor);
            _threadAntiDebug = ReadBool(root, "thread_anti_debug", _threadAntiDebug);
            _hideExistingThreads = ReadBool(root, "hide_existing_threads", _hideExistingThreads);
            _dropHandles = ReadBool(root, "drop_handles", _dropHandles);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Protect] 读取设置文件失败,回退默认值(仅句柄降级 + 丢弃高危句柄)");
            _handleDowngrade = true;
            _imageLoadMonitor = false;
            _threadAntiDebug = false;
            _hideExistingThreads = false;
            _dropHandles = true;
        }
    }

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

    private void PersistSettingUnsafe()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(new
            {
                handle_downgrade = _handleDowngrade,
                image_load_monitor = _imageLoadMonitor,
                thread_anti_debug = _threadAntiDebug,
                hide_existing_threads = _hideExistingThreads,
                drop_handles = _dropHandles,
                updated_at = DateTime.UtcNow.ToString("o"),
            });
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Protect] 写入设置文件失败");
        }
    }
}
