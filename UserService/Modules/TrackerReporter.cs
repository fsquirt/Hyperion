using System.Text.Json;
using Hyperion.Tracker.EtwTracker;
using Hyperion.Tracker.Services;
using Hyperion.Tracker.WinEventTracker;
using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 运行时检测上报器：把 Tracker 源（Windows 事件 + ETW 事件）与各类取证产物
/// （会话策略 / IOCTL 统计 / 附着设备 / 取证文件 / 进程树快照）实时上报到 Server。
/// 内部复用 Tracker 项目的 ServerConnection 与事件监听管理器。
/// </summary>
public sealed class TrackerReporter : IDisposable
{
    private readonly ServerConnection _conn;
    private readonly WinEventTrackerManager _win;
    private readonly EtwTrackerManager _etw;
    private bool _started;

    public TrackerReporter(string serverBase)
    {
        _conn = new ServerConnection(serverBase);
        _win = new WinEventTrackerManager();
        _etw = new EtwTrackerManager();
    }

    public string? SessionId => _conn.SessionId;

    /// <summary>启动：创建会话（携带采纳的策略）→ 开始订阅 Windows 事件 / ETW 事件。</summary>
    public bool Start(ServerConnection.PolicyInfoDto? policy)
    {
        bool ok = _conn.StartSessionAsync(policy).GetAwaiter().GetResult();
        if (!ok) return false;

        _win.OnEvent += OnWinEvent;
        _etw.OnEvent += OnEtwEvent;
        _win.Start();
        _etw.Start();
        _started = true;
        return true;
    }

    // ── 事件订阅（运行时检测引擎产生的 Windows 事件 / ETW 事件）─────────────

    private void OnWinEvent(MonitoredEvent evt)
    {
        // CodeIntegrity：未签名驱动被阻止 → 高危
        if (evt.Channel.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase))
        {
            _conn.PostEvent(new ServerConnection.TrackedEventDto
            {
                type = "winevent",
                timestamp = evt.TimeCreated.ToString("o"),
                level = "HIGH",
                source = evt.Channel,
                title = "代码完整性违规",
                detail = evt.Description,
                xml = evt.RawXml,
            });
            return;
        }

        // Defender 恶意软件 → 高危
        if (evt.Channel.Contains("Defender", StringComparison.OrdinalIgnoreCase))
        {
            _conn.PostEvent(new ServerConnection.TrackedEventDto
            {
                type = "winevent",
                timestamp = evt.TimeCreated.ToString("o"),
                level = "HIGH",
                source = evt.Channel,
                title = "Defender 告警",
                detail = evt.Description,
                xml = evt.RawXml,
            });
            return;
        }

        var level = evt.Level switch
        {
            1 => "CRIT",
            2 => "ERR ",
            3 => "WARN",
            _ => "INFO",
        };
        _conn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "winevent",
            timestamp = evt.TimeCreated.ToString("o"),
            level = level.Trim(),
            source = evt.Channel,
            title = $"ID={evt.EventId} ({evt.Provider})",
            detail = evt.Description,
            xml = evt.RawXml,
        });
    }

    private void OnEtwEvent(EtwEvent evt)
    {
        if (evt.EventName is "DriverLoad" or "DriverInstall" or "DriverInstallComplete")
        {
            _conn.PostEvent(new ServerConnection.TrackedEventDto
            {
                type = "etw",
                timestamp = evt.TimeCreated.ToString("o"),
                level = "HIGH",
                source = evt.ProviderName,
                title = $"⚠ {evt.EventName}",
                detail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                         string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}")),
            });
            return;
        }

        _conn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "etw",
            timestamp = evt.TimeCreated.ToString("o"),
            level = "INFO",
            source = evt.ProviderName,
            title = evt.EventName,
            detail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                     string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}")),
        });
    }

    // ── 产物上报（采集即上传，非阻塞）────────────────────────────────────

    public void ReportPolicy(ServerConnection.PolicyInfoDto policy)
    {
        _conn.PostJson("/api/tracker/policy", new
        {
            sessionId = _conn.SessionId,
            policy = policy,
        });
    }

    public void ReportIoctlStats(Dictionary<string, ulong> counts, List<string> modules)
    {
        _conn.PostJson("/api/tracker/ioctl-stats", new
        {
            sessionId = _conn.SessionId,
            stats = new { IoctlCounts = counts, Modules = modules },
        });
    }

    public void ReportDevices(IReadOnlyDictionary<uint, KernelServiceIo.AttachEntry> attachments)
    {
        var devices = attachments.Select(e => new
        {
            attachId = e.Value.AttachId,
            deviceName = e.Value.TargetPath,
            targetPath = e.Value.TargetPath,
        }).ToList();
        _conn.PostJson("/api/tracker/devices", new
        {
            sessionId = _conn.SessionId,
            devices = devices,
        });
    }

    public void ReportFile(string path, string kind)
    {
        var fi = new FileInfo(path);
        _conn.PostJson("/api/tracker/files", new
        {
            sessionId = _conn.SessionId,
            files = new[]
            {
                new
                {
                    kind = kind,
                    name = fi.Name,
                    path = path,
                    size = fi.Exists ? fi.Length : 0L,
                    time = fi.Exists ? fi.CreationTimeUtc.ToString("o") : DateTime.UtcNow.ToString("o"),
                }
            },
        });
    }

    public void ReportSnapshot(string rawJson)
    {
        _conn.PostJson("/api/tracker/snapshots", new
        {
            sessionId = _conn.SessionId,
            snapshots = new[] { rawJson },
        });
    }

    public void Stop()
    {
        if (!_started) return;
        _started = false;
        try { _win.Dispose(); } catch { }
        try { _etw.Dispose(); } catch { }
        try { _conn.EndSessionAsync().GetAwaiter().GetResult(); } catch { }
    }

    public void Dispose() => Stop();
}
