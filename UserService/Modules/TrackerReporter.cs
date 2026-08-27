using System.Collections.Generic;
using System.Text.Json;
using Hyperion.UserService.Comm;
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
    private bool _released;

    public TrackerReporter(string serverBase)
    {
        _conn = new ServerConnection(serverBase);
        _win = new WinEventTrackerManager();
        _etw = new EtwTrackerManager();
    }

    public string? SessionId => _conn.SessionId;

    /// <summary>启动：创建会话（携带采纳的策略）→ 开始订阅 Windows 事件 / ETW 事件。失败时释放连接，避免后台循环泄漏。</summary>
    public bool Start(ServerConnection.PolicyInfoDto? policy)
    {
        if (_released) return false;

        bool ok = _conn.StartSessionAsync(policy).GetAwaiter().GetResult();
        if (!ok)
        {
            ReleaseConnection();
            return false;
        }

        _win.OnEvent += OnWinEvent;
        _etw.OnEvent += OnEtwEvent;
        _win.Start();
        _etw.Start();
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
        string sessionId = _conn.SessionId ?? "";
        string name = fi.Name;
        string time = fi.Exists ? fi.CreationTimeUtc.ToString("o") : DateTime.UtcNow.ToString("o");

        // 优先上传文件内容（multipart），服务端落地存储并提供下载；
        // 文件读取/上传失败时退化为仅上报元数据，保证文件列表不丢失。
        if (fi.Exists && fi.Length > 0)
        {
            _conn.UploadFile("/api/tracker/files", new Dictionary<string, string>
            {
                ["sessionId"] = sessionId,
                ["kind"] = kind,
                ["name"] = name,
                ["path"] = path,
                ["time"] = time,
            }, path);
            return;
        }

        _conn.PostJson("/api/tracker/files", new
        {
            sessionId = sessionId,
            files = new[]
            {
                new
                {
                    kind = kind,
                    name = name,
                    path = path,
                    size = fi.Exists ? fi.Length : 0L,
                    time = time,
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

    /// <summary>
    /// 上报一条运行时 HIGH 事件(未签名 ImageLoad / 远程线程注入预警)。
    /// payload 需含 { imagePath | creatorPid, ... } 等字段,由调用方组装。
    /// 走 /api/tracker/events 端点,与 Windows/ETW 事件同通道。
    /// </summary>
    public void ReportHighRuntimeEvent(object payload)
    {
        _conn.PostJson("/api/tracker/events", new
        {
            sessionId = _conn.SessionId,
            type = "runtime",
            level = "HIGH",
            timestamp = DateTime.UtcNow.ToString("o"),
            data = payload,
        });
    }

    /// <summary>上报未签名 ImageLoad 取证事件(HIGH)。</summary>
    public void ReportImageLoadUnsigned(object data)
    {
        ReportHighRuntimeEvent(new
        {
            kind = "unsign_imageload",
            data = data,
        });
    }

    /// <summary>上报远程线程注入预警(HIGH)。</summary>
    public void ReportRemoteThreadInjection(object data)
    {
        ReportHighRuntimeEvent(new
        {
            kind = "remote_thread_injection",
            data = data,
        });
    }

    /// <summary>
    /// 停止（顺序敏感，避免结束会话时序丢数据）：
    /// 1. 停止采集源（不再产生新事件/产物）
    /// 2. FlushAsync 排空事件/JSON/上传队列（限时，未发完的项目被统计输出）
    /// 3. EndSessionAsync 结束会话（此时 token 仍在，服务端正常收尾）
    /// 4. 释放 ServerConnection（含后台循环与 HttpClient）
    /// 幂等：只完整释放一次；释放后再次 Start/Stop 均不动作。
    /// </summary>
    public void Stop()
    {
        if (_released) return;

        // 1. 停止采集源
        try { _win.Dispose(); } catch { }
        try { _etw.Dispose(); } catch { }

        // 2. 排空发送队列（事件/JSON/上传）
        try { _conn.FlushAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult(); } catch { }

        // 3. 结束会话
        try { _conn.EndSessionAsync().GetAwaiter().GetResult(); } catch { }

        // 4. 释放连接
        ReleaseConnection();
    }

    public void Dispose() => Stop();

    /// <summary>释放 ServerConnection（幂等）。Start 失败与 Stop 共用此路径。</summary>
    private void ReleaseConnection()
    {
        if (_released) return;
        _released = true;
        try { _conn.Dispose(); } catch { }
    }
}
