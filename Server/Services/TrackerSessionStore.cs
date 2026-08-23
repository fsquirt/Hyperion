using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using Microsoft.AspNetCore.Http;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hyperion.Server.Services;

/// <summary>
/// Tracker 会话存储。
/// 活跃会话在内存中；结束后持久化到 SQLite。
/// 查询时合并内存（活跃）+ 数据库（已结束）。
/// </summary>
public sealed class TrackerSessionStore
{
    private readonly ConcurrentDictionary<string, LiveSession> _sessions = new();
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly ILogger<TrackerSessionStore> _logger;

    /// <summary>上传取证文件的落地根目录（TrackerFiles/{sessionId}/{storedName}）。</summary>
    private static readonly string FilesRoot = Path.Combine(AppContext.BaseDirectory, "TrackerFiles");

    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromMinutes(2);

    // ═══════════════════════════════════════════════════════════════
    //  配额与限制（宽松默认：兼容 minidump / 大模块取证场景）
    // ═══════════════════════════════════════════════════════════════

    /// <summary>单文件大小上限：512MB。</summary>
    public const long MaxFileSizeBytes = 512L * 1024 * 1024;
    /// <summary>单个会话取证文件总大小上限：4GB。</summary>
    public const long MaxFilesPerSessionBytes = 4L * 1024 * 1024 * 1024;
    /// <summary>全局取证文件磁盘配额：50GB。</summary>
    public const long MaxGlobalFilesBytes = 50L * 1024 * 1024 * 1024;
    /// <summary>单个会话事件条数上限。</summary>
    public const int MaxEventsPerSession = 200_000;
    /// <summary>事件单字段（detail/xml）长度上限：64KB。</summary>
    public const int MaxEventFieldLength = 64 * 1024;
    /// <summary>单条快照（原始 JSON）大小上限：2MB。</summary>
    public const int MaxSnapshotBytes = 2 * 1024 * 1024;

    /// <summary>上传配额串行门：检查与写入必须原子，消除并发超额窗口。</summary>
    private readonly object _uploadGate = new();
    /// <summary>全局已落地字节数（惰性首扫 + 定期校准，软配额，避免每次上传递归扫目录）。</summary>
    private long _globalUploadedBytes;
    private bool _globalScanned;
    private DateTime _lastGlobalRescan = DateTime.MinValue;
    /// <summary>
    /// 各 session 已写盘字节数（_uploadGate 保护）。
    /// 与 session.Files 的 AppendFiles 解耦：AppendFiles 在端点写盘后才追加条目，
    /// 若配额检查依赖 session.Files，同 session 并发上传会读到旧值突破上限。
    /// </summary>
    private readonly Dictionary<string, long> _sessionWrittenBytes = new();

    public TrackerSessionStore(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<TrackerSessionStore> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        new Timer(Cleanup, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    /// <summary>创建会话：生成 12 位小写十六进制 sessionId + 32 字节随机 sessionToken。token 为后续写接口的短期凭据。</summary>
    public TrackerSessionStartResult CreateSession(string machineName, int pid, PolicyInfo? policy = null)
    {
        var id = Guid.NewGuid().ToString("N")[..12];
        var token = RandomNumberGenerator.GetHexString(32, lowercase: true);
        var now = DateTime.UtcNow.ToString("o");

        var session = new LiveSession
        {
            Id = id,
            Token = token,
            MachineName = machineName,
            Pid = pid,
            StartedAt = now,
            LastHeartbeat = now,
            Status = "active",
            Policy = policy,
        };

        _sessions[id] = session;
        _logger.LogInformation("[Tracker] 会话创建: {Id} ({Machine})", id, machineName);
        return new TrackerSessionStartResult
        {
            Id = id,
            Token = token,
            MachineName = machineName,
        };
    }

    /// <summary>
    /// 校验会话写权限：session 存在、处于 active 且提供的 token 与创建时下发的一致。
    /// 所有 /api/tracker/* 写接口都必须先通过此校验。
    /// </summary>
    public bool TryAuthorizeSession(string sessionId, string token)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return false;
        if (session.Status != "active") return false;
        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(session.Token)) return false;
        // 服务端本地比较，无远程时序面；字符串比较即可
        return string.Equals(session.Token, token, StringComparison.Ordinal);
    }

    /// <summary>判断 session 是否存在且处于 active（供非写场景使用）。</summary>
    public bool IsActiveSession(string sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) && session.Status == "active";
    }

    public bool Heartbeat(string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return false;
        if (session.Status != "active") return false;
        session.LastHeartbeat = DateTime.UtcNow.ToString("o");
        return true;
    }

    public bool EndSession(string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return false;
        if (session.Status != "active")
        {
            _sessions[sessionId] = session;
            return true;
        }

        session.Status = "finished";
        session.EndedAt = DateTime.UtcNow.ToString("o");
        _logger.LogInformation("[Tracker] 会话结束: {Id} ({EventCount} 事件)", sessionId, session.Events.Count);

        // 异步持久化到数据库
        _ = PersistSessionAsync(session);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════
    //  策略 / 产物追加
    // ═══════════════════════════════════════════════════════════════

    public void SetPolicy(string sessionId, PolicyInfo policy)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return;
        session.Policy = policy;
    }

    public int AppendEvents(string sessionId, List<TrackedEvent> events)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return 0;
        if (session.Status != "active") return 0;

        lock (session.Lock)
        {
            if (session.Events.Count >= MaxEventsPerSession) return 0;

            var room = MaxEventsPerSession - session.Events.Count;
            var accepted = events.Take(room)
                .Select(e => e with
                {
                    Title = Truncate(e.Title, 512),
                    Detail = Truncate(e.Detail, MaxEventFieldLength),
                    RawXml = Truncate(e.RawXml, MaxEventFieldLength),
                })
                .ToList();

            session.Events.AddRange(accepted);
            return accepted.Count;
        }
    }

    public void SetIoctlStats(string sessionId, IoctlStats stats)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return;
        lock (session.Lock) { session.IoctlStats = stats; }
    }

    public void SetDevices(string sessionId, List<AttachedDevice> devices)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return;
        lock (session.Lock) { session.Devices = devices; }
    }

    public void AppendFiles(string sessionId, List<FileEntry> files)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return;
        if (session.Status != "active") return;
        lock (session.Lock) { session.Files.AddRange(files); }
    }

    // ═══════════════════════════════════════════════════
    //  上传文件落地存储
    // ═══════════════════════════════════════════════════

    /// <summary>
    /// 把客户端上传的取证文件落到磁盘，返回服务端存储名（防穿越、带 GUID 前缀避免重名）。
    /// 前置校验：session 存在且 active、单文件/单会话/全局配额；失败返回 null。
    /// 整个"检查 + 写入 + 计数"在全局上传锁内完成，消除并发超额窗口。
    /// </summary>
    public string? SaveUploadedFile(string sessionId, IFormFile file)
    {
        // 会话必须存在且 active（未认证请求无法通过此校验）
        if (!_sessions.TryGetValue(sessionId, out var session) || session.Status != "active")
            return null;

        lock (_uploadGate)
        {
            // 配额：单文件
            if (file.Length > MaxFileSizeBytes)
            {
                _logger.LogWarning("[Tracker] 拒绝超大文件: {Size} > {Limit} (session={SessionId})",
                    file.Length, MaxFileSizeBytes, sessionId);
                return null;
            }

            // 配额：单 session 文件总大小（已写盘计数，锁内累加；不依赖 AppendFiles，
            // 消除"写盘后条目未追加"造成的并发检查窗口）
            var sessionWritten = _sessionWrittenBytes.TryGetValue(sessionId, out var written) ? written : 0;
            if (sessionWritten + file.Length > MaxFilesPerSessionBytes)
            {
                _logger.LogWarning("[Tracker] 拒绝超出会话文件配额: session={SessionId}", sessionId);
                return null;
            }

            // 配额：全局磁盘配额（内存计数，惰性首扫 + 定期校准，避免每次上传递归扫目录）
            EnsureGlobalCountFresh();
            if (_globalUploadedBytes + file.Length > MaxGlobalFilesBytes)
            {
                _logger.LogWarning("[Tracker] 拒绝超出全局磁盘配额: session={SessionId}", sessionId);
                return null;
            }

            var sessionDir = Path.Combine(FilesRoot, sessionId);
            Directory.CreateDirectory(sessionDir);

            var safeName = Path.GetFileName(file.FileName);
            safeName = string.Join("_", safeName.Split(Path.GetInvalidFileNameChars()));
            if (string.IsNullOrWhiteSpace(safeName)) safeName = "file";

            var storedName = $"{Guid.NewGuid():N}_{safeName}";
            var dest = Path.Combine(sessionDir, storedName);

            // 纵深防御：解析后的目标必须仍在 FilesRoot 内（防御 sessionId/storedName 携带路径片段）
            var rootFull = Path.GetFullPath(FilesRoot);
            var destFull = Path.GetFullPath(dest);
            if (!destFull.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                _logger.LogWarning("[Tracker] 拒绝越界写入路径: {Dest}", dest);
                return null;
            }

            using var fs = File.Create(destFull);
            file.CopyTo(fs);

            // 写盘成功才计入配额计数（AppendFiles 在端点锁外追加条目，计数在此先行）
            _globalUploadedBytes += file.Length;
            _sessionWrittenBytes[sessionId] = sessionWritten + file.Length;
            return storedName;
        }
    }

    /// <summary>
    /// 保证全局计数新鲜：首次调用扫描一次；此后每 10 分钟校准一次
    /// （会话删除等外部变化会释放配额，周期校准避免长期误拒）。
    /// </summary>
    private void EnsureGlobalCountFresh()
    {
        if (_globalScanned && DateTime.UtcNow - _lastGlobalRescan <= TimeSpan.FromMinutes(10))
            return;
        _globalUploadedBytes = GetGlobalFilesTotalSize();
        _globalScanned = true;
        _lastGlobalRescan = DateTime.UtcNow;
    }    /// <summary>统计 TrackerFiles 根目录下所有落地文件的总大小（字节）。上传为低频操作，直接扫描可接受。</summary>
    private static long GetGlobalFilesTotalSize()
    {
        if (!Directory.Exists(FilesRoot)) return 0;
        long total = 0;
        foreach (var f in Directory.EnumerateFiles(FilesRoot, "*", SearchOption.AllDirectories))
        {
            try { total += new FileInfo(f).Length; }
            catch { /* 文件被并发删除等竞态，忽略 */ }
        }
        return total;
    }

    /// <summary>截断字符串到指定字符长度上限（null 视为空串，返回非空）。</summary>
    private static string Truncate(string? value, int maxChars)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxChars) return value ?? "";
        return value[..maxChars];
    }

    /// <summary>解析已存储文件的绝对路径（已做目录穿越防护）。</summary>
    public string? GetFilePath(string sessionId, string storedName)
    {
        var sessionDir = Path.Combine(FilesRoot, sessionId);
        var full = Path.Combine(sessionDir, storedName);
        // 确保解析结果仍在 sessionDir 内（防止 storedName 携带路径字符导致穿越）
        if (!full.StartsWith(sessionDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) &&
            !full.Equals(sessionDir, StringComparison.OrdinalIgnoreCase))
            return null;
        return full;
    }

    public void AppendSnapshots(string sessionId, List<string> snapshots)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return;
        if (session.Status != "active") return;
        lock (session.Lock)
        {
            foreach (var s in snapshots)
            {
                // 单条快照按 UTF-8 字节数限长，超限丢弃并告警
                if (Encoding.UTF8.GetByteCount(s) > MaxSnapshotBytes)
                {
                    _logger.LogWarning("[Tracker] 丢弃超大快照: session={SessionId}", sessionId);
                    continue;
                }
                session.Snapshots.Add(s);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  查询（内存 + 数据库合并）
    // ═══════════════════════════════════════════════════════════════

    public async Task<List<TrackerSessionSummary>> GetSummariesAsync()
    {
        var live = _sessions.Values
            .Where(s => s.Status == "active")
            .Select(ToSummary)
            .ToList();

        var dbFinished = await LoadFinishedSummariesAsync();

        return live.Concat(dbFinished)
            .OrderByDescending(s => s.StartedAt)
            .ToList();
    }

    public async Task<TrackerSessionDetail?> GetDetailAsync(
        string sessionId, string? level = null, string? search = null)
    {
        TrackerSessionDetail? detail;

        if (_sessions.TryGetValue(sessionId, out var live))
            detail = ToDetail(live);
        else
            detail = await LoadDetailFromDbAsync(sessionId);

        if (detail is null) return null;

        // 事件过滤（仅对 Tracker 事件生效；其它产物原样展示）
        var events = detail.Events.AsEnumerable();
        if (!string.IsNullOrWhiteSpace(level))
        {
            var lvl = level.Trim().ToUpperInvariant();
            events = events.Where(e => e.Level.Equals(lvl, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search.Trim();
            events = events.Where(e =>
                (e.Title?.Contains(kw, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Detail?.Contains(kw, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Source?.Contains(kw, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (e.Type?.Contains(kw, StringComparison.OrdinalIgnoreCase) ?? false));
        }
        detail = detail with { Events = events.ToList() };
        return detail;
    }

    // ═══════════════════════════════════════════════════════════════
    //  过期清理（内存 → 数据库）
    // ═══════════════════════════════════════════════════════════════

    private void Cleanup(object? state)
    {
        var cutoff = DateTime.UtcNow - HeartbeatTimeout;
        var cutoffStr = cutoff.ToString("o");

        foreach (var (id, session) in _sessions)
        {
            if (session.Status == "active" &&
                string.Compare(session.LastHeartbeat, cutoffStr, StringComparison.Ordinal) < 0)
            {
                _sessions.TryRemove(id, out _);
                session.Status = "finished";
                session.EndedAt = DateTime.UtcNow.ToString("o");
                _logger.LogInformation("[Tracker] 会话超时结束: {Id}", id);
                _ = PersistSessionAsync(session);
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  数据库持久化
    // ═══════════════════════════════════════════════════════════════

    private async Task PersistSessionAsync(LiveSession session)
    {
        try
        {
            List<TrackedEvent> events;
            PolicyInfo? policy;
            IoctlStats? ioctlStats;
            List<AttachedDevice> devices;
            List<FileEntry> files;
            List<string> snapshots;
            lock (session.Lock)
            {
                events = [.. session.Events];
                policy = session.Policy;
                ioctlStats = session.IoctlStats;
                devices = [.. session.Devices];
                files = [.. session.Files];
                snapshots = [.. session.Snapshots];
            }

            var extra = new ExtraPayload
            {
                Policy = policy,
                IoctlStats = ioctlStats,
                Devices = devices,
                Files = files,
                Snapshots = snapshots,
            };

            await using var db = await _dbFactory.CreateDbContextAsync();
            db.TrackerSessions.Add(new TrackerSessionEntity
            {
                Id = session.Id,
                MachineName = session.MachineName,
                Pid = session.Pid,
                StartedAt = session.StartedAt,
                EndedAt = session.EndedAt ?? "",
                EventCount = events.Count,
                EventsJson = JsonSerializer.Serialize(events),
                ExtraJson = JsonSerializer.Serialize(extra),
            });
            await db.SaveChangesAsync();
            _logger.LogInformation("[Tracker] 会话已持久化: {Id} ({Count} 事件)", session.Id, events.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Tracker] 持久化失败: {Id}", session.Id);
        }
    }

    private async Task<List<TrackerSessionSummary>> LoadFinishedSummariesAsync()
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            return await db.TrackerSessions
                .OrderByDescending(e => e.StartedAt)
                .Take(200)
                .Select(e => new TrackerSessionSummary
                {
                    Id = e.Id,
                    MachineName = e.MachineName,
                    Pid = e.Pid,
                    StartedAt = e.StartedAt,
                    LastHeartbeat = e.EndedAt,
                    EndedAt = e.EndedAt,
                    Status = "finished",
                    EventCount = e.EventCount,
                })
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Tracker] 加载历史会话失败");
            return [];
        }
    }

    private async Task<TrackerSessionDetail?> LoadDetailFromDbAsync(string sessionId)
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var entity = await db.TrackerSessions.FindAsync(sessionId);
            if (entity == null) return null;

            var events = JsonSerializer.Deserialize<List<TrackedEvent>>(entity.EventsJson) ?? [];
            var extra = JsonSerializer.Deserialize<ExtraPayload>(entity.ExtraJson) ?? new ExtraPayload();

            return new TrackerSessionDetail
            {
                Id = entity.Id,
                MachineName = entity.MachineName,
                Pid = entity.Pid,
                StartedAt = entity.StartedAt,
                LastHeartbeat = entity.EndedAt,
                EndedAt = entity.EndedAt,
                Status = "finished",
                EventCount = entity.EventCount,
                Events = events,
                Policy = extra.Policy,
                IoctlStats = extra.IoctlStats,
                AttachedDevices = extra.Devices,
                FileEntries = extra.Files,
                Snapshots = extra.Snapshots,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Tracker] 加载会话详情失败: {Id}", sessionId);
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  映射
    // ═══════════════════════════════════════════════════════════════

    private static TrackerSessionSummary ToSummary(LiveSession s) => new()
    {
        Id = s.Id,
        MachineName = s.MachineName,
        Pid = s.Pid,
        StartedAt = s.StartedAt,
        LastHeartbeat = s.LastHeartbeat,
        EndedAt = s.EndedAt,
        Status = s.Status,
        EventCount = s.Events.Count,
        HasPolicy = s.Policy != null,
        HasIoctlStats = s.IoctlStats != null,
        DeviceCount = s.Devices.Count,
        FileCount = s.Files.Count,
        SnapshotCount = s.Snapshots.Count,
    };

    private static TrackerSessionDetail ToDetail(LiveSession s)
    {
        List<TrackedEvent> events;
        PolicyInfo? policy;
        IoctlStats? ioctlStats;
        List<AttachedDevice> devices;
        List<FileEntry> files;
        List<string> snapshots;
        lock (s.Lock)
        {
            events = [.. s.Events];
            policy = s.Policy;
            ioctlStats = s.IoctlStats;
            devices = [.. s.Devices];
            files = [.. s.Files];
            snapshots = [.. s.Snapshots];
        }

        return new TrackerSessionDetail
        {
            Id = s.Id,
            MachineName = s.MachineName,
            Pid = s.Pid,
            StartedAt = s.StartedAt,
            LastHeartbeat = s.LastHeartbeat,
            EndedAt = s.EndedAt,
            Status = s.Status,
            EventCount = events.Count,
            Events = events,
            Policy = policy,
            IoctlStats = ioctlStats,
            AttachedDevices = devices,
            FileEntries = files,
            Snapshots = snapshots,
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  内部模型
    // ═══════════════════════════════════════════════════════════════

    private sealed class LiveSession
    {
        public required string Id { get; init; }
        public required string Token { get; init; }
        public required string MachineName { get; init; }
        public required int Pid { get; init; }
        public required string StartedAt { get; init; }
        public string LastHeartbeat { get; set; } = "";
        public string? EndedAt { get; set; }
        public string Status { get; set; } = "active";
        public List<TrackedEvent> Events { get; } = [];
        public PolicyInfo? Policy { get; set; }
        public IoctlStats? IoctlStats { get; set; }
        public List<AttachedDevice> Devices { get; set; } = [];
        public List<FileEntry> Files { get; } = [];
        public List<string> Snapshots { get; } = [];
        public object Lock { get; } = new();
    }

    /// <summary>持久化用载荷（除 events 外的全部新产物）。</summary>
    private sealed class ExtraPayload
    {
        public PolicyInfo? Policy { get; set; }
        public IoctlStats? IoctlStats { get; set; }
        public List<AttachedDevice> Devices { get; set; } = new();
        public List<FileEntry> Files { get; set; } = new();
        public List<string> Snapshots { get; set; } = new();
    }
}
