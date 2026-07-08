using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using System.Collections.Concurrent;
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

    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromMinutes(2);

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

    public TrackerSessionSummary CreateSession(string machineName, int pid)
    {
        var id = Guid.NewGuid().ToString("N")[..12];
        var now = DateTime.UtcNow.ToString("o");

        var session = new LiveSession
        {
            Id = id,
            MachineName = machineName,
            Pid = pid,
            StartedAt = now,
            LastHeartbeat = now,
            Status = "active",
        };

        _sessions[id] = session;
        _logger.LogInformation("[Tracker] 会话创建: {Id} ({Machine})", id, machineName);
        return ToSummary(session);
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
        if (!_sessions.TryRemove(sessionId, out var session)) return false;
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
    //  事件追加
    // ═══════════════════════════════════════════════════════════════

    public int AppendEvents(string sessionId, List<TrackedEvent> events)
    {
        if (!_sessions.TryGetValue(sessionId, out var session)) return 0;
        if (session.Status != "active") return 0;

        lock (session.Lock)
        {
            session.Events.AddRange(events);
        }
        return events.Count;
    }

    // ═══════════════════════════════════════════════════════════════
    //  查询（内存 + 数据库合并）
    // ═══════════════════════════════════════════════════════════════

    public async Task<List<TrackerSessionSummary>> GetSummariesAsync()
    {
        // 内存中的活跃会话
        var live = _sessions.Values
            .Where(s => s.Status == "active")
            .Select(ToSummary)
            .ToList();

        // 数据库中已结束的会话
        var dbFinished = await LoadFinishedSummariesAsync();

        return live.Concat(dbFinished)
            .OrderByDescending(s => s.StartedAt)
            .ToList();
    }

    public async Task<TrackerSessionDetail?> GetDetailAsync(
        string sessionId, string? level = null, string? search = null)
    {
        TrackerSessionDetail? detail;

        // 先查内存
        if (_sessions.TryGetValue(sessionId, out var live))
            detail = ToDetail(live);
        else
            detail = await LoadDetailFromDbAsync(sessionId);

        if (detail is null) return null;

        // 服务端过滤
        var events = detail.Events.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(level))
        {
            var lvl = level.Trim().ToUpperInvariant();
            events = events.Where(e =>
                e.Level.Equals(lvl, StringComparison.OrdinalIgnoreCase));
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
                // 超时 → 结束并持久化
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
            lock (session.Lock) { events = [.. session.Events]; }

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
    };

    private static TrackerSessionDetail ToDetail(LiveSession s)
    {
        List<TrackedEvent> events;
        lock (s.Lock) { events = [.. s.Events]; }

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
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  内部模型
    // ═══════════════════════════════════════════════════════════════

    private sealed class LiveSession
    {
        public required string Id { get; init; }
        public required string MachineName { get; init; }
        public required int Pid { get; init; }
        public required string StartedAt { get; init; }
        public string LastHeartbeat { get; set; } = "";
        public string? EndedAt { get; set; }
        public string Status { get; set; } = "active";
        public List<TrackedEvent> Events { get; } = [];
        public object Lock { get; } = new();
    }
}
