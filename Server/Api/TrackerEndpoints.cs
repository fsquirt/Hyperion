using Hyperion.Server.Data;
using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace Hyperion.Server.Api;

/// <summary>
/// 运行时追踪 API — 4 种独立数据流 + 配置 + 会话管理。
/// 4 种数据流:
///   1. events:    Tracker 的 Windows 事件 + ETW 事件
///   2. snapshots: 进程树快照(全量 baseline + tree 轮询)
///   3. kernel-comms: 驱动扫描 + 附着 + IOCTL 拦截
///   4. dumps:     通信 dump 文件记录
/// </summary>
public static class TrackerEndpoints
{
    public static void MapTrackerApi(this WebApplication app)
    {
        // ═══ 会话生命周期 ═══
        app.MapPost("/api/tracker/start", HandleStart);
        app.MapPost("/api/tracker/heartbeat", HandleHeartbeat);
        app.MapPost("/api/tracker/end", HandleEnd);

        // ═══ 会话管理(管理员) ═══
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
        app.MapDelete("/api/tracker/sessions/{id}", HandleDeleteSession);

        // ═══ 1. 事件(winevent + etw) ═══
        app.MapPost("/api/tracker/events", HandlePostEvents);
        app.MapGet("/api/tracker/sessions/{id}/events", HandleGetEvents);

        // ═══ 2. 进程树快照 ═══
        app.MapPost("/api/tracker/snapshots", HandlePostSnapshot);
        app.MapGet("/api/tracker/sessions/{id}/snapshots", HandleGetSnapshots);

        // ═══ 3. 内核通信(驱动+附着+IOCTL) ═══
        app.MapPost("/api/tracker/kernel-comms", HandlePostKernelComm);
        app.MapGet("/api/tracker/sessions/{id}/kernel-comms", HandleGetKernelComms);

        // ═══ 4. Dump 触发 ═══
        app.MapPost("/api/tracker/dumps", HandlePostDump);
        app.MapGet("/api/tracker/sessions/{id}/dumps", HandleGetDumps);

        // ═══ 配置 ═══
        app.MapGet("/api/tracker/config", HandleGetConfig);
        app.MapPost("/api/tracker/config", HandleSetConfig);
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleStart(
        TrackerStartRequest req,
        TrackerSessionStore store,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.MachineName))
            return Results.BadRequest(new { error = "machineName required" });

        var summary = store.CreateSession(req.MachineName, req.Pid);
        logger.LogInformation("[Tracker] 新会话: {Id} from {Machine}", summary.Id, summary.MachineName);
        return Results.Json(summary);
    }

    private static IResult HandleHeartbeat(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        var ok = store.Heartbeat(req.SessionId);
        return ok ? Results.Ok() : Results.NotFound();
    }

    private static IResult HandleEnd(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        store.EndSession(req.SessionId);
        return Results.Ok();
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话管理
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetSessions(HttpContext ctx, TrackerSessionStore store)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        return Results.Json(await store.GetSummariesAsync());
    }

    private static async Task<IResult> HandleGetSessionDetail(
        HttpContext ctx, string id, TrackerSessionStore store)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id);
        return detail is not null ? Results.Json(detail) : Results.NotFound();
    }

    private static async Task<IResult> HandleDeleteSession(
        HttpContext ctx, string id,
        TrackerSessionStore store,
        IDbContextFactory<AttestationDbContext> dbFactory)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        // 内存中活跃会话:先标记结束
        store.EndSession(id);

        // 数据库:删除会话 + 关联的快照/通信/dump 记录
        await using var db = await dbFactory.CreateDbContextAsync();

        // 删除会话本身
        var session = await db.TrackerSessions.FindAsync(id);
        if (session != null) db.TrackerSessions.Remove(session);

        // 删除关联数据
        db.TrackerSnapshots.RemoveRange(db.TrackerSnapshots.Where(s => s.SessionId == id));
        db.TrackerKernelComms.RemoveRange(db.TrackerKernelComms.Where(k => k.SessionId == id));
        db.TrackerDumps.RemoveRange(db.TrackerDumps.Where(d => d.SessionId == id));

        await db.SaveChangesAsync();
        return Results.Ok();
    }

    // ═══════════════════════════════════════════════════════════════
    //  1. 事件(winevent + etw)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandlePostEvents(
        TrackerEventsRequest req,
        TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        if (req.Events.Count == 0)
            return Results.Ok(new { added = 0 });

        var added = store.AppendEvents(req.SessionId, req.Events);
        return Results.Ok(new { added });
    }

    private static async Task<IResult> HandleGetEvents(
        HttpContext ctx, string id, TrackerSessionStore store,
        string? level = null, string? type = null, string? search = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id, level, search, type);
        return detail is not null ? Results.Json(detail) : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  2. 进程树快照
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostSnapshot(
        SnapshotRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerSnapshots.Add(new TrackerSnapshotEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Kind = req.Kind == "security" ? "security" : "tree",
            ProcessCount = req.ProcessCount,
            ProcessesJson = req.ProcessesJson ?? "[]",
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] 快照入库: {Id} ({Kind}, {Count} 进程)",
            id, req.Kind, req.ProcessCount);
        return Results.Json(new { id, count = req.ProcessCount });
    }

    private static async Task<IResult> HandleGetSnapshots(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? kind = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerSnapshots.Where(s => s.SessionId == id);
        if (!string.IsNullOrWhiteSpace(kind))
            q = q.Where(s => s.Kind == kind);

        var list = await q.OrderByDescending(s => s.Timestamp)
            .Select(s => new
            {
                s.Id,
                s.SessionId,
                s.Timestamp,
                s.Kind,
                s.ProcessCount,
                processesJson = s.ProcessesJson,
            })
            .ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  3. 内核通信(驱动+附着+IOCTL)
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostKernelComm(
        KernelCommRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerKernelComms.Add(new TrackerKernelCommEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Kind = req.Kind,
            Level = req.Level,
            Source = req.Source,
            Title = req.Title,
            Detail = req.Detail,
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] 内核通信入库: {Id} ({Kind}) {Title}", id, req.Kind, req.Title);
        return Results.Json(new { id });
    }

    private static async Task<IResult> HandleGetKernelComms(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? kind = null, string? level = null, string? search = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerKernelComms.Where(k => k.SessionId == id);

        if (!string.IsNullOrWhiteSpace(kind))
            q = q.Where(k => k.Kind == kind);
        if (!string.IsNullOrWhiteSpace(level))
            q = q.Where(k => k.Level == level);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search;
            q = q.Where(k => k.Title.Contains(kw) || k.Detail.Contains(kw) || k.Source.Contains(kw));
        }

        var list = await q.OrderByDescending(k => k.Timestamp).ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  4. Dump 触发
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostDump(
        DumpRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerDumps.Add(new TrackerDumpEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Level = req.Level,
            Title = req.Title,
            Detail = req.Detail,
            DumpFilesJson = req.DumpFilesJson ?? "[]",
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] Dump 入库: {Id} {Title}", id, req.Title);
        return Results.Json(new { id });
    }

    private static async Task<IResult> HandleGetDumps(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? level = null, string? search = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerDumps.Where(d => d.SessionId == id);

        if (!string.IsNullOrWhiteSpace(level))
            q = q.Where(d => d.Level == level);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search;
            q = q.Where(d => d.Title.Contains(kw) || d.Detail.Contains(kw));
        }

        var list = await q.OrderByDescending(d => d.Timestamp).ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  配置
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetConfig(
        IDbContextFactory<AttestationDbContext> dbFactory)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var cfg = await db.TrackerConfig.FindAsync("default");
        if (cfg == null)
        {
            return Results.Json(new
            {
                treePollIntervalSec = 10,
                ioctlEnabled = false,
                dumpMode = "mini",
                fileCopyEnabled = true,
            });
        }
        return Results.Json(new
        {
            treePollIntervalSec = cfg.TreePollIntervalSec,
            ioctlEnabled = cfg.IoctlEnabled != 0,
            dumpMode = cfg.DumpMode,
            fileCopyEnabled = cfg.FileCopyEnabled != 0,
        });
    }

    private static async Task<IResult> HandleSetConfig(
        HttpContext ctx,
        TrackerConfigRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        if (req.TreePollIntervalSec < 1 || req.TreePollIntervalSec > 3600)
            return Results.BadRequest(new { error = "treePollIntervalSec must be 1..3600" });

        var validDumpModes = new[] { "raw", "mini", "full" };
        var dumpMode = string.IsNullOrWhiteSpace(req.DumpMode) ? "mini" : req.DumpMode.ToLowerInvariant();
        if (!validDumpModes.Contains(dumpMode))
            return Results.BadRequest(new { error = "dumpMode must be raw/mini/full" });

        await using var db = await dbFactory.CreateDbContextAsync();
        var cfg = await db.TrackerConfig.FindAsync("default");
        if (cfg == null)
        {
            cfg = new TrackerConfigEntity { Id = "default" };
            db.TrackerConfig.Add(cfg);
        }

        cfg.TreePollIntervalSec = req.TreePollIntervalSec;
        cfg.IoctlEnabled = req.IoctlEnabled ? 1 : 0;
        cfg.DumpMode = dumpMode;
        cfg.FileCopyEnabled = req.FileCopyEnabled ? 1 : 0;
        cfg.UpdatedAt = DateTime.UtcNow.ToString("o");

        await db.SaveChangesAsync();
        return Results.Json(new
        {
            treePollIntervalSec = cfg.TreePollIntervalSec,
            ioctlEnabled = cfg.IoctlEnabled != 0,
            dumpMode = cfg.DumpMode,
            fileCopyEnabled = cfg.FileCopyEnabled != 0,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private static bool IsAuth(HttpContext ctx) =>
        ctx.Session.GetString("authenticated") == "true";

    // ═══════════════════════════════════════════════════════════════
    //  请求模型
    // ═══════════════════════════════════════════════════════════════

    private sealed record TrackerStartRequest
    {
        public string MachineName { get; init; } = "";
        public int Pid { get; init; }
    }

    private sealed record TrackerSessionIdRequest
    {
        public string SessionId { get; init; } = "";
    }

    private sealed record TrackerEventsRequest
    {
        public string SessionId { get; init; } = "";
        public List<TrackedEvent> Events { get; init; } = [];
    }

    /// <summary>进程树快照上传请求。</summary>
    public sealed class SnapshotRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        /// <summary>"security"(初始全量) | "tree"(后续轮询)</summary>
        public string Kind { get; set; } = "tree";
        public int ProcessCount { get; set; }
        /// <summary>完整进程列表 JSON 字符串</summary>
        public string? ProcessesJson { get; set; }
    }

    /// <summary>内核通信记录上传请求。</summary>
    public sealed class KernelCommRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        /// <summary>"driver" | "attach" | "ioctl"</summary>
        public string Kind { get; set; } = "driver";
        public string Level { get; set; } = "INFO";
        public string Source { get; set; } = "";
        public string Title { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    /// <summary>Dump 记录上传请求。</summary>
    public sealed class DumpRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        public string Level { get; set; } = "INFO";
        public string Title { get; set; } = "";
        public string Detail { get; set; } = "";
        /// <summary>JSON 数组: [{path, kind, pid, hitCount, abnormal}]</summary>
        public string? DumpFilesJson { get; set; }
    }

    private sealed record TrackerConfigRequest
    {
        public int TreePollIntervalSec { get; init; } = 10;
        public bool IoctlEnabled { get; init; } = false;
        public string DumpMode { get; init; } = "mini";
        public bool FileCopyEnabled { get; init; } = true;
    }
}
