using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// Tracker 实时事件上报 API
/// </summary>
public static class TrackerEndpoints
{
    public static void MapTrackerApi(this WebApplication app)
    {
        app.MapPost("/api/tracker/start", HandleStart);
        app.MapPost("/api/tracker/events", HandleEvents);
        app.MapPost("/api/tracker/heartbeat", HandleHeartbeat);
        app.MapPost("/api/tracker/end", HandleEnd);
        app.MapPost("/api/tracker/policy", HandlePolicy);
        app.MapPost("/api/tracker/ioctl-stats", HandleIoctlStats);
        app.MapPost("/api/tracker/devices", HandleDevices);
        app.MapPost("/api/tracker/files", HandleFiles);
        app.MapPost("/api/tracker/snapshots", HandleSnapshots);
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/start
    //  创建会话，返回 sessionId（可选携带会话建立时采纳的策略）
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleStart(
        TrackerStartRequest req,
        TrackerSessionStore store,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.MachineName))
            return Results.BadRequest(new { error = "machineName required" });

        var summary = store.CreateSession(req.MachineName, req.Pid, req.Policy);
        logger.LogInformation("[Tracker] 新会话: {Id} from {Machine}", summary.Id, summary.MachineName);
        return Results.Json(summary);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/events
    //  批量追加 Windows/ETW 事件
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleEvents(
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/policy
    //  设置会话采纳的策略（与会话建立事件一同展示）
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandlePolicy(TrackerPolicyRequest req, TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });
        store.SetPolicy(req.SessionId, req.Policy);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/ioctl-stats
    //  覆盖式更新最新 IOCTL 通信统计快照（客户端每 30 秒上报一次）
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleIoctlStats(TrackerIoctlStatsRequest req, TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });
        store.SetIoctlStats(req.SessionId, req.Stats);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/devices
    //  覆盖设置附着设备列表（每次增量重扫后全量刷新）
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleDevices(TrackerDevicesRequest req, TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });
        store.SetDevices(req.SessionId, req.Devices);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/files
    //  追加 FileCopy / DebugDump 取证文件条目
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleFiles(TrackerFilesRequest req, TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });
        store.AppendFiles(req.SessionId, req.Files);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/snapshots
    //  追加进程树快照（采集即上传，原始 JSON）
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleSnapshots(TrackerSnapshotsRequest req, TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });
        store.AppendSnapshots(req.SessionId, req.Snapshots);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/heartbeat
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleHeartbeat(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        var ok = store.Heartbeat(req.SessionId);
        return ok ? Results.Ok() : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/end
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleEnd(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        store.EndSession(req.SessionId);
        return Results.Ok();
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/tracker/sessions
    //  返回所有会话摘要
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetSessions(HttpContext ctx, TrackerSessionStore store)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await store.GetSummariesAsync());
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/tracker/sessions/{id}
    //  返回会话详情（含事件 + 全部取证产物）
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetSessionDetail(
        HttpContext ctx,
        string id,
        TrackerSessionStore store,
        string? level = null,
        string? search = null)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id, level, search);
        return detail is not null
            ? Results.Json(detail)
            : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  请求模型
    // ═══════════════════════════════════════════════════════════════

    private sealed record TrackerStartRequest
    {
        public string MachineName { get; init; } = "";
        public int Pid { get; init; }
        public PolicyInfo? Policy { get; init; }
    }

    private sealed record TrackerEventsRequest
    {
        public string SessionId { get; init; } = "";
        public List<TrackedEvent> Events { get; init; } = [];
    }

    private sealed record TrackerPolicyRequest
    {
        public string SessionId { get; init; } = "";
        public PolicyInfo Policy { get; init; } = new();
    }

    private sealed record TrackerIoctlStatsRequest
    {
        public string SessionId { get; init; } = "";
        public IoctlStats Stats { get; init; } = new();
    }

    private sealed record TrackerDevicesRequest
    {
        public string SessionId { get; init; } = "";
        public List<AttachedDevice> Devices { get; init; } = [];
    }

    private sealed record TrackerFilesRequest
    {
        public string SessionId { get; init; } = "";
        public List<FileEntry> Files { get; init; } = [];
    }

    private sealed record TrackerSnapshotsRequest
    {
        public string SessionId { get; init; } = "";
        public List<string> Snapshots { get; init; } = [];
    }

    private sealed record TrackerSessionIdRequest
    {
        public string SessionId { get; init; } = "";
    }
}
