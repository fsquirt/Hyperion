using SEWindows.Server.Models;
using SEWindows.Server.Services;

namespace SEWindows.Server.Api;

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
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/start
    //  创建会话，返回 sessionId
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/events
    //  批量追加事件
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
    //  返回会话详情（含事件列表）
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
    //  请求模型（API 内部使用，不暴露到 Models/）
    // ═══════════════════════════════════════════════════════════════

    private sealed record TrackerStartRequest
    {
        public string MachineName { get; init; } = "";
        public int Pid { get; init; }
    }

    private sealed record TrackerEventsRequest
    {
        public string SessionId { get; init; } = "";
        public List<TrackedEvent> Events { get; init; } = [];
    }

    private sealed record TrackerSessionIdRequest
    {
        public string SessionId { get; init; } = "";
    }
}
