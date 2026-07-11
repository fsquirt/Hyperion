using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// Tracker 实时事件上报 API
/// </summary>
public static class TrackerEndpoints
{
    /// <summary>Tree 轮询频率(秒),可由管理员通过 /api/tracker/config 调整。默认 10。</summary>
    private static int _treePollIntervalSec = 10;

    public static void MapTrackerApi(this WebApplication app)
    {
        // 从配置读取默认值
        var cfg = app.Configuration.GetSection("Tracker");
        _treePollIntervalSec = cfg.GetValue("TreePollIntervalSec", 10);

        app.MapPost("/api/tracker/start", HandleStart);
        app.MapPost("/api/tracker/events", HandleEvents);
        app.MapPost("/api/tracker/heartbeat", HandleHeartbeat);
        app.MapPost("/api/tracker/end", HandleEnd);
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
        app.MapGet("/api/tracker/sessions/{id}/types", HandleGetSessionTypes);
        app.MapGet("/api/tracker/config", HandleGetConfig);
        app.MapPost("/api/tracker/config", HandleSetConfig);
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
        string? type = null,
        string? search = null)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id, level, search, type);
        return detail is not null
            ? Results.Json(detail)
            : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/tracker/sessions/{id}/types
    //  返回该会话中出现过的事件 Type 列表(前端过滤栏动态渲染)
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetSessionTypes(
        HttpContext ctx,
        string id,
        TrackerSessionStore store)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var types = await store.GetEventTypesAsync(id);
        return Results.Json(new { types });
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/tracker/config
    //  返回 Tracker 运行配置(客户端拉取,无需认证)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleGetConfig()
    {
        return Results.Json(new { treePollIntervalSec = _treePollIntervalSec });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/tracker/config
    //  调整 Tracker 运行配置(需管理员认证)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleSetConfig(
        HttpContext ctx,
        TrackerConfigRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        if (req.TreePollIntervalSec < 1 || req.TreePollIntervalSec > 3600)
            return Results.BadRequest(new { error = "treePollIntervalSec must be 1..3600" });

        _treePollIntervalSec = req.TreePollIntervalSec;
        return Results.Json(new { treePollIntervalSec = _treePollIntervalSec });
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

    private sealed record TrackerConfigRequest
    {
        public int TreePollIntervalSec { get; init; } = 10;
    }
}
