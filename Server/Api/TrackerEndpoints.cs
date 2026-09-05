using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.IO;
using System.Text.RegularExpressions;

namespace Hyperion.Server.Api;

/// <summary>
/// Tracker 实时事件上报 API
/// 所有写接口中除 /start 外均要求：
///   1. sessionId 符合服务端生成格式，即 12 位小写十六进制
///   2. X-Session-Token header 与 /api/tracker/start 下发的 token 一致，且会话处于 active
/// </summary>
public static class TrackerEndpoints
{
    /// <summary>服务端生成的 sessionId 固定格式：12 位小写十六进制，取 Guid.N 的前 12 位。</summary>
    private static readonly Regex SessionIdPattern = new("^[0-9a-f]{12}$", RegexOptions.Compiled);

    public static void MapTrackerApi(this WebApplication app)
    {
        // 写接口带 per-endpoint body limit：在反序列化阶段前拦截超大请求，
        // 避免 500MB 全局限制被单个巨型 body 打满内存；AppendEvents 等上限只保护存储。
        app.MapPost("/api/tracker/start", HandleStart).RequireRateLimiting("tracker-start");
        app.MapPost("/api/tracker/events", HandleEvents)
            .WithMetadata(new RequestSizeLimitAttribute(50 * 1024 * 1024)); // 50MB ≈ 20 万条事件
        app.MapPost("/api/tracker/heartbeat", HandleHeartbeat);
        app.MapPost("/api/tracker/end", HandleEnd);
        app.MapPost("/api/tracker/policy", HandlePolicy)
            .WithMetadata(new RequestSizeLimitAttribute(1024 * 1024)); // 1MB
        app.MapPost("/api/tracker/ioctl-stats", HandleIoctlStats)
            .WithMetadata(new RequestSizeLimitAttribute(1024 * 1024)); // 1MB
        app.MapPost("/api/tracker/devices", HandleDevices)
            .WithMetadata(new RequestSizeLimitAttribute(2 * 1024 * 1024)); // 2MB
        // files 保持全局 500MB，供 multipart 大文件上传，例如 minidump 或驱动 dump
        app.MapPost("/api/tracker/files", HandleFiles).RequireRateLimiting("tracker-files");
        app.MapPost("/api/tracker/snapshots", HandleSnapshots)
            .WithMetadata(new RequestSizeLimitAttribute(20 * 1024 * 1024)); // 20MB
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
        app.MapGet("/api/tracker/files/{sessionId}/{storedName}", HandleDownloadFile);
    }

    
    //  鉴权辅助
    

    /// <summary>sessionId 必须是服务端生成的固定格式，拒绝任意路径字符串。</summary>
    private static bool IsValidSessionId(string sessionId) =>
        SessionIdPattern.IsMatch(sessionId);

    /// <summary>
    /// 校验写权限：sessionId 格式 + 会话存在/active + X-Session-Token 匹配。
    /// 校验失败返回对应的 IResult，通过返回 null。
    /// </summary>
    private static IResult? AuthorizeSession(HttpContext ctx, TrackerSessionStore store, string sessionId)
    {
        if (!IsValidSessionId(sessionId))
            return Results.BadRequest(new { error = "invalid sessionId" });

        var token = ctx.Request.Headers["X-Session-Token"].ToString();
        if (!store.TryAuthorizeSession(sessionId, token))
            return Results.Unauthorized();
        return null;
    }

    
    //  POST /api/tracker/start
    //  创建会话，返回 sessionId + sessionToken，两者即后续写接口的凭据
    private static IResult HandleStart(
        TrackerStartRequest req,
        TrackerSessionStore store,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.MachineName))
            return Results.BadRequest(new { error = "machineName required" });

        var result = store.CreateSession(req.MachineName, req.Pid, req.Policy);
        logger.LogInformation("[Tracker] 新会话: {Id} from {Machine}", result.Id, result.MachineName);
        return Results.Json(result);
    }

    
    //  POST /api/tracker/events
    //  批量追加 Windows/ETW 事件
    private static IResult HandleEvents(
        HttpContext ctx,
        TrackerEventsRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        if (req.Events.Count == 0)
            return Results.Ok(new { added = 0 });

        var added = store.AppendEvents(req.SessionId, req.Events);
        return Results.Ok(new { added });
    }

    //  POST /api/tracker/policy
    //  设置会话采纳的策略，该策略与会话建立事件一同展示
    private static IResult HandlePolicy(
        HttpContext ctx,
        TrackerPolicyRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        store.SetPolicy(req.SessionId, req.Policy);
        return Results.Ok(new { ok = true });
    }

    
    //  POST /api/tracker/ioctl-stats
    //  覆盖式更新最新 IOCTL 通信统计快照，客户端每 30 秒上报一次
    private static IResult HandleIoctlStats(
        HttpContext ctx,
        TrackerIoctlStatsRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        store.SetIoctlStats(req.SessionId, req.Stats);
        return Results.Ok(new { ok = true });
    }

    
    //  POST /api/tracker/devices
    //  覆盖设置附着设备列表，每次增量重扫后全量刷新
    private static IResult HandleDevices(
        HttpContext ctx,
        TrackerDevicesRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        store.SetDevices(req.SessionId, req.Devices);
        return Results.Ok(new { ok = true });
    }

    
    //  POST /api/tracker/files
    //  追加 FileCopy / DebugDump 取证文件条目，multipart 负责落地存储，JSON 仅上报元数据
    private static async Task<IResult> HandleFiles(HttpContext ctx, TrackerSessionStore store)
    {
        var ct = ctx.RequestAborted;

        // 优先：multipart 上传文件内容，由客户端真正落地存储
        if (ctx.Request.HasFormContentType &&
            ctx.Request.ContentType?.StartsWith("multipart", StringComparison.OrdinalIgnoreCase) == true)
        {
            var form = await ctx.Request.ReadFormAsync(ct);
            var sessionId = form["sessionId"].ToString();
            var authError = AuthorizeSession(ctx, store, sessionId);
            if (authError != null) return authError;

            var file = form.Files["file"];
            if (file == null || file.Length == 0)
                return Results.BadRequest(new { error = "missing file" });

            var storedName = store.SaveUploadedFile(sessionId, file);
            if (storedName == null)
                return Results.BadRequest(new { error = "upload rejected (invalid session or quota exceeded)" });

            var entry = new FileEntry
            {
                Kind = form["kind"].ToString(),
                Name = form["name"].ToString(),
                Path = form["path"].ToString(),
                Size = file.Length,
                Time = form["time"].ToString(),
                StoredName = storedName,
                DownloadUrl = $"/api/tracker/files/{sessionId}/{Uri.EscapeDataString(storedName)}",
            };
            store.AppendFiles(sessionId, new List<FileEntry> { entry });
            return Results.Ok(new { ok = true });
        }

        // 回退：仅 JSON 元数据上报，兼容旧客户端
        var req = await ctx.Request.ReadFromJsonAsync<TrackerFilesRequest>(ct);
        if (req == null || string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var authErr = AuthorizeSession(ctx, store, req.SessionId);
        if (authErr != null) return authErr;

        store.AppendFiles(req.SessionId, req.Files);
        return Results.Ok(new { ok = true });
    }

    /// <summary>下载已落地的取证文件，需鉴权并防目录穿越。</summary>
    private static IResult HandleDownloadFile(
        HttpContext ctx, string sessionId, string storedName, TrackerSessionStore store)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        // 路径穿越防护
        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(storedName) ||
            sessionId.Contains('\\') || sessionId.Contains('/') || sessionId.Contains("..") ||
            storedName.Contains('\\') || storedName.Contains('/') || storedName.Contains(".."))
            return Results.BadRequest(new { error = "invalid path" });

        var full = store.GetFilePath(sessionId, storedName);
        if (full == null || !File.Exists(full))
            return Results.NotFound();

        return Results.File(full, "application/octet-stream", storedName);
    }

    
    //  POST /api/tracker/snapshots
    //  追加进程树快照，采集即上传，内容为原始 JSON
    private static IResult HandleSnapshots(
        HttpContext ctx,
        TrackerSnapshotsRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        store.AppendSnapshots(req.SessionId, req.Snapshots);
        return Results.Ok(new { ok = true });
    }

    
    //  POST /api/tracker/heartbeat
    private static IResult HandleHeartbeat(
        HttpContext ctx,
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        var ok = store.Heartbeat(req.SessionId);
        return ok ? Results.Ok() : Results.NotFound();
    }

    
    //  POST /api/tracker/end
    private static IResult HandleEnd(
        HttpContext ctx,
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        var authError = AuthorizeSession(ctx, store, req.SessionId);
        if (authError != null) return authError;

        store.EndSession(req.SessionId);
        return Results.Ok();
    }

    
    //  GET /api/tracker/sessions
    //  返回所有会话摘要
    private static async Task<IResult> HandleGetSessions(HttpContext ctx, TrackerSessionStore store)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await store.GetSummariesAsync());
    }

    
    //  GET /api/tracker/sessions/{id}
    //  返回会话详情，包含事件与全部取证产物
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

    
    //  请求模型
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
