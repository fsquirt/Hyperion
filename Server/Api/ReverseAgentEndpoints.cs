using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Hyperion.Server.Api;

/// <summary>
/// 逆向分析 Agent 端 API。
/// Agent 通过 connect 认证，凭据为 Bearer LLM token，认证后获得短期 agent_token，
/// 后续所有端点，包括心跳、领任务、上下文、下载、报告、日志与断连，必须以
/// X-Agent-Token header 携带该 token 作为身份凭据，agent_id 仅作展示标识。
///
/// 路径前缀:/api/reverse-agent
/// </summary>
public static class ReverseAgentEndpoints
{
    public static void MapReverseAgentApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/reverse-agent");
        g.MapPost("/connect", HandleConnect);
        g.MapPost("/heartbeat", HandleHeartbeat);
        g.MapGet("/next-task", HandleNextTask);
        g.MapGet("/session-context/{sessionId}", HandleSessionContext);
        g.MapGet("/download/{sessionId}/{storedName}", HandleDownload);
        // 报告正文为 markdown，限制 20MB；日志单条上限 200KB，服务端另有 60k 字符截断兜底
        g.MapPost("/report", HandleReport)
            .WithMetadata(new RequestSizeLimitAttribute(20 * 1024 * 1024));
        g.MapPost("/disconnect", HandleDisconnect);
        g.MapPost("/log", HandleLog)
            .WithMetadata(new RequestSizeLimitAttribute(200 * 1024));
    }

    // ═══════════════════════════════════════════════════════════════
    //  鉴权辅助
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 从 X-Agent-Token header 认证 Agent。失败返回 401 响应，成功返回 null 并通过 out 给出 agentId。
    /// </summary>
    private static IResult? TryAuthenticateAgent(HttpContext ctx, ReverseAgentService svc, out string agentId)
    {
        agentId = "";
        var token = ctx.Request.Headers["X-Agent-Token"].ToString();
        if (string.IsNullOrEmpty(token) || !svc.TryAuthenticateAgent(token, out agentId))
            return Results.Json(
                new { error = "unauthorized", message = "缺少或无效的 agent token" },
                statusCode: StatusCodes.Status401Unauthorized);
        return null;
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/connect
    //  从 Authorization header 取 Bearer token,认证成功返回 agent_id + agent_token + LLM API 列表
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleConnect(
        HttpContext ctx, ReverseAgentService svc)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        var resp = await svc.ConnectAsync(auth);
        if (resp == null)
        {
            return Results.Json(
                new { error = "invalid credential", message = "访问凭据无效或已禁用" },
                statusCode: StatusCodes.Status401Unauthorized);
        }
        return Results.Json(resp);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/heartbeat
    //  X-Agent-Token 认证；body JSON 携带 current_status
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleHeartbeat(
        HttpContext ctx, ReverseAgentService svc)
    {
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        var req = await ctx.Request.ReadFromJsonAsync<ReverseAgentHeartbeatRequest>(ctx.RequestAborted);
        if (req == null)
            return Results.BadRequest(new { error = "invalid body" });

        var ok = svc.Heartbeat(agentId, req.CurrentStatus);
        return ok ? Results.Ok(new { ok = true }) : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/reverse-agent/next-task
    //  领取下一个待分析会话,无任务时 has_task=false
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleNextTask(
        HttpContext ctx, ReverseAgentService svc)
    {
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        var resp = await svc.ClaimNextTaskAsync(agentId);
        return Results.Json(resp);
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/reverse-agent/session-context/{sessionId}
    //  返回会话完整上下文：Windows事件、IOCTL通信记录、附着设备列表、
    //  进程树快照、取证文件列表。要求 Agent 拥有该会话，即 Agent 是领取者且会话处于 analyzing。
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleSessionContext(
        string sessionId,
        HttpContext ctx,
        ReverseAgentService svc,
        TrackerSessionStore store)
    {
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        // 归属校验：只能读取自己领取、且仍在分析中的会话
        if (!await svc.CanAgentAccessSessionAsync(agentId, sessionId))
            return Results.Json(
                new { error = "forbidden", message = "该会话不属于当前 Agent 或已结束分析" },
                statusCode: StatusCodes.Status403Forbidden);

        var detail = await store.GetDetailAsync(sessionId);
        return detail is not null
            ? Results.Json(detail)
            : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/reverse-agent/download/{sessionId}/{storedName}
    //  下载已落地的取证文件。
    //  双通道鉴权：有效 Agent token + 会话归属，或后台管理员会话。
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleDownload(
        string sessionId, string storedName,
        HttpContext ctx, ReverseAgentService svc, TrackerSessionStore store)
    {
        // 通道一：后台管理员会话
        if (ctx.Session.GetString("authenticated") == "true")
            return DownloadFile(sessionId, storedName, store);

        // 通道二：Agent token + 会话归属
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        if (!await svc.CanAgentAccessSessionAsync(agentId, sessionId))
            return Results.Json(
                new { error = "forbidden", message = "该会话不属于当前 Agent 或已结束分析" },
                statusCode: StatusCodes.Status403Forbidden);

        return DownloadFile(sessionId, storedName, store);
    }

    /// <summary>路径穿越防护 + 文件下载。本方法仅负责取文件，鉴权由调用方完成。</summary>
    private static IResult DownloadFile(string sessionId, string storedName, TrackerSessionStore store)
    {
        // 路径穿越防护
        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(storedName) ||
            sessionId.Contains('\\') || sessionId.Contains('/') || sessionId.Contains("..") ||
            storedName.Contains('\\') || storedName.Contains('/') || storedName.Contains(".."))
            return Results.BadRequest(new { error = "invalid path" });

        // storedName 可能是 URL 编码的,先解码再做穿越检查
        storedName = Uri.UnescapeDataString(storedName);
        if (storedName.Contains('\\') || storedName.Contains('/') || storedName.Contains(".."))
            return Results.BadRequest(new { error = "invalid path" });

        var full = store.GetFilePath(sessionId, storedName);
        if (full == null || !File.Exists(full))
            return Results.NotFound();

        return Results.File(full, "application/octet-stream", storedName);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/report
    //  multipart form: session_id, file_name, result, content；agent 身份来自 X-Agent-Token
    //  ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleReport(
        HttpContext ctx, ReverseAgentService svc)
    {
        var ct = ctx.RequestAborted;

        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        string sessionId;
        string fileName;
        string result;
        string content;

        if (ctx.Request.HasFormContentType)
        {
            var form = await ctx.Request.ReadFormAsync(ct);
            sessionId = form["session_id"].ToString();
            fileName = form["file_name"].ToString();
            result = form["result"].ToString();
            content = form["content"].ToString();
        }
        else
        {
            // 回退 JSON
            var req = await ctx.Request.ReadFromJsonAsync<ReportSubmitRequest>(ct);
            sessionId = req?.SessionId ?? "";
            fileName = req?.FileName ?? "";
            result = req?.Result ?? "";
            content = req?.Content ?? "";
        }

        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(result))
            return Results.BadRequest(new { error = "missing required fields: session_id, result" });

        // 原子条件提交：仅领取者 + analyzing 状态可成功，403 语义以此区分于参数错误
        var ok = await svc.SubmitReportAsync(sessionId, agentId, fileName, result, content);
        return ok
            ? Results.Ok(new { ok = true })
            : Results.Json(
                new { error = "submit rejected", message = "会话不属于当前 Agent、已结束分析或已提交过报告" },
                statusCode: StatusCodes.Status403Forbidden);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/disconnect
    //  X-Agent-Token 认证后从内存移除，防止冒充他人断连
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleDisconnect(
        HttpContext ctx, ReverseAgentService svc)
    {
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        await svc.DisconnectAsync(agentId);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/log
    //  body JSON，字段为 session_id, file, level, text；身份来自 X-Agent-Token，
    //  且只能给自己领取的会话写日志
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleLog(
        HttpContext ctx, ReverseAgentService svc)
    {
        var authError = TryAuthenticateAgent(ctx, svc, out var agentId);
        if (authError != null) return authError;

        var req = await ctx.Request.ReadFromJsonAsync<AgentLogRequest>(ctx.RequestAborted);
        if (req == null || string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "session_id required" });

        // 归属校验：只能给自己领取、且仍在分析的会话写日志
        if (!await svc.CanAgentAccessSessionAsync(agentId, req.SessionId))
            return Results.Json(
                new { error = "forbidden", message = "该会话不属于当前 Agent 或已结束分析" },
                statusCode: StatusCodes.Status403Forbidden);

        await svc.AppendAnalysisLogAsync(req.SessionId, agentId, req.File, req.Level, req.Text);
        return Results.Ok(new { ok = true });
    }

    // ═══════════════════════════════════════════════════════════════
    //  请求模型
    // ═══════════════════════════════════════════════════════════════

    private sealed class ReportSubmitRequest
    {
        public string SessionId { get; set; } = "";
        public string AgentId { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Result { get; set; } = "";
        public string Content { get; set; } = "";
    }
}
