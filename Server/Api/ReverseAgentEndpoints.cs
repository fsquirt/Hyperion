using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.AspNetCore.Http;

namespace Hyperion.Server.Api;

/// <summary>
/// 逆向分析 Agent 端 API。
/// Agent 通过 connect 认证后，循环领取任务、下载文件、提交报告。
///
/// 路径前缀:/api/reverse-agent
/// 认证方式:connect 时 Bearer token,之后用 agent_id 标识。
/// </summary>
public static class ReverseAgentEndpoints
{
    public static void MapReverseAgentApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/reverse-agent");
        g.MapPost("/connect", HandleConnect);
        g.MapPost("/heartbeat", HandleHeartbeat);
        g.MapGet("/next-task", HandleNextTask);
        g.MapGet("/download/{sessionId}/{storedName}", HandleDownload);
        g.MapPost("/report", HandleReport);
        g.MapPost("/disconnect", HandleDisconnect);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/connect
    //  从 Authorization header 取 Bearer token,认证成功返回 agent_id + LLM API 列表
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
    //  读 body JSON (agent_id, current_status),更新心跳
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleHeartbeat(
        HttpContext ctx, ReverseAgentService svc)
    {
        var req = await ctx.Request.ReadFromJsonAsync<ReverseAgentHeartbeatRequest>(ctx.RequestAborted);
        if (req == null || string.IsNullOrWhiteSpace(req.AgentId))
            return Results.BadRequest(new { error = "agent_id required" });

        var ok = svc.Heartbeat(req.AgentId, req.CurrentStatus);
        return ok ? Results.Ok(new { ok = true }) : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/reverse-agent/next-task?agent_id=xxx
    //  领取下一个待分析会话,无任务时 has_task=false
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleNextTask(
        HttpContext ctx, ReverseAgentService svc)
    {
        // 优先从 query 取,其次从 header X-Agent-Id 取
        var agentId = ctx.Request.Query["agent_id"].ToString();
        if (string.IsNullOrWhiteSpace(agentId))
            agentId = ctx.Request.Headers["X-Agent-Id"].ToString();
        if (string.IsNullOrWhiteSpace(agentId))
            return Results.BadRequest(new { error = "agent_id required" });

        var resp = await svc.ClaimNextTaskAsync(agentId);
        return Results.Json(resp);
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/reverse-agent/download/{sessionId}/{storedName}
    //  下载已落地的取证文件(无需 session 鉴权,需路径穿越防护)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleDownload(
        string sessionId, string storedName, TrackerSessionStore store)
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
    //  multipart form: session_id, agent_id, file_name, result, content
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleReport(
        HttpContext ctx, ReverseAgentService svc)
    {
        var ct = ctx.RequestAborted;

        string sessionId;
        string agentId;
        string fileName;
        string result;
        string content;

        if (ctx.Request.HasFormContentType)
        {
            var form = await ctx.Request.ReadFormAsync(ct);
            sessionId = form["session_id"].ToString();
            agentId = form["agent_id"].ToString();
            fileName = form["file_name"].ToString();
            result = form["result"].ToString();
            content = form["content"].ToString();
        }
        else
        {
            // 回退 JSON
            var req = await ctx.Request.ReadFromJsonAsync<ReportSubmitRequest>(ct);
            sessionId = req?.SessionId ?? "";
            agentId = req?.AgentId ?? "";
            fileName = req?.FileName ?? "";
            result = req?.Result ?? "";
            content = req?.Content ?? "";
        }

        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(agentId) ||
            string.IsNullOrWhiteSpace(fileName) || string.IsNullOrWhiteSpace(result))
            return Results.BadRequest(new { error = "missing required fields" });

        var ok = await svc.SubmitReportAsync(sessionId, agentId, fileName, result, content);
        return ok
            ? Results.Ok(new { ok = true })
            : Results.BadRequest(new { error = "submit failed (invalid session/result or agent not found)" });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/reverse-agent/disconnect
    //  读 body JSON (agent_id),从内存移除
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleDisconnect(
        HttpContext ctx, ReverseAgentService svc)
    {
        var req = await ctx.Request.ReadFromJsonAsync<DisconnectRequest>(ctx.RequestAborted);
        if (req == null || string.IsNullOrWhiteSpace(req.AgentId))
            return Results.BadRequest(new { error = "agent_id required" });

        await svc.DisconnectAsync(req.AgentId);
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

    private sealed class DisconnectRequest
    {
        public string AgentId { get; set; } = "";
    }
}
