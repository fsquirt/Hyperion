using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.AspNetCore.Http;

namespace Hyperion.Server.Api;

/// <summary>
/// 逆向分析 Agent 管理端 API。
/// 供 Web 后台查看活跃 Agent、分析队列、分析报告。
///
/// 路径前缀:/api/admin
/// 认证方式:Session(authenticated == "true")
/// </summary>
public static class ReverseAgentAdminEndpoints
{
    public static void MapReverseAgentAdminApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin");
        g.MapGet("/reverse-agents", HandleGetAgents);
        g.MapGet("/analysis-queue", HandleGetQueue);
        g.MapGet("/reports", HandleGetReports);
        g.MapGet("/reports/{id}", HandleGetReport);
        g.MapPost("/sessions/{sessionId}/delete", HandleDeleteSession);
        g.MapPost("/sessions/{sessionId}/reset", HandleResetSession);

        // 终端日志
        g.MapGet("/analysis-logs/{sessionId}", HandleGetAnalysisLogs);
    }

    
    //  GET /api/admin/reverse-agents
    //  返回内存中所有活跃 Agent
    private static IResult HandleGetAgents(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(svc.GetActiveAgents());
    }

    
    //  GET /api/admin/analysis-queue
    //  返回所有 Tracker 会话的分析状态，数据合并自内存与数据库
    private static async Task<IResult> HandleGetQueue(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetAnalysisQueueAsync());
    }

    
    //  GET /api/admin/reports
    //  返回所有分析报告，不含 content 正文
    private static async Task<IResult> HandleGetReports(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetReportsAsync());
    }

    
    //  GET /api/admin/reports/{id}
    //  返回单条报告，包含 content 正文
    private static async Task<IResult> HandleGetReport(
        HttpContext ctx, string id, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var report = await svc.GetReportAsync(id);
        return report is not null
            ? Results.Json(report)
            : Results.NotFound();
    }

    
    //  POST /api/admin/sessions/{sessionId}/delete
    //  删除游戏会话，并连带删除 tracker 记录、分析状态、报告与本地文件
    private static async Task<IResult> HandleDeleteSession(
        HttpContext ctx, string sessionId, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var (ok, error) = await svc.DeleteSessionAsync(sessionId);
        return ok
            ? Results.Ok(new { ok = true })
            : Results.BadRequest(new { error = error ?? "删除失败" });
    }

    
    //  POST /api/admin/sessions/{sessionId}/reset
    //  重置会话分析状态为尚未分析，同时清空结果与报告并重新排队
    private static async Task<IResult> HandleResetSession(
        HttpContext ctx, string sessionId, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var (ok, error) = await svc.ResetAnalysisAsync(sessionId);
        return ok
            ? Results.Ok(new { ok = true })
            : Results.BadRequest(new { error = error ?? "重置失败" });
    }

    
    //  GET /api/admin/analysis-logs/{sessionId}
    //  返回该会话的全部终端日志，按序号升序排列
    private static async Task<IResult> HandleGetAnalysisLogs(
        HttpContext ctx, string sessionId, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetAnalysisLogsAsync(sessionId));
    }
}
