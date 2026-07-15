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
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/reverse-agents
    //  返回内存中所有活跃 Agent
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleGetAgents(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(svc.GetActiveAgents());
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/analysis-queue
    //  返回所有 Tracker 会话的分析状态（合并内存 + 数据库）
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetQueue(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetAnalysisQueueAsync());
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/reports
    //  返回所有分析报告（不含 content）
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetReports(
        HttpContext ctx, ReverseAgentService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetReportsAsync());
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/reports/{id}
    //  返回单条报告（含 content）
    // ═══════════════════════════════════════════════════════════════

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
}
