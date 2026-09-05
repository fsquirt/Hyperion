using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 危险内核函数列表 API 端点
/// </summary>
public static class KernelFuncEndpoints
{
    public static void MapKernelFuncApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/kernel-funcs");

        g.MapGet("/", HandleList);
        g.MapGet("/stats", HandleStats);
        g.MapPost("/", HandleAdd);                    // 添加
        g.MapPut("/{id}", HandleUpdate);
        g.MapDelete("/{id}", HandleDelete);
        g.MapPost("/reset-defaults", HandleReset);    // 恢复默认 4 个
    }

    //  GET /api/admin/kernel-funcs?search=&category=&severity=&enabled=&page=&pageSize=
    private static async Task<IResult> HandleList(
        HttpContext ctx,
        KernelFuncService svc,
        string? search = null,
        string? category = null,
        string? severity = null,
        bool? enabled = null,
        int page = 1,
        int pageSize = 100)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        if (pageSize > 500) pageSize = 500;
        var (rows, total) = await svc.QueryAsync(search, category, severity, enabled, page, pageSize);
        return Results.Json(new { rows, total, page, pageSize });
    }

    
    //  GET /api/admin/kernel-funcs/stats
    private static async Task<IResult> HandleStats(
        HttpContext ctx,
        KernelFuncService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetStatsAsync());
    }

    
    //  POST /api/admin/kernel-funcs
    private static async Task<IResult> HandleAdd(
        HttpContext ctx,
        KernelFuncService svc,
        KernelFuncAddRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.AddAsync(req);
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }

    
    //  PUT /api/admin/kernel-funcs/{id}
    private static async Task<IResult> HandleUpdate(
        HttpContext ctx,
        KernelFuncService svc,
        string id,
        KernelFuncUpdateRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.UpdateAsync(id, req);
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }

    
    //  DELETE /api/admin/kernel-funcs/{id}
    private static async Task<IResult> HandleDelete(
        HttpContext ctx,
        KernelFuncService svc,
        string id)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return await svc.DeleteAsync(id) ? Results.Ok() : Results.NotFound();
    }

    
    //  POST /api/admin/kernel-funcs/reset-defaults
    //  清空所有,塞入默认 4 个
    private static async Task<IResult> HandleReset(
        HttpContext ctx,
        KernelFuncService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.ResetToDefaultsAsync();
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }
}
