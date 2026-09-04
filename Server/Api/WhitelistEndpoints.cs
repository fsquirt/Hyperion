using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 附着白名单 API 端点
/// </summary>
public static class WhitelistEndpoints
{
    public static void MapWhitelistApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/whitelist");

        g.MapGet("/", HandleList);
        g.MapGet("/stats", HandleStats);
        g.MapPost("/upload-sys", HandleUploadSys);      // 上传 sys 解析多签名，返回结果供选择
        g.MapPost("/add-hash", HandleAddByHash);         // 按哈希添加
        g.MapPost("/add-cert", HandleAddByCert);         // 按证书添加
        g.MapPut("/{id}", HandleUpdate);
        g.MapDelete("/{id}", HandleDelete);
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/whitelist?type=&search=&page=&pageSize=
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleList(
        HttpContext ctx,
        WhitelistService svc,
        string? type = null,
        string? search = null,
        int page = 1,
        int pageSize = 50)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        if (pageSize > 500) pageSize = 500;
        var (rows, total) = await svc.QueryAsync(type, search, page, pageSize);
        return Results.Json(new { rows, total, page, pageSize });
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/admin/whitelist/stats
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleStats(
        HttpContext ctx,
        WhitelistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetStatsAsync());
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/admin/whitelist/upload-sys
    //  上传 .sys,返回解析结果，含哈希与多签名列表
    //  注意:此处只解析不写入,由前端让管理员选择后再调 add-hash 或 add-cert
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleUploadSys(
        HttpContext ctx,
        WhitelistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var form = await ctx.Request.ReadFormAsync();
        var file = form.Files.FirstOrDefault();
        if (file == null || file.Length == 0)
            return Results.Json(new SysParseResult { Error = "未上传文件" });
        if (file.Length > 100 * 1024 * 1024)
            return Results.Json(new SysParseResult { Error = "文件过大 (>100MB)" });

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var bytes = ms.ToArray();

        var result = await svc.ParseSysAsync(bytes, file.FileName);
        return Results.Json(result);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/admin/whitelist/add-hash
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleAddByHash(
        HttpContext ctx,
        WhitelistService svc,
        WhitelistAddHashRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.AddHashAsync(req);
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/admin/whitelist/add-cert
    //  前端在上传 sys 后,从返回的 signers 列表里选一个,把其
    //  subject + thumbprint_sha256 提交到这里。
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleAddByCert(
        HttpContext ctx,
        WhitelistService svc,
        WhitelistAddCertRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.AddCertAsync(req);
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }

    // ═══════════════════════════════════════════════════════════════
    //  PUT /api/admin/whitelist/{id}   — 只允许改 display_name / notes
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleUpdate(
        HttpContext ctx,
        WhitelistService svc,
        string id,
        WhitelistUpdateRequest req)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        var result = await svc.UpdateAsync(id, req);
        return result.Success ? Results.Json(result) : Results.BadRequest(result);
    }

    // ═══════════════════════════════════════════════════════════════
    //  DELETE /api/admin/whitelist/{id}
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleDelete(
        HttpContext ctx,
        WhitelistService svc,
        string id)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return await svc.DeleteAsync(id) ? Results.Ok() : Results.NotFound();
    }
}
