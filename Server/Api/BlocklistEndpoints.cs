using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 恶意驱动阻止列表 API 端点
/// </summary>
public static class BlocklistEndpoints
{
    public static void MapBlocklistApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/blocklist");

        g.MapGet("/", HandleList);
        g.MapGet("/stats", HandleStats);
        g.MapPost("/update-loldrivers", HandleUpdateLoldrivers);
        g.MapPost("/update-msft", HandleUpdateMsft);
        g.MapPost("/upload-sys", HandleUploadSys);
        g.MapPost("/add-hash", HandleAddByHash);
        g.MapPut("/{id}", HandleUpdate);
        g.MapDelete("/{id}", HandleDelete);
    }

    
    //  GET /api/admin/blocklist?source=&search=&page=&pageSize=
    private static async Task<IResult> HandleList(
        HttpContext ctx,
        BlocklistService svc,
        string? source = null,
        string? search = null,
        int page = 1,
        int pageSize = 50)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        if (pageSize > 500) pageSize = 500;
        var (rows, total) = await svc.QueryAsync(source, search, page, pageSize);
        return Results.Json(new { rows, total, page, pageSize });
    }

    
    //  GET /api/admin/blocklist/stats
    private static async Task<IResult> HandleStats(
        HttpContext ctx,
        BlocklistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();
        return Results.Json(await svc.GetStatsAsync());
    }

    
    //  POST /api/admin/blocklist/update-loldrivers
    //  可选 ?local=true 仅解析本地文件不联网
    private static async Task<IResult> HandleUpdateLoldrivers(
        HttpContext ctx,
        BlocklistService svc,
        bool local = false)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var result = await svc.UpdateLoldriversAsync(fetchFromUrl: !local);
        return Results.Json(result);
    }

    
    //  POST /api/admin/blocklist/update-msft
    //  可选 ?local=true 仅解析本地文件不联网
    private static async Task<IResult> HandleUpdateMsft(
        HttpContext ctx,
        BlocklistService svc,
        bool local = false)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var result = await svc.UpdateMsftAsync(fetchFromUrl: !local);
        return Results.Json(result);
    }

    
    //  POST /api/admin/blocklist/upload-sys
    //  multipart/form-data: file=xxx.sys [,notes=...]
    private static async Task<IResult> HandleUploadSys(
        HttpContext ctx,
        BlocklistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var form = await ctx.Request.ReadFormAsync();
        var file = form.Files.FirstOrDefault();
        if (file == null || file.Length == 0)
            return Results.Json(new ManualBlockResult { Error = "未上传文件" });

        // 限制 100MB
        if (file.Length > 100 * 1024 * 1024)
            return Results.Json(new ManualBlockResult { Error = "文件过大 (>100MB)" });

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var bytes = ms.ToArray();

        var notes = form["notes"].FirstOrDefault();
        var result = await svc.AddManualAsync(bytes, file.FileName, notes);
        return Results.Json(result);
    }

    
    //  POST /api/admin/blocklist/add-hash
    //  body: { driver_name, md5?, sha1?, sha256?, notes? }
    private static async Task<IResult> HandleAddByHash(
        HttpContext ctx,
        BlocklistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = await ctx.Request.ReadFromJsonAsync<ManualHashAddRequest>();
        if (req == null)
            return Results.Json(new ManualBlockResult { Error = "请求体为空或格式错误" });

        var result = await svc.AddManualByHashAsync(
            req.DriverName, req.Md5, req.Sha1, req.Sha256, req.Notes);
        return Results.Json(result);
    }

    
    //  PUT /api/admin/blocklist/{id}
    //  body: { driver_name?, md5?, sha1?, sha256?, notes? }
    private static async Task<IResult> HandleUpdate(
        HttpContext ctx,
        string id,
        BlocklistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = await ctx.Request.ReadFromJsonAsync<BlocklistUpdateRequest>();
        if (req == null)
            return Results.Json(new ManualBlockResult { Error = "请求体为空或格式错误" });

        var result = await svc.UpdateAsync(
            id, req.DriverName, req.Md5, req.Sha1, req.Sha256, req.Notes);
        return Results.Json(result);
    }

    
    //  DELETE /api/admin/blocklist/{id}
    private static async Task<IResult> HandleDelete(
        HttpContext ctx,
        string id,
        BlocklistService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var ok = await svc.DeleteAsync(id);
        return ok ? Results.Ok(new { success = true }) : Results.NotFound(new { error = "not found" });
    }
}
