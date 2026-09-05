using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 大模型 API 配置 + 访问凭据 管理端 API 端点，采用 session 认证。
/// </summary>
public static class LlmApiEndpoints
{
    public static void MapLlmApiApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/llm-apis");

        //  LLM API CRUD 
        g.MapGet("/", HandleListApis);
        g.MapGet("/stats", HandleApiStats);
        g.MapPost("/", HandleAddApi);
        g.MapPut("/{id}", HandleUpdateApi);
        g.MapDelete("/{id}", HandleDeleteApi);
        g.MapPost("/{id}/test", HandleTestApi);

        //  访问凭据 CRUD 
        g.MapGet("/credentials", HandleListCreds);
        g.MapGet("/credentials/stats", HandleCredStats);
        g.MapPost("/credentials", HandleAddCred);
        g.MapPut("/credentials/{id}", HandleUpdateCred);
        g.MapDelete("/credentials/{id}", HandleDeleteCred);
    }

    private static bool IsAuthed(HttpContext ctx) =>
        ctx.Session.GetString("authenticated") == "true";

    
    //  LLM API
    private static async Task<IResult> HandleListApis(
        HttpContext ctx, LlmApiService svc,
        string? search = null, string? provider = null,
        bool? enabled = null, int page = 1, int pageSize = 100)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        if (pageSize > 500) pageSize = 500;
        var (rows, total) = await svc.QueryApisAsync(search, provider, enabled, page, pageSize);
        return Results.Json(new { rows, total, page, pageSize });
    }

    private static async Task<IResult> HandleApiStats(
        HttpContext ctx, LlmApiService svc)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        return Results.Json(await svc.GetApiStatsAsync());
    }

    private static async Task<IResult> HandleAddApi(
        HttpContext ctx, LlmApiService svc, LlmApiAddRequest req)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        var r = await svc.AddApiAsync(req);
        return r.Success ? Results.Json(r) : Results.BadRequest(r);
    }

    private static async Task<IResult> HandleUpdateApi(
        HttpContext ctx, LlmApiService svc, string id, LlmApiUpdateRequest req)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        var r = await svc.UpdateApiAsync(id, req);
        return r.Success ? Results.Json(r) : Results.BadRequest(r);
    }

    private static async Task<IResult> HandleDeleteApi(
        HttpContext ctx, LlmApiService svc, string id)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        return await svc.DeleteApiAsync(id) ? Results.Ok() : Results.NotFound();
    }

    private static async Task<IResult> HandleTestApi(
        HttpContext ctx, LlmApiService svc, string id)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        var (success, response, error) = await svc.TestApiAsync(id);
        return Results.Json(new { success, response, error });
    }

    
    //  访问凭据
    private static async Task<IResult> HandleListCreds(
        HttpContext ctx, LlmApiService svc,
        string? search = null, bool? enabled = null,
        int page = 1, int pageSize = 100)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        if (pageSize > 500) pageSize = 500;
        var (rows, total) = await svc.QueryCredentialsAsync(search, enabled, page, pageSize);
        return Results.Json(new { rows, total, page, pageSize });
    }

    private static async Task<IResult> HandleCredStats(
        HttpContext ctx, LlmApiService svc)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        return Results.Json(await svc.GetCredentialStatsAsync());
    }

    private static async Task<IResult> HandleAddCred(
        HttpContext ctx, LlmApiService svc, LlmCredentialAddRequest req)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        var r = await svc.AddCredentialAsync(req);
        return r.Success ? Results.Json(r) : Results.BadRequest(r);
    }

    private static async Task<IResult> HandleUpdateCred(
        HttpContext ctx, LlmApiService svc, string id,
        string? name, bool? enabled, string? notes)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        var r = await svc.UpdateCredentialAsync(id, enabled, name, notes);
        return r.Success ? Results.Json(r) : Results.BadRequest(r);
    }

    private static async Task<IResult> HandleDeleteCred(
        HttpContext ctx, LlmApiService svc, string id)
    {
        if (!IsAuthed(ctx)) return Results.Unauthorized();
        return await svc.DeleteCredentialAsync(id) ? Results.Ok() : Results.NotFound();
    }
}
