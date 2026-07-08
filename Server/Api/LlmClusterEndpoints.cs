using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 集群端 API — 供集群内机器(Tracker / Verifyer / AI Agent)调用。
///
/// 认证方式:Authorization: Bearer &lt;token&gt;
/// token 在 Web 后台 "大模型 API 配置 → 访问凭据" tab 创建。
///
/// 路径:/api/cluster/llm-apis
///   GET — 返回启用中的 LLM API 列表(按 priority 升序),含完整 api_key
/// </summary>
public static class LlmClusterEndpoints
{
    public static void MapLlmClusterApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/cluster");

        // GET /api/cluster/llm-apis
        // 返回可用的大模型 API 列表(含完整 api_key)
        g.MapGet("/llm-apis", HandleGetLlmApis);
    }

    private static async Task<IResult> HandleGetLlmApis(
        HttpContext ctx, LlmApiService svc)
    {
        // Bearer token 认证
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!await svc.ValidateCredentialAsync(auth))
        {
            return Results.Json(
                new { error = "invalid credential", message = "访问凭据无效或已禁用" },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var apis = await svc.GetClusterLlmApisAsync();
        return Results.Json(new
        {
            count = apis.Count,
            apis = apis,
            fetched_at = DateTime.UtcNow.ToString("o"),
        });
    }
}
