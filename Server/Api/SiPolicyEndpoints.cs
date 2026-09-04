using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// SiPolicy.p7b 管理端点，需登录。
///   GET /api/admin/sipolicy        — 开关状态 + 服务器上 p7b 文件状态
///   PUT /api/admin/sipolicy        — 设置开关 body: { enabled: bool }
/// p7b 文件本体由 /api/client/sipolicy.p7b 下发给 UserService。
/// </summary>
public static class SiPolicyEndpoints
{
    public static void MapSiPolicyApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/sipolicy");
        g.MapGet("/", HandleGet);
        g.MapPut("/", HandleSet);
    }

    private static IResult HandleGet(HttpContext ctx, SiPolicyService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        return Results.Json(new
        {
            enabled = svc.Enabled,
            file = svc.GetFileInfo(),
        });
    }

    private sealed class SetRequest
    {
        public bool Enabled { get; set; }
    }

    private static IResult HandleSet(HttpContext ctx, SiPolicyService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = ctx.Request.ReadFromJsonAsync<SetRequest>().GetAwaiter().GetResult();
        if (req == null)
            return Results.Json(new { error = "请求体为空或格式错误" });

        svc.SetEnabled(req.Enabled);
        return Results.Json(new { success = true, enabled = svc.Enabled });
    }
}
