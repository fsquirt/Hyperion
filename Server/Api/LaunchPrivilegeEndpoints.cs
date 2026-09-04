using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 游戏启动权限策略管理端点，需登录。
///   GET /api/admin/launch  — 当前模式 { mode: "inherit" | "explorer" }
///   PUT /api/admin/launch  — 设置模式 body: { mode: "inherit" | "explorer" }
/// 模式经 /api/client/policies 的 launch 字段下发给 UserService。
/// </summary>
public static class LaunchPrivilegeEndpoints
{
    public static void MapLaunchPrivilegeApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/launch");
        g.MapGet("/", HandleGet);
        g.MapPut("/", HandleSet);
    }

    private static IResult HandleGet(HttpContext ctx, LaunchPrivilegeService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        return Results.Json(new { mode = svc.Mode });
    }

    private sealed class SetRequest
    {
        public string? Mode { get; set; }
    }

    private static IResult HandleSet(HttpContext ctx, LaunchPrivilegeService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = ctx.Request.ReadFromJsonAsync<SetRequest>().GetAwaiter().GetResult();
        if (req == null)
            return Results.Json(new { error = "请求体为空或格式错误" });

        if (!LaunchPrivilegeService.IsValidMode(req.Mode))
            return Results.Json(new { error = $"非法的启动权限模式: {req.Mode}" });

        svc.Set(req.Mode);
        return Results.Json(new { success = true, mode = svc.Mode });
    }
}
