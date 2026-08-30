using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 游戏进程保护能力策略管理端点(需登录)。
///   GET /api/admin/protect  — 当前五个保护开关状态
///   PUT /api/admin/protect  — 设置开关 body:
///       { handle_downgrade, image_load_monitor, thread_anti_debug, hide_existing_threads, drop_handles }
/// 开关经 /api/client/policies 的 protect 字段下发给 UserService,决定对游戏进程施加哪些保护。
/// </summary>
public static class GameProtectEndpoints
{
    public static void MapGameProtectApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/protect");
        g.MapGet("/", HandleGet);
        g.MapPut("/", HandleSet);
    }

    private static IResult HandleGet(HttpContext ctx, GameProtectService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        return Results.Json(new
        {
            handle_downgrade = svc.HandleDowngrade,
            image_load_monitor = svc.ImageLoadMonitor,
            thread_anti_debug = svc.ThreadAntiDebug,
            hide_existing_threads = svc.HideExistingThreads,
            drop_handles = svc.DropHandles,
        });
    }

    private sealed class SetRequest
    {
        public bool HandleDowngrade { get; set; }
        public bool ImageLoadMonitor { get; set; }
        public bool ThreadAntiDebug { get; set; }
        public bool HideExistingThreads { get; set; }
        public bool DropHandles { get; set; }
    }

    private static IResult HandleSet(HttpContext ctx, GameProtectService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = ctx.Request.ReadFromJsonAsync<SetRequest>().GetAwaiter().GetResult();
        if (req == null)
            return Results.Json(new { error = "请求体为空或格式错误" });

        svc.Set(req.HandleDowngrade, req.ImageLoadMonitor, req.ThreadAntiDebug,
                req.HideExistingThreads, req.DropHandles);

        return Results.Json(new
        {
            success = true,
            handle_downgrade = svc.HandleDowngrade,
            image_load_monitor = svc.ImageLoadMonitor,
            thread_anti_debug = svc.ThreadAntiDebug,
            hide_existing_threads = svc.HideExistingThreads,
            drop_handles = svc.DropHandles,
        });
    }
}
