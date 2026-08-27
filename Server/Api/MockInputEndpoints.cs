using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 模拟键鼠策略管理端点(需登录)。
///   GET /api/admin/mockinput  — 当前开关状态
///   PUT /api/admin/mockinput  — 设置开关 body: { report: bool, block: bool }
/// 开关经 /api/client/policies 的 mock_input 字段下发给 UserService。
/// </summary>
public static class MockInputEndpoints
{
    public static void MapMockInputApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/admin/mockinput");
        g.MapGet("/", HandleGet);
        g.MapPut("/", HandleSet);
    }

    private static IResult HandleGet(HttpContext ctx, MockInputService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        return Results.Json(new { report = svc.Report, block = svc.Block });
    }

    private sealed class SetRequest
    {
        public bool Report { get; set; }
        public bool Block { get; set; }
    }

    private static IResult HandleSet(HttpContext ctx, MockInputService svc)
    {
        if (ctx.Session.GetString("authenticated") != "true")
            return Results.Unauthorized();

        var req = ctx.Request.ReadFromJsonAsync<SetRequest>().GetAwaiter().GetResult();
        if (req == null)
            return Results.Json(new { error = "请求体为空或格式错误" });

        svc.Set(req.Report, req.Block);
        return Results.Json(new { success = true, report = svc.Report, block = svc.Block });
    }
}
