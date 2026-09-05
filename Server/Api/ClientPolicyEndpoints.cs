using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 客户端策略接口，无需鉴权。
///
/// 供 UserService 在启动时拉取服务端下发的策略配置，内容只读、非敏感:
///   - 危险内核函数列表，仅含启用中的条目
///   - 附着白名单，覆盖 hash 维度与证书维度
///
/// 设计为无需登录即可访问:这些本就是客户端需要"应用"的配置,
/// 不含任何账号/凭据信息。若未来需要防滥用,可在此叠加来源 IP 限流或共享密钥。
/// </summary>
public static class ClientPolicyEndpoints
{
    public static void MapClientPolicyApi(this WebApplication app)
    {
        var g = app.MapGroup("/api/client");
        g.MapGet("/policies", HandlePolicies);
        g.MapGet("/sipolicy.p7b", HandleDownloadP7b);
    }

    private static async Task<IResult> HandlePolicies(
        KernelFuncService kfuncSvc,
        WhitelistService whitelistSvc,
        SiPolicyService siPolicySvc,
        MockInputService mockInputSvc,
        LaunchPrivilegeService launchSvc,
        GameProtectService protectSvc)
    {
        var funcs = await kfuncSvc.GetEnabledEntriesAsync();
        var (md5, sha1, sha256, certSubjects, certThumbs) = whitelistSvc.GetAll();

        var resp = new ClientPolicyResponse
        {
            KernelFuncs = funcs.ConvertAll(f => new ClientKernelFuncDto
            {
                FuncName = f.FuncName,
                DisplayName = f.DisplayName,
                Category = f.Category,
                Severity = f.Severity.ToString(),
            }),
            Whitelist = new ClientWhitelistDto
            {
                Hashes = new ClientHashWhitelistDto
                {
                    Md5 = md5,
                    Sha1 = sha1,
                    Sha256 = sha256,
                },
                Certs = new ClientCertWhitelistDto
                {
                    Subjects = certSubjects,
                    ThumbprintsSha256 = certThumbs,
                },
            },
            SiPolicy = new ClientSiPolicyDto
            {
                Enabled = siPolicySvc.Enabled,
            },
            MockInput = new ClientMockInputDto
            {
                Report = mockInputSvc.Report,
                Block = mockInputSvc.Block,
            },
            Launch = new ClientLaunchDto
            {
                Mode = launchSvc.Mode,
            },
            Protect = new ClientProtectDto
            {
                HandleDowngrade = protectSvc.HandleDowngrade,
                ImageLoadMonitor = protectSvc.ImageLoadMonitor,
                ThreadAntiDebug = protectSvc.ThreadAntiDebug,
                HideExistingThreads = protectSvc.HideExistingThreads,
                DropHandles = protectSvc.DropHandles,
            },
            FetchedAt = DateTime.UtcNow.ToString("o"),
        };

        return Results.Json(resp);
    }

    
    //  GET /api/client/sipolicy.p7b — 下载微软漏洞驱动 WDAC 策略二进制
    //  开关关闭时 UserService 不应调用; 此处仍返回文件以保持端点无状态
    private static IResult HandleDownloadP7b(SiPolicyService siPolicySvc)
    {
        var bytes = siPolicySvc.ReadP7b();
        if (bytes == null)
            return Results.NotFound(new { error = "SiPolicy_Enforced_LegacyFormat.p7b 不存在,请先在管理端执行微软列表更新" });

        return Results.File(bytes, "application/octet-stream", "SiPolicy.p7b");
    }
}
