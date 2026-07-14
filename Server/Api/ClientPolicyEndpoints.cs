using Hyperion.Server.Models;
using Hyperion.Server.Services;

namespace Hyperion.Server.Api;

/// <summary>
/// 客户端策略接口(无需鉴权)。
///
/// 供 UserService 在启动时拉取服务端下发的策略配置(只读、非敏感):
///   - 危险内核函数列表(启用中的)
///   - 附着白名单(hash 维度 + 证书维度)
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
    }

    private static async Task<IResult> HandlePolicies(
        KernelFuncService kfuncSvc,
        WhitelistService whitelistSvc)
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
            FetchedAt = DateTime.UtcNow.ToString("o"),
        };

        return Results.Json(resp);
    }
}
