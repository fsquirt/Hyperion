using Hyperion.Server.Data;
using Hyperion.Server.Services;
using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;

namespace Hyperion.Server.Api;

/// <summary>
/// VBS/HVCI 运行态检测 API (接收来自 VBSRemoteDetect 客户端的请求)。
///
///   GET  /api/vbs/challenge → { session_id, nonce }   32B challenge, 5 分钟有效
///   POST /api/vbs/verify    → 验证 claim + PoP + 运行时报告, 结果入库
///   GET  /api/vbs/history   → 最近 50 条验证历史 (仪表盘"运行时检测"菜单)
///
/// 与 TPM 证明链的关系: nonce 与 /request_nonce 的 challenge 相互独立;
/// 若客户端是 Hyperion.Verifier (C#), 建议改走 /verify_vbs (带 history_id
/// 关联 TPM 证明链); VBSRemoteDetect (C++) 走本组独立端点。
/// </summary>
public static class VbsEndpoints
{
    private sealed record VbsSession(byte[] Nonce, DateTime Created);
    private static readonly ConcurrentDictionary<string, VbsSession> Sessions = new();
    private static readonly TimeSpan SessionTimeout = TimeSpan.FromMinutes(5);

    public static void MapVbsApi(this WebApplication app)
    {
        app.MapGet("/api/vbs/challenge", HandleChallenge);
        app.MapPost("/api/vbs/verify", HandleVerify);
        app.MapGet("/api/vbs/history", HandleHistory);
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/vbs/challenge
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleChallenge()
    {
        var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var sessionId = Guid.NewGuid().ToString("N");
        Sessions[sessionId] = new VbsSession(nonce, DateTime.UtcNow.AddMinutes(5));
        foreach (var kv in Sessions) if (kv.Value.Created < DateTime.UtcNow) Sessions.TryRemove(kv.Key, out _);

        return Results.Json(new
        {
            session_id = sessionId,
            nonce = Convert.ToBase64String(nonce),
            expires_in_seconds = 300,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/vbs/verify
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleVerify(
        VbsVerifyRequest req, AttestationDbContext store, HttpContext http, ILogger<Program> logger)
    {
        try
        {
            // 1. 会话校验
            if (string.IsNullOrEmpty(req.SessionId) ||
                !Sessions.TryRemove(req.SessionId, out var session) || session.Created < DateTime.UtcNow)
                return Results.Json(new { verdict = "FAIL", reason = "session invalid or expired" });

            // 2. 解码提交材料
            byte[]? claimBlob = B64(req.ClaimBlob);
            byte[]? signature = B64(req.Signature);
            byte[]? runtimeReport = string.IsNullOrEmpty(req.RuntimeReport) ? null : Convert.FromBase64String(req.RuntimeReport);

            // 3. A: NCryptVerifyClaim 远程验证 (claim nonce = challenge, KSP 校验绑定)
            var claimResult = VbsRuntimeVerifier.VerifyVbsRootClaim(claimBlob, B64(req.AttestPub), session.Nonce);

            // 4. D: PoP 签名验证 (公钥从 claim Attributes 的 SPKI 提取, 覆盖 session_id+nonce+claimHash)
            var (popValid, popNote) = VbsRuntimeVerifier.VerifyPop(
                claimBlob, signature, req.SessionId, session.Nonce);

            // 5. C: 运行时报告解析
            var rr = runtimeReport is { Length: > 0 }
                ? VbsRuntimeVerifier.ParseRuntimeReport(runtimeReport, session.Nonce)
                : new VbsRuntimeVerifier.RuntimeReportInfo(false, false,
                    new { present = false, note = "not submitted" });

            bool claimMagicOk = claimBlob is { Length: > 100 } &&
                BitConverter.ToUInt32(claimBlob, 0) == 0x53414B56;

            // 6. 综合判定 — 全部服务器侧验证, 客户端自报字段不参与
            string verdict;
            if (claimResult.Verified && popValid && rr.Valid)
                verdict = "PASS — VBS/HVCI 运行态确认: claim 链验证通过 (IDKS/VTL1, nonce 绑定), 运行时报告有效 (nonce 绑定 + digest 一致)";
            else if (claimResult.Verified && popValid)
                verdict = "PARTIAL — VBS 运行态确认 (claim 链验证通过); 运行时报告无效或未提交 (HVCI 运行态未证明)";
            else if (!popValid)
                verdict = "FAIL — PoP 签名验证失败 (无法证明 VTL1 密钥持有)";
            else if (claimResult.Status == unchecked((int)0x80090029))
                verdict = "FAIL — NTE_NOT_SUPPORTED: Secure Kernel 未运行 (VBS 未启动/不支持)";
            else
                verdict = $"FAIL — claim 验证失败: 0x{claimResult.Status:X8}";

            var payload = new
            {
                verdict,
                session_id = req.SessionId,
                claim = new
                {
                    verified = claimResult.Verified,
                    status = $"0x{claimResult.Status:X8}",
                    claim_blob_size = claimBlob?.Length ?? 0,
                    claimMagicOk,
                    claimResult.Details
                },
                pop = new { valid = popValid, note = popNote },
                vbs_running = claimResult.Verified && popValid,
                hvci_runtime_report = rr.Payload,
            };

            // 7. 入库 (仪表盘"运行时检测"菜单)
            int driverCount = 0;
            try
            {
                if (rr.Payload.GetType().GetProperty("reports") is { } reportsProp &&
                    reportsProp.GetValue(rr.Payload) is System.Collections.IEnumerable list)
                    foreach (var item in list)
                        if (item!.GetType().GetProperty("driverCount") is { } dc &&
                            dc.GetValue(item) is int count) { driverCount = count; break; }
            }
            catch { }

            var entry = new VbsVerifyHistoryEntity
            {
                Id = Guid.NewGuid().ToString("N")[..12],
                Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ClientIp = http.Connection.RemoteIpAddress?.ToString() ?? "",
                ClaimVerified = claimResult.Verified ? 1 : 0,
                PopValid = popValid ? 1 : 0,
                ReportPresent = rr.Present ? 1 : 0,
                ReportValid = rr.Valid ? 1 : 0,
                NonceMatch = (bool)(rr.Payload.GetType().GetProperty("nonceMatch")?.GetValue(rr.Payload) ?? false) ? 1 : 0,
                DriverCount = driverCount,
                Verdict = verdict.Split('—')[0].Trim(),
                ResultJson = System.Text.Json.JsonSerializer.Serialize(payload),
            };
            store.VbsVerifyHistory.Add(entry);
            await store.SaveChangesAsync();

            logger.LogInformation("[vbs/verify] {Verdict} claimOk={ClaimOk} pop={Pop} reportValid={ReportValid}",
                entry.Verdict, claimResult.Verified, popValid, rr.Valid);

            return Results.Json(payload);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "vbs/verify error");
            return Results.Json(new { verdict = "FAIL", reason = ex.Message });
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/vbs/history — 仪表盘历史列表
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleHistory(AttestationDbContext store)
    {
        var items = await store.VbsVerifyHistory
            .OrderByDescending(h => h.Timestamp)
            .Take(50)
            .ToListAsync();
        return Results.Json(items.Select(h => new
        {
            id = h.Id,
            timestamp = h.Timestamp,
            client_ip = h.ClientIp,
            claim_verified = h.ClaimVerified == 1,
            pop_valid = h.PopValid == 1,
            report_present = h.ReportPresent == 1,
            report_valid = h.ReportValid == 1,
            nonce_match = h.NonceMatch == 1,
            driver_count = h.DriverCount,
            verdict = h.Verdict,
        }));
    }

    static byte[]? B64(string? s) =>
        string.IsNullOrEmpty(s) ? null : Convert.FromBase64String(s);

    public sealed record VbsVerifyRequest(
        [property: System.Text.Json.Serialization.JsonPropertyName("session_id")] string SessionId,
        [property: System.Text.Json.Serialization.JsonPropertyName("claim_blob")] string ClaimBlob,
        [property: System.Text.Json.Serialization.JsonPropertyName("attest_pub")] string AttestPub,
        [property: System.Text.Json.Serialization.JsonPropertyName("signature")] string Signature,
        [property: System.Text.Json.Serialization.JsonPropertyName("runtime_report")] string RuntimeReport);
}
