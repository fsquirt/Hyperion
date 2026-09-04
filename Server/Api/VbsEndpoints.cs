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
        app.MapGet("/api/vbs/history/{id}", HandleHistoryDetail);
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
            //    方案C 可选: 客户端无 GetRuntimeAttestationReport 导出时不提交,
            //    A+D 即可确认 VBS 运行态; 有导出则必须提交并验证
            string cMark = !rr.Present ? "—(未提交: 客户端无 GetRuntimeAttestationReport 或系统不支持)"
                         : rr.Valid ? "✔(nonce 绑定 + digest 一致)"
                         : "✘(已提交但校验未通过)";
            string verdict;
            if (claimResult.Verified && popValid && rr.Valid)
                verdict = "PASS — 方案A✔ VBS Root Claim 链验证通过 (IDKS/VTL1, nonce 绑定), 方案D✔ PoP 签名验证通过 (VTL1 密钥持有), 方案C✔ 运行时报告有效 " + cMark + " → HVCI 正在运行";
            else if (claimResult.Verified && popValid && !rr.Present)
                verdict = "PASS(PARTIAL) — 方案A✔ VBS Root Claim 链验证通过 (IDKS/VTL1, nonce 绑定), 方案D✔ PoP 签名验证通过 → VBS 正在运行; 方案C" + cMark + " → HVCI 运行态未证明";
            else if (claimResult.Verified && popValid)
                verdict = "FAIL — 方案A✔ 方案D✔, 但方案C" + cMark + " → HVCI 运行态存疑";
            else if (!popValid)
                verdict = "FAIL — 方案D✘ PoP 签名验证失败 (无法证明 VTL1 密钥持有); 方案A=" + (claimResult.Verified ? "✔" : "✘");
            else if (claimResult.Status == unchecked((int)0x80090029))
                verdict = "FAIL — 方案A✘ NTE_NOT_SUPPORTED: Secure Kernel 未运行 (VBS 未启动/不支持)";
            else
                verdict = $"FAIL — 方案A✘ claim 验证失败: 0x{claimResult.Status:X8}";

            var schemes = new
            {
                // 方案A: NCryptVerifyClaim 远程验证 VBS Root Claim (IDKS/VTL1 签名链)
                A_claim_chain = new { verified = claimResult.Verified, nonce_bound = claimResult.Details?.ToString()?.Contains("without nonce") != true },
                // 方案D: PoP 签名 (公钥提取自 claim Attributes, 覆盖 session_id+nonce+claimHash)
                D_pop_signature = new { valid = popValid },
                // 方案C: GetRuntimeAttestationReport 运行时报告 (可选 — 无导出时跳过)
                C_runtime_report = new { submitted = runtimeReport != null, present = rr.Present, valid = rr.Valid },
            };

            var driverReport = new
            {
                count = rr.DriverCount,
                boot = rr.BootCount,
                unloaded = rr.UnloadedCount,
                digest_verification = rr.DigestVerification,
                nonce_match = rr.NonceMatch,
                signature_scheme = rr.SignatureScheme,
                // 全部驱动明细 (与 hvci_runtime_report.reports 同源)
                drivers = rr.DriverReport?.Drivers.Select(d => new
                {
                    d.Name, d.Boot, d.Unloaded, d.LoadTimes, d.Oem, d.ImageHash, d.PublisherThumbprint,
                }),
            };

            var payload = new
            {
                verdict,
                schemes,
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
                driver_report = driverReport,
                hvci_runtime_report = rr.Payload,
            };

            // 7. 入库 (仪表盘"运行时检测"菜单)
            var entry = new VbsVerifyHistoryEntity
            {
                Id = Guid.NewGuid().ToString("N")[..12],
                Timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ClientIp = http.Connection.RemoteIpAddress?.ToString() ?? "",
                ClaimVerified = claimResult.Verified ? 1 : 0,
                PopValid = popValid ? 1 : 0,
                ReportPresent = rr.Present ? 1 : 0,
                ReportValid = rr.Valid ? 1 : 0,
                NonceMatch = rr.NonceMatch ? 1 : 0,
                DriverCount = rr.DriverCount,
                Verdict = verdict.Split('—')[0].Trim(),
                ResultJson = System.Text.Json.JsonSerializer.Serialize(payload),
            };
            store.VbsVerifyHistory.Add(entry);
            await store.SaveChangesAsync();

            logger.LogInformation("[vbs/verify] {Verdict} claimOk={ClaimOk} pop={Pop} report={Report} drivers={Drivers} unloaded={Unloaded}",
                entry.Verdict, claimResult.Verified, popValid, rr.Valid, rr.DriverCount, rr.UnloadedCount);

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

    // ═══════════════════════════════════════════════════════════════
    //  GET /api/vbs/history/{id} — 单条完整详情 (含全部驱动明细)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleHistoryDetail(string id, AttestationDbContext store)
    {
        var h = store.VbsVerifyHistory.FirstOrDefault(x => x.Id == id);
        if (h == null) return Results.Json(new { error = "not found" }, statusCode: 404);
        return Results.Content(h.ResultJson, "application/json");
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
