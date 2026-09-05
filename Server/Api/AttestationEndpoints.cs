using Hyperion.Server.Data;
using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Security.Cryptography.X509Certificates;

namespace Hyperion.Server.Api;

/// <summary>
/// 远程证明 API 端点，兼容现有 C# 客户端
/// </summary>
public static class AttestationEndpoints
{
    public static void MapAttestationApi(this WebApplication app)
    {
        app.MapPost("/verify_chain", HandleVerifyChain);
        app.MapPost("/make_credential", HandleMakeCredential);
        app.MapPost("/verify", HandleVerify);
        app.MapPost("/request_nonce", HandleRequestNonce);
        app.MapPost("/verify_quote", HandleVerifyQuote);
        app.MapPost("/verify_certs", HandleVerifyCerts);
        app.MapPost("/verify_drivers", HandleVerifyDrivers);
        app.MapPost("/verify_vbs", HandleVerifyVbs);
    }

    //  POST /api/verify_chain
    private static async Task<IResult> HandleVerifyChain(
        VerifyChainRequest req,
        CertificateVerifier certVerifier,
        SqliteStore store,
        ILogger<Program> logger)
    {
        if (req.Certs.Count == 0)
            return Results.Json(new VerifyChainResponse { Reason = "no certificates provided" });

        try
        {
            // 解析 DER 证书
            var certs = new List<X509Certificate2>();
            foreach (var b64 in req.Certs)
            {
                var der = Convert.FromBase64String(b64);
                certs.Add(X509CertificateLoader.LoadCertificate(der));
            }

            var (success, chain, reason) = certVerifier.BuildChain(certs);

            if (success)
            {
                // 计算 EK 指纹并注册
                var spki = CertificateVerifier.GetSpkiDer(certs[0]);
                var fp = SqliteStore.EkFingerprint(spki);
                await store.StoreEkAsync(fp, certs[0].Subject);
                logger.LogInformation("EK registered: {Fingerprint}", fp[..16]);

                return Results.Json(new VerifyChainResponse
                {
                    Result = "success",
                    Chain = chain,
                    Reason = reason,
                    EkFingerprint = fp
                });
            }

            return Results.Json(new VerifyChainResponse
            {
                Result = "fail",
                Chain = chain,
                Reason = reason
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify_chain error");
            return Results.Json(new VerifyChainResponse { Reason = ex.Message });
        }
    }

    
    //  POST /api/make_credential
    private static async Task<IResult> HandleMakeCredential(
        MakeCredentialRequest req,
        AttestationSessionStore sessions,
        SqliteStore store,
        ILogger<Program> logger)
    {
        try
        {
            var ekPubDer = Convert.FromBase64String(req.EkPub);
            var akName = Convert.FromBase64String(req.AkName);

            // 验证 EK 已注册
            var fp = SqliteStore.EkFingerprint(ekPubDer);
            if (!await store.IsEkRegisteredAsync(fp))
                return Results.Json(new { result = "fail", reason = "EK not registered" }, statusCode: 403);

            // 生成随机 secret 和会话
            var secret = RandomNumberGenerator.GetBytes(32);
            var sid = sessions.CreateMcSession(secret, Convert.ToHexString(akName).ToLowerInvariant(), fp);

            // MakeCredential
            var (credentialBlob, encSecret) = Tpm2Crypto.MakeCredential(ekPubDer, akName, secret);

            logger.LogInformation("MakeCredential session created: {Sid}", sid[..16]);

            return Results.Json(new MakeCredentialResponse
            {
                SessionId = sid,
                CredentialBlob = Convert.ToBase64String(credentialBlob),
                EncryptedSecret = Convert.ToBase64String(encSecret)
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "make_credential error");
            return Results.Json(new { result = "fail", reason = ex.Message });
        }
    }

    
    //  POST /api/verify — 执行 ActivateCredential 验证
    private static async Task<IResult> HandleVerify(
        VerifyRequest req,
        AttestationSessionStore sessions,
        SqliteStore store,
        ILogger<Program> logger)
    {
        var session = sessions.PopMcSession(req.SessionId);
        if (session == null)
            return Results.Json(new { result = "fail", reason = "unknown or expired session" });

        try
        {
            var receivedSecret = Convert.FromBase64String(req.Secret);

            // 常量时间比较
            if (!CryptographicOperations.FixedTimeEquals(session.Value.secret, receivedSecret))
                return Results.Json(new { result = "fail", reason = "secret mismatch" });

            // 存储 AK，前提是请求提供了公钥
            if (!string.IsNullOrEmpty(req.AkPub))
            {
                await store.StoreAkAsync(session.Value.akNameHex, req.AkPub, session.Value.ekFp);
                logger.LogInformation("AK registered: {AkName}", session.Value.akNameHex[..16]);
            }

            return Results.Json(new { result = "success" });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify error");
            return Results.Json(new { result = "fail", reason = ex.Message });
        }
    }

    
    //  POST /api/request_nonce
    private static async Task<IResult> HandleRequestNonce(
        RequestNonceRequest req,
        AttestationSessionStore sessions,
        SqliteStore store,
        ILogger<Program> logger)
    {
        try
        {
            var akNameHex = Convert.ToHexString(Convert.FromBase64String(req.AkName)).ToLowerInvariant();

            // 验证 AK 已注册
            var akRecord = await store.GetAkRecordAsync(akNameHex);
            if (akRecord == null)
                return Results.Json(new { result = "fail", reason = "AK not registered" }, statusCode: 403);

            // 生成 nonce
            var nonce = RandomNumberGenerator.GetBytes(32);
            var qsid = sessions.CreateQuoteSession(nonce, akNameHex);

            logger.LogInformation("Quote session created: {Qsid}", qsid[..16]);

            return Results.Json(new RequestNonceResponse
            {
                QuoteSid = qsid,
                Nonce = Convert.ToBase64String(nonce)
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "request_nonce error");
            return Results.Json(new { result = "fail", reason = ex.Message });
        }
    }

    
    //  POST /api/verify_quote
    private static async Task<IResult> HandleVerifyQuote(
        VerifyQuoteRequest req,
        AttestationSessionStore sessions,
        SqliteStore store,
        ILogger<Program> logger)
    {
        // 1. 会话查找
        var session = sessions.PopQuoteSession(req.QuoteSid);
        if (session == null)
            return Results.Json(new VerifyQuoteResponse { Reason = "unknown or expired session" });

        try
        {
            // 2. AK 查找
            var akRecord = await store.GetAkRecordAsync(session.Value.akNameHex);
            if (akRecord == null)
                return Results.Json(new VerifyQuoteResponse { Reason = "AK not found" });

            var akPubDer = Convert.FromBase64String(akRecord.AkPub);
            var attestBytes = Convert.FromBase64String(req.Attest);
            var sigBytes = Convert.FromBase64String(req.Sig);
            var wbclBytes = Convert.FromBase64String(req.Wbcl);

            // 3. Check 1: AK 签名验证
            bool sigValid = VerifyAkSignature(akPubDer, attestBytes, sigBytes);

            // 4. Check 2: TPMS_ATTEST 解析
            var attest = TpmsAttestParser.Parse(attestBytes);
            bool magicOk = attest.Magic == TpmsAttestParser.TPM_GENERATED_MAGIC;

            // 5. Check 3: Nonce 防重放
            bool nonceOk = CryptographicOperations.FixedTimeEquals(attest.ExtraData, session.Value.nonce);

            // 6. Check 4: PCR 回放
            bool pcrMatch = false;
            try
            {
                var pr = WbclParser.Parse(wbclBytes);
                var banks = PcrReplayer.Replay(pr);
                var expectedDigest = PcrReplayer.ComputePcrDigest(banks, attest.PcrSelections);
                if (expectedDigest != null)
                    pcrMatch = CryptographicOperations.FixedTimeEquals(expectedDigest, attest.PcrDigest);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "PCR replay error");
            }

            // 7. 安全特性分析，即使 pcr_match 失败也执行
            var features = new List<SecurityFeature>();
            try
            {
                var pr = WbclParser.Parse(wbclBytes);
                features = SecurityFeatureAnalyzer.Analyze(pr);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Security feature analysis error");
            }

            // 8. 记录历史
            var ekFp = akRecord.EkFingerprint;

            // PCR12 VSMIDKSInfo (0x00050023) — 被 AIK Quote 锚定的 IDKS 公钥材料,
            // 存入 history 供 /verify_vbs 验证 SK 运行时报告签名，不信任客户端自报
            string idksPubB64 = "";
            try
            {
                var prIdks = WbclParser.Parse(wbclBytes);
                idksPubB64 = SecurityFeatureAnalyzer.ExtractPcr12IdksPub(prIdks);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "PCR12 IDKS extraction error");
            }

            var allOk = sigValid && magicOk && nonceOk && pcrMatch;
            var historyEntry = new AttestationHistoryEntry
            {
                EkFingerprint = ekFp,
                AkName = session.Value.akNameHex,
                SigValid = sigValid,
                MagicOk = magicOk,
                NonceOk = nonceOk,
                PcrMatch = pcrMatch,
                SecurityFeatures = features,
                Result = allOk ? "success" : "fail",
                Nonce = Convert.ToBase64String(session.Value.nonce),
                Pcr12IdksPub = idksPubB64,
            };
            await store.AppendHistoryAsync(historyEntry);

            var reason = allOk ? "ok" :
                $"sig={sigValid}, magic={magicOk}, nonce={nonceOk}, pcr={pcrMatch}";

            return Results.Json(new VerifyQuoteResponse
            {
                Id = historyEntry.Id,
                Result = allOk ? "success" : "fail",
                SigValid = sigValid,
                MagicOk = magicOk,
                NonceOk = nonceOk,
                PcrMatch = pcrMatch,
                SecurityFeatures = features,
                Reason = reason
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify_quote error");
            return Results.Json(new VerifyQuoteResponse { Reason = ex.Message });
        }
    }

    
    //  POST /api/verify_certs
    private static async Task<IResult> HandleVerifyCerts(
        VerifyCertsRequest req,
        CertAllowListService certAllowList,
        SqliteStore store,
        ILogger<Program> logger)
    {
        try
        {
            var suspicious = certAllowList.FindSuspicious(req.Certs);

            logger.LogInformation("[verify_certs] 客户端证书 {Client} 个, 微软信任列表 {Trusted} 个, 可疑 {Suspicious} 个",
                req.Certs.Count, certAllowList.TrustedCount, suspicious.Count);

            // 存储校验历史
            var entry = new CertVerifyHistoryEntry
            {
                ClientCertCount = req.Certs.Count,
                TrustedCount = certAllowList.TrustedCount,
                SuspiciousCount = suspicious.Count,
                SuspiciousCerts = suspicious,
                Result = suspicious.Count == 0 ? "pass" : "fail",
            };
            await store.AppendCertVerifyHistoryAsync(entry);

            return Results.Json(new VerifyCertsResponse
            {
                Id = entry.Id,
                Suspicious = suspicious,
                TrustedCount = certAllowList.TrustedCount,
                ClientCount = req.Certs.Count,
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify_certs error");
            return Results.Json(new VerifyCertsResponse { Suspicious = [], TrustedCount = 0, ClientCount = 0 });
        }
    }

    
    //  POST /api/verify_drivers
    //  body: { drivers: [{ file_name, file_path, md5, sha1, sha256, ... }] }
    //  返回客户端已加载驱动中命中拉黑列表的部分,并存储校验历史。
    private static async Task<IResult> HandleVerifyDrivers(
        VerifyDriversRequest req,
        BlocklistService blocklist,
        SqliteStore store,
        ILogger<Program> logger)
    {
        try
        {
            var blocked = blocklist.FindBlocked(req.Drivers);

            logger.LogInformation("[verify_drivers] 客户端驱动 {Client} 个, 命中拉黑 {Blocked} 个",
                req.Drivers.Count, blocked.Count);

            var entry = new DriverVerifyHistoryEntry
            {
                ClientDriverCount = req.Drivers.Count,
                BlockedCount = blocked.Count,
                SuspiciousDrivers = blocked,
                AllDrivers = req.Drivers,
                Result = blocked.Count == 0 ? "pass" : "fail",
            };
            await store.AppendDriverVerifyHistoryAsync(entry);

            return Results.Json(new VerifyDriversResponse
            {
                Id = entry.Id,
                Suspicious = blocked,
                BlockedCount = blocked.Count,
                ClientCount = req.Drivers.Count,
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify_drivers error");
            return Results.Json(new VerifyDriversResponse { Suspicious = [], BlockedCount = 0, ClientCount = 0 });
        }
    }

    
    //  AK 签名验证 (RSA PKCS#1 v1.5 + SHA-256)
    static byte[]? B64OrNull(string? s) =>
        string.IsNullOrEmpty(s) ? null : Convert.FromBase64String(s);

    private static bool VerifyAkSignature(byte[] spkiDer, byte[] message, byte[] signature)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
            return rsa.VerifyData(message, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch { return false; }
    }

    
    //  POST /verify_vbs — VBS/HVCI 运行态验证
    //
    //  客户端在 /verify_quote 成功后调用, 提交:
    //    - history_id : /verify_quote 返回的 id，用于关联已验证的 TPM 证明链
    //    - nonce      : 与 TPM2_Quote 相同的 b64 格式 challenge
    //    - claim_blob : VBS Root Claim，由 IDKS 在 VTL1 内签发并绑定 nonce
    //    - signature  : PoP 签名，使用 VTL1 密钥按 PKCS1/SHA256 签名，公钥取自 claim
    //    - runtime_report : GetRuntimeAttestationReport 运行时报告，nonce 与上述一致
    private static async Task<IResult> HandleVerifyVbs(
        VerifyVbsRequest req,
        AttestationDbContext store,
        HttpContext http,
        ILogger<Program> logger)
    {
        try
        {
            // 1. 关联已通过 TPM 验证的历史记录，作为 EK→AK→Quote 链的锚点
            var history = store.History.FirstOrDefault(h => h.Id == req.HistoryId);
            if (history == null)
                return Results.Json(new { verdict = "FAIL", reason = "history id not found，请先完成 /verify_quote" });
            if (!history.NonceOk || history.Result != "success")
                return Results.Json(new { verdict = "FAIL", reason = "关联的 TPM 证明链未通过验证" });
            // 防证据重放: 一次成功判定即 A+D 通过，随即消费该 history
            if (history.VbsConsumed == 1)
                return Results.Json(new { verdict = "FAIL", reason = "该 TPM 证明链已被 VBS 验证消费, 疑似重放，请重新完成 /verify_quote" });

            // 1.5 nonce 绑定校验: 客户端提交的 nonce 必须等于本次 Quote 的 challenge
            // 该 nonce 由 /verify_quote 存入 history，是 VBS 证据与 TPM 硬件身份的锚点
            var nonce = Convert.FromBase64String(req.Nonce);
            if (string.IsNullOrEmpty(history.Nonce) ||
                !CryptographicOperations.FixedTimeEquals(nonce, Convert.FromBase64String(history.Nonce)))
                return Results.Json(new { verdict = "FAIL", reason = "nonce 与该 TPM Quote 的 challenge 不匹配, VBS 证据无法锚定 TPM 证明链" });

            var claimBlob = Convert.FromBase64String(req.ClaimBlob);
            var signature = Convert.FromBase64String(req.Signature);
            var runtimeReport = string.IsNullOrEmpty(req.RuntimeReport)
                ? null : Convert.FromBase64String(req.RuntimeReport);

            // 2. A: NCryptVerifyClaim 远程验证 claim，nonce 取 quote challenge
            var claimResult = VbsRuntimeVerifier.VerifyVbsRootClaim(claimBlob, Convert.FromBase64String(req.AttestPub), nonce);

            // 3. D: PoP 签名验证，公钥从 claim Attributes 的 SPKI 提取
            var (popValid, popNote) = VbsRuntimeVerifier.VerifyPop(claimBlob, signature, req.HistoryId, nonce);

            // 4. C: 运行时报告解析，含 nonce 绑定、digest 校验与 IDKS SK 签名验证
            //    IDKS 公钥信任锚: 优先使用 /verify_quote 从 WBCL 提取并随 AIK Quote
            //    一起入库的 PCR12 VSMIDKSInfo payload，该 payload 被 Quote 覆盖，因而不可伪造;
            //    客户端自报的 idks_pub 仅在服务器无留存时兜底, 且与服务端留存不一致
            //    时视为篡改 → 方案C 直接判无效
            var serverIdksPub = B64OrNull(history.Pcr12IdksPub);
            var clientIdksPub = B64OrNull(req.IdksPub);
            byte[]? idksPub;
            bool idksTampered = false;
            if (serverIdksPub != null)
            {
                idksPub = serverIdksPub;
                // 客户端提交的 key 材料，即 exp/mod 数据段，必须与服务器留存的
                // PCR12 VSMIDKSInfo 一致 — 两种格式前 16B 头不同, 只比对数据段
                if (clientIdksPub != null)
                {
                    var serverKey = VbsRuntimeVerifier.ParseIdksKeyBytes(serverIdksPub);
                    var clientKey = VbsRuntimeVerifier.ParseIdksKeyBytes(clientIdksPub);
                    idksTampered = serverKey == null || clientKey == null ||
                        !serverKey.Value.Exp.AsSpan().SequenceEqual(clientKey.Value.Exp) ||
                        !serverKey.Value.Mod.AsSpan().SequenceEqual(clientKey.Value.Mod);
                }
            }
            else
            {
                // 旧 history 无 PCR12 留存, 即无服务端信任锚, 不能使用客户端自报的 idks_pub 参与验签,
                // 否则攻击者可用自造密钥签名自造报告骗取 PASS。
                // 传入 null 后 ParseRuntimeReport 内的 sigOk 恒为 null, 不参与 valid 判定,
                // 报告按"仅完成 nonce 与 digest 校验"降级处理
                idksPub = null;
            }

            var rr = runtimeReport is { Length: > 0 }
                ? VbsRuntimeVerifier.ParseRuntimeReport(runtimeReport, nonce, idksPub)
                : new VbsRuntimeVerifier.RuntimeReportInfo(false, false,
                    new { present = false, note = "not submitted" });
            if (idksTampered && rr.Present)
                rr = rr with
                {
                    Valid = false,
                    Payload = new { present = true, valid = false, note = "idks_pub 与服务器留存的 PCR12 VSMIDKSInfo 不一致 — 疑似篡改, 方案C 判无效" }
                };

            bool claimMagicOk = claimBlob.Length > 100 && BitConverter.ToUInt32(claimBlob, 0) == 0x53414B56;
            bool claimNonceBound = VbsRuntimeVerifier.ClaimHasNonce(claimBlob);
            string aMark = claimNonceBound ? "IDKS/VTL1, nonce 绑定" : "IDKS/VTL1, 未绑定 nonce";

            // 5. 综合判定 — 全部基于服务器侧验证; 方案C 可选，无导出时按 A+D 判定
            string cMark = !rr.Present ? "—未提交: 客户端无 GetRuntimeAttestationReport 或系统不支持"
                         : rr.Valid ? "✔, nonce 绑定 + digest 一致"
                         : "✘, 已提交但校验未通过";
            string verdict;
            if (claimResult.Verified && popValid && rr.Valid)
                verdict = "PASS — 方案A✔ VBS Root Claim 链验证通过, " + aMark + ", 方案D✔ PoP 签名验证通过, 方案C✔ 运行时报告有效 " + cMark
                        + (rr.SignatureVerifiedByIdks == true ? ", SK 签名验证通过, IDKS 锚定于本次 AIK Quote 覆盖的 PCR12" : "")
                        + " → HVCI 正在运行, 且已通过 AIK Quote 锚定 TPM 证明链";
            else if (claimResult.Verified && popValid && !rr.Present)
                verdict = "PASS(PARTIAL) — 方案A✔ 方案D✔ → VBS 正在运行; 方案C" + cMark + " → HVCI 运行态未证明; 已通过 AIK Quote 锚定 TPM 证明链";
            else if (claimResult.Verified && popValid)
                verdict = "FAIL — 方案A✔ 方案D✔, 但方案C" + cMark + " → HVCI 运行态存疑";
            else if (!popValid)
                verdict = "FAIL — 方案D✘ PoP 签名验证失败";
            else
                verdict = $"FAIL — 方案A✘ claim 验证失败: 0x{claimResult.Status:X8}";

            logger.LogInformation("[verify_vbs] history={Id} verdict={Verdict} claimOk={ClaimOk} pop={Pop} report={Report} drivers={Drivers} unloaded={Unloaded}",
                req.HistoryId, verdict.Split('—')[0].Trim(), claimResult.Verified, popValid, rr.Valid, rr.DriverCount, rr.UnloadedCount);

            //  入库，供仪表盘"运行时检测"展示 
            var payload = new
            {
                verdict,
                schemes = new
                {
                    A_claim_chain = new { verified = claimResult.Verified, nonce_bound = claimNonceBound },
                    D_pop_signature = new { valid = popValid },
                    C_runtime_report = new { submitted = runtimeReport != null, present = rr.Present, valid = rr.Valid, signature_verified_by_idks = rr.SignatureVerifiedByIdks },
                },
                history_id = req.HistoryId,
                ak_name = history.AkName,
                ek_fingerprint = history.EkFingerprint,
                tpm_history_id = req.HistoryId,
                tpm_chain_verified = history.Result == "success",
                client_ip = http.Connection.RemoteIpAddress?.ToString() ?? "",
                idks_fingerprint = VbsRuntimeVerifier.IdksFingerprint(idksPub),
                idks_source = serverIdksPub != null ? "pcr12_measured (server)" : (idksPub != null ? "client_submitted" : "none"),
                vbs_running = claimResult.Verified && popValid,
                driver_report = new
                {
                    count = rr.DriverCount,
                    boot = rr.BootCount,
                    unloaded = rr.UnloadedCount,
                    digest_verification = rr.DigestVerification,
                    nonce_match = rr.NonceMatch,
                    signature_scheme = rr.SignatureScheme,
                    drivers = rr.DriverReport?.Drivers.Select(d => new
                    {
                        d.Name, d.Boot, d.Unloaded, d.LoadTimes, d.Oem, d.ImageHash, d.PublisherThumbprint,
                    }),
                },
                hvci_runtime_report = rr.Payload,
                claim = new
                {
                    verified = claimResult.Verified,
                    status = $"0x{claimResult.Status:X8}",
                    claim_blob_size = claimBlob.Length,
                    claimResult.Details
                },
                pop = new { valid = popValid, note = popNote }
            };

            var vbsEntry = new Data.VbsVerifyHistoryEntity
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
                ResultJson = System.Text.Json.JsonSerializer.Serialize(payload, VbsRuntimeVerifier.WebJsonOpts),
            };
            store.VbsVerifyHistory.Add(vbsEntry);

            // A+D 两项通过即代表本次 VBS 运行态判定成立, 此处原子消费该 history 以防重放。
            // 条件更新保证并发下同一 history_id 只有一个请求能消费成功, 其余请求一律判重放。
            // 旧实现先读后写, 并发时可能双双通过
            if (claimResult.Verified && popValid)
            {
                var consumed = await store.History
                    .Where(h => h.Id == req.HistoryId && h.VbsConsumed == 0)
                    .ExecuteUpdateAsync(u => u.SetProperty(x => x.VbsConsumed, 1));
                if (consumed != 1)
                    return Results.Json(new { verdict = "FAIL", reason = "该 TPM 证明链已被 VBS 验证消费, 疑似重放，请重新完成 /verify_quote" });
            }

            await store.SaveChangesAsync();

            return Results.Json(payload);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "verify_vbs error");
            return Results.Json(new { verdict = "FAIL", reason = "internal error" });
        }
    }
}

/// <summary>/verify_vbs 请求体</summary>
public sealed record VerifyVbsRequest(
    [property: JsonPropertyName("history_id")] string HistoryId,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("claim_blob")] string ClaimBlob,
    [property: JsonPropertyName("attest_pub")] string AttestPub,
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("runtime_report")] string RuntimeReport,
    [property: JsonPropertyName("idks_pub")] string IdksPub);

