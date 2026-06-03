using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SEWindows.Server.Models;
using SEWindows.Server.Services;
using SEWindows.Server.Storage;

namespace SEWindows.Server.Api;

/// <summary>
/// 远程证明 API 端点（兼容现有 C# 客户端）
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
    }

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/verify_chain
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleVerifyChain(
        VerifyChainRequest req,
        CertificateVerifier certVerifier,
        JsonFileStore store,
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
                var fp = JsonFileStore.EkFingerprint(spki);
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/make_credential
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleMakeCredential(
        MakeCredentialRequest req,
        AttestationSessionStore sessions,
        JsonFileStore store,
        ILogger<Program> logger)
    {
        try
        {
            var ekPubDer = Convert.FromBase64String(req.EkPub);
            var akName = Convert.FromBase64String(req.AkName);

            // 验证 EK 已注册
            var fp = JsonFileStore.EkFingerprint(ekPubDer);
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/verify (ActivateCredential 验证)
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleVerify(
        VerifyRequest req,
        AttestationSessionStore sessions,
        JsonFileStore store,
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

            // 存储 AK（如果提供了公钥）
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/request_nonce
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleRequestNonce(
        RequestNonceRequest req,
        AttestationSessionStore sessions,
        JsonFileStore store,
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

    // ═══════════════════════════════════════════════════════════════
    //  POST /api/verify_quote
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleVerifyQuote(
        VerifyQuoteRequest req,
        AttestationSessionStore sessions,
        JsonFileStore store,
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

            // 7. 安全特性分析（即使 pcr_match 失败也执行）
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
            var allOk = sigValid && magicOk && nonceOk && pcrMatch;
            var historyEntry = new AttestationHistoryEntry
            {
                EkFingerprint = ekFp.Length > 16 ? ekFp[..16] + "..." : ekFp,
                AkName = session.Value.akNameHex.Length > 16 ? session.Value.akNameHex[..16] + "..." : session.Value.akNameHex,
                SigValid = sigValid,
                MagicOk = magicOk,
                NonceOk = nonceOk,
                PcrMatch = pcrMatch,
                SecurityFeatures = features,
                Result = allOk ? "success" : "fail"
            };
            await store.AppendHistoryAsync(historyEntry);

            var reason = allOk ? "ok" :
                $"sig={sigValid}, magic={magicOk}, nonce={nonceOk}, pcr={pcrMatch}";

            return Results.Json(new VerifyQuoteResponse
            {
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

    // ═══════════════════════════════════════════════════════════════
    //  AK 签名验证 (RSA PKCS#1 v1.5 + SHA-256)
    // ═══════════════════════════════════════════════════════════════

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
}
