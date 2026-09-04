// VBSRemoteDetectServer — 远程验证 VBS/HVCI 运行态（服务器）
//
// 协议 (D):
//   GET  /api/challenge → { sessionId, nonce }          （32B 随机 challenge, 5 分钟有效）
//   POST /api/verify    → 提交 { sessionId, claimBlob, attestPub, signature, runtimeReport }
//
// 验证逻辑:
//   A. NCryptVerifyClaim 远程验证 VBS Root Claim:
//      claim 由 IDKS (VBS 根签名密钥, 只存在于 VTL1) 签发 — 验证通过即证明
//      客户端密钥来自 VTL1 隔离环境 → VBS 正在运行
//   D. 验证 proof-of-possession: 客户端用同一把 VTL1 密钥对 canonical payload
//      (含 sessionId + challenge nonce + claim 摘要) 做 RSA-PSS 签名 → 防重放/防转投
//   C. 解析 GetRuntimeAttestationReport 运行时报告 (Secure Kernel 签名):
//      nonce 绑定校验 + SHA-512 digest 一致性校验 + Driver/CodeIntegrity 报告解析
//      (报告生成成功本身即证明 HVCI 正在运行; 签名链验证留待微软根证书材料)

using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;

await VbsVerifyServer.RunAsync();

static class VbsVerifyServer
{
    // 放宽转义: 默认编码器会把 base64 的 '+' 转成 \\u002B、把中文转成 \\uXXXX,
    // 导致客户端解析困难 → 这里输出原始字符（响应内容均为 ASCII base64 与固定文案）
    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    static readonly ConcurrentDictionary<string, (byte[] Nonce, DateTime Expires)> Sessions = new();

    // ── 常量 (ncrypt.h / winnt.h, Windows SDK 10.0.28000.0) ──
    internal const uint NCRYPT_CLAIM_VBS_ROOT = 0x00000005;
    internal const uint NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG = 0x00100000;
    internal const uint NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE = 49;
    internal const uint NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS = 94;

    public static async Task RunAsync()
    {
        var listener = new HttpListener();
        listener.Prefixes.Add("http://192.168.31.207:8899/");
        listener.Start();
        Console.WriteLine($"[Server] listening on http://192.168.31.207:8899/  ({DateTime.Now:HH:mm:ss})");

        while (true)
        {
            var ctx = await listener.GetContextAsync();
            try
            {
                var path = ctx.Request.Url?.AbsolutePath ?? "/";
                if (ctx.Request.HttpMethod == "GET" && path == "/api/challenge")
                {
                    var nonce = RandomNumberGenerator.GetBytes(32);
                    var sessionId = Guid.NewGuid().ToString("N");
                    Sessions[sessionId] = (nonce, DateTime.UtcNow.AddMinutes(5));
                    foreach (var kv in Sessions) if (kv.Value.Expires < DateTime.UtcNow) Sessions.TryRemove(kv.Key, out _);

                    var resp = JsonSerializer.Serialize(new
                    {
                        sessionId,
                        nonce = Convert.ToBase64String(nonce),
                        expiresInSeconds = 300
                    });
                    await WriteJson(ctx, 200, resp);
                }
                else if (ctx.Request.HttpMethod == "POST" && path == "/api/verify")
                {
                    using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
                    var body = await reader.ReadToEndAsync();
                    var verdict = VerifySubmission(body);
                    Console.WriteLine($"[Server] verify → {verdict.GetType().GetProperty("verdict")?.GetValue(verdict)}");
                    await WriteJson(ctx, 200, JsonSerializer.Serialize(verdict, JsonOpts));
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                    ctx.Response.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Server] error: {ex.Message}");
                try { await WriteJson(ctx, 500, JsonSerializer.Serialize(new { error = ex.Message })); } catch { }
            }
        }
    }

    // ══════════════════════════════════════════════════════════
    //  验证主流程
    // ══════════════════════════════════════════════════════════

    static object VerifySubmission(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        string sessionId = root.TryGetProperty("sessionId", out var sid) ? sid.GetString() ?? "" : "";
        byte[]? claimBlob = B64(root, "claimBlob");
        byte[]? attestPub = B64(root, "attestPub");
        byte[]? signature = B64(root, "signature");
        byte[]? runtimeReport = B64(root, "runtimeReport");

        // ── 会话 / challenge 校验 ──
        if (string.IsNullOrEmpty(sessionId) ||
            !Sessions.TryRemove(sessionId, out var session) || session.Expires < DateTime.UtcNow)
            return new { verdict = "FAIL", reason = "session invalid or expired" };

        // ── D-1: proof-of-possession 签名验证 ──
        // 公钥从 claim Attributes 的 SPKI 提取（SK 报告哈希覆盖了 Attributes → 公钥与 claim 密码学绑定）
        // claim 布局: [VKAS 4][ver 4][type 4][VRCH 24: magic,ver,cbAttr,cbNonce,cbReport,cbSig][Attributes: 3×u32 + SPKI][Nonce][Report][SK Signature]
        bool sigValid = false;
        string sigNote = "no signature submitted";
        if (signature is { Length: > 0 } && claimBlob is { Length: > 44 + 162 })
        {
            uint cbAttr = BitConverter.ToUInt32(claimBlob, 20);
            uint spkiLen = BitConverter.ToUInt32(claimBlob, 44);
            int spkiOff = 48;
            if (cbAttr >= 12 + spkiLen && spkiLen > 0 && spkiOff + (int)spkiLen <= claimBlob.Length)
            {
                var spki = claimBlob[spkiOff..(spkiOff + (int)spkiLen)];
                var claimHash = SHA256.HashData(claimBlob);
                var canonical = Encoding.UTF8.GetBytes(
                    $"VBSRemoteDetect-v1\n{sessionId}\n{Convert.ToBase64String(session.Nonce)}\n{ToHexLower(claimHash)}");
                var canonHash = SHA256.HashData(canonical);
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(spki, out _);
                sigValid = rsa.VerifyHash(canonHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            sigNote = sigValid ? "RSA PKCS1/SHA256 signature valid — 公钥提取自 claim Attributes (被 Secure Kernel 报告哈希绑定)"
                               : "signature invalid";
        }

        // ── A: NCryptVerifyClaim 远程验证 VBS Root Claim ──
        var claimResult = VerifyVbsRootClaim(claimBlob, attestPub, session.Nonce);

        // ── C: 运行时报告解析 ──
        var rr = runtimeReport is { Length: > 0 }
            ? ParseRuntimeReport(runtimeReport, session.Nonce)
            : new RuntimeReportInfo(false, false, new { present = false, note = "not submitted (client may be < Win11 24H2 or HVCI not running)" });

    bool hvciPresent = rr.Present;
    bool hvciValid = rr.Valid;

    // ── claim blob 结构校验 (magic 'VKAS' = VBS Key Attestation Statement) ──
    bool claimMagicOk = claimBlob is { Length: > 100 } && BitConverter.ToUInt32(claimBlob, 0) == 0x53414B56;
    bool claimVerifiedLocally = root.TryGetProperty("claimVerifiedLocally", out var cvl) && cvl.GetBoolean();

    // ── 综合判定 ──
    // 信任依据全部来自服务器侧验证:
    //   1. PoP 签名 (公钥提取自 claim Attributes, 被 SK 报告哈希绑定)
    //   2. NCryptVerifyClaim 远程验证 claim 签名链 (Windows KSP 完成)
    //   3. 运行时报告 nonce 绑定 + SHA-512 digest 一致
    // 客户端自报的 claimVerifiedLocally 不参与判定 (可伪造), 仅作展示
    bool claimOk = claimResult.Verified;
    string verdict;
    if (sigValid && claimMagicOk && claimOk && hvciValid)
        verdict = "PASS — VBS 正在运行 (VTL1 密钥 PoP 验证通过 + 服务器 claim 链验证通过), HVCI 运行时报告已验证 (nonce 绑定 + digest 一致)";
    else if (sigValid && claimMagicOk && claimOk)
        verdict = "PARTIAL — VBS 正在运行 (VTL1 密钥 PoP + 服务器 claim 链验证通过); 运行时报告不可用 (HVCI 运行态未证明)";
    else if (sigValid && claimMagicOk)
        verdict = "UNKNOWN — PoP 签名有效, 但服务器 claim 链验证未通过 (需排查 NCryptVerifyClaim)";
    else if (!sigValid)
        verdict = "FAIL — proof-of-possession 签名验证失败 (无法证明 VTL1 密钥持有)";
    else
        verdict = "FAIL — 证明材料不完整";

    return new
    {
        verdict,
        sessionId,
        signatureValid = sigValid,
        signatureNote = sigNote,
        claimMagicOk,
        claimVerifiedLocallySelfReported = claimVerifiedLocally,   // 仅展示, 不参与判定
        vbsRunning = claimOk && sigValid && claimMagicOk,
        hvciRuntimeReport = rr.Payload,
        claim = new
        {
            verified = claimResult.Verified,
            serverSideVerify = claimResult.Verified
                ? "服务器远程 NCryptVerifyClaim 验证通过 (claim 签名链由 Windows KSP 校验)"
                : "服务器远程 NCryptVerifyClaim 未通过",
            status = $"0x{claimResult.Status:X8}",
            claimBlobSize = claimBlob?.Length ?? 0,
            claimResult.Details
        }
    };
}

    // ══════════════════════════════════════════════════════════
    //  A: NCryptVerifyClaim (P/Invoke, 可远程执行 — 只需公钥 blob)
    // ══════════════════════════════════════════════════════════

    static ClaimVerifyResult VerifyVbsRootClaim(byte[]? claimBlob, byte[]? attestPub, byte[] nonce)
    {
        if (claimBlob is not { Length: > 0 } || attestPub is not { Length: > 0 })
            return new ClaimVerifyResult(false, 0, "no claim material submitted");

        IntPtr hProv = 0, hAttestKey = 0;
        try
        {
            int st = NCryptNative.NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0);
            if (st != 0) return new ClaimVerifyResult(false, st, "NCryptOpenStorageProvider failed");

            st = NCryptNative.NCryptImportKey(hProv, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero,
                                              out hAttestKey, attestPub, attestPub.Length, 0);
            if (st != 0) return new ClaimVerifyResult(false, st, $"NCryptImportKey(attestPub) failed: 0x{st:X8}");

            // KSP 调用不传 nonce 参数: 实测 NCryptVerifyClaim 不接受
            // NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE 输入 (0xD000000D STATUS_INVALID_PARAMETER)
            // → nonce 绑定由下方服务器侧比对 claim 内嵌 nonce 完成
            st = NCryptNative.NCryptVerifyClaim(hAttestKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero,
                                                claimBlob, claimBlob.Length, out var outDesc,
                                                NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG);

            object? details = null;
            if (st == 0)
            {
                // outDesc 由 KSP 填充; pBuffers 指向 KSP 分配的 NCryptBuffer 数组, 读完后释放
                // (找 type 94 = NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS)
                for (uint i = 0; i < outDesc.cBuffers; i++)
                {
                    var buf = Marshal.PtrToStructure<NCryptBuffer>(outDesc.pBuffers + (int)(i * Marshal.SizeOf<NCryptBuffer>()));
                    if (buf.BufferType == NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS && buf.cbBuffer >= 24)
                    {
                        details = new
                        {
                            keyFlags = $"0x{Marshal.ReadInt32(buf.pvBuffer, 0):X}",
                            trustletId = $"0x{Marshal.ReadInt64(buf.pvBuffer, 8):X}",
                            trustletSecurityVersion = Marshal.ReadInt32(buf.pvBuffer, 16),
                            debuggable = Marshal.ReadInt32(buf.pvBuffer, 20) != 0
                        };
                    }
                }
                _ = NCryptNative.NCryptFreeBuffer(outDesc.pBuffers);
            }

            if (st != 0)
                return new ClaimVerifyResult(false, st, details);

            // nonce 绑定校验 (服务器侧强制): claim 布局 [头 12][VRCH 24][Attributes cbAttr][Nonce cbNonce][Report][Sig]
            // → 内嵌 nonce @ 36+cbAttr; 无 nonce claim 仅在 cbNonce==0 时按旧语义接受 (标注 nonce_bound=false)
            byte[]? claimNonce = null;
            if (claimBlob is { Length: >= 36 })
            {
                uint cbAttr = BitConverter.ToUInt32(claimBlob, 20);
                uint cbNonce = BitConverter.ToUInt32(claimBlob, 24);
                long off = 36L + cbAttr;
                if (cbNonce > 0 && cbNonce <= 64 && off + cbNonce <= claimBlob.Length)
                    claimNonce = claimBlob[(int)off..(int)(off + cbNonce)];
            }
            if (claimNonce == null)
                return new ClaimVerifyResult(true, 0, new { note = "verified without nonce (claim created without challenge binding)", nonce_bound = false });
            if (!CryptographicOperations.FixedTimeEquals(claimNonce, nonce))
                return new ClaimVerifyResult(false, 0, new { note = "claim nonce does not match server challenge (replayed or cross-session claim)", nonce_bound = true });

            return new ClaimVerifyResult(true, 0, details ?? "verified (nonce-bound)");
        }
        finally
        {
            if (hAttestKey != 0) NCryptNative.NCryptFreeObject(hAttestKey);
            if (hProv != 0) NCryptNative.NCryptFreeObject(hProv);
        }
    }

    // ══════════════════════════════════════════════════════════
    //  C: GetRuntimeAttestationReport 报告解析
    //  结构来源: winnt.h (10.0.28000.0) — RUNTIME_REPORT_PACKAGE 格式
    // ══════════════════════════════════════════════════════════

    sealed record RuntimeReportInfo(bool Present, bool Valid, object Payload);

    static RuntimeReportInfo ParseRuntimeReport(byte[] report, byte[] expectedNonce)
    {
        try
        {
            // RUNTIME_REPORT_PACKAGE_HEADER (36 bytes)
            uint magic = BitConverter.ToUInt32(report, 0);
            if (magic != 0x52545250) // "RTRP"
                return new RuntimeReportInfo(true, false, new { note = $"bad magic 0x{magic:X}" });
            ushort packageVersion = BitConverter.ToUInt16(report, 4);
            ushort numberOfReports = BitConverter.ToUInt16(report, 6);
            ulong reportTypesBitmap = BitConverter.ToUInt64(report, 8);
            ushort digestType = BitConverter.ToUInt16(report, 20);
            ushort totalDigestsSize = BitConverter.ToUInt16(report, 22);
            ushort signatureScheme = BitConverter.ToUInt16(report, 26);
            uint signatureSize = BitConverter.ToUInt32(report, 28);
            uint totalAuthSize = BitConverter.ToUInt32(report, 32);

            // Nonce 绑定校验 — 头部实际 sizeof(RUNTIME_REPORT_PACKAGE_HEADER) = 40
            // (8 字节对齐填充到 40), nonce 位于 offset 40，在被签名的部分内
            bool nonceMatch = report.Length >= 72 &&
                report.AsSpan(40, 32).SequenceEqual(expectedNonce);

            // Digest headers @68, 每个 68B (u16 type + u16 rsvd + 64B SHA-512)
            var digests = new List<(ushort type, byte[] digest)>();
            int off = 72;   // 40 (header) + 32 (nonce)
            int digestsEnd = off + totalDigestsSize;
            while (off + 68 <= digestsEnd)
            {
                digests.Add((BitConverter.ToUInt16(report, off),
                             report[(off + 4)..(off + 4 + 64)]));
                off += 68;
            }
            int sigOff = digestsEnd;
            int reportsOff = sigOff + (int)signatureSize;

            // 遍历 authenticated reports, 校验 SHA-512 digest 与签名部分一致
            var reports = new List<object>();
            int p = reportsOff;
            int reportsEnd = Math.Min(reportsOff + (int)totalAuthSize, report.Length);
            int digestOk = 0;
            while (p + 8 <= reportsEnd)
            {
                ushort rtype = BitConverter.ToUInt16(report, p);
                int rsize = (int)BitConverter.ToUInt32(report, p + 4);
                if (rsize < 8 || p + rsize > reportsEnd) break;
                var reportData = report[p..(p + rsize)];
                var digest = SHA512.HashData(reportData);
                bool dOk = digests.Any(d => d.type == rtype && d.digest.AsSpan().SequenceEqual(digest));
                if (dOk) digestOk++;

                if (rtype == 0) // RuntimeReportTypeDriver — DRIVER_RUNTIME_REPORT
                    reports.Add(ParseDriverReport(reportData));
                else if (rtype == 1) // RuntimeReportTypeCodeIntegrity — CODE_INTEGRITY_RUNTIME_REPORT
                {
                    ulong generation = BitConverter.ToUInt64(reportData, 8);
                    uint numGens = BitConverter.ToUInt32(reportData, 16);
                    reports.Add(new { type = "CodeIntegrity", policyGeneration = generation, generationsInReport = numGens });
                }
                p += rsize;
            }

            return new RuntimeReportInfo(true, nonceMatch && digestOk == reports.Count, new
            {
                packageVersion,
                reportTypesBitmap = $"0x{reportTypesBitmap:X}",
                signatureScheme = signatureScheme == 1 ? "SHA512_RSA_PSS_SHA512" : $"0x{signatureScheme:X}",
                nonceMatch,
                digestVerification = $"{digestOk}/{reports.Count} OK",
                signatureVerifiedByMicrosoftRoot = false,
                // TODO: SK 签名信任锚实验记录 — VBS_ROOT_PUB (IDKS, RSA-2048) 可从
                // KSP 属性读取, 但对 [0,sigOff)/[40,..)/[72,..) 等范围 × PSS/PKCS1 均
                // 验签失败 → SK 运行时报告可能用独立密钥或规范外输入格式, 待逆向/Azure 材料
                reports
            });
        }
        catch (Exception ex)
        {
            return new RuntimeReportInfo(true, false, new { error = ex.Message });
        }
    }

    static object ParseDriverReport(byte[] report)
    {
        // RUNTIME_REPORT_HEADER(8B) + NumberOfDrivers(2B) + Flags(2B) + DRIVER_INFO_ENTRY[] + dynamic buffer
        ushort numDrivers = BitConverter.ToUInt16(report, 8);
        ushort flags = BitConverter.ToUInt16(report, 10);
        var drivers = new List<object>();
        const int entrySize = 56; // sizeof(DRIVER_INFO_ENTRY)

        for (int i = 0; i < numDrivers; i++)
        {
            int e = 12 + i * entrySize;
            if (e + entrySize > report.Length) break;

            ushort loadTimes = BitConverter.ToUInt16(report, e + 44);
            int imageHashOff0 = (int)BitConverter.ToUInt32(report, e + 36);
            // 过滤未占用的空槽位 (ghost entry): loadTimes=0 且无镜像哈希偏移
            if (loadTimes == 0 && imageHashOff0 == 0) continue;

            // CHAR InternalName[32]
            int nameEnd = 0;
            for (int k = 0; k < 32; k++) { if (report[e + k] == 0) break; nameEnd = k + 1; }
            string internalName = Encoding.ASCII.GetString(report, e, nameEnd);

            // 两个独立的算法 ID: 镜像哈希 (通常 SHA-256) 与 发布者证书指纹哈希 (通常 SHA-1)
            ushort imgHashAlg = BitConverter.ToUInt16(report, e + 32);
            ushort pubHashAlg = BitConverter.ToUInt16(report, e + 34);
            int imageHashOff = (int)BitConverter.ToUInt32(report, e + 36);
            int pubHashOff = (int)BitConverter.ToUInt32(report, e + 40);
            ushort oemNameSize = BitConverter.ToUInt16(report, e + 46);
            int oemNameOff = (int)BitConverter.ToUInt32(report, e + 48);
            ushort drvFlags = BitConverter.ToUInt16(report, e + 52);

            // 各自按自己的算法取长度 — 修 bug: 之前复用镜像哈希长度(32B)切发布者
            // 指纹(20B), 多读 12 字节把相邻的 OEM 字符串切进了 thumbprint
            int imgHashSize = HashSizeFromCalg(imgHashAlg);
            int pubHashSize = HashSizeFromCalg(pubHashAlg);
            string imgHash = (imgHashSize > 0 && imageHashOff > 0 && imageHashOff + imgHashSize <= report.Length)
                ? Convert.ToHexString(report, imageHashOff, imgHashSize) : "?";
            string pubHash = (pubHashSize > 0 && pubHashOff > 0 && pubHashOff + pubHashSize <= report.Length)
                ? Convert.ToHexString(report, pubHashOff, pubHashSize) : "?";
            string oem = (oemNameSize > 0 && oemNameOff > 0 && oemNameOff + oemNameSize <= report.Length)
                ? Encoding.UTF8.GetString(report, oemNameOff, oemNameSize) : "";

            drivers.Add(new
            {
                name = internalName,
                boot = (drvFlags & 0x2) != 0,
                unloaded = (drvFlags & 0x1) != 0,
                loadTimes,
                oem,
                imageHash = imgHash.ToLowerInvariant(),
                publisherThumbprint = pubHash.ToLowerInvariant()
            });
        }

        return new
        {
            type = "Driver",
            driverCount = numDrivers,
            overflow = (flags & 0x1) != 0,
            partial = (flags & 0x2) != 0,
            includeBootDrivers = (flags & 0x4) != 0,
            drivers
        };
    }

    static int HashSizeFromCalg(ushort calg) => calg switch
    {
        0x8004 => 20, // CALG_SHA1
        0x800c => 32, // CALG_SHA_256
        0x800d => 48, // CALG_SHA_384
        0x800e => 64, // CALG_SHA_512
        _ => -1
    };

    // ══════════════════════════════════════════════════════════
    //  工具
    // ══════════════════════════════════════════════════════════

    static byte[]? B64(JsonElement root, string prop) =>
        root.TryGetProperty(prop, out var el) && el.ValueKind == JsonValueKind.String
            ? Convert.FromBase64String(el.GetString()!) : null;

    static string ToHexLower(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    // 解析 BCRYPT_RSAKEY_BLOB (magic "RSA1" = 0x31415352) → RSAParameters
    static RSA? ParseRsaPublicBlob(byte[] blob)
    {
        try
        {
            uint magic = BitConverter.ToUInt32(blob, 0);
            if (magic != 0x31415352) return null; // BCRYPT_RSAPUBLIC_MAGIC
            uint bitLen = BitConverter.ToUInt32(blob, 4);
            uint cbExp = BitConverter.ToUInt32(blob, 8);
            uint cbMod = BitConverter.ToUInt32(blob, 12);
            int off = 16;
            var exp = blob[off..(off + (int)cbExp)]; off += (int)cbExp;
            var mod = blob[off..(off + (int)cbMod)];
            if (mod.Length != bitLen / 8) return null;
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Exponent = exp, Modulus = mod });
            return rsa;
        }
        catch { return null; }
    }

    static async Task WriteJson(HttpListenerContext ctx, int code, string json)
    {
        ctx.Response.StatusCode = code;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        var buf = Encoding.UTF8.GetBytes(json);
        ctx.Response.ContentLength64 = buf.Length;
        await ctx.Response.OutputStream.WriteAsync(buf);
        ctx.Response.Close();
    }
}

// ═══════════════════════════════════════════════════════════════
//  NCrypt P/Invoke
// ═══════════════════════════════════════════════════════════════

static class NCryptNative
{
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, byte[] pbData, int cbData, int dwFlags);
    // 第 7 参按文档是 NCryptBufferDesc* — native 往调用方提供的 24B 结构体里填充输出。
    // 不能声明为 out IntPtr: native 写 24 字节导致溢出, 读回的垃圾值被当指针解引用 → AccessViolation
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptVerifyClaim(IntPtr hSubjectKey, IntPtr hAuthorityKey, uint dwClaimType, IntPtr pParameterList, byte[] pbClaimBlob, int cbClaimBlob, out NCryptBufferDesc pOutput, uint dwFlags);
    [DllImport("ncrypt.dll")] public static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("ncrypt.dll")] public static extern int NCryptFreeBuffer(IntPtr pvBuffer);
}

[StructLayout(LayoutKind.Sequential)]
struct NCryptBuffer { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }

[StructLayout(LayoutKind.Sequential)]
struct NCryptBufferDesc { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }

record ClaimVerifyResult(bool Verified, int Status, object? Details);
