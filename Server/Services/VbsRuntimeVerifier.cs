using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Hyperion.Server.Services;

/// <summary>
/// VBS 运行态验证器 (方案 A+C+D, 与 VBSRemoteDetectServer 同源逻辑)。
///
///   A. NCryptVerifyClaim 远程验证 VBS Root Claim (claim 由 IDKS 在 VTL1 内签发)
///   C. GetRuntimeAttestationReport 运行时报告解析 (nonce 绑定 + SHA-512 digest 校验)
///   D. PoP 签名: 公钥提取自 claim Attributes 的 SPKI (被 SK 报告哈希绑定),
///      覆盖 canonical(attestationId, nonce, claimHash) → 防重放/防转投
///
/// 客户端 (Hyperion.Verifier.RemoteVerify.VbsRuntimeVerify) 在 PCR Quote 验证
/// 成功后调用本服务, nonce 使用与 TPM2_Quote 相同的 challenge → 运行态证据与
/// TPM 硬件身份绑定 (Azure Attestation VBS 协议思路)。
/// </summary>
public static class VbsRuntimeVerifier
{
    // ── 常量 (ncrypt.h / winnt.h, Windows SDK 10.0.28000.0) ──
    internal const uint NCRYPT_CLAIM_VBS_ROOT = 0x00000005;
    internal const uint NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG = 0x00100000;
    internal const uint NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE = 49;
    internal const uint NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS = 94;

    public sealed record ClaimVerifyResult(bool Verified, int Status, object? Details);

    /// <summary>单个驱动条目 (DRIVER_INFO_ENTRY 解析结果)</summary>
    public sealed record DriverEntry(
        string Name, bool Boot, bool Unloaded, int LoadTimes,
        string Oem, string ImageHash, string PublisherThumbprint);

    /// <summary>DRIVER_RUNTIME_REPORT 汇总</summary>
    public sealed record DriverReportInfo(
        int DriverCount, bool Overflow, bool Partial, bool IncludeBootDrivers,
        List<DriverEntry> Drivers);

    /// <summary>运行时报告解析结果 (Payload 为完整 JSON; 其余为常用字段快捷访问)</summary>
    public sealed record RuntimeReportInfo(
        bool Present, bool Valid, object Payload,
        int DriverCount = 0, int BootCount = 0, int UnloadedCount = 0,
        string DigestVerification = "", bool NonceMatch = false,
        string SignatureScheme = "", DriverReportInfo? DriverReport = null);

    // ══════════════════════════════════════════════════════════
    //  A: NCryptVerifyClaim 远程验证
    // ══════════════════════════════════════════════════════════

    public static ClaimVerifyResult VerifyVbsRootClaim(byte[]? claimBlob, byte[]? attestPub, byte[] nonce)
    {
        // attestPub: 客户端 NCryptExportKey 的 BCRYPT_RSAPUBLICBLOB (NCrypt 原生格式,
        //   实测可直接 NCryptImportKey; .NET ExportRSAPublicKey 反而导入失败 0x80090005)
        // 安全校验: 导入后取模数, 与 claim Attributes 内 SPKI 的模数比对 —
        //   SPKI 被 SK 报告哈希绑定 → 公钥与 claim 的绑定关系成立
        if (claimBlob is not { Length: > 48 } || attestPub is not { Length: > 16 })
            return new ClaimVerifyResult(false, 0, "no claim material submitted");
        uint spkiLen = BitConverter.ToUInt32(claimBlob, 44);
        if (spkiLen == 0 || 48 + (int)spkiLen > claimBlob.Length)
            return new ClaimVerifyResult(false, 0, "claim Attributes layout invalid");

        IntPtr hProv = 0, hAttestKey = 0, pOutput = 0;
        IntPtr pDesc = 0, pBuffers = 0, nonceBuf = 0;
        try
        {
            int st = NCryptNative.NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0);
            if (st != 0) return new ClaimVerifyResult(false, st, "NCryptOpenStorageProvider failed");

            st = NCryptNative.NCryptImportKey(hProv, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero,
                                              out hAttestKey, attestPub, attestPub.Length, 0);
            if (st != 0) return new ClaimVerifyResult(false, st, $"NCryptImportKey(attestPub) failed: 0x{st:X8}");

            // 模数一致性校验: claim Attributes 内 SPKI 的模数必须出现在 attestPub 中
            // (VTL1 密钥的 NCrypt 导出 blob 布局与标准 BCRYPT_RSAKEY_BLOB 略有差异,
            //  155B vs 147B, 含 KSP 附加字段 → 用子串搜索而非固定偏移)
            try
            {
                using var rsaSpki = RSA.Create();
                rsaSpki.ImportSubjectPublicKeyInfo(claimBlob[48..(48 + (int)spkiLen)], out _);
                var spkiMod = rsaSpki.ExportParameters(false).Modulus;
                if (attestPub.AsSpan().IndexOf(spkiMod) < 0)
                    return new ClaimVerifyResult(false, 0, "attestPub does not contain claim SPKI modulus (claim/key mismatch)");
            }
            catch (Exception ex)
            {
                return new ClaimVerifyResult(false, 0, $"modulus cross-check failed: {ex.Message}");
            }

            // nonce 参数绑定 challenge
            nonceBuf = Marshal.AllocHGlobal(nonce.Length);
            Marshal.Copy(nonce, 0, nonceBuf, nonce.Length);
            pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBuffer>());
            Marshal.StructureToPtr(new NCryptBuffer
            {
                cbBuffer = (uint)nonce.Length,
                BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE,
                pvBuffer = nonceBuf
            }, pBuffers, false);
            pDesc = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBufferDesc>());
            Marshal.StructureToPtr(new NCryptBufferDesc { ulVersion = 0, cBuffers = 1, pBuffers = pBuffers }, pDesc, false);

            st = NCryptNative.NCryptVerifyClaim(hAttestKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, pDesc,
                                                claimBlob, claimBlob.Length, out pOutput,
                                                NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG);

            object? details = null;
            if (st == 0 && pOutput != IntPtr.Zero)
            {
                var outDesc = Marshal.PtrToStructure<NCryptBufferDesc>(pOutput);
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
                _ = NCryptNative.NCryptFreeBuffer(pOutput);
                pOutput = 0;
            }

            if (st != 0)
            {
                // 兼容未绑定 nonce 的旧 claim
                st = NCryptNative.NCryptVerifyClaim(hAttestKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero,
                                                    claimBlob, claimBlob.Length, out _, 0);
                if (st == 0)
                    return new ClaimVerifyResult(true, 0, new { note = "verified without nonce (claim created without challenge binding)" });
                return new ClaimVerifyResult(false, st, details);
            }

            return new ClaimVerifyResult(true, 0, details ?? "verified (no details buffer)");
        }
        finally
        {
            if (pOutput != 0) NCryptNative.NCryptFreeBuffer(pOutput);
            if (pDesc != 0) Marshal.FreeHGlobal(pDesc);
            if (pBuffers != 0) Marshal.FreeHGlobal(pBuffers);
            if (nonceBuf != 0) Marshal.FreeHGlobal(nonceBuf);
            if (hAttestKey != 0) NCryptNative.NCryptFreeObject(hAttestKey);
            if (hProv != 0) NCryptNative.NCryptFreeObject(hProv);
        }
    }

    // ══════════════════════════════════════════════════════════
    //  D: PoP 签名验证 (公钥从 claim Attributes 的 SPKI 提取)
    // ══════════════════════════════════════════════════════════

    public static (bool Valid, string Note) VerifyPop(
        byte[]? claimBlob, byte[]? signature, string attestId, byte[] nonce)
    {
        if (signature is not { Length: > 0 })
            return (false, "no signature submitted");
        if (claimBlob is not { Length: > 44 + 162 })
            return (false, "claim blob too small");

        // claim 布局: [VKAS 4][ver 4][type 4][VRCH 24: magic,ver,cbAttr,cbNonce,cbReport,cbSig][Attributes: 3×u32 + SPKI][Nonce][Report][SK Signature]
        uint cbAttr = BitConverter.ToUInt32(claimBlob, 20);
        uint spkiLen = BitConverter.ToUInt32(claimBlob, 44);
        int spkiOff = 48;
        if (cbAttr < 12 + spkiLen || spkiLen == 0 || spkiOff + (int)spkiLen > claimBlob.Length)
            return (false, "claim Attributes layout invalid");

        var spki = claimBlob[spkiOff..(spkiOff + (int)spkiLen)];
        var claimHash = SHA256.HashData(claimBlob);
        var canonical = Encoding.UTF8.GetBytes(
            $"VBSRemoteDetect-v1\n{attestId}\n{Convert.ToBase64String(nonce)}\n{ToHexLower(claimHash)}");
        var canonHash = SHA256.HashData(canonical);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        bool ok = rsa.VerifyHash(canonHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return (ok, ok ? "RSA PKCS1/SHA256 signature valid — 公钥提取自 claim Attributes (被 Secure Kernel 报告哈希绑定)"
                       : "signature invalid");
    }

    // ══════════════════════════════════════════════════════════
    //  C: 运行时报告解析 (winnt.h RUNTIME_REPORT_PACKAGE + 实测偏移)
    // ══════════════════════════════════════════════════════════

    public static RuntimeReportInfo ParseRuntimeReport(byte[] report, byte[] expectedNonce)
    {
        try
        {
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

            // Nonce @40 (sizeof(RUNTIME_REPORT_PACKAGE_HEADER)=40, 含 8 字节对齐填充)
            bool nonceMatch = report.Length >= 72 &&
                report.AsSpan(40, 32).SequenceEqual(expectedNonce);

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

            var reports = new List<object>();
            var driverReport = (DriverReportInfo?)null;
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
                {
                    driverReport = ParseDriverReport(reportData);
                    reports.Add(driverReport);
                }
                else if (rtype == 1) // RuntimeReportTypeCodeIntegrity
                {
                    ulong generation = BitConverter.ToUInt64(reportData, 8);
                    uint numGens = BitConverter.ToUInt32(reportData, 16);
                    reports.Add(new { type = "CodeIntegrity", policyGeneration = generation, generationsInReport = numGens });
                }
                p += rsize;
            }

            bool valid = nonceMatch && digestOk == reports.Count;
            string digestVerif = $"{digestOk}/{reports.Count} OK";
            string sigScheme = signatureScheme == 1 ? "SHA512_RSA_PSS_SHA512" : $"0x{signatureScheme:X}";

            return new RuntimeReportInfo(true, valid, new
            {
                present = true,
                valid,
                packageVersion,
                reportTypesBitmap = $"0x{reportTypesBitmap:X}",
                signatureScheme = sigScheme,
                nonceMatch,
                digestVerification = digestVerif,
                signatureVerifiedByMicrosoftRoot = false,
                // TODO: SK 签名信任锚 — VBS_ROOT_PUB (IDKS, RSA-2048) 可从 KSP 读取,
                // 但对报告签名验签未通过 (多种范围×padding), 待 Azure 材料或逆向
                reports
            },
            DriverCount: driverReport?.DriverCount ?? 0,
            BootCount: driverReport?.Drivers.Count(d => d.Boot) ?? 0,
            UnloadedCount: driverReport?.Drivers.Count(d => d.Unloaded) ?? 0,
            DigestVerification: digestVerif,
            NonceMatch: nonceMatch,
            SignatureScheme: sigScheme,
            DriverReport: driverReport);
        }
        catch (Exception ex)
        {
            return new RuntimeReportInfo(true, false, new { error = ex.Message });
        }
    }

    static DriverReportInfo ParseDriverReport(byte[] report)
    {
        ushort numDrivers = BitConverter.ToUInt16(report, 8);
        ushort flags = BitConverter.ToUInt16(report, 10);
        var drivers = new List<DriverEntry>();
        const int entrySize = 56; // sizeof(DRIVER_INFO_ENTRY)

        for (int i = 0; i < numDrivers; i++)
        {
            int e = 12 + i * entrySize;
            if (e + entrySize > report.Length) break;

            ushort loadTimes = BitConverter.ToUInt16(report, e + 44);
            int imageHashOff0 = (int)BitConverter.ToUInt32(report, e + 36);
            // 过滤未占用的空槽位 (ghost entry)
            if (loadTimes == 0 && imageHashOff0 == 0) continue;

            int nameEnd = 0;
            for (int k = 0; k < 32; k++) { if (report[e + k] == 0) break; nameEnd = k + 1; }
            string internalName = Encoding.ASCII.GetString(report, e, nameEnd);

            ushort imgHashAlg = BitConverter.ToUInt16(report, e + 32);
            ushort pubHashAlg = BitConverter.ToUInt16(report, e + 34);
            int imageHashOff = (int)BitConverter.ToUInt32(report, e + 36);
            int pubHashOff = (int)BitConverter.ToUInt32(report, e + 40);
            ushort oemNameSize = BitConverter.ToUInt16(report, e + 46);
            int oemNameOff = (int)BitConverter.ToUInt32(report, e + 48);
            ushort drvFlags = BitConverter.ToUInt16(report, e + 52);

            // 镜像哈希 (SHA-256/32B) 与发布者指纹 (SHA-1/20B) 各自按算法取长度
            int imgHashSize = HashSizeFromCalg(imgHashAlg);
            int pubHashSize = HashSizeFromCalg(pubHashAlg);
            string imgHash = (imgHashSize > 0 && imageHashOff > 0 && imageHashOff + imgHashSize <= report.Length)
                ? Convert.ToHexString(report, imageHashOff, imgHashSize) : "?";
            string pubHash = (pubHashSize > 0 && pubHashOff > 0 && pubHashOff + pubHashSize <= report.Length)
                ? Convert.ToHexString(report, pubHashOff, pubHashSize) : "?";
            string oem = (oemNameSize > 0 && oemNameOff > 0 && oemNameOff + oemNameSize <= report.Length)
                ? Encoding.UTF8.GetString(report, oemNameOff, oemNameSize) : "";

            drivers.Add(new DriverEntry(
                internalName,
                Boot: (drvFlags & 0x2) != 0,
                Unloaded: (drvFlags & 0x1) != 0,
                LoadTimes: loadTimes,
                Oem: oem,
                ImageHash: imgHash.ToLowerInvariant(),
                PublisherThumbprint: pubHash.ToLowerInvariant()));
        }

        return new DriverReportInfo(
            drivers.Count,
            Overflow: (flags & 0x1) != 0,
            Partial: (flags & 0x2) != 0,
            IncludeBootDrivers: (flags & 0x4) != 0,
            drivers);
    }

    static int HashSizeFromCalg(ushort calg) => calg switch
    {
        0x8004 => 20, // CALG_SHA1
        0x800C => 32, // CALG_SHA_256
        0x800D => 48, // CALG_SHA_384
        0x800E => 64, // CALG_SHA_512
        _ => -1
    };

    static string ToHexLower(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();
}

// ═══════════════════════════════════════════════════════════════
//  NCrypt P/Invoke (CharSet=Unicode 必须 — 默认 ANSI 会导致各种假错误)
// ═══════════════════════════════════════════════════════════════

static class NCryptNative
{
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, byte[] pbData, int cbData, int dwFlags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptVerifyClaim(IntPtr hSubjectKey, IntPtr hAuthorityKey, uint dwClaimType, IntPtr pParameterList, byte[] pbClaimBlob, int cbClaimBlob, out IntPtr pOutput, uint dwFlags);
    [DllImport("ncrypt.dll")] public static extern int NCryptFreeObject(IntPtr hObject);
    [DllImport("ncrypt.dll")] public static extern int NCryptFreeBuffer(IntPtr pvBuffer);
}

[StructLayout(LayoutKind.Sequential)]
struct NCryptBuffer { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }

[StructLayout(LayoutKind.Sequential)]
struct NCryptBufferDesc { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }
