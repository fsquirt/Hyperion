using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Hyperion.Verifier.RemoteVerify
{
    // ── 返回值 ─────────────────────────────────────────────────────────────────
    public class VbsRuntimeVerifyResult
    {
        public bool Success { get; init; }
        public string Verdict { get; init; } = "";
        public bool VbsRunning { get; init; }
        public bool PopValid { get; init; }
        public bool ClaimVerified { get; init; }
        public bool ReportValid { get; init; }
        public string Raw { get; init; } = "";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // VbsRuntimeVerify — 方案 A+C+D 客户端 (C#)
    //
    // 在 PCRVerify (TPM2_Quote) 成功后调用, 向 /verify_vbs 提交:
    //   A. VBS Root Claim: NCRYPT_REQUIRE_VBS_FLAG 创建 VTL1 隔离密钥 →
    //      NCryptCreateClaim(VBS_ROOT, nonce=quote challenge), 由 IDKS 签发
    //   D. PoP 签名: PKCS1/SHA256 over canonical(history_id, nonce, claimHash)
    //   C. GetRuntimeAttestationReport 运行时报告 (同一 nonce, SK 签名)
    //
    // 实测要点 (与 tools/runtimetest 探针一致):
    //   - NCrypt DllImport 必须 CharSet=Unicode
    //   - KeyUsage 只设 NCRYPT_ALLOW_SIGNING_FLAG (ATTESTATION 位 → 0x80090027)
    //   - claim 需绑定 nonce (KeyUsage=SIGNING 后可用)
    //   - GetRuntimeAttestationReport 导出在 kernelbase.dll, 只支持 bitmap=1
    //   - VTL1 密钥 NCryptSignHash 实际使用 PKCS1/SHA256
    // ══════════════════════════════════════════════════════════════════════════
    public static class VbsRuntimeVerify
    {
        private const string KEY_NAME = "Hyperion_VbsAttestKey";

        public static async Task<VbsRuntimeVerifyResult> RunAsync(
            HttpClient http, string historyId, byte[] nonce)
        {
            // ── A: 创建 VTL1 隔离密钥 + 生成 claim ────────────────────────────
            Console.WriteLine("[*] VbsRuntimeVerify: 创建 VTL1 密钥 + claim...");
            var (claim, status) = CreateClaim(nonce);
            if (claim == null)
            {
                string hint = status == unchecked((int)0x80090029)
                    ? "NTE_NOT_SUPPORTED: Secure Kernel 未运行 (VBS 未启动/不支持)"
                    : $"0x{status:X8}";
                Console.WriteLine($"[✘] VbsRuntimeVerify: 创建 claim 失败 — {hint}");
                return new VbsRuntimeVerifyResult { Success = false, Verdict = $"FAIL — claim 创建失败: {hint}" };
            }
            Console.WriteLine($"    claim: {claim.Length} bytes");

            // ── 导出公钥 (NCrypt 原生 BCRYPT_RSAPUBLICBLOB) ───────────────────
            var attestPub = ExportAttestPub();

            // ── D: PoP 签名 (PKCS1/SHA256 over canonical) ─────────────────────
            var claimHash = SHA256.HashData(claim);
            var canonical = Encoding.UTF8.GetBytes(
                $"VBSRemoteDetect-v1\n{historyId}\n{Convert.ToBase64String(nonce)}\n{Convert.ToHexString(claimHash).ToLowerInvariant()}");
            var canonHash = SHA256.HashData(canonical);
            var sig = SignHashPkcs1(canonHash);
            if (sig == null)
                return new VbsRuntimeVerifyResult { Success = false, Verdict = "FAIL — PoP 签名失败" };
            Console.WriteLine($"    PoP 签名: {sig.Length} bytes (PKCS1/SHA256)");

            // ── C: 运行时报告 (可选 — 有导出必须调用, 无导出跳过由 A+D 判定) ──
            var runtimeReport = GetRuntimeReport(nonce);
            if (runtimeReport != null)
                Console.WriteLine($"    运行时报告: {runtimeReport.Length} bytes (SK 签名)");
            else
                Console.WriteLine("    运行时报告: 本机无 GetRuntimeAttestationReport 导出 — 跳过方案C (A+D 已足够确认 VBS 运行态)");

            // ── 提交 /verify_vbs ───────────────────────────────────────────────
            Console.WriteLine("[*] VbsRuntimeVerify: POST /verify_vbs...");
            HttpResponseMessage resp;
            try
            {
                resp = await http.PostAsJsonAsync("/verify_vbs", new
                {
                    history_id = historyId,
                    nonce = Convert.ToBase64String(nonce),
                    claim_blob = Convert.ToBase64String(claim),
                    attest_pub = Convert.ToBase64String(attestPub ?? []),
                    signature = Convert.ToBase64String(sig),
                    runtime_report = runtimeReport == null ? "" : Convert.ToBase64String(runtimeReport),
                });
            }
            catch (Exception ex) { return new VbsRuntimeVerifyResult { Success = false, Verdict = $"HTTP: {ex.Message}" }; }

            var raw = await resp.Content.ReadAsStringAsync();
            JsonElement body;
            try { body = JsonDocument.Parse(raw).RootElement; }
            catch (Exception ex) { return new VbsRuntimeVerifyResult { Success = false, Verdict = $"JSON: {ex.Message}", Raw = raw }; }

            string verdict = body.TryGetProperty("verdict", out var vv) ? vv.GetString() ?? "" : "";
            bool vbsRunning = body.TryGetProperty("vbs_running", out var vr) && vr.GetBoolean();
            bool popValid = body.TryGetProperty("pop", out var popEl) &&
                            popEl.TryGetProperty("valid", out var pv) && pv.GetBoolean();
            bool claimVerified = body.TryGetProperty("claim", out var claimEl) &&
                                 claimEl.TryGetProperty("verified", out var cv) && cv.GetBoolean();
            bool reportValid = body.TryGetProperty("hvci_runtime_report", out var rrEl) &&
                               rrEl.TryGetProperty("valid", out var rv) && rv.GetBoolean();
            bool reportPresent = body.TryGetProperty("hvci_runtime_report", out var rrEl2) &&
                                 rrEl2.TryGetProperty("present", out var rp) && rp.GetBoolean();

            // ── 方案 A/C/D 判定 + 驱动摘要 (与服务器侧验证结果一致) ──
            Console.WriteLine($"    方案A claim链 : {(claimVerified ? "✔ NCryptVerifyClaim 通过 (IDKS/VTL1, nonce 绑定)" : "✘")}");
            Console.WriteLine($"    方案D PoP签名 : {(popValid ? "✔ PKCS1/SHA256 验证通过 (VTL1 密钥持有)" : "✘")}");
            if (!reportPresent)
                Console.WriteLine("    方案C 运行时报告: — 未提交 (本机无 GetRuntimeAttestationReport 导出, A+D 已足够确认 VBS 运行态)");
            else
                Console.WriteLine($"    方案C 运行时报告: {(reportValid ? "✔ nonce 绑定 + digest 一致" : "✘ 校验未通过")}");
            if (body.TryGetProperty("driver_report", out var drEl))
            {
                int dCount = drEl.TryGetProperty("count", out var dc) ? dc.GetInt32() : 0;
                int dBoot = drEl.TryGetProperty("boot", out var db) ? db.GetInt32() : 0;
                int dUnl = drEl.TryGetProperty("unloaded", out var du) ? du.GetInt32() : 0;
                Console.WriteLine($"    驱动报告     : {dCount} 个 (Boot {dBoot} / Unloaded {dUnl}) — 全量明细见仪表盘\"运行时检测\"");
                if (drEl.TryGetProperty("drivers", out var dl) && dl.ValueKind == JsonValueKind.Array)
                {
                    int shown = 0;
                    foreach (var dv in dl.EnumerateArray())
                    {
                        if (shown++ >= 12) break;
                        string nm = dv.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        bool unloaded = dv.TryGetProperty("unloaded", out var u) && u.GetBoolean();
                        int lt = dv.TryGetProperty("load_times", out var l) ? l.GetInt32() : 0;
                        Console.WriteLine($"      {nm,-24} {(unloaded ? "Unloaded" : "Runtime ")} 次数={lt}");
                    }
                    if (dCount > shown)
                        Console.WriteLine($"      ... 其余 {dCount - shown} 个见服务器完整解析");
                }
            }

            Console.WriteLine($"[✔] VbsRuntimeVerify: {verdict}");
            return new VbsRuntimeVerifyResult
            {
                Success = vbsRunning,
                Verdict = verdict,
                VbsRunning = vbsRunning,
                PopValid = popValid,
                ClaimVerified = claimVerified,
                ReportValid = reportValid,
                Raw = raw,
            };
        }

        // ── NCrypt: 创建 VTL1 密钥 + VBS Root Claim (nonce 绑定) ─────────────

        private static (byte[]? claim, int status) CreateClaim(byte[] nonce)
        {
            int st = NCryptVbs.NCryptOpenStorageProvider(out var hProv, "Microsoft Software Key Storage Provider", 0);
            if (st != 0) return (null, st);
            IntPtr hKey = 0;
            try
            {
                st = NCryptVbs.NCryptCreatePersistedKey(hProv, out hKey, "RSA", KEY_NAME,
                    0, (int)(0x00000080 /*OVERWRITE*/ | 0x00020000 /*REQUIRE_VBS*/));
                if (st != 0) return (null, st);

                // 只设 SIGNING (ATTESTATION 位 → 0x80090027)
                var usage = BitConverter.GetBytes(0x00000002u /*NCRYPT_ALLOW_SIGNING_FLAG*/);
                st = NCryptVbs.NCryptSetProperty(hKey, "Key Usage", usage, usage.Length, 0);
                if (st != 0) Console.WriteLine($"    [!] KeyUsage 设置失败: 0x{st:X8} (非致命)");

                st = NCryptVbs.NCryptFinalizeKey(hKey, 0);
                if (st != 0) return (null, st);

                // nonce 绑定的 VBS Root Claim
                var pNonce = Marshal.AllocHGlobal(nonce.Length);
                Marshal.Copy(nonce, 0, pNonce, nonce.Length);
                var pBufs = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBufferVbs>());
                Marshal.StructureToPtr(new NCryptBufferVbs
                {
                    cbBuffer = (uint)nonce.Length,
                    BufferType = 49 /*NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE*/,
                    pvBuffer = pNonce,
                }, pBufs, false);
                var pDesc = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBufferDescVbs>());
                Marshal.StructureToPtr(new NCryptBufferDescVbs { ulVersion = 0, cBuffers = 1, pBuffers = pBufs }, pDesc, false);

                st = NCryptVbs.NCryptCreateClaim(hKey, IntPtr.Zero, 5 /*NCRYPT_CLAIM_VBS_ROOT*/,
                    pDesc, null, 0, out uint cb, 0);
                if (st != 0) return (null, st);
                var claim = new byte[cb];
                st = NCryptVbs.NCryptCreateClaim(hKey, IntPtr.Zero, 5, pDesc, claim, cb, out cb, 0);

                Marshal.FreeHGlobal(pNonce);
                Marshal.FreeHGlobal(pBufs);
                Marshal.FreeHGlobal(pDesc);
                return (st == 0 ? claim : null, st);
            }
            finally
            {
                if (hKey != 0) NCryptVbs.NCryptFreeObject(hKey);
                NCryptVbs.NCryptFreeObject(hProv);
            }
        }

        private static byte[]? ExportAttestPub()
        {
            try
            {
                int st = NCryptVbs.NCryptOpenStorageProvider(out var hProv, "Microsoft Software Key Storage Provider", 0);
                if (st != 0) return null;
                try
                {
                    st = NCryptVbs.NCryptOpenKey(hProv, out var hKey, KEY_NAME, 0, 0);
                    if (st != 0) return null;
                    try
                    {
                        st = NCryptVbs.NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero,
                            null, 0, out uint cb, 0);
                        if (st != 0) return null;
                        var blob = new byte[cb];
                        st = NCryptVbs.NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero,
                            blob, cb, out cb, 0);
                        return st == 0 ? blob : null;
                    }
                    finally { NCryptVbs.NCryptFreeObject(hKey); }
                }
                finally { NCryptVbs.NCryptFreeObject(hProv); }
            }
            catch { return null; }
        }

        private static byte[]? SignHashPkcs1(byte[] hash)
        {
            try
            {
                int st = NCryptVbs.NCryptOpenStorageProvider(out var hProv, "Microsoft Software Key Storage Provider", 0);
                if (st != 0) return null;
                try
                {
                    st = NCryptVbs.NCryptOpenKey(hProv, out var hKey, KEY_NAME, 0, 0);
                    if (st != 0) return null;
                    try
                    {
                        var pAlg = Marshal.StringToHGlobalUni("SHA256");
                        var info = new BcryptPkcs1PaddingInfo { pszAlgId = pAlg };
                        var pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<BcryptPkcs1PaddingInfo>());
                        Marshal.StructureToPtr(info, pInfo, false);

                        st = NCryptVbs.NCryptSignHash(hKey, pInfo, hash, hash.Length,
                            null, 0, out uint cbSig, 0x2 /*BCRYPT_PAD_PKCS1*/);
                        var sig = new byte[cbSig];
                        st = NCryptVbs.NCryptSignHash(hKey, pInfo, hash, hash.Length,
                            sig, cbSig, out cbSig, 0x2);

                        Marshal.FreeHGlobal(pInfo);
                        Marshal.FreeHGlobal(pAlg);
                        return st == 0 ? sig : null;
                    }
                    finally { NCryptVbs.NCryptFreeObject(hKey); }
                }
                finally { NCryptVbs.NCryptFreeObject(hProv); }
            }
            catch { return null; }
        }

        // ── C: GetRuntimeAttestationReport (kernelbase.dll, 仅 Driver 报告) ──

        private static byte[]? GetRuntimeReport(byte[] nonce)
        {
            // 实测: 导出在 kernelbase.dll (文档写 kernel32.dll 是错的)
            IntPtr pfn = GetProcAddress(GetModuleHandle("kernelbase.dll"), "GetRuntimeAttestationReport");
            if (pfn == IntPtr.Zero)
                pfn = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetRuntimeAttestationReport");
            if (pfn == IntPtr.Zero) return null;

            var pfnDelegate = Marshal.GetDelegateForFunctionPointer<RuntimeReportDelegate>(pfn);
            uint cb = 0;
            // 第一次调用: size 查询 (实测返回 FALSE + ERROR_INSUFFICIENT_BUFFER 并回填 cb)
            if (!pfnDelegate(nonce, 1, 1 /*1<<RuntimeReportTypeDriver*/, IntPtr.Zero, ref cb) &&
                Marshal.GetLastWin32Error() != 0x7A /*ERROR_INSUFFICIENT_BUFFER*/)
                return null;
            var buf = new byte[cb];
            bool ok = pfnDelegate(nonce, 1, 1, Marshal.UnsafeAddrOfPinnedArrayElement(buf, 0), ref cb);
            return ok ? buf : null;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool RuntimeReportDelegate(byte[] nonce, ushort packageVersion,
            ulong reportTypesBitmap, IntPtr reportBuffer, ref uint reportBufferSize);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        private static VbsRuntimeVerifyResult Fail(string reason)
        {
            Console.WriteLine($"[✘] VbsRuntimeVerify: {reason}");
            return new VbsRuntimeVerifyResult { Success = false, Verdict = $"FAIL — {reason}" };
        }
    }

    // ── NCrypt P/Invoke (CharSet=Unicode 必须) ────────────────────────────────

    internal static class NCryptVbs
    {
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptExportKey(IntPtr hKey, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, uint cbOutput, out uint pcbResult, int dwFlags);
        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] public static extern int NCryptCreateClaim(IntPtr hSubjectKey, IntPtr hAuthorityKey, uint dwClaimType, IntPtr pParameterList, byte[] pbClaimBlob, uint cbClaimBlob, out uint pcbResult, int dwFlags);
        [DllImport("ncrypt.dll")] public static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, uint cbSignature, out uint pcbResult, int dwFlags);
        [DllImport("ncrypt.dll")] public static extern int NCryptFreeObject(IntPtr hObject);
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptBufferVbs { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NCryptBufferDescVbs { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BcryptPkcs1PaddingInfo { public IntPtr pszAlgId; }
}
