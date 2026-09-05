// 探测脚本: 本机 OS 版本 / GetRuntimeAttestationReport 可用性 / NCrypt VBS 证明链
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

Console.WriteLine($"OS: {Environment.OSVersion.VersionString} (build {Environment.OSVersion.Version.Build})");
try
{
    var ubr = Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR", null);
    var display = Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", null);
    var productName = Microsoft.Win32.Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", null);
    Console.WriteLine($"OS 详细: {productName} {display} build {Environment.OSVersion.Version.Build}.{ubr}");
}
catch (Exception ex) { Console.WriteLine($"读取版本信息失败: {ex.Message}"); }

// 导出表探测: kernel32 / kernelbase
foreach (var dll in new[] { "kernel32.dll", "kernelbase.dll", "ntdll.dll" })
{
    var h = LoadLibrary(dll);
    var addr = GetProcAddress(h, "GetRuntimeAttestationReport");
    Console.WriteLine($"[导出探测] {dll}: module=0x{h:X} GetRuntimeAttestationReport=0x{addr:X} {(addr != 0 ? "→ 存在!" : "→ 不存在")}");
}


// C. GetRuntimeAttestationReport (kernelbase.dll)

Console.WriteLine("\n\u2500\u2500 C. GetRuntimeAttestationReport \u2500\u2500");
unsafe
{
    var nonce = new byte[32];
    new Random(42).NextBytes(nonce);
    // 实测: PackageVersion=1, 只能请求 Driver 报告 (bitmap=1 = 1<<RuntimeReportTypeDriver)
    fixed (byte* pN0 = nonce)
    {
        uint cb = 0;
        GetRuntimeAttestationReport(pN0, 1, 1, null, ref cb);   // 预期 FALSE + ERROR_INSUFFICIENT_BUFFER
        var gle = Marshal.GetLastWin32Error();
        Console.WriteLine($"[C] size-query: cb={cb} gle=0x{gle:X8}");
        var buf = new byte[cb];
        bool ok;
        fixed (byte* pBuf = buf)
            ok = GetRuntimeAttestationReport(pN0, 1, 1, pBuf, ref cb);
        Console.WriteLine($"[C] 获取报告: ok={ok} size={cb} gle=0x{Marshal.GetLastWin32Error():X8}");
        if (ok)
        {
            File.WriteAllBytes("runtime_report.bin", buf);
            Console.WriteLine($"[C] 已保存 runtime_report.bin ({buf.Length}B)");
            Console.WriteLine($"[C] head 64B: {Convert.ToHexString(buf, 0, 64)}");
            Console.WriteLine($"[C] nonce@36: {Convert.ToHexString(buf, 36, 32)}");
        }
    }
}

// A. NCrypt VBS 证明链

Console.WriteLine("\n A. NCrypt VBS 证明链 ");
const uint NCRYPT_REQUIRE_VBS_FLAG = 0x00020000;
const uint NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080;
const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
const uint NCRYPT_ALLOW_SIGNING_FLAG = 0x2;
const uint NCRYPT_ALLOW_KEY_ATTESTATION_FLAG = 0x10;
const uint NCRYPT_CLAIM_VBS_ROOT = 0x00000005;
const uint NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE = 49;
const uint NCRYPTBUFFER_ATTESTATION_STATEMENT_SIGNATURE_HASH = 90;
const uint NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS = 94;
const uint NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG = 0x00100000;

NCryptOpenStorageProvider(out var hProv, "Microsoft Software Key Storage Provider", 0);
var st = NCryptCreatePersistedKey(hProv, out var hKey, "RSA", "VBSDetect_ProbeKey",
    0, (int)(NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_REQUIRE_VBS_FLAG));
Console.WriteLine($"[A] NCryptCreatePersistedKey(REQUIRE_VBS) = 0x{st:X8} {(st == 0 ? "→ VTL1 密钥创建成功, VBS 运行中" : "→ 失败")}");
if (st != 0) { Console.WriteLine("[A] 结论: Secure Kernel 未运行, 方案 A 不可用"); return; }

var usage = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_KEY_ATTESTATION_FLAG;
st = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, BitConverter.GetBytes(usage), 4, unchecked((int)0x80000000));
Console.WriteLine($"[A] SetProperty(KeyUsage=SIGNING|ATTESTATION) = 0x{st:X8}");
st = NCryptFinalizeKey(hKey, 0);
Console.WriteLine($"[A] NCryptFinalizeKey = 0x{st:X8}");

// 导出公钥
st = NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, null, 0, out uint cbPub, 0);
var pub = new byte[cbPub];
st = NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, pub, cbPub, out cbPub, 0);
Console.WriteLine($"[A] 公钥导出 {cbPub} bytes");

// 创建 VBS Root Claim, 绑定 nonce
var nonce2 = RandomNumberGenerator.GetBytes(32);
var pNonce = Marshal.AllocHGlobal(32);
Marshal.Copy(nonce2, 0, pNonce, 32);
var hashAlg = Encoding.Unicode.GetBytes("SHA256\0");
var pHash = Marshal.AllocHGlobal(hashAlg.Length);
Marshal.Copy(hashAlg, 0, pHash, hashAlg.Length);

var bufs = new[]
{
    new NCryptBuffer { cbBuffer = 32, BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE, pvBuffer = pNonce },
    new NCryptBuffer { cbBuffer = (uint)hashAlg.Length, BufferType = NCRYPTBUFFER_ATTESTATION_STATEMENT_SIGNATURE_HASH, pvBuffer = pHash },
};
var pBufArr = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBuffer>() * 2);
Marshal.StructureToPtr(bufs[0], pBufArr, false);
Marshal.StructureToPtr(bufs[1], pBufArr + Marshal.SizeOf<NCryptBuffer>(), false);
var desc = new NCryptBufferDesc { ulVersion = 0, cBuffers = 2, pBuffers = pBufArr };
var pDesc = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBufferDesc>());
Marshal.StructureToPtr(desc, pDesc, false);

st = NCryptCreateClaim(hKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, pDesc, null, 0, out uint cbClaim, 0);
Console.WriteLine($"[A] NCryptCreateClaim(VBS_ROOT) 并绑定 nonce = 0x{st:X8}, size={cbClaim}");
if (st == 0)
{
    var claim = new byte[cbClaim];
    st = NCryptCreateClaim(hKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, pDesc, claim, cbClaim, out cbClaim, 0);
    File.WriteAllBytes("probe_claim.bin", claim);
    Console.WriteLine($"[A] claim blob 已保存 probe_claim.bin, magic 预期 'VKAS'=0x53414B56, 实际: 0x{BitConverter.ToUInt32(claim, 0):X8}");

    // 本地 NCryptVerifyClaim 验证,与服务器验证逻辑相同 — 变体矩阵
    // 变体1: subject=私钥句柄, 无参数
    st = NCryptVerifyClaim(hKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero, claim, claim.Length,
        out var pOutput, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG);
    Console.WriteLine($"[A] Verify 以私钥句柄调用, 无参数 = 0x{st:X8}");
    // 变体2: subject=导入的公钥, 无参数
    st = NCryptImportKey(hProv, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, out var hPubKey, pub, (int)cbPub, 0);
    Console.WriteLine($"[A] 导入公钥句柄 = 0x{st:X8}");
    if (st == 0)
    {
        st = NCryptVerifyClaim(hPubKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero, claim, claim.Length,
            out pOutput, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG);
        Console.WriteLine($"[A] Verify 以公钥句柄调用, 无参数 = 0x{st:X8} {(st == 0 ? "→ 验证通过! 签名链锚定 IDKS, VBS 运行态被密码学证明" : "")}");
    }
    if (st == 0 && pOutput != IntPtr.Zero)
    {
        var outDesc = Marshal.PtrToStructure<NCryptBufferDesc>(pOutput);
        for (uint i = 0; i < outDesc.cBuffers; i++)
        {
            var b = Marshal.PtrToStructure<NCryptBuffer>(outDesc.pBuffers + (int)(i * Marshal.SizeOf<NCryptBuffer>()));
            Console.WriteLine($"[A] details buffer: type=0x{b.BufferType:X} cb={b.cbBuffer}");
            if (b.BufferType == NCRYPTBUFFER_VBS_ATTESTATION_STATEMENT_ROOT_DETAILS && b.cbBuffer >= 24)
                Console.WriteLine($"    KeyFlags=0x{Marshal.ReadInt32(b.pvBuffer):X} TrustletId=0x{Marshal.ReadInt64(b.pvBuffer, 8):X} SVN={Marshal.ReadInt32(b.pvBuffer, 16)} Debuggable={Marshal.ReadInt32(b.pvBuffer, 20)}");
        }
        NCryptFreeBuffer(pOutput);
    }
}

Marshal.FreeHGlobal(pNonce); Marshal.FreeHGlobal(pHash); Marshal.FreeHGlobal(pBufArr); Marshal.FreeHGlobal(pDesc);


// HTTP 端到端测试: 用刚创建的 VTL1 密钥走一遍完整协议

if (args.Length > 0 && args[0] == "--http")
{
    string baseUrl = args.Length > 1 ? args[1] : "http://127.0.0.1:8899";
    Console.WriteLine($"\n HTTP 端到端测试 → {baseUrl} ");

    // 重新打开密钥并签名
    st = NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0);
    st = NCryptOpenKey(hProv, out hKey, "VBSDetect_ProbeKey", 0, 0);
    Console.WriteLine($"[HTTP] NCryptOpenKey = 0x{st:X8}");
    if (st != 0) return;

    // 1. challenge
    using (var hc = new System.Net.Http.HttpClient(new System.Net.Http.SocketsHttpHandler { UseProxy = false }))
    {
        var challengeJson = hc.GetStringAsync($"{baseUrl}/api/vbs/challenge").Result;
        Console.WriteLine($"[HTTP] challenge: {challengeJson}");
        var sid = System.Text.Json.JsonDocument.Parse(challengeJson).RootElement.GetProperty("session_id").GetString();
        var nonceB = Convert.FromBase64String(System.Text.Json.JsonDocument.Parse(challengeJson).RootElement.GetProperty("nonce").GetString());

        // 2. claim,重新生成一份
        st = NCryptCreateClaim(hKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero, null, 0, out uint cbC, 0);
        var claim2 = new byte[cbC];
        st = NCryptCreateClaim(hKey, IntPtr.Zero, NCRYPT_CLAIM_VBS_ROOT, IntPtr.Zero, claim2, cbC, out cbC, 0);
        Console.WriteLine($"[HTTP] claim 重新生成: 0x{st:X8} {cbC}B");

        // 3.5 解析 claim 结构: [VKAS 4][ver 4][claimType 4][VRCH 24: magic,ver,cbAttr,cbNonce,cbReport,cbSig][Attributes][Nonce][Report][Signature]
        uint cbAttr = BitConverter.ToUInt32(claim2, 12 + 8);
        uint cbN = BitConverter.ToUInt32(claim2, 12 + 12);
        uint cbR = BitConverter.ToUInt32(claim2, 12 + 16);
        uint cbS = BitConverter.ToUInt32(claim2, 12 + 20);
        Console.WriteLine($"[HTTP] claim 结构: cbAttr={cbAttr} cbNonce={cbN} cbReport={cbR} cbSig={cbS}");
        var attrPub = claim2[36..(36 + (int)Math.Min(cbAttr, 400))];
        Console.WriteLine($"[HTTP] Attributes[0..32]: {Convert.ToHexString(attrPub, 0, Math.Min(32, attrPub.Length))}");

        // 3. PoP 签名: canonical = VBSRemoteDetect-v1\n{sid}\n{nonceB64}\n{claimHashHex}
        var claimHash = SHA256.HashData(claim2);
        var canonical = Encoding.UTF8.GetBytes(
            $"VBSRemoteDetect-v1\n{sid}\n{Convert.ToBase64String(nonceB)}\n{Convert.ToHexString(claimHash).ToLowerInvariant()}");
        var canonHash = SHA256.HashData(canonical);
        var sha256W = Encoding.Unicode.GetBytes("SHA256\0");
        var pAlg = Marshal.AllocHGlobal(sha256W.Length);
        Marshal.Copy(sha256W, 0, pAlg, sha256W.Length);
        var pss = new BCRYPT_PSS_PADDING_INFO { pszAlgId = pAlg, cbSalt = 32 };
        var pPss = Marshal.AllocHGlobal(Marshal.SizeOf<BCRYPT_PSS_PADDING_INFO>());
        Marshal.StructureToPtr(pss, pPss, false);
        st = NCryptSignHash(hKey, pPss, canonHash, canonHash.Length, null, 0, out uint cbSig, 0x2 /*BCRYPT_PAD_PSS*/);
        var sig = new byte[cbSig];
        st = NCryptSignHash(hKey, pPss, canonHash, canonHash.Length, sig, cbSig, out cbSig, 0x2);
        Console.WriteLine($"[HTTP] PoP 签名: 0x{st:X8} {cbSig}B");

        // 导出公钥
        st = NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, null, 0, out uint cbP2, 0);
        var pub2 = new byte[cbP2];
        NCryptExportKey(hKey, IntPtr.Zero, "RSAPUBLICBLOB", IntPtr.Zero, pub2, cbP2, out cbP2, 0);
        Console.WriteLine($"[HTTP] pub blob {cbP2}B: magic=0x{BitConverter.ToUInt32(pub2, 0):X8} bitLen={BitConverter.ToUInt32(pub2, 4)} cbExp={BitConverter.ToUInt32(pub2, 8)} cbMod={BitConverter.ToUInt32(pub2, 12)}");

        // 本地 .NET RSA 验签,与服务器逻辑一致 — 公钥从 claim Attributes 的 SPKI 提取
        var spki = claim2[48..(48 + (int)BitConverter.ToUInt32(claim2, 44))];
        using (var rsaCheck = RSA.Create())
        {
            rsaCheck.ImportSubjectPublicKeyInfo(spki, out _);
            foreach (var halg in new[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 })
            foreach (var pad in new[] { RSASignaturePadding.Pkcs1 })
                if (rsaCheck.VerifyHash(canonHash, sig, halg, pad)) Console.WriteLine($"[HTTP] 匹配: {halg} {pad}");
        }

        var payload = System.Text.Json.JsonSerializer.Serialize(new
        {
            session_id = sid,
            claim_blob = Convert.ToBase64String(claim2),
            attest_pub = Convert.ToBase64String(pub2),
            idks_pub = IdksB64(),
            signature = Convert.ToBase64String(sig),
            runtime_report = GetRuntimeReportB64(nonceB)
        });
        var resp = hc.PostAsync($"{baseUrl}/api/vbs/verify",
            new System.Net.Http.StringContent(payload, Encoding.UTF8, "application/json")).Result;
        Console.WriteLine($"[HTTP] 服务器响应 (HTTP {(int)resp.StatusCode}):");
        Console.WriteLine(resp.Content.ReadAsStringAsync().Result);
    }
}

NCryptFreeObject(hKey); NCryptFreeObject(hProv);

// 实验: ① KeyUsage=SIGNING only ② nonce 绑定 claim ③ VBS_ROOT_PUB 验报告签名

Console.WriteLine("\n 实验段 ");
{
    // 重新开一把 key
    st = NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0);
    st = NCryptCreatePersistedKey(hProv, out hKey, "RSA", "VBSDetect_ProbeKey",
        0, (int)(NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_REQUIRE_VBS_FLAG));
    Console.WriteLine($"[实验] CreatePersistedKey = 0x{st:X8}");

    // ① 只设 SIGNING,不带 ATTESTATION
    var usageSign = BitConverter.GetBytes((uint)NCRYPT_ALLOW_SIGNING_FLAG);
    st = NCryptSetProperty(hKey, "Key Usage", usageSign, usageSign.Length, 0);
    Console.WriteLine($"[实验①] SetProperty(KeyUsage=SIGNING only, flags=0) = 0x{st:X8}");
    st = NCryptFinalizeKey(hKey, 0);
    Console.WriteLine($"[实验①] FinalizeKey = 0x{st:X8}");

    // ② 带 nonce 的 claim
    var nonce3 = RandomNumberGenerator.GetBytes(32);
    var pN3 = Marshal.AllocHGlobal(32); Marshal.Copy(nonce3, 0, pN3, 32);
    var bufs3 = new[] { new NCryptBuffer { cbBuffer = 32, BufferType = 49, pvBuffer = pN3 } };
    var pBufs3 = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBuffer>());
    Marshal.StructureToPtr(bufs3[0], pBufs3, false);
    var pDesc3 = Marshal.AllocHGlobal(Marshal.SizeOf<NCryptBufferDesc>());
    Marshal.StructureToPtr(new NCryptBufferDesc { ulVersion = 0, cBuffers = 1, pBuffers = pBufs3 }, pDesc3, false);
    st = NCryptCreateClaim(hKey, IntPtr.Zero, 5, pDesc3, null, 0, out uint cbC3, 0);
    Console.WriteLine($"[实验②] CreateClaim(VBS_ROOT) 绑定 nonce = 0x{st:X8} size={cbC3}");
    byte[]? claim3 = null;
    if (st == 0) { claim3 = new byte[cbC3]; NCryptCreateClaim(hKey, IntPtr.Zero, 5, pDesc3, claim3, cbC3, out cbC3, 0); File.WriteAllBytes("probe_claim_nonce.bin", claim3); }

    // ③ VBS_ROOT_PUB 属性, 即 IDKS 公钥
    st = NCryptGetProperty(hProv, "VBS_ROOT_PUB", null, 0, out uint cbRoot, 0);
    Console.WriteLine($"[实验③] GetProperty(VBS_ROOT_PUB) size-query = 0x{st:X8} cb={cbRoot}");
    if (st == 0 && cbRoot > 0)
    {
        var rootPub = new byte[cbRoot];
        NCryptGetProperty(hProv, "VBS_ROOT_PUB", rootPub, cbRoot, out _, 0);
        File.WriteAllBytes("vbs_root_pub.bin", rootPub);
        Console.WriteLine($"[实验③] VBS_ROOT_PUB {cbRoot}B → vbs_root_pub.bin, magic=0x{BitConverter.ToUInt32(rootPub, 0):X8}");

        // 用 IDKS 公钥验 runtime_report.bin 的签名 (SHA512 RSA-PSS over [0, sigOff))
        var rep = File.ReadAllBytes("runtime_report.bin");
        ushort digestsSize = BitConverter.ToUInt16(rep, 22);
        uint sigSize = BitConverter.ToUInt32(rep, 28);
        int sigOff = 72 + digestsSize;
        var signedData = rep[..sigOff];
        var signature = rep[sigOff..(sigOff + (int)sigSize)];
        var dataHash = SHA512.HashData(signedData);
        try
        {
            using var rsaRoot = RSA.Create();
            // rootPub 是 BCRYPT_RSAKEY_BLOB (magic RSA1), 不是 DER SPKI
            uint bl = BitConverter.ToUInt32(rootPub, 4);
            uint ce = BitConverter.ToUInt32(rootPub, 8);
            uint cm = BitConverter.ToUInt32(rootPub, 12);
            rsaRoot.ImportParameters(new RSAParameters
            {
                Exponent = rootPub[16..(16 + (int)ce)],
                Modulus = rootPub[(16 + (int)ce)..(16 + (int)ce + (int)cm)]
            });
            Console.WriteLine($"[实验③] root pub: bitLen={bl} exp={ce}B mod={cm}B");
            foreach (var (name, rng) in new[] {
                ("[0,sigOff) 全包", (0, sigOff)),
                ("[4,sigOff) 跳过magic", (4, sigOff)),
                ("[40,sigOff) nonce起", (40, sigOff)),
                ("[72,sigOff) digest起", (72, sigOff)),
            })
            {
                var dh = SHA512.HashData(rep[rng.Item1..rng.Item2]);
                bool vp = rsaRoot.VerifyHash(dh, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                bool vk = rsaRoot.VerifyHash(dh, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                if (vp || vk) Console.WriteLine($"[实验③] ★ 匹配! 范围={name} PSS={vp} PKCS1={vk}");
            }
            Console.WriteLine($"[实验③] 范围遍历完成");
        }
        catch (Exception ex) { Console.WriteLine($"[实验③] 验签异常: {ex.Message}"); }
    }
    Marshal.FreeHGlobal(pN3); Marshal.FreeHGlobal(pBufs3); Marshal.FreeHGlobal(pDesc3);
    NCryptFreeObject(hKey); NCryptFreeObject(hProv);
}

Console.WriteLine("\nprobe 完成.");

static unsafe string GetRuntimeReportB64(byte[] nonce)
{
    fixed (byte* pN = nonce)
    {
        uint cb = 0;
        GetRuntimeAttestationReport(pN, 1, 1, null, ref cb);
        var buf = new byte[cb];
        bool ok;
        fixed (byte* pBuf = buf)
            ok = GetRuntimeAttestationReport(pN, 1, 1, pBuf, ref cb);
        Console.WriteLine($"[HTTP] 运行时报告: ok={ok} size={cb}");
        return ok ? Convert.ToBase64String(buf) : "";
    }
}

// IDKS 公钥,来自 exp2 实验提取的度量启动日志 PCR12 VSMIDKSInfo —
// e2e 验证用; 生产路径在 Hyperion.Verifier.VbsRuntimeVerify.ExtractIdksPub
static string? IdksB64()
{
    try
    {
        var keys = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(
            File.ReadAllText("idk_keys.json"));
        var exp = keys!["VSMIDKSInfo"].GetProperty("exp").GetString()!.Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
        var mod = keys["VSMIDKSInfo"].GetProperty("mod").GetString()!.Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
        var blob = new byte[16 + exp.Length + mod.Length];
        BitConverter.GetBytes(0x31415352).CopyTo(blob, 0);
        BitConverter.GetBytes((uint)(mod.Length * 8)).CopyTo(blob, 4);
        BitConverter.GetBytes((uint)exp.Length).CopyTo(blob, 8);
        BitConverter.GetBytes((uint)mod.Length).CopyTo(blob, 12);
        exp.CopyTo(blob, 16);
        mod.CopyTo(blob, 16 + exp.Length);
        return Convert.ToBase64String(blob);
    }
    catch { return null; }
}

//  P/Invoke 
[DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr LoadLibrary(string lpLibFileName);
[DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
[DllImport("kernelbase.dll", SetLastError = true)]
static extern unsafe bool GetRuntimeAttestationReport(byte* Nonce, ushort PackageVersion,
    ulong ReportTypesBitmap, void* ReportBuffer, ref uint ReportBufferSize);

[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptImportKey(IntPtr hProvider, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, out IntPtr phKey, byte[] pbData, int cbData, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptExportKey(IntPtr hKey, IntPtr hImportKey, string pszBlobType, IntPtr pParameterList, byte[] pbOutput, uint cbOutput, out uint pcbResult, int dwFlags);
[DllImport("ncrypt.dll")] static extern int NCryptSignHash(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, uint cbSignature, out uint pcbResult, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptCreateClaim(IntPtr hSubjectKey, IntPtr hAuthorityKey, uint dwClaimType, IntPtr pParameterList, byte[] pbClaimBlob, uint cbClaimBlob, out uint pcbResult, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptVerifyClaim(IntPtr hSubjectKey, IntPtr hAuthorityKey, uint dwClaimType, IntPtr pParameterList, byte[] pbClaimBlob, int cbClaimBlob, out IntPtr pOutput, uint dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptGetProperty(IntPtr hObject, string pszProperty, byte[]? pbOutput, uint cbOutput, out uint pcbResult, int dwFlags);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptFreeObject(IntPtr hObject);
[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)] static extern int NCryptFreeBuffer(IntPtr pvBuffer);

[StructLayout(LayoutKind.Sequential)]
struct NCryptBuffer { public uint cbBuffer; public uint BufferType; public IntPtr pvBuffer; }

[StructLayout(LayoutKind.Sequential)]
struct NCryptBufferDesc { public uint ulVersion; public uint cBuffers; public IntPtr pBuffers; }

[StructLayout(LayoutKind.Sequential)]
struct BCRYPT_PSS_PADDING_INFO { public IntPtr pszAlgId; public uint cbSalt; }
