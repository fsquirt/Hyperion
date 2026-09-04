using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

var rootPub = File.ReadAllBytes("vbs_root_pub.bin");
var claim = File.ReadAllBytes("probe_claim_nonce.bin");
var report = File.ReadAllBytes("runtime_report.bin");

using var rsaRoot = RSA.Create();
{
    uint ce = BitConverter.ToUInt32(rootPub, 8);
    uint cm = BitConverter.ToUInt32(rootPub, 12);
    rsaRoot.ImportParameters(new RSAParameters
    {
        Exponent = rootPub[16..(16 + (int)ce)],
        Modulus = rootPub[(16 + (int)ce)..(16 + (int)ce + (int)cm)],
    });
    Console.WriteLine($"root pub: RSA-{cm * 8}, exp {ce}B");
}

// ── 1. claim 的 SK 签名 (cbSig @32, 签名 = 末尾 cbSig 字节) ──
uint cbClaimSig = BitConverter.ToUInt32(claim, 32);
var claimSig = claim[^((int)cbClaimSig)..];
var claimSigned = claim[..^((int)cbClaimSig)];
Console.WriteLine($"\nclaim: {claim.Length}B, SK 签名 {cbClaimSig}B @ 末尾");
foreach (var (halg, pad, padName) in new[] {
    (HashAlgorithmName.SHA256, RSASignaturePadding.Pss, "SHA256-PSS"),
    (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, "SHA256-PKCS1"),
})
{
    var h = halg.Name == "SHA256" ? SHA256.HashData(claimSigned) : null;
    bool ok = rsaRoot.VerifyHash(h!, claimSig, halg, pad);
    Console.WriteLine($"  claim signed=[0,sig) {padName}: {ok}");
}

// ── 2. 运行时报告: 原生 BCrypt PSS salt 穷举 ──
ushort digestsSize = BitConverter.ToUInt16(report, 22);
uint sigSize = BitConverter.ToUInt32(report, 28);
int sigOff = 72 + digestsSize;
var repSig = report[sigOff..(sigOff + (int)sigSize)];
Console.WriteLine($"\nreport: {report.Length}B, digestsSize={digestsSize}, sig {sigSize}B @0x{sigOff:X}");

var ranges = new (string name, int from, int to)[] {
    ("[0,sigOff) 全包", 0, sigOff),
    ("[4,sigOff) 跳 magic", 4, sigOff),
    ("[40,sigOff) nonce 起", 40, sigOff),
    ("[72,sigOff) digest 起", 72, sigOff),
    ("[0,sigOff+sig) 含签名", 0, sigOff + (int)sigSize),
};

// .NET 默认 PSS (salt = hash len)
foreach (var (name, from, to) in ranges)
{
    var dh = SHA512.HashData(report[from..to]);
    bool pss = rsaRoot.VerifyHash(dh, repSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
    bool pkcs1 = rsaRoot.VerifyHash(dh, repSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
    if (pss || pkcs1) Console.WriteLine($"  ★ .NET {name}: PSS={pss} PKCS1={pkcs1}");
}
Console.WriteLine("  (.NET 遍历完成)");

// BCrypt 原生: PSS salt 长度可控
var hProv = IntPtr.Zero; var hKey = IntPtr.Zero;
Bcrypt.BCryptOpenAlgorithmProvider(out hProv, "RSA", null, 0);
Bcrypt.BCryptImportKeyPair(hProv, IntPtr.Zero, "RSAPUBLICBLOB", out hKey, rootPub, rootPub.Length, 0);

var sha512W = Encoding.Unicode.GetBytes("SHA512\0");
var pAlg = Marshal.AllocHGlobal(sha512W.Length);
Marshal.Copy(sha512W, 0, pAlg, sha512W.Length);

uint[] salts = { 0, 32, 64, 128, 190 };
bool anyHit = false;
foreach (var (name, from, to) in ranges)
{
    var dh = SHA512.HashData(report[from..to]);
    foreach (uint salt in salts)
    {
        var info = new BCRYPT_PSS_PADDING_INFO { pszAlgId = pAlg, cbSalt = salt };
        var pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<BCRYPT_PSS_PADDING_INFO>());
        Marshal.StructureToPtr(info, pInfo, false);
        uint st = Bcrypt.BCryptVerifySignature(hKey, pInfo, dh, dh.Length, repSig, repSig.Length, 0x2 /*PAD_PSS*/);
        Marshal.FreeHGlobal(pInfo);
        if (st == 0) { Console.WriteLine($"  ★★ BCrypt-PSS 命中! {name} salt={salt}"); anyHit = true; }
        else if (st != 0xC0000034 && salt == 0) { /* STATUS_INVALID_SIGNATURE 静默 */ }
    }
}
// BCrypt PKCS1 SHA512
foreach (var (name, from, to) in ranges)
{
    var dh = SHA512.HashData(report[from..to]);
    uint st = Bcrypt.BCryptVerifySignature(hKey, IntPtr.Zero, dh, dh.Length, repSig, repSig.Length, 0x2);
    if (st == 0) { Console.WriteLine($"  ★★ BCrypt-PKCS1 命中! {name}"); anyHit = true; }
}
if (!anyHit) Console.WriteLine("  (BCrypt salt 穷举: 无命中)");

Bcrypt.BCryptCloseAlgorithmProvider(hProv, 0);
// ── 3. IDK/IDKS 验证,公钥来自被 TPM Quote 锚定的 PCR12 度量日志 ──
var idks = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(
    File.ReadAllText("idk_keys.json"));
foreach (var kv in idks!)
{
    var expHex = kv.Value.GetProperty("exp").GetString()!.Split(':');
    var modHex = kv.Value.GetProperty("mod").GetString()!.Split(':');
    var exp = expHex.Select(x => Convert.ToByte(x, 16)).ToArray();
    var mod = modHex.Select(x => Convert.ToByte(x, 16)).ToArray();
    using var rsaIdk = RSA.Create();
    rsaIdk.ImportParameters(new RSAParameters { Exponent = exp, Modulus = mod });
    Console.WriteLine($"\n[{kv.Key}] RSA-{mod.Length * 8},来自度量启动日志 PCR12");

    // claim SK 签名
    var ch256 = SHA256.HashData(claimSigned);
    bool cPss = rsaIdk.VerifyHash(ch256, claimSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    bool cPkcs = rsaIdk.VerifyHash(ch256, claimSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    Console.WriteLine($"  claim SK 签名: PSS={cPss} PKCS1={cPkcs}");

    // 报告签名: SHA512 PSS (BCrypt salt 穷举) + PKCS1
    var hKey2 = IntPtr.Zero;
    var pubBlob = new byte[16 + exp.Length + mod.Length];   // magic4+bitlen4+expLen4+modLen4
    BitConverter.GetBytes(0x31415352).CopyTo(pubBlob, 0);       // RSA1
    BitConverter.GetBytes((uint)(mod.Length * 8)).CopyTo(pubBlob, 4);
    BitConverter.GetBytes((uint)exp.Length).CopyTo(pubBlob, 8);
    BitConverter.GetBytes((uint)mod.Length).CopyTo(pubBlob, 12);
    exp.CopyTo(pubBlob, 16);
    mod.CopyTo(pubBlob, 16 + exp.Length);
    Bcrypt.BCryptOpenAlgorithmProvider(out var hAlg2, "RSA", null, 0);
    Bcrypt.BCryptImportKeyPair(hAlg2, IntPtr.Zero, "RSAPUBLICBLOB", out hKey2, pubBlob, pubBlob.Length, 0);
    var sha512W2 = System.Text.Encoding.Unicode.GetBytes("SHA512\0");
    var pAlg2 = Marshal.AllocHGlobal(sha512W2.Length);
    Marshal.Copy(sha512W2, 0, pAlg2, sha512W2.Length);
    bool hit = false;
    foreach (var (name, from, to) in ranges)
    {
        var dh = SHA512.HashData(report[from..to]);
        foreach (uint salt in new uint[] { 0, 32, 64, 128, 190 })
        {
            var info2 = new BCRYPT_PSS_PADDING_INFO { pszAlgId = pAlg2, cbSalt = salt };
            var pI2 = Marshal.AllocHGlobal(Marshal.SizeOf<BCRYPT_PSS_PADDING_INFO>());
            Marshal.StructureToPtr(info2, pI2, false);
            uint st2 = Bcrypt.BCryptVerifySignature(hKey2, pI2, dh, dh.Length, repSig, repSig.Length, 0x2);
            Marshal.FreeHGlobal(pI2);
            if (st2 == 0) { Console.WriteLine($"  ★★ 报告签名命中! {name} PSS salt={salt}"); hit = true; }
        }
        bool pk = rsaIdk.VerifyHash(dh, repSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        if (pk) { Console.WriteLine($"  ★★ 报告签名命中! {name} PKCS1/SHA512"); hit = true; }
        bool pss2 = rsaIdk.VerifyHash(dh, repSig, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        if (pss2) { Console.WriteLine($"  ★★ 报告签名命中! {name} PSS/.NET默认salt"); hit = true; }
    }
    if (!hit) Console.WriteLine("  报告签名: 未命中");
    Bcrypt.BCryptCloseAlgorithmProvider(hAlg2, 0);
    if (hKey2 != IntPtr.Zero) Bcrypt.BCryptDestroyKey(hKey2);
    Marshal.FreeHGlobal(pAlg2);
}

if (hKey != IntPtr.Zero) Bcrypt.BCryptDestroyKey(hKey);
Marshal.FreeHGlobal(pAlg);
