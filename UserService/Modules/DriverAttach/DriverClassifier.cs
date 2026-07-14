using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Hyperion.UserService.Modules.DriverAttach;

/// <summary>
/// 驱动签名分类（对齐 DriverAttachSelector/DriverClassify.cpp）。
/// Authenticode 内嵌签名通过 WinVerifyTrust → 遍历证书链区分 MICROSOFT / THIRD_PARTY_WHQL；
/// 仅目录签名(Catalog) → INBOX；都失败 → UNTRUSTED。
/// </summary>
public enum DriverClass
{
    Inbox,          // 仅有目录签名
    Microsoft,      // 内嵌签名 + 微软自家
    ThirdPartyWhql, // 内嵌签名 + WHQL / 第三方厂商
    Untrusted       // 无签名或验签失败
}

public sealed class SignerInfo
{
    public string Subject = "";
    public bool IsMicrosoft;
    public bool IsWhql;
    public bool IsVendor;
}

public sealed class ClassifyResult
{
    public DriverClass Class = DriverClass.Untrusted;
    public List<SignerInfo> Signers = new();
    public string VendorName = "";
    public string ErrorReason = "";
    public bool HasCatalog;
    public bool HasEmbedded;
    public int VerifyHr;        // WinVerifyTrust 原始 HRESULT(0=内嵌签名验签通过)
    public bool CatalogVerified; // 目录签名(catalog)是否验签通过
}

public static class DriverClassifier
{
    private static readonly Guid WinVerifyTrustAction =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2

    private static readonly Guid DriverCatalogVerifyGuid =
        new(0xF750E6C3, 0x38EE, 0x11D1, 0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

    // 验签结果缓存（按路径，大小写不敏感）。WinVerifyTrust + catalog 枚举极其昂贵，
    // 同一文件在会话内签名恒定，无过期 + FIFO 2000 上限即可。缓存后：[WVT]/[CAT] 日志与
    // 验签 CPU 都只发生一次（无论 MsSignedCache 还是 IsUntrusted 调用）。
    private static readonly ConcurrentDictionary<string, ClassifyResult> _classifyCache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentQueue<string> _classifyKeys = new();
    private const int ClassifyCacheMax = 2000;

    private static void CacheClassify(string filePath, ClassifyResult result)
    {
        _classifyCache[filePath] = result;
        _classifyKeys.Enqueue(filePath);
        while (_classifyCache.Count > ClassifyCacheMax)
        {
            if (_classifyKeys.TryDequeue(out var old) &&
                !string.Equals(old, filePath, StringComparison.OrdinalIgnoreCase))
                _classifyCache.TryRemove(old, out _);
            else
                break;
        }
    }

    public static string NormalizeDriverPath(string rawPath)
    {
        if (string.IsNullOrEmpty(rawPath)) return "";
        string p = rawPath;
        if (p.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            p = p.Substring(4);
        else if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            string sysRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            p = Path.Combine(sysRoot, p.Substring(@"\SystemRoot\".Length));
        }
        else if (p.StartsWith(@"\", StringComparison.Ordinal) && p.Length >= 3 && p[2] == ':')
            p = p.Substring(1);
        return p;
    }

    public static ClassifyResult ClassifyDriver(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return new ClassifyResult { Class = DriverClass.Untrusted, ErrorReason = "路径为空" };

        // 验签昂贵(WinVerifyTrust + catalog 枚举)。同一文件在会话内签名恒定，按路径缓存，
        // 避免高频 IOCTL 下对同一 exe/driver 反复验签（CPU 与 [WVT]/[CAT] 日志都爆）。
        if (_classifyCache.TryGetValue(filePath, out var cached))
            return cached;
        var result = ClassifyDriverUncached(filePath);
        CacheClassify(filePath, result);
        return result;
    }

    private static ClassifyResult ClassifyDriverUncached(string filePath)
    {
        var result = new ClassifyResult();
        if (!File.Exists(filePath) ||
            (File.GetAttributes(filePath) & FileAttributes.Directory) != 0)
        {
            result.Class = DriverClass.Untrusted;
            result.ErrorReason = "文件不存在或不是文件";
            return result;
        }

        int hr = VerifyAuthenticode(filePath);
        result.VerifyHr = hr;
        if (hr == 0)
        {
            result.HasEmbedded = true;
            if (TryCollectSigners(filePath, result.Signers) && result.Signers.Count > 0)
            {
                bool hasMicrosoft = false, hasWhql = false, hasVendor = false;
                string vendor = "";
                foreach (var s in result.Signers)
                {
                    if (s.IsMicrosoft) hasMicrosoft = true;
                    if (s.IsWhql) hasWhql = true;
                    if (s.IsVendor) { hasVendor = true; vendor = s.Subject; }
                }

                if (hasMicrosoft) result.Class = DriverClass.Microsoft;
                else if (hasVendor)
                {
                    result.Class = DriverClass.ThirdPartyWhql;
                    result.VendorName = vendor;
                }
                else if (hasWhql)
                {
                    result.Class = DriverClass.ThirdPartyWhql;
                    result.VendorName = "(仅 WHQL,无嵌套厂商签名)";
                }
                else result.Class = DriverClass.Microsoft;
                return result;
            }
            result.Class = DriverClass.Microsoft;
            return result;
        }

        if (VerifyCatalogSignature(filePath))
        {
            result.HasCatalog = true;
            result.CatalogVerified = true;
            result.Class = DriverClass.Inbox;
            return result;
        }

        result.Class = DriverClass.Untrusted;
        result.ErrorReason = $"Authenticode 失败 hr=0x{hr:X8}, 无 Catalog 签名";
        return result;
    }

    /// <summary>快速判定文件是否未签名 / 签名不被信任（供事件触发快照决策）。</summary>
    public static bool IsUntrusted(string filePath)
    {
        try
        {
            if (string.IsNullOrEmpty(filePath)) return true;
            return ClassifyDriver(filePath).Class == DriverClass.Untrusted;
        }
        catch
        {
            return true; // 无法判定一律按可疑处理
        }
    }

    // ─────────────────────────────────────────────────────────
    //  1. WinVerifyTrust (Authenticode 内嵌签名)
    // ─────────────────────────────────────────────────────────
    private static int VerifyAuthenticode(string filePath)
    {
        // ⚠️ 历史教训:此前 WinVerifyTrustAction GUID 手抄错了(11d3-8A39 应为 11d0-8CC2),
        //   导致 WinVerifyTrust 永远返回 0x800B0001 TRUST_E_PROVIDER_UNKNOWN。
        //   且 P/Invoke 用 ref struct 传 WINTRUST_DATA 时封送器行为不可控,改为纯指针
        //   (AllocHGlobal + StructureToPtr + IntPtr) 直接喂给 API,与 C++ 完全等价。
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };
        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = 2,            // WTD_UI_NONE
            fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
            dwUnionChoice = 1,         // WTD_CHOICE_FILE
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
            dwStateAction = 0,         // WTD_STATEACTION_IGNORE
            dwProvFlags = 0x100         // WTD_SAFER_FLAG
        };
        int hr;
        IntPtr dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, trustData.pFile, false);
            Marshal.StructureToPtr(trustData, dataPtr, false);

            hr = WinVerifyTrust((IntPtr)(-1), WinVerifyTrustAction, dataPtr);
            int le1 = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"  [WVT] VERIFY hr=0x{hr & 0xFFFFFFFF:X8} ({HrName((uint)hr)}) lastErr=0x{le1:X8} file='{filePath}'");

            trustData.dwStateAction = 1; // WTD_STATEACTION_CLOSE
            Marshal.StructureToPtr(trustData, dataPtr, false);
            WinVerifyTrust((IntPtr)(-1), WinVerifyTrustAction, dataPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(trustData.pFile);
        }
        return hr;
    }

    internal static string HrName(uint hr)
    {
        return hr switch
        {
            0 => "S_OK",
            0x800B0001 => "TRUST_E_PROVIDER_UNKNOWN",
            0x800B0100 => "TRUST_E_NOSIGNATURE",
            0x800B0101 => "CERT_E_EXPIRED",
            0x800B0004 => "TRUST_E_SUBJECT_NOT_TRUSTED",
            _ => "?",
        };
    }

    // ─────────────────────────────────────────────────────────
    //  2. 目录签名 (Catalog) 验证
    // ─────────────────────────────────────────────────────────
    private static bool VerifyCatalogSignature(string filePath)
    {
        // 逐步诊断: 打印 catalog 验证链每一步结果 + 最后 Win32 错误,
        // 便于定位为何 KslD 等微软目录签名驱动在这里返回 false。
        if (!CryptCATAdminAcquireContext(out IntPtr hCatAdmin, DriverCatalogVerifyGuid, 0))
        {
            Console.Error.WriteLine($"  [CAT] CryptCATAdminAcquireContext FAILED lastErr=0x{Marshal.GetLastWin32Error():X8}");
            return false;
        }
        try
        {
            using var fs = File.OpenRead(filePath);
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, null, 0) || hashSize == 0)
            {
                Console.Error.WriteLine($"  [CAT] CryptCATAdminCalcHash(1) FAILED hashSize={hashSize} lastErr=0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }
            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, hash, 0))
            {
                Console.Error.WriteLine($"  [CAT] CryptCATAdminCalcHash(2) FAILED lastErr=0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }
            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero)
            {
                Console.Error.WriteLine($"  [CAT] CryptCATAdminEnumCatalogFromHash: 无目录匹配 (lastErr=0x{Marshal.GetLastWin32Error():X8})");
                return false;
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            Console.Error.WriteLine($"  [CAT] OK 文件哈希命中某个目录 → 目录签名有效");
            return true;
        }
        finally
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    // ─────────────────────────────────────────────────────────
    //  3. 收集签名者:读主签名证书 + 证书链(覆盖 WHQL 嵌套签发)
    // ─────────────────────────────────────────────────────────
    private static bool TryCollectSigners(string filePath, List<SignerInfo> signers)
    {
        X509Certificate2? leaf;
        try
        {
            leaf = X509CertificateLoader.LoadCertificateFromFile(filePath); // 读主签名(内嵌)证书
        }
        catch
        {
            return false;
        }

        using (leaf)
        {
            AddSigner(signers, leaf.Subject);

            // 遍历证书链,捕获 WHQL 等中间/根签名者
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(leaf);
                foreach (var el in chain.ChainElements)
                {
                    if (el.Certificate.Thumbprint == leaf.Thumbprint) continue;
                    AddSigner(signers, el.Certificate.Subject);
                }
            }
            catch
            {
                // 链构建失败不影响已收集的主签名者
            }
        }
        return true;
    }

    private static void AddSigner(List<SignerInfo> signers, string subject)
    {
        if (string.IsNullOrEmpty(subject)) return;
        if (signers.Any(s => s.Subject == subject)) return;
        bool isWhql = subject.Contains("Hardware Compatibility Publisher", StringComparison.OrdinalIgnoreCase);
        bool isTimestamp = subject.Contains("Time Stamping", StringComparison.OrdinalIgnoreCase)
            || subject.Contains("Timestamp", StringComparison.OrdinalIgnoreCase);
        bool isMicrosoft = !isWhql && !isTimestamp &&
            (subject.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
             subject.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase));
        signers.Add(new SignerInfo
        {
            Subject = subject,
            IsWhql = isWhql,
            IsMicrosoft = isMicrosoft,
            IsVendor = !isMicrosoft && !isWhql && !isTimestamp
        });
    }

    // ─────────────────────────────────────────────────────────
    //  P/Invoke
    // ─────────────────────────────────────────────────────────
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, Guid pgSubsystem, int dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile, ref uint pcbHash,
        [Out] byte[]? pbHash, int dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, int dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;          // 联合体: 此处仅用 pFile (WTD_CHOICE_FILE)
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
