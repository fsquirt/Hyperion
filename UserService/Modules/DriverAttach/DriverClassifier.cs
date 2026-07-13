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
}

public static class DriverClassifier
{
    private static readonly Guid WinVerifyTrustAction =
        new("aac56b-cd44-11d3-8a39-00c04f72d04a"); // WINTRUST_ACTION_GENERIC_VERIFY_V2

    private static readonly Guid DriverCatalogVerifyGuid =
        new(0xF750E6C3, 0x38EE, 0x11D1, 0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

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
        var result = new ClassifyResult();
        if (string.IsNullOrEmpty(filePath) ||
            (File.GetAttributes(filePath) & FileAttributes.Directory) != 0)
        {
            result.Class = DriverClass.Untrusted;
            result.ErrorReason = "文件不存在或不是文件";
            return result;
        }

        int hr = VerifyAuthenticode(filePath);
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
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath
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
        Marshal.StructureToPtr(fileInfo, trustData.pFile, false);
        try
        {
            int hr = WinVerifyTrust((IntPtr)(-1), WinVerifyTrustAction, trustData);
            trustData.dwStateAction = 1; // WTD_STATEACTION_CLOSE
            WinVerifyTrust((IntPtr)(-1), WinVerifyTrustAction, trustData);
            return hr;
        }
        finally
        {
            Marshal.FreeHGlobal(trustData.pFile);
        }
    }

    // ─────────────────────────────────────────────────────────
    //  2. 目录签名 (Catalog) 验证
    // ─────────────────────────────────────────────────────────
    private static bool VerifyCatalogSignature(string filePath)
    {
        if (!CryptCATAdminAcquireContext(out IntPtr hCatAdmin, DriverCatalogVerifyGuid, 0))
            return false;
        try
        {
            using var fs = File.OpenRead(filePath);
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, null, 0) || hashSize == 0)
                return false;
            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle, ref hashSize, hash, 0))
                return false;
            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return false;
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
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
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, Guid pgActionID, WINTRUST_DATA pWVTData);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, Guid pgSubsystem, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile, ref uint pcbHash,
        [Out] byte[]? pbHash, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, int dwFlags, IntPtr phPrevCatInfo);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string? pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private sealed class WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
