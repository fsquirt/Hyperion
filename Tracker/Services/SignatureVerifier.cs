using Microsoft.Win32.SafeHandles;
using Hyperion.Tracker.SysmonEventTracker;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace Hyperion.Tracker.Services;

/// <summary>
/// 文件签名验证引擎。
/// 支持 Authenticode 内嵌签名 + Windows 目录签名 (Catalog Signature) 双重验证。
/// 供 ETW 驱动验签等场景复用。
/// </summary>
public static class SignatureVerifier
{
    // 签名验证缓存，容量 1000，避免重复读磁盘
    private static readonly CacheVerify _cache = new(1000);

    // Microsoft 签名缓存：文件路径 → 是否由 Microsoft 签名
    private static readonly ConcurrentDictionary<string, bool> _msCache = new();

    // 系统目录前缀（用于系统目录判断）
    private static readonly string[] SystemPaths =
    [
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
        @"C:\Windows\WinSxS\",
    ];

    /// <summary>判断路径是否位于 Windows 系统目录下。</summary>
    public static bool IsSystemPath(string filePath)
        => SystemPaths.Any(p => filePath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    // ══════════════════════════════════════════════════════════════════
    //  Microsoft 签名判断
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// 检查文件是否由 Microsoft 签名（Authenticode 签名者是 Microsoft，或有目录签名）。
    /// 目录签名由 Microsoft 维护的 Windows 安全目录 (.cat) 提供，隐含 Microsoft 背书。
    /// </summary>
    public static bool CachedIsMicrosoftSignedPublic(string filePath)
    {
        if (_msCache.TryGetValue(filePath, out var isMs))
            return isMs;

        isMs = IsMicrosoftSigned(filePath);
        _msCache.TryAdd(filePath, isMs);
        return isMs;
    }

    private static bool IsMicrosoftSigned(string filePath)
    {
        if (!File.Exists(filePath))
            return false;

        // 目录签名由 Microsoft 维护，等效于 Microsoft 签名
        if (VerifyCatalog(filePath))
            return true;

        // Authenticode 签名：提取签名者证书，检查 Subject 是否包含 "Microsoft"
        try
        {
            var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
            if (cert is null) return false;
            var subject = cert.Subject ?? "";
            return subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            // 文件未签名或无法加载证书时抛异常
            return false;
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  通用签名验证（返回信任状态 + 人类可读描述）
    // ══════════════════════════════════════════════════════════════════

    /// <summary>带缓存的签名验证（返回签名状态 + 描述）。</summary>
    public static (bool Trusted, string Info) CachedVerify(string filePath)
    {
        if (_cache.TryGet(filePath, out var trusted, out var info))
            return (trusted, info);

        var result = VerifyFileSignature(filePath);
        _cache.Set(filePath, result.Trusted, result.Info);
        return result;
    }

    // ══════════════════════════════════════════════════════════════════
    //  签名验证：先试 Authenticode，再试目录签名 (Catalog)
    // ══════════════════════════════════════════════════════════════════

    private static unsafe (bool Trusted, string Info) VerifyFileSignature(string filePath)
    {
        if (!File.Exists(filePath))
            return (false, "文件不存在");

        // 1. 先试 Authenticode（PE 内嵌签名）
        var hr = VerifyAuthenticode(filePath);
        if (hr == 0)
            return (true, "Authenticode 签名有效");

        // 用户明确不信任 → 直接失败，不试目录签名
        if (hr == TRUST_E_EXPLICIT_DISTRUST)
            return (false, "签名已被用户明确不信任");

        // 2. Authenticode 失败（证书链问题、过期、未签名等）→ 试目录签名
        //    目录签名是独立的信任路径，Authenticode 失败不代表目录签名也无效
        if (VerifyCatalog(filePath))
            return (true, "目录签名有效 (Catalog Signed)");

        // 3. 两种签名都没有
        return hr switch
        {
            TRUST_E_NOSIGNATURE => (false, "未签名 (Authenticode + Catalog 均无)"),
            TRUST_E_SUBJECT_NOT_TRUSTED => (false, "签名不受信任"),
            CERT_E_EXPIRED => (false, "签名证书已过期"),
            CERT_E_CHAINING => (false, "无法构建证书链"),
            _ => (false, $"验证失败 (hr=0x{hr:X8})"),
        };
    }

    // ── Authenticode 签名验证 ─────────────────────────────────────────

    private const int WTD_UI_NONE = 2;
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_SAFER_FLAG = 0x100;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);

    private static unsafe int VerifyAuthenticode(string filePath)
    {
        Guid guidAction = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        fixed (char* pFile = filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = (nint)pFile,
            };

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WTD_UI_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = (nint)(&fileInfo),
                dwStateAction = 0,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
            };

            return WinVerifyTrust(-1, &guidAction, &trustData);
        }
    }

    // ── 目录签名验证 (Windows Catalog .cat) ───────────────────────────
    // 很多 Windows 系统 DLL（如 dpapi.dll）没有内嵌 Authenticode 签名，
    // 但其哈希值在 Windows 安全目录 (.cat) 中，由 Microsoft 签名保护。

    private static readonly Guid DRIVER_VERIFY_GUID = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");

    private static unsafe bool VerifyCatalog(string filePath)
    {
        IntPtr catAdmin;
        fixed (Guid* pGuid = &DRIVER_VERIFY_GUID)
        {
            if (!CryptCATAdminAcquireContext(&catAdmin, pGuid, 0))
                return false;
        }

        try
        {
            // 打开文件获取句柄
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var handle = fs.SafeFileHandle;

            // 第一次调用：获取哈希大小
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, (byte*)0, 0))
            {
                // 某些文件（如 0 字节）会失败，不算异常
                if (hashSize == 0) return false;
            }

            // 分配缓冲区，第二次调用：计算哈希
            var hashBuf = new byte[hashSize];
            fixed (byte* pHash = hashBuf)
            {
                if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, pHash, 0))
                    return false;

                // 在所有已注册的目录中查找该哈希
                IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, pHash, hashSize, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                    return false; // 不在任何目录中

                // 找到了 → 有目录签名
                CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                return true;
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  P/Invoke
    // ══════════════════════════════════════════════════════════════════

    // ── WinVerifyTrust (Authenticode) ─────────────────────────────────

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = false)]
    private static extern unsafe int WinVerifyTrust(
        nint hwnd,
        Guid* pgActionID,
        WINTRUST_DATA* pWVTData);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public nint pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private unsafe struct WINTRUST_DATA
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public nint pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }

    // ── Catalog API (目录签名) ────────────────────────────────────────

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe bool CryptCATAdminAcquireContext(
        IntPtr* phCatAdmin,
        Guid* pgSubsystem,
        uint dwFlags);

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe bool CryptCATAdminCalcHashFromFileHandle(
        SafeFileHandle hFile,
        ref uint pcbHash,
        byte* pbHash,
        uint dwFlags);

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte* pbHash,
        uint cbHash,
        uint dwFlags,
        IntPtr phPrevCatInfo);

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [System.Runtime.InteropServices.DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr hCatAdmin,
        uint dwFlags);
}
