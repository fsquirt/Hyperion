using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Hyperion.UserService;

/// <summary>
/// 带缓存的 Authenticode 签名验证器。
/// 用于运行时检测 IOCTL 调用栈中未签名模块。
/// 验证结果按文件路径缓存，同一路径只验一次。
/// </summary>
internal static class ModuleSignatureVerifier
{
    // 缓存: 文件路径 -> 是否通过签名验证
    private static readonly ConcurrentDictionary<string, bool> _cache = new();

    /// <summary>
    /// 验证指定文件路径的 Authenticode 签名（内嵌签名或 Catalog 签名）。
    /// 结果按路径缓存，同一路径只验一次。
    /// </summary>
    /// <param name="filePath">文件完整路径</param>
    /// <returns>true=已签名且验证通过, false=未签名或验证失败或文件不存在</returns>
    public static bool Verify(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        return _cache.GetOrAdd(filePath, path =>
        {
            if (!File.Exists(path))
            {
                Console.Error.WriteLine($"[SigVerify] 文件不存在: {path}");
                return false;
            }

            bool signed = VerifyEmbeddedSignature(path) == 0;
            if (!signed)
            {
                // 内嵌签名失败，尝试 Catalog 签名（系统文件常用 Catalog）
                signed = VerifyCatalogSignature(path);
            }

            if (!signed)
            {
                Console.Error.WriteLine($"[SigVerify] 未签名: {path}");
            }

            return signed;
        });
    }

    // ══════════════════════════════════════════════════════════════════
    //  内嵌签名验证 (WinVerifyTrust + WINTRUST_ACTION_GENERIC_VERIFY_V2)
    //  P/Invoke 和逻辑提取自 SelfSignatureCheck.cs
    // ══════════════════════════════════════════════════════════════════

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int WTD_UI_NONE = 2;
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_CHOICE_CATALOG = 2;
    private const int WTD_STATE_ACTION_IGNORE = 0;
    private const int WTD_STATE_ACTION_VERIFY = 1;
    private const int WTD_STATE_ACTION_CLOSE = 2;
    private const int WTD_REVOKE_NONE = 0;
    private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const int WTD_SAFER_FLAG = 0x00000100;
    private const int WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    /// <summary>
    /// 验证 PE 内嵌 Authenticode 签名。
    /// 使用 WINTRUST_ACTION_GENERIC_VERIFY_V2 + WTD_REVOKE_NONE + WTD_UI_NONE。
    /// </summary>
    /// <returns>WinVerifyTrust 返回的 HRESULT；0 表示验证通过。</returns>
    private static unsafe int VerifyEmbeddedSignature(string filePath)
    {
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
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = (nint)(&fileInfo),
                dwStateAction = WTD_STATE_ACTION_IGNORE,
                dwProvFlags = WTD_SAFER_FLAG,
                dwUIContext = 0,
            };

            Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            return WinVerifyTrust(-1, &action, &trustData);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  Catalog 签名验证 (CryptCATAdmin + WinVerifyTrust + DRIVER_ACTION_VERIFY)
    //  P/Invoke 提取自 SelfSignatureCheck.cs，补充完整的 WinVerifyTrust Catalog 验证流程。
    //
    //  流程:
    //    1. CryptCATAdminAcquireContext (DRIVER_ACTION_VERIFY)
    //    2. CryptCATAdminCalcHashFromFileHandle (计算文件哈希)
    //    3. CryptCATAdminEnumCatalogFromHash (在已注册目录中查找该哈希)
    //    4. CryptCATAdminCatalogInfoFromContext (获取 .cat 文件路径)
    //    5. WinVerifyTrust (DRIVER_ACTION_VERIFY + WTD_STATE_ACTION_VERIFY)
    //    6. WinVerifyTrust (WTD_STATE_ACTION_CLOSE) 关闭状态数据
    //    7. 释放 catalog context 和 catadmin context
    // ══════════════════════════════════════════════════════════════════

    // DRIVER_ACTION_VERIFY
    private static readonly Guid DRIVER_ACTION_VERIFY =
        new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");

    private static unsafe bool VerifyCatalogSignature(string filePath)
    {
        IntPtr catAdmin;
        fixed (Guid* pGuid = &DRIVER_ACTION_VERIFY)
        {
            if (!CryptCATAdminAcquireContext(&catAdmin, pGuid, 0))
                return false;
        }

        IntPtr catInfo = IntPtr.Zero;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            SafeFileHandle handle = fs.SafeFileHandle;

            // 第一次调用:获取哈希大小
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, (byte*)0, 0))
            {
                if (hashSize == 0) return false;
            }

            // 分配缓冲区,第二次调用:计算哈希
            var hashBuf = new byte[hashSize];
            fixed (byte* pHash = hashBuf)
            {
                if (!CryptCATAdminCalcHashFromFileHandle(handle, ref hashSize, pHash, 0))
                    return false;

                // 在所有已注册的目录中查找该哈希
                catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, pHash, hashSize, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                    return false; // 不在任何目录中

                // 获取目录信息 (.cat 文件路径)
                var catalogInfo = new CATALOG_INFO
                {
                    cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(),
                };

                if (!CryptCATAdminCatalogInfoFromContext(catInfo, ref catalogInfo, 0))
                    return false;

                // 使用 WinVerifyTrust 验证 Catalog 签名
                fixed (char* pCatFile = catalogInfo.wszCatalogFile,
                            pMemberFile = filePath)
                {
                    var catalogFileInfo = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                        dwCertVersion = 0,
                        pcwszCatalogFilePath = (nint)pCatFile,
                        pcwszMemberTag = IntPtr.Zero,
                        pcwszMemberFilePath = (nint)pMemberFile,
                        hMemberFile = IntPtr.Zero,
                        pbCalculatedFileHash = (nint)pHash,
                        cbCalculatedFileHash = hashSize,
                        pcCatalogContext = IntPtr.Zero,
                    };

                    var trustData = new WINTRUST_DATA
                    {
                        cbStruct = (uint)sizeof(WINTRUST_DATA),
                        dwUIChoice = WTD_UI_NONE,
                        fdwRevocationChecks = WTD_REVOKE_NONE,
                        dwUnionChoice = WTD_CHOICE_CATALOG,
                        pFile = (nint)(&catalogFileInfo), // pFile/pCatalog 是 union,同一偏移
                        dwStateAction = WTD_STATE_ACTION_VERIFY,
                        dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                        dwUIContext = 0,
                    };

                    Guid action = DRIVER_ACTION_VERIFY;
                    int hr = WinVerifyTrust(-1, &action, &trustData);

                    // 无论成功与否都要关闭状态数据,避免 WinVerifyTrust 状态泄漏
                    trustData.dwStateAction = WTD_STATE_ACTION_CLOSE;
                    WinVerifyTrust(-1, &action, &trustData);

                    return hr == 0;
                }
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (catInfo != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  P/Invoke 声明 (从 SelfSignatureCheck.cs 提取)
    // ══════════════════════════════════════════════════════════════════

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern unsafe int WinVerifyTrust(
        nint hwnd,
        Guid* pgActionID,
        WINTRUST_DATA* pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public nint pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCertVersion;
        public nint pcwszCatalogFilePath;
        public nint pcwszMemberTag;
        public nint pcwszMemberFilePath;
        public nint hMemberFile;
        public nint pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public nint pcCatalogContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe bool CryptCATAdminAcquireContext(
        IntPtr* phCatAdmin,
        Guid* pgSubsystem,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe bool CryptCATAdminCalcHashFromFileHandle(
        SafeFileHandle hFile,
        ref uint pcbHash,
        byte* pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern unsafe IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte* pbHash,
        uint cbHash,
        uint dwFlags,
        IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr hCatAdmin,
        uint dwFlags);
}
