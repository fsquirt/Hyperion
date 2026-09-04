using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Hyperion.UserService;

/// <summary>
/// 启动前防御:遍历自身进程加载的所有模块,含本体 .exe,逐一验证有效签名。
///
/// 验签策略,与 Tracker.Services.SignatureVerifier 一致:
///   - 先试 Authenticode 内嵌签名 (WinVerifyTrust)
///   - Authenticode 失败再试 Windows 目录签名 (Catalog .cat)
///   - 任一通过即视为可信
///   - 两者都无则视为"未签名"→ 检测到注入
///
/// 时机:必须在程序启动早期、与驱动/游戏通信之前执行。
///       此时攻击者即使注入了未签名 DLL,也已经存在于模块列表中。
///
/// 枚举方式:用 Process.GetCurrentProcess().Modules 枚举,其内部封装 ToolHelp32
///           返回当前进程所有已加载 DLL + 本体 EXE 路径
/// </summary>
public static class SelfSignatureCheck
{
    /// <summary>
    /// 检查自身进程所有模块的签名。返回未签名模块路径列表。
    /// </summary>
    /// <param name="unsignedModules">未签名模块路径列表,包含本体和 DLL</param>
    /// <returns>true=全部已签名;false=有未签名模块</returns>
    public static bool Check(out List<string> unsignedModules)
    {
        unsignedModules = new List<string>();

        // 枚举自身进程所有模块,含本体
        var proc = Process.GetCurrentProcess();
        var modules = new List<string>();

        try
        {
            // 本体 .exe
            modules.Add(proc.MainModule?.FileName ?? Environment.ProcessPath ?? "");

            // 所有已加载 DLL
            foreach (ProcessModule module in proc.Modules)
            {
                if (!string.IsNullOrEmpty(module.FileName))
                    modules.Add(module.FileName);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[SigCheck] Module enumeration failed: {ex.Message}");
            // 枚举失败按不安全处理
            unsignedModules.Add($"模块枚举失败: {ex.Message}");
            return false;
        }
        finally
        {
            proc.Dispose();
        }

        Console.Error.WriteLine($"[SigCheck] Verifying {modules.Count} modules");

        // 逐一验签
        int verified = 0;
        foreach (var path in modules)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                Console.Error.WriteLine($"[SigCheck] SKIP (not exist): {path}");
                continue;
            }

            var (trusted, info) = VerifyFileSignature(path);
            if (trusted)
            {
                verified++;
            }
            else
            {
                Console.Error.WriteLine($"[SigCheck] UNSIGNED: {path} ({info})");
                unsignedModules.Add(path);
            }
        }

        Console.Error.WriteLine($"[SigCheck] {verified}/{modules.Count} modules trusted, {unsignedModules.Count} unsigned");
        return unsignedModules.Count == 0;
    }

    // ══════════════════════════════════════════════════════════════════
    //  签名验证:先试 Authenticode,再试目录签名 (Catalog)
    //  逻辑复制自 Tracker/Services/SignatureVerifier.cs
    // ══════════════════════════════════════════════════════════════════

    private static unsafe (bool Trusted, string Info) VerifyFileSignature(string filePath)
    {
        if (!File.Exists(filePath))
            return (false, "文件不存在");

        // 1. 先试 Authenticode(PE 内嵌签名)
        var hr = VerifyAuthenticode(filePath);
        if (hr == 0)
            return (true, "Authenticode 签名有效");

        // 用户明确不信任 → 直接失败,不试目录签名
        if (hr == TRUST_E_EXPLICIT_DISTRUST)
            return (false, "签名已被用户明确不信任");

        // 2. Authenticode 失败,如证书链问题、过期、未签名等 → 试目录签名
        //    目录签名是独立的信任路径,Authenticode 失败不代表目录签名也无效
        if (VerifyCatalog(filePath))
            return (true, "目录签名有效 (Catalog Signed)");

        // 3. 两种签名都没有
        return hr switch
        {
            TRUST_E_NOSIGNATURE => (false, "未签名,Authenticode 与 Catalog 均无"),
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
    // 很多 Windows 系统 DLL 没有内嵌 Authenticode 签名,例如 dpapi.dll,
    // 但其哈希值在 Windows 安全目录 (.cat) 中,由 Microsoft 签名保护。

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
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var handle = fs.SafeFileHandle;

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
                IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, pHash, hashSize, 0, IntPtr.Zero);
                if (catInfo == IntPtr.Zero)
                    return false; // 不在任何目录中

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
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr hCatAdmin,
        uint dwFlags);
}
