using System.Collections.Concurrent;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Win32.SafeHandles;
using SEWindows.Tracker.WinEventTracker;

namespace SEWindows.Tracker.SysmonEventTracker;

/// <summary>
/// Sysmon 事件分类与签名验证。
/// 支持 Authenticode 签名 + Windows 目录签名 (Catalog Signature) 双重验证。
/// ProcessAccess 事件通过 CallTrace 分析过滤系统组件的正常访问。
/// </summary>
public static class SysmonEventClassifier
{
    // 高危事件 ID：ProcessAccess=10, DriverLoad=6, CreateRemoteThread=8, ProcessTampering=25
    private static readonly HashSet<int> HighRiskEvents = [10, 6, 8, 25];

    // 签名验证缓存，容量 1000，避免重复读磁盘
    private static readonly CacheVerify _cache = new(1000);

    // Microsoft 签名缓存：文件路径 → 是否由 Microsoft 签名
    private static readonly ConcurrentDictionary<string, bool> _msCache = new();

    // 系统目录前缀（用于 ImageLoad 严重级别判断）
    private static readonly string[] SystemPaths =
    [
        @"C:\Windows\System32\",
        @"C:\Windows\SysWOW64\",
        @"C:\Windows\WinSxS\",
    ];

    /// <summary>
    /// 对 Sysmon 事件进行分级，验证签名，并输出到控制台。
    /// </summary>
    /// <param name="evt">事件。</param>
    /// <param name="debug">是否显示 INFO 级别事件。false 时 INFO 事件静默跳过。</param>
    /// <returns>true 表示已处理（是 Sysmon 事件），false 表示非 Sysmon 事件。</returns>
    public static bool ClassifyAndPrint(MonitoredEvent evt, bool debug = false)
    {
        if (evt.Provider != "Microsoft-Windows-Sysmon")
            return false;

        var sysmonData = ParseEventData(evt.RawXml);
        sysmonData.TryGetValue("ImageLoaded", out var imageLoaded);
        sysmonData.TryGetValue("Image", out var processImage);

        // ── ProcessCreate：检查进程签名 ─────────────────────────────
        if (evt.EventId == 1 && processImage is not null)
        {
            var (ok, signInfo) = CachedVerify(processImage);
            if (!ok)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("[SYSMON-WARN] ");
                Console.ResetColor();
                Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=1  ProcessCreate");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"         ⚠ 进程无有效签名: {signInfo}");
                Console.ResetColor();
                Console.WriteLine($"         Image: {processImage}");
                Console.WriteLine();
            }
            else if (debug)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[SYSMON-INFO] ");
                Console.ResetColor();
                Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=1  ProcessCreate");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"         ✓ {signInfo}");
                Console.ResetColor();
                Console.WriteLine($"         Image: {processImage}");
                Console.WriteLine();
            }
            return true;
        }

        // ── ImageLoad：检查 DLL 签名（Authenticode + 目录签名）─────
        if (evt.EventId == 7 && imageLoaded is not null)
        {
            var (ok, signInfo) = CachedVerify(imageLoaded);

            if (!ok)
            {
                // 系统目录下两种签名都没有 → CRIT（极高危证据）
                var isSystemPath = SystemPaths.Any(p =>
                    imageLoaded.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (isSystemPath)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[SYSMON-CRIT] ");
                    Console.ResetColor();
                    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=7  ImageLoad");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"         ‼ 系统目录发现无签名文件: {signInfo}");
                    Console.ResetColor();
                    Console.WriteLine($"         Image: {imageLoaded}");
                    Console.WriteLine();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[SYSMON-HIGH] ");
                    Console.ResetColor();
                    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=7  ImageLoad");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"         ⚠ 签名验证失败: {signInfo}");
                    Console.ResetColor();
                    Console.WriteLine($"         Image: {imageLoaded}");
                    Console.WriteLine();
                }
            }
            else if (debug)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[SYSMON-INFO] ");
                Console.ResetColor();
                Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=7  ImageLoad");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"         ✓ {signInfo}");
                Console.ResetColor();
                Console.WriteLine($"         Image: {imageLoaded}");
                Console.WriteLine();
            }
            return true;
        }

        // ── 高危事件：ProcessAccess / DriverLoad / CreateRemoteThread / ProcessTampering
        if (HighRiskEvents.Contains(evt.EventId))
        {
            PrintHighRiskEvent(evt, sysmonData, debug);
            return true;
        }

        // ── RegistryEvent：证书和服务注册表变更 ─────────────────────
        if (evt.EventId is 12 or 13)
        {
            PrintRegistryEvent(evt, sysmonData, debug);
            return true;
        }

        // ── 其余 Sysmon 事件（INFO 级别，仅 --debug 显示）──────────
        if (debug)
            PrintDefault(evt, "SYSMON-INFO");
        return true;
    }

    // ── 高危事件详细输出（含 CallTrace 过滤）────────────────────────

    private static void PrintHighRiskEvent(MonitoredEvent evt, Dictionary<string, string> data, bool debug)
    {
        var eventName = evt.EventId switch
        {
            6 => "DriverLoad",
            8 => "CreateRemoteThread",
            10 => "ProcessAccess",
            25 => "ProcessTampering",
            _ => $"ID={evt.EventId}",
        };

        // ── ProcessAccess：分层过滤 ────────────────────────────────
        // 第一层：GrantedAccess 无害权限 → 直接放行
        // 第二层：有危险权限 → 检查 CallTrace 是否全是 Microsoft 签名
        if (evt.EventId == 10)
        {
            data.TryGetValue("GrantedAccess", out var accessStr);
            data.TryGetValue("CallTrace", out var callTrace);
            data.TryGetValue("SourceImage", out var sourceImage);

            var access = ParseAccess(accessStr);
            var risk = ClassifyAccessRisk(access);

            // 第一层：无害权限，直接放行（不需要看 CallTrace）
            if (risk == AccessRisk.Harmless)
            {
                if (debug)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("[SYSMON-INFO] ");
                    Console.ResetColor();
                    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=10  ProcessAccess (无害权限)");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"         ✓ {sourceImage} → 权限: {DecodeAccess(access)}");
                    Console.ResetColor();
                }
                return;
            }

            // 第二层：有危险权限，检查 CallTrace
            // 权限级别只影响显示标签，不影响是否验证 CallTrace
            // csrss.exe ALL_ACCESS 但 CallTrace 全是 Microsoft → 放行
            // Cheat Engine VM_READ 但 CallTrace 有非 Microsoft → 告警
            if (IsCallTraceTrusted(callTrace))
            {
                if (debug)
                {
                    var label = risk == AccessRisk.Critical ? "ALL_ACCESS (系统组件)" : "系统组件";
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("[SYSMON-INFO] ");
                    Console.ResetColor();
                    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=10  ProcessAccess ({label})");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"         ✓ 调用链已验证: {sourceImage}");
                    Console.ResetColor();
                    Console.WriteLine($"         权限详情: {DecodeAccess(access)}");
                    PrintField(data, "TargetImage",     "目标进程");
                    Console.WriteLine();
                }
                return; // 静默放行
            }

            // CallTrace 中有非 Microsoft 签名 → 高危
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[SYSMON-HIGH] ");
            Console.ResetColor();
            Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=10  ProcessAccess");
            PrintField(data, "SourceImage",         "请求进程");
            PrintField(data, "TargetImage",         "目标进程");
            Console.WriteLine($"         权限详情: {DecodeAccess(access)}");

            // 输出源 exe 签名验证结果
            if (!string.IsNullOrEmpty(sourceImage))
            {
                var (srcOk, srcInfo) = CachedVerify(sourceImage);
                var srcMs = CachedIsMicrosoftSigned(sourceImage);
                Console.WriteLine($"         源exe签名: {(srcOk ? "✓" : "✗")} {srcInfo}  Microsoft={srcMs}");
            }

            // 输出 CallTrace 中每个 DLL 的签名验证结果（不截断）
            if (!string.IsNullOrEmpty(callTrace))
            {
                Console.WriteLine($"         调用栈签名分析:");
                var entries = callTrace.Split('|');
                foreach (var entry in entries)
                {
                    var dllPath = entry.Split('+')[0].Trim();
                    if (dllPath.StartsWith("UNKNOWN", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine($"           {entry}  [内核地址，无法验证]");
                        continue;
                    }
                    if (!dllPath.Contains('\\'))
                    {
                        Console.WriteLine($"           {entry}  [非路径，跳过]");
                        continue;
                    }
                    var (dllOk, dllInfo) = CachedVerify(dllPath);
                    var dllMs = CachedIsMicrosoftSigned(dllPath);
                    Console.WriteLine($"           {entry}  签名:{(dllOk ? "✓" : "✗")} {dllInfo}  Microsoft={dllMs}");
                }
            }

            Console.WriteLine();
            return;
        }

        // ── 其他高危事件：直接输出 ─────────────────────────────────
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("[SYSMON-HIGH] ");
        Console.ResetColor();
        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID={evt.EventId}  {eventName}");

        switch (evt.EventId)
        {
            case 6: // DriverLoad
                PrintField(data, "ImageLoaded",         "驱动文件");
                PrintField(data, "Signed",              "签名状态");
                PrintField(data, "Signature",           "签名者");
                PrintField(data, "SignatureStatus",     "签名验证");
                break;

            case 8: // CreateRemoteThread
                PrintField(data, "SourceImage",         "源进程");
                PrintField(data, "TargetImage",         "目标进程");
                PrintField(data, "StartAddress",        "线程起始地址");
                PrintField(data, "StartModule",         "起始模块");
                break;

            case 25: // ProcessTampering
                PrintField(data, "Image",               "目标进程");
                PrintField(data, "Type",                "篡改类型");
                break;
        }

        Console.WriteLine();
    }

    // ── CallTrace 信任判断 ──────────────────────────────────────────
    // 解析 CallTrace 中的 DLL 路径，验证每个 DLL 是否由 Microsoft 签名
    // 只看证书，严禁基于目录路径判断

    private static bool IsCallTraceTrusted(string? callTrace)
    {
        if (string.IsNullOrEmpty(callTrace))
            return false;

        // 格式: "C:\xxx\ntdll.dll+162164|C:\xxx\KERNELBASE.dll+360c6|UNKNOWN(addr)|..."
        var entries = callTrace.Split('|');

        foreach (var entry in entries)
        {
            var dllPath = entry.Split('+')[0].Trim();

            // UNKNOWN 是内核地址，跳过（无法验证）
            if (dllPath.StartsWith("UNKNOWN", StringComparison.OrdinalIgnoreCase))
                continue;

            // 非 DLL/EXE 路径（可能是纯地址），跳过
            if (!dllPath.Contains('\\'))
                continue;

            // 只看签名证书是否是 Microsoft，不看目录路径
            if (!CachedIsMicrosoftSigned(dllPath))
                return false;
        }

        return true;
    }

    // ── GrantedAccess 权限分级 ────────────────────────────────────────

    // 进程访问权限常量
    private const uint PROCESS_TERMINATE            = 0x0001;
    private const uint PROCESS_CREATE_THREAD        = 0x0002;
    private const uint PROCESS_VM_OPERATION         = 0x0008;
    private const uint PROCESS_VM_READ              = 0x0010;
    private const uint PROCESS_VM_WRITE             = 0x0020;
    private const uint PROCESS_DUP_HANDLE           = 0x0040;
    private const uint PROCESS_CREATE_PROCESS       = 0x0080;
    private const uint PROCESS_SET_QUOTA            = 0x0100;
    private const uint PROCESS_SET_INFORMATION      = 0x0200;
    private const uint PROCESS_QUERY_INFORMATION    = 0x0400;
    private const uint PROCESS_SUSPEND_RESUME       = 0x0800;
    private const uint PROCESS_QUERY_LIMITED_INFO   = 0x1000;

    // 高危权限位：读写内存、创建线程、操作内存、挂起恢复
    private const uint DANGEROUS_MASK =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME;

    private enum AccessRisk
    {
        Harmless,   // 无害：QUERY / DUP_HANDLE / SYNCHRONIZE 等，直接放行
        Suspicious, // 可疑：包含一个或多个高危权限位，需要检查 CallTrace
        Critical,   // 极高危：ALL_ACCESS 或同时包含多个高危位，直接告警
    }

    private static uint ParseAccess(string? accessStr)
    {
        if (string.IsNullOrEmpty(accessStr)) return 0;
        accessStr = accessStr.Trim();
        if (accessStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            accessStr = accessStr[2..];
        return uint.TryParse(accessStr, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : 0;
    }

    private static AccessRisk ClassifyAccessRisk(uint access)
    {
        // 去掉标准权限位（高位），只看进程特有权限
        var procAccess = access & 0xFFFF;

        // 无高危权限位 → 无害
        if ((procAccess & DANGEROUS_MASK) == 0)
            return AccessRisk.Harmless;

        // ALL_ACCESS (0x1FFFFF) 或同时包含 3 个以上高危位 → 极高危
        var dangerCount = BitOperations.PopCount(procAccess & DANGEROUS_MASK);
        if (procAccess == 0x1FFFFF || dangerCount >= 3)
            return AccessRisk.Critical;

        // 包含高危权限但不多 → 可疑，需要检查 CallTrace
        return AccessRisk.Suspicious;
    }

    /// <summary>将 GrantedAccess 位掩码解码为可读的权限列表。</summary>
    private static string DecodeAccess(uint access)
    {
        var parts = new List<string>();
        var procAccess = access & 0xFFFF;

        if ((procAccess & PROCESS_TERMINATE) != 0)          parts.Add("TERMINATE");
        if ((procAccess & PROCESS_CREATE_THREAD) != 0)      parts.Add("CREATE_THREAD");
        if ((procAccess & PROCESS_VM_OPERATION) != 0)       parts.Add("VM_OPERATION");
        if ((procAccess & PROCESS_VM_READ) != 0)            parts.Add("VM_READ");
        if ((procAccess & PROCESS_VM_WRITE) != 0)           parts.Add("VM_WRITE");
        if ((procAccess & PROCESS_DUP_HANDLE) != 0)         parts.Add("DUP_HANDLE");
        if ((procAccess & PROCESS_CREATE_PROCESS) != 0)     parts.Add("CREATE_PROCESS");
        if ((procAccess & PROCESS_SET_QUOTA) != 0)          parts.Add("SET_QUOTA");
        if ((procAccess & PROCESS_SET_INFORMATION) != 0)    parts.Add("SET_INFORMATION");
        if ((procAccess & PROCESS_QUERY_INFORMATION) != 0)  parts.Add("QUERY_INFORMATION");
        if ((procAccess & PROCESS_SUSPEND_RESUME) != 0)     parts.Add("SUSPEND_RESUME");
        if ((procAccess & PROCESS_QUERY_LIMITED_INFO) != 0) parts.Add("QUERY_LIMITED_INFO");

        return parts.Count > 0
            ? $"0x{access:X} ({string.Join(" | ", parts)})"
            : $"0x{access:X}";
    }

    // ── Microsoft 签名缓存 ─────────────────────────────────────────

    /// <summary>
    /// 检查文件是否由 Microsoft 签名（Authenticode 签名者是 Microsoft，或有目录签名）。
    /// 目录签名由 Microsoft 维护的 Windows 安全目录 (.cat) 提供，隐含 Microsoft 背书。
    /// </summary>
    private static bool CachedIsMicrosoftSigned(string filePath)
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

    // ── RegistryEvent 输出 ───────────────────────────────────────────
    // 全部算 INFO，仅 --debug 显示

    private static void PrintRegistryEvent(MonitoredEvent evt, Dictionary<string, string> data, bool debug)
    {
        if (!debug) return;

        data.TryGetValue("TargetObject", out var targetObj);
        data.TryGetValue("Image", out var image);

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("[SYSMON-INFO] ");
        Console.ResetColor();
        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID={evt.EventId}  RegistryEvent");
        PrintField(data, "TargetObject",    "注册表路径");
        PrintField(data, "Image",           "操作进程");
        Console.WriteLine();
    }

    // ── 辅助：输出单个字段（仅在有值时显示）──────────────────────────

    private static void PrintField(Dictionary<string, string> data, string key, string label)
    {
        if (data.TryGetValue(key, out var value) && !string.IsNullOrEmpty(value))
        {
            if (key == "CallTrace" && value.Length > 200)
                value = value[..200] + "...";
            Console.WriteLine($"         {label}: {value}");
        }
    }

    /// <summary>默认格式输出事件（完整描述，不截断）。</summary>
    public static void PrintDefault(MonitoredEvent evt, string tag)
    {
        Console.ForegroundColor = tag.Contains("HIGH") ? ConsoleColor.Red
            : tag.Contains("WARN") ? ConsoleColor.Yellow
            : ConsoleColor.Cyan;
        Console.Write($"[{tag}] ");
        Console.ResetColor();

        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");
        Console.WriteLine($"         {evt.Description}");
        Console.WriteLine();
    }

    // ── Sysmon EventData 解析 ──────────────────────────────────────────

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");

            var dataNodes = doc.SelectNodes("//e:EventData/e:Data", ns);
            if (dataNodes is null) return result;

            foreach (XmlNode node in dataNodes)
            {
                var name = node.Attributes?["Name"]?.Value;
                var value = node.InnerText;
                if (!string.IsNullOrEmpty(name))
                    result[name] = value;
            }
        }
        catch { /* 解析失败返回空字典 */ }
        return result;
    }

    // ── 带缓存的签名验证（返回签名状态 + 描述）──────────────────────

    private static (bool Trusted, string Info) CachedVerify(string filePath)
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
