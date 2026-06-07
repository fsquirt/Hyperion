using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Xml;
using SEWindows.Tracker.WinEventTracker;

namespace SEWindows.Tracker.SysmonEventTracker;

/// <summary>
/// Sysmon 事件分类与签名验证。
/// </summary>
public static class SysmonEventClassifier
{
    // 高危事件 ID：ProcessAccess=10, DriverLoad=6, CreateRemoteThread=8, ProcessTampering=25
    private static readonly HashSet<int> HighRiskEvents = [10, 6, 8, 25];

    // 签名验证缓存，容量 1000，避免重复读磁盘
    private static readonly CacheVerify _cache = new(1000);

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
                // WARN 级别：始终显示
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
                // INFO 级别：仅 --debug 显示
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

        // ── ImageLoad：检查 DLL 签名 ───────────────────────────────
        if (evt.EventId == 7 && imageLoaded is not null)
        {
            // 系统目录跳过验证
            if (imageLoaded.StartsWith(@"C:\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
                imageLoaded.StartsWith(@"C:\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
                imageLoaded.StartsWith(@"C:\Windows\WinSxS\", StringComparison.OrdinalIgnoreCase))
            {
                // INFO 级别：仅 --debug 显示
                if (debug)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("[SYSMON-INFO] ");
                    Console.ResetColor();
                    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID=7  ImageLoad");
                    Console.WriteLine($"         Image: {imageLoaded}");
                    Console.WriteLine();
                }
            }
            else
            {
                var (ok, signInfo) = CachedVerify(imageLoaded);
                if (!ok)
                {
                    // HIGH 级别：始终显示
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
                else if (debug)
                {
                    // INFO 级别：仅 --debug 显示
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
            }
            return true;
        }

        // ── 高危事件：ProcessAccess / DriverLoad / CreateRemoteThread / ProcessTampering
        if (HighRiskEvents.Contains(evt.EventId))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("[SYSMON-HIGH] ");
            Console.ResetColor();
            Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  Sysmon  ID={evt.EventId}");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"         ⚠ 高危事件");
            Console.ResetColor();
            Console.WriteLine(evt.Description);
            Console.WriteLine();
            return true;
        }

        // ── 其余 Sysmon 事件（INFO 级别，仅 --debug 显示）──────────
        if (debug)
            PrintDefault(evt, "SYSMON-INFO");
        return true;
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

    // ── WinVerifyTrust Authenticode 签名验证 ──────────────────────────

    private const int WTD_UI_NONE = 2;
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_SAFER_FLAG = 0x100;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);

    private static unsafe (bool Trusted, string Info) VerifyFileSignature(string filePath)
    {
        if (!File.Exists(filePath))
            return (false, "文件不存在");

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

            var hr = WinVerifyTrust(-1, &guidAction, &trustData);

            return hr switch
            {
                0 => (true, "签名有效 (Trusted)"),
                TRUST_E_NOSIGNATURE => (false, "未签名"),
                TRUST_E_EXPLICIT_DISTRUST => (false, "签名已被用户明确不信任"),
                TRUST_E_SUBJECT_NOT_TRUSTED => (false, "签名不受信任"),
                CERT_E_EXPIRED => (false, "签名证书已过期"),
                CERT_E_CHAINING => (false, "无法构建证书链"),
                _ => (false, $"验证失败 (hr=0x{hr:X8})"),
            };
        }
    }

    // ── WinVerifyTrust P/Invoke ────────────────────────────────────────

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
}
