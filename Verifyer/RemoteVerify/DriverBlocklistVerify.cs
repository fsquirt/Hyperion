using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SEWindows.Verifyer.RemoteVerify
{
    /// <summary>
    /// 已加载驱动拉黑验证。
    ///
    /// 通过 PSAPI 枚举系统中所有已加载的内核驱动模块,
    /// 读取对应文件计算 MD5/SHA1/SHA256,
    /// 上传到服务端与拉黑列表比对。
    /// </summary>
    public static class DriverBlocklistVerify
    {
        // ── PSAPI P/Invoke ────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool EnumDeviceDrivers(
            [Out] IntPtr[]? lpImageBase,
            int cb,
            out int lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetDeviceDriverBaseName(
            IntPtr ImageBase,
            [Out] StringBuilder lpBaseName,
            int nSize);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetDeviceDriverFileName(
            IntPtr ImageBase,
            [Out] StringBuilder lpFilename,
            int nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(
            IntPtr hProcess,
            IntPtr hModule,
            out MODULEINFO lpmodinfo,
            uint cb);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        // ───────────────────────────────────────────────────────────────

        /// <summary>
        /// 枚举已加载驱动、计算哈希、上传服务端验证。
        /// </summary>
        /// <returns>(Success, BlockedCount, Reason, Id)</returns>
        public static async Task<(bool Success, int BlockedCount, string Reason, string Id)> RunAsync(HttpClient http)
        {
            try
            {
                Console.WriteLine("  [*] 枚举系统中已加载的驱动模块...");

                var drivers = CollectLoadedDrivers();
                Console.WriteLine($"  [*] 共枚举到 {drivers.Count} 个驱动模块,开始计算哈希...");

                int hashed = 0;
                foreach (var d in drivers)
                {
                    if (!string.IsNullOrEmpty(d.FilePath) && File.Exists(d.FilePath))
                    {
                        try
                        {
                            var bytes = File.ReadAllBytes(d.FilePath);
                            d.Md5 = Convert.ToHexString(MD5.HashData(bytes)).ToLowerInvariant();
                            d.Sha1 = Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant();
                            d.Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                            hashed++;
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            // 文件被占用或无权限,跳过
                        }
                    }
                }
                Console.WriteLine($"  [*] 成功计算 {hashed}/{drivers.Count} 个驱动文件的哈希");

                // 3. 上传到服务端(字段名 snake_case,匹配服务端 DriverInfo)
                var uploadObj = new DriverUpload { Drivers = drivers };
                var json = JsonSerializer.Serialize(uploadObj, JsonOpts);
                var resp = await http.PostAsync("/verify_drivers",
                    new StringContent(json, Encoding.UTF8, "application/json"));

                if (!resp.IsSuccessStatusCode)
                    return (false, 0, $"服务端返回 {resp.StatusCode}", "");

                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
                var root = doc.RootElement;

                var id = root.TryGetProperty("id", out var idEl) ? idEl.GetString() ?? "" : "";
                var clientCount = root.GetProperty("client_count").GetInt32();
                var blockedCount = root.GetProperty("blocked_count").GetInt32();

                var blocked = new List<(string Name, string Path, string? Sha256)>();
                if (root.TryGetProperty("suspicious", out var arr))
                {
                    foreach (var item in arr.EnumerateArray())
                    {
                        blocked.Add((
                            item.TryGetProperty("file_name", out var n) ? n.GetString() ?? "?" : "?",
                            item.TryGetProperty("file_path", out var p) ? p.GetString() ?? "?" : "?",
                            item.TryGetProperty("sha256", out var s) ? s.GetString() : null));
                    }
                }

                Console.WriteLine($"  [*] 已加载驱动: {clientCount} 个, 命中拉黑: {blockedCount} 个");

                if (blocked.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  [!] 发现 {blocked.Count} 个被拉黑的驱动已加载:");
                    Console.ResetColor();
                    foreach (var b in blocked)
                    {
                        Console.WriteLine($"      驱动名: {b.Name}");
                        Console.WriteLine($"      文件路径: {b.Path}");
                        if (!string.IsNullOrEmpty(b.Sha256))
                            Console.WriteLine($"      SHA-256: {b.Sha256[..Math.Min(16, b.Sha256.Length)]}...");
                    }
                }
                else
                {
                    Console.WriteLine("  [✔] 未发现已加载的拉黑驱动");
                }

                return (true, blocked.Count, blocked.Count > 0
                    ? $"{blocked.Count} 个驱动命中拉黑列表"
                    : "全部通过", id);
            }
            catch (Exception ex)
            {
                return (false, 0, $"异常: {ex.Message}", "");
            }
        }

        // ═══════════════════════════════════════════════════════════════
        //  PSAPI 枚举已加载驱动
        // ═══════════════════════════════════════════════════════════════

        private sealed class DriverEntry
        {
            public string FileName { get; set; } = "";
            public string FilePath { get; set; } = "";
            public string? Md5 { get; set; }
            public string? Sha1 { get; set; }
            public string? Sha256 { get; set; }
            public ulong BaseAddr { get; set; }
            public uint Size { get; set; }
        }

        // 注:服务端 DriverInfo 字段使用 snake_case JSON(file_name/file_path...),
        // 这里用 SnakeCase 命名策略让序列化自动适配。
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        };

        private sealed class DriverUpload
        {
            public List<DriverEntry> Drivers { get; set; } = new();
        }

        private static List<DriverEntry> CollectLoadedDrivers()
        {
            var result = new List<DriverEntry>();

            // 第一次调用获取所需字节数
            EnumDeviceDrivers(null, 0, out int needed);
            if (needed == 0) return result;

            int count = needed / IntPtr.Size;
            var bases = new IntPtr[count];

            if (!EnumDeviceDrivers(bases, needed, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "EnumDeviceDrivers 失败");

            var nameBuf = new StringBuilder(1024);
            var pathBuf = new StringBuilder(260);

            foreach (var baseAddr in bases)
            {
                if (baseAddr == IntPtr.Zero) continue;

                string name = "";
                string rawPath = "";

                nameBuf.Clear();
                if (GetDeviceDriverBaseName(baseAddr, nameBuf, nameBuf.Capacity) > 0)
                    name = nameBuf.ToString();

                pathBuf.Clear();
                if (GetDeviceDriverFileName(baseAddr, pathBuf, pathBuf.Capacity) > 0)
                    rawPath = pathBuf.ToString();

                // 获取模块大小
                uint size = 0;
                if (GetModuleInformation(GetCurrentProcess(), baseAddr, out var info, (uint)Marshal.SizeOf<MODULEINFO>()))
                    size = info.SizeOfImage;

                // 转换内核路径为用户态可用路径
                var realPath = NormalizeDriverPath(rawPath);

                result.Add(new DriverEntry
                {
                    FileName = name,
                    FilePath = realPath,
                    BaseAddr = (ulong)baseAddr,
                    Size = size,
                });
            }

            return result;
        }

        /// <summary>
        /// 把 PSAPI 返回的内核路径转换为可读的真实文件系统路径。
        /// 常见格式:
        ///   \SystemRoot\System32\drivers\xxx.sys
        ///   \??\C:\Windows\System32\drivers\xxx.sys
        ///   \Device\HarddiskVolumeN\Windows\...
        ///   C:\Windows\System32\drivers\xxx.sys (已是绝对路径)
        /// </summary>
        private static string NormalizeDriverPath(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";

            // 已是绝对路径
            if (raw.Length >= 2 && raw[1] == ':')
                return raw;

            // \??\C:\... 前缀
            if (raw.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                return raw.Substring(4);

            // \SystemRoot\... → C:\Windows\...
            if (raw.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            {
                var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                return Path.Combine(sysRoot, raw.Substring(11).TrimStart('\\'));
            }

            // \Device\HarddiskVolumeN\... → 通过 QueryDosDevice 把卷号映射成盘符
            if (raw.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                var resolved = TryResolveDevicePath(raw);
                if (resolved != null) return resolved;
            }

            return raw;
        }

        /// <summary>
        /// 尝试把 \Device\HarddiskVolumeN\... 转换为 C:\... 形式。
        /// 遍历所有盘符,用 QueryDosDevice 获取其设备路径进行匹配。
        /// </summary>
        private static string? TryResolveDevicePath(string raw)
        {
            // 提取设备路径前缀(\Device\HarddiskVolumeN)和剩余路径
            int sep = raw.IndexOf('\\', 1);
            if (sep < 0) return null;
            // 找到 \Device\ 后再找下一个 \ 的位置
            int devEnd = raw.IndexOf('\\', "Device".Length + 1);
            if (devEnd < 0) return null;

            var devicePrefix = raw.Substring(0, devEnd);  // \Device\HarddiskVolumeN
            var remaining = raw.Substring(devEnd + 1);    // Windows\System32\drivers\xxx.sys

            // 枚举盘符 C..Z
            foreach (var drive in Directory.GetLogicalDrives())
            {
                try
                {
                    var driveLetter = drive.TrimEnd('\\');   // C:
                    var devPath = QueryDosDevice(driveLetter);
                    if (!string.IsNullOrEmpty(devPath) &&
                        string.Equals(devPath, devicePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return Path.Combine(drive, remaining.TrimStart('\\'));
                    }
                }
                catch { /* 忽略不可访问的盘符 */ }
            }

            return null;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMaxChars);

        private static string? QueryDosDevice(string deviceName)
        {
            var buf = new StringBuilder(260);
            int n = QueryDosDevice(deviceName, buf, buf.Capacity);
            return n > 0 ? buf.ToString() : null;
        }

        // 让 DriverEntry 序列化时与服务端 DriverInfo 字段对齐(camelCase)
        // 由于使用了 JsonNamingPolicy.CamelCase, public 字段会自动转为 camelCase
        // 通过上面的 DriverUpload + JsonSerializer.Serialize 包装即可
    }
}
