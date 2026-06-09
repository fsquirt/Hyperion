using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SEWindows.Tracker.SysmonEventTracker;

/// <summary>
/// Sysmon 生命周期管理：从服务器下载、安装服务、卸载清理。
/// </summary>
public static class SysmonInstaller
{
    private const string SysmonExe = "Sysmon.exe";
    private const string SysmonXml = "Sysmon.xml";

    /// <summary>从服务器下载 Sysmon.exe 和 Sysmon.xml 到当前目录。</summary>
    public static async Task DownloadAsync(string serverBase)
    {
        Console.WriteLine("[*] 从服务器下载 Sysmon 文件...");

        using var http = new HttpClient
        {
            BaseAddress = new Uri(serverBase),
            Timeout = TimeSpan.FromSeconds(30),
        };

        // 根据架构选择 Sysmon 可执行文件
        var arch = RuntimeInformation.ProcessArchitecture;
        var remoteExe = arch switch
        {
            Architecture.Arm64 => "/Sysmon/Sysmon64a.exe",
            _ => "/Sysmon/Sysmon.exe",
        };

        try
        {
            var exeBytes = await http.GetByteArrayAsync(remoteExe);
            await File.WriteAllBytesAsync(SysmonExe, exeBytes);
            Console.WriteLine($"  ├─ {SysmonExe} ({exeBytes.Length / 1024} KB) ← {remoteExe}");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ├─ 下载 {SysmonExe} 失败: {ex.Message}");
            Console.ResetColor();
            throw;
        }

        try
        {
            var xmlBytes = await http.GetByteArrayAsync("/Sysmon/Sysmon.xml");
            await File.WriteAllBytesAsync(SysmonXml, xmlBytes);
            Console.WriteLine($"  └─ {SysmonXml} ({xmlBytes.Length / 1024} KB)");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  └─ 下载 {SysmonXml} 失败: {ex.Message}");
            Console.ResetColor();
            throw;
        }

        Console.WriteLine();
    }

    /// <summary>卸载已有实例后安装 Sysmon 服务。</summary>
    public static void Install()
    {
        Console.WriteLine("[*] 部署 Sysmon 服务...");

        // 先卸载已有实例（忽略错误）
        RunSysmon("-u", ignoreError: true);

        // 安装
        var (exitCode, output) = RunSysmon("-accepteula -i Sysmon.xml");
        if (exitCode != 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  └─ Sysmon 安装失败 (exit={exitCode}): {output}");
            Console.ResetColor();
            throw new InvalidOperationException($"Sysmon 安装失败 (exit={exitCode})");
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("  └─ Sysmon 服务安装成功");
        Console.ResetColor();
        Console.WriteLine();
    }

    /// <summary>清理 Sysmon 生成的事件日志。</summary>
    public static void ClearEventLog()
    {
        Console.WriteLine("[*] 清理 Sysmon 事件日志...");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wevtutil",
                Arguments = "cl Microsoft-Windows-Sysmon/Operational",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) { Console.WriteLine("  └─ 无法启动 wevtutil"); return; }
            proc.WaitForExit();
            if (proc.ExitCode == 0)
                Console.WriteLine("  └─ Sysmon 事件日志已清空");
            else
                Console.WriteLine($"  └─ 清理失败 (exit={proc.ExitCode}): {proc.StandardError.ReadToEnd().Trim()}");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  └─ 清理跳过: {ex.Message}");
            Console.ResetColor();
        }
    }

    /// <summary>卸载 Sysmon 服务。</summary>
    public static void Uninstall()
    {
        Console.WriteLine("[*] 卸载 Sysmon 服务...");
        RunSysmon("-u", ignoreError: true);
    }

    private static (int ExitCode, string Output) RunSysmon(string args, bool ignoreError = false)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = SysmonExe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null) return (-1, "无法启动进程");

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            var output = string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;

            if (proc.ExitCode != 0 && !ignoreError)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  ├─ Sysmon {args} 警告 (exit={proc.ExitCode}): {output.Trim()}");
                Console.ResetColor();
            }

            return (proc.ExitCode, output);
        }
        catch (Exception ex) when (ignoreError)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  ├─ Sysmon {args} 跳过: {ex.Message}");
            Console.ResetColor();
            return (-1, ex.Message);
        }
    }
}
