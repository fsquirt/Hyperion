using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using Hyperion.UserService.Comm;

namespace Hyperion.UserService.Modules;

/// <summary>
/// SiPolicy.p7b 免重启更新器。
///
/// 流程:游戏启动前,由 AntiCheatService 按服务端开关调用。
///   1. 从服务端 GET /api/client/sipolicy.p7b 下载微软漏洞驱动 WDAC 策略二进制
///   2. 写入 %windir%\System32\CodeIntegrity\SiPolicy.p7b,与本地已有文件相同则跳过写盘
///   3. NtSetSystemInformation(SystemCodeIntegrityPolicyInformation=0x87, 32字节缓冲, 首DWORD=0x10000000)
///      免重启刷新 CodeIntegrity 策略,由内核在驱动加载层面阻止已知漏洞驱动,即 BYOVD
///
/// 所有失败均非致命,仅记日志,不阻断游戏启动。
/// </summary>
public static class SiPolicyUpdater
{
    //v0 = NtSetSystemInformation(
    //   SystemInformationClass: SystemContextSwitchInformation|0x80,
    //   SystemInformation,
    //   SystemInformationLength: 0x20u);

    //在 Windows 的 SYSTEM_INFORMATION_CLASS 枚举中，SystemContextSwitchInformation 的常量值为 0x24
    //0x24 | 0x80 = 0xA4
    private const int SystemCodeIntegrityPolicyInformation = 0xA4;

    // 策略刷新选项:0x10000000 = CODEINTEGRITYPOLICY_OPTION_REFRESH,触发重读磁盘上的 SiPolicy.p7b
    private const uint PolicyOptionRefresh = 0x10000000;

    /// <summary>SiPolicy.p7b 在系统中的标准位置。</summary>
    private static readonly string TargetPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "CodeIntegrity", "SiPolicy.p7b");

    [DllImport("ntdll.dll")]
    private static extern int NtSetSystemInformation(int infoClass, byte[] info, uint length);

    /// <summary>
    /// 下载并应用 SiPolicy.p7b。失败抛出异常,由调用方决定是否致命。
    /// </summary>
    public static async Task UpdateAsync(string serverUrl, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
            throw new InvalidOperationException("未配置服务端地址,无法下载 SiPolicy.p7b");

        // 1. 下载
        var url = serverUrl.TrimEnd('/') + "/api/client/sipolicy.p7b";
        byte[] policyBytes;
        using (var http = CertPinning.CreatePinnedClient(timeout: TimeSpan.FromSeconds(30)))
        {
            using var resp = await http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"下载 SiPolicy.p7b 失败 HTTP {(int)resp.StatusCode}");
            policyBytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }

        if (policyBytes.Length == 0)
            throw new InvalidDataException("下载的 SiPolicy.p7b 为空");

        // 2. 写入 CodeIntegrity,与本地一致则跳过写盘,减少对系统目录的无谓改动;
        //    但重启后内存策略会回到引导时的状态,故刷新调用始终执行)
        bool needWrite = true;
        try
        {
            if (File.Exists(TargetPath))
            {
                var existing = await File.ReadAllBytesAsync(TargetPath, ct).ConfigureAwait(false);
                needWrite = !existing.AsSpan().SequenceEqual(policyBytes);
            }
        }
        catch
        {
            needWrite = true; // 读不了旧文件就强制覆盖
        }

        if (needWrite)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(TargetPath)!);
            await File.WriteAllBytesAsync(TargetPath, policyBytes, ct).ConfigureAwait(false);
        }

        // 3. 免重启刷新策略:32 字节缓冲,首 DWORD=0x10000000,其余为零
        var info = new byte[0x20];
        BitConverter.GetBytes(PolicyOptionRefresh).CopyTo(info, 0);
        int status = NtSetSystemInformation(SystemCodeIntegrityPolicyInformation, info, (uint)info.Length);
        if (status < 0)
            throw new InvalidOperationException($"NtSetSystemInformation 刷新失败 NTSTATUS=0x{status:X8}");

        Console.Error.WriteLine(
            $"[SiPolicy] 已更新 {TargetPath},大小 {policyBytes.Length} bytes,{(needWrite ? "已写入" : "内容未变跳过写盘")},策略已刷新");
    }
}
