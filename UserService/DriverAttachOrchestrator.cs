using System.Text;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 驱动附着编排器: 把 DriverAttachSelector 的能力接入 UserService。
///
/// 流程:
///   1. FetchScanAndClassify 扫描所有已加载驱动, 按签名分类
///      (INBOX / MICROSOFT / THIRD_PARTY_WHQL / UNTRUSTED)
///   2. 只对 THIRD_PARTY_WHQL 驱动逐个 FetchScanIat 检查 IAT 危险函数
///   3. 跳过 KernelService.sys (自己的内核驱动, 不能附着自己)
///   4. 对 DangerousApiCount > 0 的驱动 FetchEnumDevices 找暴露的设备
///   5. 对每个设备 FetchAttach 附着 (IRP 透传监控)
///   6. 附着结果通过 ITrackerSink 投递 (Type="attach")
/// </summary>
internal sealed class DriverAttachOrchestrator
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;

    // 附着的设备列表 (供后续解绑用)
    private readonly List<(string DevicePath, uint AttachId)> _attached = new();

    // 跳过自家驱动 (KernelService.sys)
    private const string SelfDriverName = "KernelService.sys";

    public DriverAttachOrchestrator(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 执行完整的扫描→IAT检查→附着流程。
    /// 在驱动加载后、游戏启动前调用。
    /// </summary>
    public void ScanAndAttach()
    {
        Console.Error.WriteLine("[Attach] ═══ 开始驱动扫描与附着 ═══");

        // 1. 扫描 + 分类
        var classifyEntries = ScanAndClassify();
        if (classifyEntries == null || classifyEntries.Length == 0)
        {
            Console.Error.WriteLine("[Attach] 扫描无结果, 跳过附着");
            return;
        }

        // 1.1 全量投递驱动分类结果到服务端 kernel-comms API (每个驱动一条)
        foreach (var driver in classifyEntries)
        {
            _ = _server?.PostKernelCommAsync(
                kind: "driver",
                level: GetDriverLevel(driver.Klass),
                source: "DriverScan",
                title: $"驱动: {driver.FileName} ({GetClassName(driver.Klass)})",
                detail: BuildDriverDetail(driver));
        }

        // 2. 筛选 THIRD_PARTY_WHQL 驱动 (Klass == 2)
        var thirdParty = classifyEntries
            .Where(e => e.Klass == 2)
            .ToList();

        Console.Error.WriteLine(
            $"[Attach] 扫描到 {classifyEntries.Length} 个驱动, " +
            $"其中 {thirdParty.Count} 个 THIRD_PARTY_WHQL");

        // 3. 对每个 THIRD_PARTY 驱动检查 IAT + 附着设备
        int attachedCount = 0;
        foreach (var driver in thirdParty)
        {
            // 跳过自家驱动
            if (driver.FileName.Equals(SelfDriverName, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine($"[Attach] 跳过自家驱动: {driver.FileName}");
                continue;
            }

            // 4. 扫描 IAT 危险函数
            var (iatOk, iat) = ScanIat(driver.FilePath);
            if (!iatOk || iat.DangerousApiCount == 0)
            {
                Console.Error.WriteLine(
                    $"[Attach] {driver.FileName}: IAT 无危险函数, 跳过");
                continue;
            }

            Console.Error.WriteLine(
                $"[Attach] {driver.FileName}: 发现 {iat.DangerousApiCount} 个危险 API, " +
                $"开始枚举设备...");

            // 5. 投递 IAT 告警到服务端 kernel-comms API
            _ = _server?.PostKernelCommAsync(
                kind: "attach",
                level: "WARN",
                source: "DriverAttach",
                title: $"危险驱动: {driver.FileName}",
                detail: $"Vendor: {driver.VendorName}\n" +
                        $"IAT 危险 API 数: {iat.DangerousApiCount}\n" +
                        $"签名: {GetSignerSummary(driver)}");

            // 6. 枚举设备
            var devices = EnumDevices(driver.FileName);
            if (devices == null || devices.Length == 0)
            {
                Console.Error.WriteLine($"[Attach] {driver.FileName}: 无暴露设备, 跳过");
                continue;
            }

            // 7. 对每个设备附着
            foreach (var device in devices)
            {
                if (string.IsNullOrEmpty(device.DeviceName)) continue;

                var (attachOk, attachResult) = AttachDevice(device.DeviceName);
                if (attachOk && attachResult.Status == 0)
                {
                    attachedCount++;
                    _attached.Add((device.DeviceName, attachResult.AttachId));

                    _ = _server?.PostKernelCommAsync(
                        kind: "attach",
                        level: "HIGH",
                        source: "DriverAttach",
                        title: $"已附着设备: {device.DeviceName}",
                        detail: $"驱动: {driver.FileName}\n" +
                                $"AttachId: {attachResult.AttachId}\n" +
                                $"FilterDevice: 0x{attachResult.FilterDeviceAddr:X}\n" +
                                $"LowerDevice: 0x{attachResult.LowerDeviceAddr:X}");
                }
            }
        }

        Console.Error.WriteLine(
            $"[Attach] ═══ 扫描附着完成: 共附着 {attachedCount} 个设备 ═══");
    }

    // ═══════════════════════════════════════════════════════════════
    //  各步骤封装
    // ═══════════════════════════════════════════════════════════════

    /// <summary>扫描所有已加载驱动并按签名分类。</summary>
    private CbnClassifyEntry[]? ScanAndClassify()
    {
        using var result = _host.Service.FetchScanAndClassify();
        if (!result.Success)
        {
            _ = _server?.PostKernelCommAsync(
                kind: "driver",
                level: "ERR",
                source: "DriverAttach",
                title: "驱动扫描失败",
                detail: result.ErrorMessage);
            return null;
        }
        return result.Entries;
    }

    /// <summary>扫描单个驱动的 IAT 危险函数。返回 (success, result)。</summary>
    private (bool ok, CbnIatResult result) ScanIat(string filePath)
    {
        using var result = _host.Service.FetchScanIat(filePath);
        if (!result.Success)
        {
            Console.Error.WriteLine($"[Attach] IAT 扫描失败: {filePath} - {result.ErrorMessage}");
            return (false, default);
        }
        return (true, result.SingleEntry);
    }

    /// <summary>枚举单个驱动的暴露设备。</summary>
    private DeviceEntry[]? EnumDevices(string driverName)
    {
        using var result = _host.Service.FetchEnumDevices(driverName);
        if (!result.Success)
        {
            Console.Error.WriteLine($"[Attach] 设备枚举失败: {driverName} - {result.ErrorMessage}");
            return null;
        }
        return result.Entries;
    }

    /// <summary>附着到指定设备。返回 (success, result)。</summary>
    private (bool ok, CbnAttachResult result) AttachDevice(string devicePath)
    {
        using var result = _host.Service.FetchAttach(devicePath);
        if (!result.Success)
        {
            Console.Error.WriteLine($"[Attach] 附着失败: {devicePath} - {result.ErrorMessage}");
            return (false, default);
        }
        return (true, result.SingleEntry);
    }

    /// <summary>获取签名信息摘要。</summary>
    private static string GetSignerSummary(CbnClassifyEntry entry)
    {
        if (entry.SignerCount == 0) return "无签名";
        var signers = entry.Signers.Take(entry.SignerCount)
            .Where(s => !string.IsNullOrEmpty(s.Subject))
            .Select(s => s.Subject);
        return string.Join(", ", signers);
    }

    /// <summary>获取已附着设备列表 (供解绑用)。</summary>
    public IReadOnlyList<(string DevicePath, uint AttachId)> AttachedDevices => _attached;

    // ═══════════════════════════════════════════════════════════════
    //  辅助: 驱动分类信息
    // ═══════════════════════════════════════════════════════════════

    /// <summary>根据分类返回级别: UNTRUSTED=HIGH, THIRD_PARTY=WARN, 其他=INFO。</summary>
    private static string GetDriverLevel(int klass) => klass switch
    {
        3 => "HIGH",   // UNTRUSTED
        2 => "WARN",   // THIRD_PARTY_WHQL
        1 => "INFO",   // MICROSOFT
        0 => "INFO",   // INBOX
        _ => "INFO",
    };

    /// <summary>分类数字 → 名称。</summary>
    private static string GetClassName(int klass) => klass switch
    {
        0 => "INBOX",
        1 => "MICROSOFT",
        2 => "THIRD_PARTY_WHQL",
        3 => "UNTRUSTED",
        _ => $"UNKNOWN({klass})",
    };

    /// <summary>构建驱动详情字符串 (含签名者信息)。</summary>
    private static string BuildDriverDetail(CbnClassifyEntry driver)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"FileName: {driver.FileName}");
        sb.AppendLine($"FilePath: {driver.FilePath}");
        sb.AppendLine($"Class: {GetClassName(driver.Klass)}");
        sb.AppendLine($"Vendor: {driver.VendorName}");
        sb.AppendLine($"SignerCount: {driver.SignerCount}");

        if (driver.SignerCount > 0)
        {
            sb.AppendLine("Signers:");
            var signers = driver.Signers.Take((int)driver.SignerCount);
            foreach (var s in signers)
            {
                if (!string.IsNullOrEmpty(s.Subject))
                    sb.AppendLine($"  - {s.Subject}");
            }
        }

        return sb.ToString();
    }
}
