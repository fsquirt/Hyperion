using System.Text.Json;
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
///
/// 数据上报 (全部结构化, kind 区分):
///   - kind="driver": 每个驱动的完整 CbnClassifyEntry (含 Signers[])
///   - kind="iat":    IAT 扫描结果 CbnIatResult (含 Entries[].Apis[])
///   - kind="device": 设备枚举 DeviceEntry[]
///   - kind="attach": 附着结果 CbnAttachResult
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

        // 1.1 全量投递驱动分类结果到服务端 kernel-comms API (每个驱动一条, kind="driver")
        foreach (var driver in classifyEntries)
        {
            var driverObj = new
            {
                fileName = driver.FileName,
                filePath = driver.FilePath,
                driverObjectName = driver.DriverObjectName,
                klass = driver.Klass,
                klassName = GetClassName(driver.Klass),
                signerCount = driver.SignerCount,
                signers = driver.Signers.Take(driver.SignerCount).Select(s => new
                {
                    subject = s.Subject,
                    issuer = s.Issuer,
                    isMicrosoft = s.IsMicrosoft,
                    isWhql = s.IsWhql,
                    isVendor = s.IsVendor,
                }).ToArray(),
                vendorName = driver.VendorName,
                errorReason = driver.ErrorReason,
                hasCatalog = driver.HasCatalog,
                hasEmbedded = driver.HasEmbedded,
                // 驱动映像信息 (Category A: 之前 FFI 丢失, 现已补齐)
                imageBase = driver.ImageBase,
                imageSize = driver.ImageSize,
                loadOrderIndex = driver.LoadOrderIndex,
            };

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "driver",
                Level = GetDriverLevel(driver.Klass),
                Source = "DriverScan",
                Title = $"驱动: {driver.FileName} ({GetClassName(driver.Klass)})",
                DataJson = JsonSerializer.Serialize(driverObj),
                DriverFileName = driver.FileName,
                DriverClass = driver.Klass,
                VendorName = driver.VendorName,
                HasCatalog = driver.HasCatalog,
                HasEmbedded = driver.HasEmbedded,
                // 索引列: 驱动映像信息 (Category A)
                ImageBase = driver.ImageBase,
                ImageSize = driver.ImageSize,
                LoadOrderIndex = driver.LoadOrderIndex,
            });
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

            // 5. 投递 IAT 扫描结果到服务端 kernel-comms API (kind="iat")
            var iatObj = new
            {
                filePath = iat.FilePath,
                dllCount = iat.DllCount,
                totalApiCount = iat.TotalApiCount,
                dangerousApiCount = iat.DangerousApiCount,
                entries = iat.Entries.Take(iat.DllCount).Select(e => new
                {
                    dllName = e.DllName,
                    apiCount = e.ApiCount,
                    apis = e.Apis.Take(e.ApiCount).Select(a => new
                    {
                        name = a.Name,
                        isDangerous = a.IsDangerous,
                    }).ToArray(),
                }).ToArray(),
            };

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "iat",
                Level = "WARN",
                Source = "DriverAttach",
                Title = $"IAT 危险函数: {driver.FileName} ({iat.DangerousApiCount} 个)",
                DataJson = JsonSerializer.Serialize(iatObj),
                DriverFileName = driver.FileName,
                DangerousApiCount = iat.DangerousApiCount,
            });

            // 6. 枚举设备
            var devices = EnumDevices(driver.FileName);
            if (devices == null || devices.Length == 0)
            {
                Console.Error.WriteLine($"[Attach] {driver.FileName}: 无暴露设备, 跳过");
                continue;
            }

            // 6.1 投递设备枚举结果到服务端 (kind="device")
            var deviceObjs = devices
                .Where(d => !string.IsNullOrEmpty(d.DeviceName))
                .Select(d => new
                {
                    deviceObject = d.DeviceObject,
                    deviceType = d.DeviceType,
                    characteristics = d.Characteristics,
                    flags = d.Flags,
                    attachedCount = d.AttachedCount,
                    stackSize = d.StackSize,
                    deviceName = d.DeviceName,
                }).ToArray();

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "device",
                Level = "INFO",
                Source = "DriverAttach",
                Title = $"设备枚举: {driver.FileName} ({deviceObjs.Length} 个设备)",
                DataJson = JsonSerializer.Serialize(new { driverFileName = driver.FileName, devices = deviceObjs }),
                DriverFileName = driver.FileName,
            });

            // 7. 对每个设备附着
            foreach (var device in devices)
            {
                if (string.IsNullOrEmpty(device.DeviceName)) continue;

                var (attachOk, attachResult) = AttachDevice(device.DeviceName);
                if (attachOk && attachResult.Status == 0)
                {
                    attachedCount++;
                    _attached.Add((device.DeviceName, attachResult.AttachId));

                    var attachObj = new
                    {
                        driverFileName = driver.FileName,
                        deviceName = device.DeviceName,
                        status = attachResult.Status,
                        attachId = attachResult.AttachId,
                        filterDeviceAddr = attachResult.FilterDeviceAddr,
                        lowerDeviceAddr = attachResult.LowerDeviceAddr,
                        newStackSize = attachResult.NewStackSize,
                        targetStackSize = attachResult.TargetStackSize,
                    };

                    _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                    {
                        Kind = "attach",
                        Level = "HIGH",
                        Source = "DriverAttach",
                        Title = $"已附着设备: {device.DeviceName}",
                        DataJson = JsonSerializer.Serialize(attachObj),
                        AttachId = attachResult.AttachId,
                        DeviceName = device.DeviceName,
                        FilterDeviceAddr = attachResult.FilterDeviceAddr,
                    });
                }
            }
        }

        Console.Error.WriteLine(
            $"[Attach] ═══ 扫描附着完成: 共附着 {attachedCount} 个设备 ═══");

        // 8. 上报完整附着列表到服务端 (kind="attach-summary")
        //     Category B: 之前 UserService 维护 _attached 但从不上报, 现补齐
        ReportAttachments();
    }

    /// <summary>
    /// 上报当前附着列表到服务端。
    /// 调用 FetchListAttachments 从内核拿到权威列表 (FilterDeviceAddr/LowerDeviceAddr/TargetPath/AttachId/StackSize),
    /// 与本地 _attached 合并后整体投递为 kind="attach-summary"。
    /// </summary>
    private void ReportAttachments()
    {
        try
        {
            using var result = _host.Service.FetchListAttachments();
            if (!result.Success)
            {
                Console.Error.WriteLine($"[Attach] 上报附着列表失败: {result.ErrorMessage}");
                return;
            }

            var kernelAttachments = result.Entries;
            if (kernelAttachments.Length == 0) return;

            var attachSummary = new
            {
                count = kernelAttachments.Length,
                attachments = kernelAttachments.Select(a => new
                {
                    filterDeviceAddr = a.FilterDeviceAddr,
                    lowerDeviceAddr = a.LowerDeviceAddr,
                    targetPath = a.TargetPath,
                    attachId = a.AttachId,
                    stackSize = a.StackSize,
                }).ToArray(),
            };

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "attach-summary",
                Level = "HIGH",
                Source = "DriverAttach",
                Title = $"附着列表汇总: {kernelAttachments.Length} 个设备",
                DataJson = JsonSerializer.Serialize(attachSummary),
            });

            Console.Error.WriteLine(
                $"[Attach] 已上报附着列表: {kernelAttachments.Length} 个设备");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Attach] 上报附着列表异常: {ex.Message}");
        }
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
            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "driver",
                Level = "ERR",
                Source = "DriverAttach",
                Title = "驱动扫描失败",
                DataJson = JsonSerializer.Serialize(new { error = result.ErrorMessage }),
            });
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
}
