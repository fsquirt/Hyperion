using System.Text;
using System.Text.Json;
using UserService.Native;

namespace Hyperion.UserService;

/// <summary>
/// 驱动附着编排器: 把 DriverAttachSelector 的能力接入 UserService。
///
/// 流程:
///   1. FetchScanAndClassify 扫描所有已加载驱动, 按签名分类
///      (INBOX / MICROSOFT / THIRD_PARTY_WHQL / UNTRUSTED)
///   2. 对所有驱动逐个 FetchScanIat 检查 IAT (空 IAT 视为动态解析, 无条件附着)
///   3. 跳过 KernelService.sys (自己的内核驱动, 不能附着自己)
///   4. 对 IAT 为空 或 (THIRD_PARTY_WHQL + DangerousApiCount > 0) 的驱动
///      FetchEnumDevices 找暴露的设备
///   5. 对每个设备 FetchAttach 附着 (IRP 透传监控)
///   6. 附着结果通过 ITrackerSink 投递 (Type="attach")
///
/// 数据上报 (全部结构化, kind 区分):
///   - kind="driver": 每个驱动的完整 CbnClassifyEntry (含 Signers[])
///   - kind="iat":    IAT 扫描结果 CbnIatResult (含 Entries[].Apis[])
///   - kind="iat-empty-alert": IAT 为空且有设备暴露 (HIGH, 疑似动态解析)
///   - kind="iat-empty-no-device": IAT 为空且无设备暴露 (WARN)
///   - kind="device": 设备枚举 DeviceEntry[]
///   - kind="attach": 附着结果 CbnAttachResult
/// </summary>
internal sealed class DriverAttachOrchestrator : IDisposable
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;
    // H3: 服务端下发的完整策略 (白名单 + 危险函数), 启动时拉取一次
    private readonly ServerDataClient.TrackerPolicy? _policy;

    // 附着的设备列表 (供后续解绑用)
    // H5: 之前只记录从不上报也不解绑, 游戏退出后设备仍附着, 仅靠 DriverLoader.UnloadDriver
    //     卸载驱动时内核强制断开。若驱动卸载失败, 设备持续附着, 下次启动重复附着同一设备。
    //     现在加 DetachAll 在 Cleanup 时主动解绑。
    private readonly List<(string DevicePath, uint AttachId)> _attached = new();

    // 跳过自家驱动 (KernelService.sys)
    private const string SelfDriverName = "KernelService.sys";

    public DriverAttachOrchestrator(NativeHost host, ServerDataClient? server,
                                    ServerDataClient.TrackerPolicy? policy)
    {
        _host = host;
        _server = server;
        _policy = policy;
    }

    // ═══════════════════════════════════════════════════════════════
    //  白名单检查 (服务端策略下发的可信驱动, 跳过附着)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 检查驱动是否在白名单中 (可信驱动, 跳过附着)。
    /// hash 类型: 比较 Sha256 (忽略大小写)
    /// cert 类型: 检查签名者 Subject 是否包含 CertSubject (忽略大小写)
    /// </summary>
    private bool IsWhitelisted(CbnClassifyEntry driver)
    {
        if (_policy == null || _policy.Whitelist.Count == 0) return false;

        foreach (var entry in _policy.Whitelist)
        {
            if (entry.Type.Equals("hash", StringComparison.OrdinalIgnoreCase))
            {
                // hash 匹配: 比较 Sha256
                if (string.IsNullOrEmpty(entry.Sha256)) continue;
                string driverHash = GetDriverSha256Hex(driver);
                if (string.Equals(driverHash, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine($"[Attach] {driver.FileName}: 白名单匹配 (hash {entry.DisplayName})");
                    return true;
                }
            }
            else if (entry.Type.Equals("cert", StringComparison.OrdinalIgnoreCase))
            {
                // cert 匹配: 检查签名者 Subject 是否包含 CertSubject
                if (string.IsNullOrEmpty(entry.CertSubject)) continue;
                for (int i = 0; i < driver.SignerCount && i < driver.Signers.Length; i++)
                {
                    string signerSubject = driver.Signers[i].Subject ?? "";
                    if (signerSubject.IndexOf(entry.CertSubject, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Console.Error.WriteLine($"[Attach] {driver.FileName}: 白名单匹配 (cert {entry.DisplayName})");
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// <summary>
    /// 从 CbnClassifyEntry 提取 SHA256 hex 字符串。
    /// C++ 端 sha256 是 char[65] (ANSI), C# 端用 byte[] marshal,
    /// 这里通过 ASCII 解码并去除尾部 '\0'。
    /// </summary>
    private static string GetDriverSha256Hex(CbnClassifyEntry driver)
    {
        if (driver.Sha256 == null || driver.Sha256.Length == 0) return "";
        return Encoding.ASCII.GetString(driver.Sha256).TrimEnd('\0');
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

        // 2. 对所有分类的驱动逐个检查 IAT + 附着设备
        //    - 跳过 INBOX (Klass==0) / MICROSOFT (Klass==1) — 可信驱动不扫 IAT
        //    - IAT 扫描失败 (文件不存在等) = 疑似加载后自删除 = 直接查设备
        //    - IAT 为空 (DllCount==0 或 TotalApiCount==0) = 动态 API 解析 = 无条件附着 (跳过白名单)
        //    - IAT 非空: 仅 THIRD_PARTY_WHQL (Klass==2) + DangerousApiCount>0 才附着 (走白名单)
        int thirdPartyWhqlCount = classifyEntries.Count(e => e.Klass == 2);
        Console.Error.WriteLine(
            $"[Attach] 扫描到 {classifyEntries.Length} 个驱动, " +
            $"其中 {thirdPartyWhqlCount} 个 THIRD_PARTY_WHQL");

        int attachedCount = 0;
        foreach (var driver in classifyEntries)
        {
            // 跳过自家驱动
            if (driver.FileName.Equals(SelfDriverName, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine($"[Attach] 跳过自家驱动: {driver.FileName}");
                continue;
            }

            // 3. 跳过 INBOX (Klass==0) 和 MICROSOFT (Klass==1) 驱动 — 可信驱动不扫 IAT
            if (driver.Klass == 0 || driver.Klass == 1)
            {
                continue;
            }

            // 4. 扫描 IAT 危险函数 (仅 THIRD_PARTY_WHQL / UNTRUSTED)
            //    IAT 扫描失败 (文件不存在等) = 疑似加载后自删除 = 直接查设备
            var (iatOk, iat) = ScanIat(driver.FilePath);
            bool iatScanFailed = !iatOk;
            bool iatEmpty = iatOk && (iat.DllCount == 0 || iat.TotalApiCount == 0);
            bool hasDangerous = iatOk && (iat.DangerousApiCount > 0);
            bool isThirdPartyWhql = (driver.Klass == 2);

            bool shouldAttach = false;
            if (iatScanFailed)
            {
                // IAT 扫描失败 (文件不存在/无法读取) = 疑似加载后自删除 = 直接查设备
                shouldAttach = true;
            }
            else if (iatEmpty)
            {
                // IAT 为空 = 动态 API 解析 = 可疑, 无条件附着 (跳过白名单检查)
                shouldAttach = true;
            }
            else if (isThirdPartyWhql && hasDangerous)
            {
                // THIRD_PARTY_WHQL + 危险函数: 走白名单检查
                if (!IsWhitelisted(driver))
                {
                    shouldAttach = true;
                }
            }

            if (!shouldAttach)
            {
                continue;
            }

            if (iatScanFailed)
            {
                Console.Error.WriteLine(
                    $"[Attach] {driver.FileName}: IAT 扫描失败 (疑似文件不存在/加载后删除), 直接枚举设备...");
            }
            else if (iatEmpty)
            {
                Console.Error.WriteLine(
                    $"[Attach] {driver.FileName}: IAT 为空 (疑似动态解析), 开始枚举设备...");
            }
            else
            {
                Console.Error.WriteLine(
                    $"[Attach] {driver.FileName}: 发现 {iat.DangerousApiCount} 个危险 API, " +
                    $"开始枚举设备...");
            }

            // 5. 投递 IAT 扫描结果到服务端 kernel-comms API (kind="iat") — 仅 IAT 扫描成功时
            if (iatOk)
            {
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
            }

            // 5.1 IAT 异常告警: 扫描失败 或 IAT 为空
            if (iatScanFailed)
            {
                // IAT 扫描失败 (文件不存在/无法读取) = 疑似加载后自删除
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "iat-scan-failed-alert",
                    Level = "HIGH",
                    Source = "DriverAttach",
                    Title = $"IAT 扫描失败 (疑似加载后删除): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
            }
            else if (iatEmpty)
            {
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "iat-empty-alert",
                    Level = "HIGH",
                    Source = "DriverAttach",
                    Title = $"IAT 为空 (疑似动态解析): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                        dllCount = iat.DllCount,
                        totalApiCount = iat.TotalApiCount,
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
            }

            // 6. 枚举设备 — 使用内核驱动对象名 (不带 .sys 后缀, 由 ImageBase 反查)
            //    ca985782 DriverAttachSelector 注释: 不要从文件名砍后缀(会错,如 OpenArkDrv64.sys → OpenArkDrv)
            if (string.IsNullOrEmpty(driver.DriverObjectName))
            {
                // 内核 ImageBase 反查失败, 无法定位 DriverObject
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "driver-object-name-missing",
                    Level = "WARN",
                    Source = "DriverAttach",
                    Title = $"驱动对象名缺失 (内核反查失败): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
                Console.Error.WriteLine(
                    $"[Attach] {driver.FileName}: DriverObjectName 为空 (内核反查失败), 跳过设备枚举");
                continue;
            }

            var devices = EnumDevices(driver.DriverObjectName);
            if (devices == null || devices.Length == 0)
            {
                if (iatScanFailed)
                {
                    // IAT 扫描失败且无设备暴露: 仍然告警
                    _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                    {
                        Kind = "iat-scan-failed-no-device",
                        Level = "WARN",
                        Source = "DriverAttach",
                        Title = $"IAT 扫描失败且无设备暴露: {driver.FileName}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            driverFileName = driver.FileName,
                            filePath = driver.FilePath,
                            klass = driver.Klass,
                            klassName = GetClassName(driver.Klass),
                        }),
                        DriverFileName = driver.FileName,
                        DriverClass = driver.Klass,
                    });
                }
                else if (iatEmpty)
                {
                    // IAT 为空但无设备暴露: 仍然告警
                    _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                    {
                        Kind = "iat-empty-no-device",
                        Level = "WARN",
                        Source = "DriverAttach",
                        Title = $"IAT 为空且无设备暴露: {driver.FileName}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            driverFileName = driver.FileName,
                            filePath = driver.FilePath,
                            klass = driver.Klass,
                            klassName = GetClassName(driver.Klass),
                        }),
                        DriverFileName = driver.FileName,
                        DriverClass = driver.Klass,
                    });
                }
                else
                {
                    Console.Error.WriteLine($"[Attach] {driver.FileName}: 无暴露设备, 跳过");
                }
                continue;
            }

            // 5.1 投递设备枚举结果到服务端 (kind="device")
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

            // 6. 对每个设备附着
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
    /// 对单个新加载的驱动执行扫描+IAT检查+附着。
    /// 在游戏运行期间收到 LoadImage 通知时调用。
    /// 流程与 ScanAndAttach 相同, 但只处理一个驱动:
    ///   1. 调 FetchScanAndClassify 获取所有已加载驱动, 按路径找到目标驱动
    ///   2. 扫描 IAT, 判定 IAT 是否为空 / 是否有危险函数
    ///   3. IAT 为空 → 无条件附着 (跳过白名单)
    ///      THIRD_PARTY_WHQL + 有危险函数 → 走白名单检查
    ///      其他 → 仅记录
    ///   4. 附着成功上报 kind="runtime-attach", 仅记录上报 kind="runtime-driver-loaded"
    /// </summary>
    public void ScanAndAttachSingle(string driverFilePath)
    {
        try
        {
            if (string.IsNullOrEmpty(driverFilePath))
            {
                Console.Error.WriteLine("[Attach] ScanAndAttachSingle: driverFilePath 为空");
                return;
            }

            Console.Error.WriteLine($"[Attach] ═══ 运行时单驱动扫描: {driverFilePath} ═══");

            // 1. 扫描 + 分类, 按路径找到目标驱动 (新驱动刚加载, 应在列表中)
            var classifyEntries = ScanAndClassify();
            if (classifyEntries == null || classifyEntries.Length == 0)
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: 扫描无结果, 无法定位 {driverFilePath}");
                return;
            }

            CbnClassifyEntry? driverFound = null;
            foreach (var entry in classifyEntries)
            {
                if (string.Equals(entry.FilePath, driverFilePath,
                                  StringComparison.OrdinalIgnoreCase))
                {
                    driverFound = entry;
                    break;
                }
            }

            if (driverFound == null)
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: 未在已加载驱动列表中找到 {driverFilePath}");
                return;
            }

            var driver = driverFound.Value;

            // 2. 跳过自家驱动 (KernelService.sys)
            if (driver.FileName.Equals(SelfDriverName, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: 跳过自家驱动 {driver.FileName}");
                return;
            }

            // 3. 跳过 INBOX (Klass==0) 和 MICROSOFT (Klass==1) 驱动 — 可信驱动不扫 IAT
            if (driver.Klass == 0 || driver.Klass == 1)
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: 跳过可信驱动 (Klass={driver.Klass}) {driver.FileName}");
                return;
            }

            // 4. 扫描 IAT 危险函数
            //    IAT 扫描失败 (文件不存在等) = 疑似加载后自删除 = 直接查设备
            var (iatOk, iat) = ScanIat(driver.FilePath);
            bool iatScanFailed = !iatOk;
            bool iatEmpty = iatOk && (iat.DllCount == 0 || iat.TotalApiCount == 0);
            bool hasDangerous = iatOk && (iat.DangerousApiCount > 0);
            bool isThirdPartyWhql = (driver.Klass == 2);

            bool shouldAttach = false;
            if (iatScanFailed)
            {
                // IAT 扫描失败 (文件不存在/无法读取) = 疑似加载后自删除 = 直接查设备
                shouldAttach = true;
            }
            else if (iatEmpty)
            {
                // IAT 为空 = 动态 API 解析 = 可疑, 无条件附着 (跳过白名单检查)
                shouldAttach = true;
            }
            else if (isThirdPartyWhql && hasDangerous)
            {
                // THIRD_PARTY_WHQL + 危险函数: 走白名单检查
                if (!IsWhitelisted(driver))
                {
                    shouldAttach = true;
                }
            }

            // 5. 不需要附着: 仅记录上报 kind="runtime-driver-loaded"
            if (!shouldAttach)
            {
                var driverObj = new
                {
                    fileName = driver.FileName,
                    filePath = driver.FilePath,
                    klass = driver.Klass,
                    klassName = GetClassName(driver.Klass),
                    vendorName = driver.VendorName,
                    iatEmpty,
                    hasDangerous,
                };

                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "runtime-driver-loaded",
                    Level = "INFO",
                    Source = "RuntimeDriverMonitor",
                    Title = $"新驱动加载 (无需附着): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(driverObj),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                    VendorName = driver.VendorName,
                });

                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: {driver.FileName} 无需附着 " +
                    $"(iatEmpty={iatEmpty}, hasDangerous={hasDangerous})");
                return;
            }

            // 5.1 捕获 sys 文件 (新驱动被判定需要监控: IAT 为空/扫描失败/有危险函数)
            //     拷贝 .sys 到 filecopy\ 并触发上传, 失败不阻塞扫描流程
            //     注意: IAT 扫描失败时 iat.DangerousApiCount 为 0, 但仍尝试拷贝 (文件可能存在)
            CaptureDriverSysFile(driver.FilePath, driver.FileName, iatEmpty || iatScanFailed, iatOk ? iat.DangerousApiCount : 0);

            // 6. 需要附着: IAT 报告 + 设备枚举 + 附着
            if (iatScanFailed)
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: {driver.FileName}: IAT 扫描失败 (疑似文件不存在/加载后删除), 直接枚举设备...");
            }
            else if (iatEmpty)
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: {driver.FileName}: IAT 为空 (疑似动态解析), 开始枚举设备...");
            }
            else
            {
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: {driver.FileName}: 发现 {iat.DangerousApiCount} 个危险 API, " +
                    $"开始枚举设备...");
            }

            // 6.1 投递 IAT 扫描结果 (kind="iat", 同 ScanAndAttach) — 仅 IAT 扫描成功时
            if (iatOk)
            {
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
            }

            // 6.2 IAT 异常告警: 扫描失败 或 IAT 为空 (同 ScanAndAttach)
            if (iatScanFailed)
            {
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "iat-scan-failed-alert",
                    Level = "HIGH",
                    Source = "RuntimeDriverMonitor",
                    Title = $"IAT 扫描失败 (疑似加载后删除): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
            }
            else if (iatEmpty)
            {
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "iat-empty-alert",
                    Level = "HIGH",
                    Source = "DriverAttach",
                    Title = $"IAT 为空 (疑似动态解析): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                        dllCount = iat.DllCount,
                        totalApiCount = iat.TotalApiCount,
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
            }

            // 6.3 枚举设备 — 使用内核驱动对象名 (不带 .sys 后缀, 由 ImageBase 反查)
            //    ca985782 DriverAttachSelector 注释: 不要从文件名砍后缀(会错,如 OpenArkDrv64.sys → OpenArkDrv)
            if (string.IsNullOrEmpty(driver.DriverObjectName))
            {
                // 内核 ImageBase 反查失败, 无法定位 DriverObject
                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "driver-object-name-missing",
                    Level = "WARN",
                    Source = "RuntimeDriverMonitor",
                    Title = $"驱动对象名缺失 (内核反查失败): {driver.FileName}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        driverFileName = driver.FileName,
                        filePath = driver.FilePath,
                        klass = driver.Klass,
                        klassName = GetClassName(driver.Klass),
                    }),
                    DriverFileName = driver.FileName,
                    DriverClass = driver.Klass,
                });
                Console.Error.WriteLine(
                    $"[Attach] ScanAndAttachSingle: {driver.FileName}: DriverObjectName 为空 (内核反查失败), 跳过设备枚举");
                return;
            }

            var devices = EnumDevices(driver.DriverObjectName);
            if (devices == null || devices.Length == 0)
            {
                if (iatScanFailed)
                {
                    // IAT 扫描失败且无设备暴露: 仍然告警 (同 ScanAndAttach)
                    _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                    {
                        Kind = "iat-scan-failed-no-device",
                        Level = "WARN",
                        Source = "RuntimeDriverMonitor",
                        Title = $"IAT 扫描失败且无设备暴露: {driver.FileName}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            driverFileName = driver.FileName,
                            filePath = driver.FilePath,
                            klass = driver.Klass,
                            klassName = GetClassName(driver.Klass),
                        }),
                        DriverFileName = driver.FileName,
                        DriverClass = driver.Klass,
                    });
                }
                else if (iatEmpty)
                {
                    // IAT 为空但无设备暴露: 仍然告警 (同 ScanAndAttach)
                    _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                    {
                        Kind = "iat-empty-no-device",
                        Level = "WARN",
                        Source = "DriverAttach",
                        Title = $"IAT 为空且无设备暴露: {driver.FileName}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            driverFileName = driver.FileName,
                            filePath = driver.FilePath,
                            klass = driver.Klass,
                            klassName = GetClassName(driver.Klass),
                        }),
                        DriverFileName = driver.FileName,
                        DriverClass = driver.Klass,
                    });
                }
                else
                {
                    Console.Error.WriteLine(
                        $"[Attach] ScanAndAttachSingle: {driver.FileName}: 无暴露设备, 跳过");
                }
                return;
            }

            // 6.4 投递设备枚举结果 (kind="device", 同 ScanAndAttach)
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

            // 6.5 对每个设备附着, 上报 kind="runtime-attach"
            int attachedCount = 0;
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
                        Kind = "runtime-attach",
                        Level = "HIGH",
                        Source = "RuntimeDriverMonitor",
                        Title = $"运行时附着设备: {device.DeviceName} (driver: {driver.FileName})",
                        DataJson = JsonSerializer.Serialize(attachObj),
                        AttachId = attachResult.AttachId,
                        DeviceName = device.DeviceName,
                        FilterDeviceAddr = attachResult.FilterDeviceAddr,
                    });
                }
                else
                {
                    Console.Error.WriteLine(
                        $"[Attach] ScanAndAttachSingle: 附着失败 {device.DeviceName} (driver: {driver.FileName})");
                }
            }

            Console.Error.WriteLine(
                $"[Attach] ═══ 运行时单驱动扫描完成: {driver.FileName} 附着 {attachedCount} 个设备 ═══");

            // 注意: 不调用 ReportAttachments() — 运行时附着只处理单驱动,
            //       完整附着列表汇总已在启动时由 ScanAndAttach 上报
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Attach] ScanAndAttachSingle 异常: {ex}");
            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "runtime-attach-error",
                Level = "ERR",
                Source = "RuntimeDriverMonitor",
                Title = $"运行时附着异常: {driverFilePath}",
                DataJson = JsonSerializer.Serialize(new
                {
                    driverFilePath,
                    error = ex.Message,
                    errorType = ex.GetType().Name,
                }),
            });
        }
    }

    /// <summary>
    /// 拷贝驱动 sys 文件到 filecopy\ 目录并触发上传。
    /// 在新驱动被判定需要监控时调用 (IAT 为空 或 有危险函数)。
    /// 所有异常被吞掉并记录, 绝不阻塞扫描/附着主流程。
    /// </summary>
    private void CaptureDriverSysFile(string driverFilePath, string driverFileName, bool iatEmpty, int dangerousApiCount)
    {
        try
        {
            if (!File.Exists(driverFilePath))
            {
                Console.Error.WriteLine($"[Attach] sys 拷贝失败: 源文件不存在 {driverFilePath}");
                return;
            }

            // 目标目录: filecopy\ (与 native 端写入位置一致, AppContext.BaseDirectory 即 exe 所在目录)
            string fileCopyDir = Path.Combine(AppContext.BaseDirectory, "filecopy");
            Directory.CreateDirectory(fileCopyDir);

            // 目标文件名: 加时间戳防冲突 (同一驱动可能多次加载)
            string timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            string destFileName = $"{Path.GetFileNameWithoutExtension(driverFileName)}_{timestamp}.sys";
            string destPath = Path.Combine(fileCopyDir, destFileName);

            File.Copy(driverFilePath, destPath, overwrite: true);
            Console.Error.WriteLine($"[Attach] sys 文件已拷贝: {driverFileName} -> {destPath}");

            // 上报 kind="driver-sys-captured" (HIGH, 便于服务端索引被捕获的驱动文件)
            var captureObj = new
            {
                originalPath = driverFilePath,
                capturedPath = destPath,
                fileName = driverFileName,
                fileSize = new FileInfo(destPath).Length,
                iatEmpty = iatEmpty,
                dangerousApiCount = dangerousApiCount,
                timestamp = DateTime.UtcNow,
            };

            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "driver-sys-captured",
                Level = "HIGH",
                Source = "RuntimeDriverMonitor",
                Title = $"驱动 sys 文件已捕获: {driverFileName}",
                DataJson = JsonSerializer.Serialize(captureObj),
                DriverFileName = driverFileName,
            });

            // 触发文件上传 (异步, 不阻塞) — fileType="driver-sys" 便于服务端分类存储
            _ = _server?.UploadFileAsync(destPath, "driver-sys", JsonSerializer.Serialize(new
            {
                originalPath = driverFilePath,
                driverFileName = driverFileName,
                iatEmpty = iatEmpty,
                dangerousApiCount = dangerousApiCount,
            }));
        }
        catch (Exception ex)
        {
            // 拷贝失败 (权限/文件锁/磁盘满) 不阻塞扫描流程, 仅记录
            Console.Error.WriteLine($"[Attach] sys 文件拷贝异常: {driverFileName} - {ex.Message}");
        }
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
    //  H5: 解绑所有附着的设备
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 解绑所有已附着设备 (在 Cleanup 时调用)。
    /// 遍历 _attached 列表, 逐个调 FetchUnattach(attachId) 解绑。
    /// 用 AttachId 而非 DevicePath, 因为 AttachId 是内核分配的唯一标识,
    /// DevicePath 可能在附着后被重命名或失效。
    /// </summary>
    /// <remarks>
    /// H5: 之前 _attached 只记录从不解绑, 游戏退出后设备仍附着。
    /// 仅靠 DriverLoader.UnloadDriver 卸载驱动时内核强制断开, 但若驱动卸载失败
    /// (DriverLoader.UnloadDriver 不检查返回值), 设备会持续附着,
    /// 下次启动时重复附着同一设备导致内核状态混乱。
    /// </remarks>
    public void DetachAll()
    {
        if (_attached.Count == 0) return;
        if (_host.IsDisposed)
        {
            Console.Error.WriteLine("[Attach] NativeHost 已释放, 跳过 DetachAll");
            return;
        }

        Console.Error.WriteLine($"[Attach] ═══ 开始解绑 {_attached.Count} 个附着设备 ═══");
        int detachedOk = 0;
        int detachedFail = 0;

        foreach (var (devicePath, attachId) in _attached.ToList()) // ToList 避免遍历时修改
        {
            try
            {
                // 用 AttachId 解绑 (C++ 端 isNumeric 分支)
                using var result = _host.Service.FetchUnattach(attachId.ToString());
                if (result.Success && result.SingleEntry.Status == 0)
                {
                    detachedOk++;
                    Console.Error.WriteLine($"[Attach] 解绑成功: AttachId={attachId} Path={devicePath}");
                }
                else
                {
                    detachedFail++;
                    Console.Error.WriteLine(
                        $"[Attach] 解绑失败: AttachId={attachId} Path={devicePath} " +
                        $"Status={result.SingleEntry.Status} Error={result.ErrorMessage}");
                }
            }
            catch (Exception ex)
            {
                detachedFail++;
                Console.Error.WriteLine($"[Attach] 解绑异常: AttachId={attachId} Path={devicePath} - {ex.Message}");
            }
        }

        _attached.Clear();
        Console.Error.WriteLine(
            $"[Attach] ═══ 解绑完成: 成功 {detachedOk}, 失败 {detachedFail} ═══");
    }

    public void Dispose()
    {
        DetachAll();
    }

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
