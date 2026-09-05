using MeasuredBootParser.Models;
using System.Text;

namespace MeasuredBootParser.Analyzers
{
    public enum FeatureStatus { Unknown, Enabled, Disabled, NotMeasured }

    public class SecurityFeature
    {
        public string Name { get; set; } = "";
        public FeatureStatus Status { get; set; }
        public string Evidence { get; set; } = "";
        public string? Detail { get; set; }
    }

    /// <summary>
    /// 安全特性判定。
    /// 所有 SIPA 事件 ID 均以 Windows SDK 10.0.22621.0 的 wbcl.h 为权威来源，
    /// 原则：事件 ID 能证明什么，就只让它证明什么；"存在事件"不等于"功能开启"。
    /// </summary>
    public static class SecurityFeatureAnalyzer
    {
        // Well-known GUIDs
        private static readonly Guid EfiGlobalVariableGuid =
            new("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        private static readonly Guid EfiImageSecurityDatabaseGuid =
            new("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

        //  SIPA 事件 ID，来源为 wbcl.h 
        private const uint SIPAEVENT_BOOT_REVOCATION_LIST            = 0x00040002; // PREOSPARAMETER
        private const uint SIPAEVENT_OSKERNELDEBUG                   = 0x00050001;
        private const uint SIPAEVENT_CODEINTEGRITY                   = 0x00050002;
        private const uint SIPAEVENT_TESTSIGNING                     = 0x00050003;
        private const uint SIPAEVENT_HYPERVISOR_LAUNCH_TYPE          = 0x0005000A; // UInt64
        private const uint SIPAEVENT_HYPERVISOR_IOMMU_POLICY         = 0x0005000C; // UInt64
        private const uint SIPAEVENT_DRIVER_LOAD_POLICY              = 0x0005000E; // UInt32
        private const uint SIPAEVENT_SI_POLICY                       = 0x0005000F; // SI_POLICY_PAYLOAD
        private const uint SIPAEVENT_VSM_LAUNCH_TYPE                 = 0x00050012; // UInt64
        private const uint SIPAEVENT_OS_REVOCATION_LIST              = 0x00050013; // REVOCATION_LIST_PAYLOAD
        private const uint SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY       = 0x00050010; // UInt64
        private const uint SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY    = 0x00050011; // UInt64
        private const uint SIPAEVENT_VSM_IDK_INFO                    = 0x00050020; // VSM 身份密钥 IUM
        private const uint SIPAEVENT_VSM_IDKS_INFO                   = 0x00050023; // VSM 身份签名密钥 SMART
        private const uint SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION  = 0x00050030; // Boolean, Win10 VB+
        private const uint SIPAEVENT_ELAM_KEYNAME                    = 0x00090001; // Unicode string
        private const uint SIPAEVENT_ELAM_POLICY                     = 0x00090003;
        private const uint SIPAEVENT_ELAM_MEASURED                   = 0x00090004;
        private const uint SIPAEVENT_VBS_VSM_REQUIRED                = 0x000A0001; // Boolean
        private const uint SIPAEVENT_VBS_IOMMU_REQUIRED              = 0x000A0003; // Boolean
        private const uint SIPAEVENT_VBS_HVCI_POLICY                 = 0x000A0007;
        // DRTM 属 0x000Cxxxx 事件段，检测已移除: 依赖 Intel TXT/vPro，多数消费级 CPU 不支持

        public static List<SecurityFeature> Analyze(TcgEventLog log)
        {
            var results = new List<SecurityFeature>();

            results.Add(AnalyzeSecureBoot(log));
            results.Add(AnalyzeVirtualization(log));
            results.Add(AnalyzeIommu(log));
            results.Add(AnalyzeHvci(log));
            results.Add(AnalyzeDriverSignature(log));
            results.Add(AnalyzeVulnerableDriverBlocklist(log));
            results.Add(AnalyzeElam(log));
            results.Add(AnalyzeBootIntegrity(log));
            // DRTM 即 System Guard Secure Launch，检测已移除: 依赖 Intel TXT / vPro
            // 平台能力，i5-13600K/KF 等大量消费级 CPU 均不支持，检测无意义

            return results;
        }

        // 
        // 1. Secure Boot
        //    核心: PCR7 SecureBoot EFI 变量，事件类型 EV_EFI_VARIABLE_DRIVER_CONFIG
        //    KernelDebug 事件 0x00050001: 必须为 false，ON → 判定不通过
        //    PK/db/dbx 与 BootRevocationList、OSRevocationList 吊销列表作为佐证 Detail
        // 
        private static SecurityFeature AnalyzeSecureBoot(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Secure Boot" };

            var secureBootEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 &&
                (e.EventType == 0x80000001 || e.EventType == 0x800000E0) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableGuid == EfiGlobalVariableGuid &&
                v.VariableName == "SecureBoot");

            if (secureBootEvent == null)
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "SecureBoot variable not found in PCR7";
                return feat;
            }

            TryParseEfiVariable(secureBootEvent.EventData, out var varData);
            bool enabled = varData?.VariableData?.Length > 0 && varData.VariableData[0] == 0x01;

            feat.Status = enabled ? FeatureStatus.Enabled : FeatureStatus.Disabled;
            feat.Evidence = $"Event #{secureBootEvent.Index} (PCR7, EFI_VARIABLE_DRIVER_CONFIG): SecureBoot={(enabled ? 1 : 0)}";

            // PK/KEK 属于 EFI_GLOBAL_VARIABLE；db/dbx 属于 EFI_IMAGE_SECURITY_DATABASE
            var details = new List<string>();
            foreach (var (name, guid) in new[]
            {
                ("PK", EfiGlobalVariableGuid),
                ("KEK", EfiGlobalVariableGuid),
                ("db", EfiImageSecurityDatabaseGuid),
                ("dbx", EfiImageSecurityDatabaseGuid)
            })
            {
                var evt = log.Events.FirstOrDefault(e =>
                    e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                    v!.VariableGuid == guid && v.VariableName == name);
                if (evt != null)
                {
                    TryParseEfiVariable(evt.EventData, out var vd);
                    details.Add($"{name} measured (DataLen={vd?.VariableData?.Length ?? 0})");
                }
            }

            //  Kernel Debugging (wbcl.h 0x00050001 OSKernelDebug, Boolean) 
            // 内核调试开启会削弱启动链安全性 → 必须为 false，否则判定不通过
            var wbcl = WbclParser.ParseAll(log);
            var kdEvent = Find(wbcl, SIPAEVENT_OSKERNELDEBUG);
            bool kernelDebugOn = IsTrue(kdEvent);
            details.Add($"KernelDebug={(kernelDebugOn ? "ON ⚠" : "OFF")}" +
                        (kdEvent != null ? $" [0x00050001, PCR{kdEvent.SourcePcr}]" : ""));
            if (kernelDebugOn)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "OSKernelDebug=ON — 内核调试开启，启动链安全被削弱，Secure Boot 判定不通过";
            }

            // OS 层协同佐证: bootmgfw.efi / winload.efi 的 ImageValidated 引导链模块签名校验
            if (IsBootModuleValidated(wbcl, "bootmgfw.efi"))
                details.Add("bootmgfw.efi ImageValidated=true — 引导管理器签名校验通过");
            if (IsBootModuleValidated(wbcl, "winload.efi"))
                details.Add("winload.efi ImageValidated=true — 内核加载器签名校验通过");

            // 吊销列表: 记录"已被吊销的启动组件/签名证书"的摘要，
            // 与 dbx 同属 Secure Boot / 可信启动链的吊销机制，不属于驱动阻止列表
            var bootRevoc = Find(wbcl, SIPAEVENT_BOOT_REVOCATION_LIST);
            if (bootRevoc != null)
                details.Add($"BootRevocationList measured ({bootRevoc.EventData.Length} bytes) [0x00040002, PCR{bootRevoc.SourcePcr}] — 启动链吊销列表");
            var osRevoc = Find(wbcl, SIPAEVENT_OS_REVOCATION_LIST);
            if (osRevoc != null)
                details.Add($"OSRevocationList measured ({osRevoc.EventData.Length} bytes) [0x00050013, PCR{osRevoc.SourcePcr}] — OS 吊销列表");

            feat.Detail = details.Count > 0 ? string.Join(", ", details) : null;
            return feat;
        }

        // 
        // 2. CPU Virtualization (VT-x / AMD-V)
        //    唯一可靠的直接证据: SIPAEVENT_HYPERVISOR_LAUNCH_TYPE 事件 0x0005000A，UInt64
        //    对应 BCD 的 hypervisorlaunchtype: 1=Auto 即开机加载 Hyper-V，VT-x 被占用,
        //    0=Off。必须为 Auto 即 1 才算通过。
        //    PCR11 启发式已删除: PCR11 是 Windows/BitLocker 测量 PCR，与 VT-x 无必然联系。
        // 
        private static SecurityFeature AnalyzeVirtualization(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "CPU Virtualization (VT-x/AMD-V)" };
            var wbcl = WbclParser.ParseAll(log);

            var launch = Find(wbcl, SIPAEVENT_HYPERVISOR_LAUNCH_TYPE);
            if (launch != null && TryGetUInt64(launch, out ulong launchType))
            {
                if (launchType == 1)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"HypervisorLaunchType=Auto [0x0005000A, PCR{launch.SourcePcr}] — Hyper-V 随系统启动加载";
                    feat.Detail = "Hyper-V 以 Auto 模式运行即代表 CPU 虚拟化扩展 VT-x/AMD-V 已启用并被 Hypervisor 占用";

                    // Hypervisor 核心模块加载证据: BIOS 关闭 VT-x/AMD-V 时 hvix64/hvax64 根本无法启动
                    if (HasLoadedModule(wbcl, "hvix64.exe"))
                        feat.Detail += "\n         已加载并校验 Intel Hypervisor 核心 hvix64.exe — VT-x 必然已启用";
                    if (HasLoadedModule(wbcl, "hvax64.exe"))
                        feat.Detail += "\n         已加载并校验 AMD Hypervisor 核心 hvax64.exe — AMD-V 必然已启用";
                    if (HasLoadedModule(wbcl, "hvloader.dll"))
                        feat.Detail += "\n         已加载 Hypervisor Loader 模块 hvloader.dll";
                    if (HasLoadedModule(wbcl, "mcupdate_GenuineIntel.dll"))
                        feat.Detail += "\n         已加载 Intel 平台微码 mcupdate_GenuineIntel.dll";
                    if (HasLoadedModule(wbcl, "secfw_GenuineIntel.dll"))
                        feat.Detail += "\n         已加载 Intel 安全固件支持 secfw_GenuineIntel.dll";
                    var mmioNx = Find(wbcl, SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY);
                    if (mmioNx != null && TryGetUInt64(mmioNx, out var nx) && nx != 0)
                        feat.Detail += $"\n         HypervisorMMIONXPolicy={nx} [0x00050010] — 虚拟化拦截加固已激活";
                    var msrFilter = Find(wbcl, SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY);
                    if (msrFilter != null && TryGetUInt64(msrFilter, out var msr) && msr != 0)
                        feat.Detail += $"\n         HypervisorMSRFilterPolicy={msr} [0x00050011] — 虚拟化拦截加固已激活";
                }
                else if (launchType == 0)
                {
                    feat.Status = FeatureStatus.Disabled;
                    feat.Evidence = $"HypervisorLaunchType=Off [0x0005000A, PCR{launch.SourcePcr}] — Hyper-V 未随系统加载";
                    feat.Detail = "hypervisorlaunchtype=Off，虚拟化引擎未启用";
                }
                else
                {
                    feat.Status = FeatureStatus.Unknown;
                    feat.Evidence = $"HypervisorLaunchType={launchType} — 异常值 [0x0005000A, PCR{launch.SourcePcr}]";
                    feat.Detail = "预期值: 1=Auto, 0=Off";
                }
                return feat;
            }

            // 辅助: PCR0 EV_EFI_PLATFORM_FIRMWARE_BLOB2 (0x8000000A, wbcl.h) 固件模块名
            // 仅说明固件包含虚拟化相关模块，不能证明"已启用"
            var blob = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 0 && e.EventType == 0x8000000A &&
                ParseFirmwareBlobName(e.EventData) is string name && name.Length > 0 &&
                (name.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("VTD", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("SVM", StringComparison.OrdinalIgnoreCase)));

            if (blob != null)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"Firmware blob '{ParseFirmwareBlobName(blob.EventData)}' measured in PCR0 (Event #{blob.Index})";
                feat.Detail = "固件包含虚拟化相关模块，但未找到 HypervisorLaunchType 测量，启用状态未知";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No HypervisorLaunchType measurement found in WBCL";
            return feat;
        }

        // 
        // 3. IOMMU (VT-d / AMD-Vi)
        //    唯一判定依据: 0x0005000C HypervisorIOMMUPolicy，UInt64，psm1 解析
        //    值语义依据 BCD 与微软"内核 DMA 保护"文档:
        //      0 = Default，自适应: 引导时 Hyper-V/内核自动检测硬件与 ACPI 状态，
        //          支持内核 DMA 保护的平台自动启用，无需配置 → 出厂/常规配置恒为 0
        //      1 = Enable，强制开启
        //      2 = Disable，强制关闭
        //    → 不等于 2 即 IOMMU 开启。
        //    反向健康证明: OEM Kernel DMA Protection 规范要求 IOMMU/DMA 保护被关闭或
        //    降级时固件 MUST 向 PCR[7] 扩展 EV_EFI_ACTION "DMA Protection Disabled"；
        //    该事件不存在 = 未被降级的合法健康度量证明。
        // 
        private static SecurityFeature AnalyzeIommu(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "IOMMU (VT-d/AMD-Vi)" };
            var wbcl = WbclParser.ParseAll(log);

            //  微软 OEM 规范检查: PCR[7] 是否存在 "DMA Protection Disabled" 
            bool dmaProtectionDowngraded = log.Events.Any(e =>
                e.PcrIndex == 7 &&
                e.EventType == 0x80000007 && // EV_EFI_ACTION
                ContainsMagic(e.EventData, "DMA Protection Disabled"u8.ToArray()));
            string dmaHealthNote = dmaProtectionDowngraded
                ? "⚠ PCR[7] 存在 \"DMA Protection Disabled\" 事件 — 引导时 IOMMU/内核 DMA 保护被关闭或降级"
                : "PCR[7] 无 \"DMA Protection Disabled\" 即 EV_EFI_ACTION 事件 — 按微软 OEM 规范，引导阶段 IOMMU/内核 DMA 保护未被关闭或降级";

            //  唯一判定: HypervisorIOMMUPolicy ≠ 2 即开启 
            var policy = Find(wbcl, SIPAEVENT_HYPERVISOR_IOMMU_POLICY);
            if (policy != null && TryGetUInt64(policy, out ulong polVal))
            {
                if (polVal == 2 || dmaProtectionDowngraded)
                {
                    feat.Status = FeatureStatus.Disabled;
                    feat.Evidence = dmaProtectionDowngraded
                        ? "PCR[7] 存在 EV_EFI_ACTION \"DMA Protection Disabled\" — 引导时 IOMMU/内核 DMA 保护被关闭或降级"
                        : $"HypervisorIOMMUPolicy=2 即 Disable 强制关闭 [0x0005000C, PCR{policy.SourcePcr}] — IOMMU 已被禁用";
                    feat.Detail = "微软 OEM Kernel DMA Protection 规范: IOMMU/内核 DMA 保护被关闭或降级时，" +
                                  "固件 MUST 向 PCR[7] 扩展该事件，这会导致 BitLocker TPM 封印失效";
                    return feat;
                }

                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"HypervisorIOMMUPolicy={polVal}，{(polVal == 0 ? "Default/自适应" : polVal == 1 ? "Enable 强制开启" : "非 Disable")} " +
                                $"[0x0005000C, PCR{policy.SourcePcr}] — IOMMU 已启用";
                feat.Detail = (polVal == 0
                        ? "0=Default: 引导时由 Hyper-V 与内核自动检测主板硬件/ACPI 状态，" +
                          "支持内核 DMA 保护的平台自动启用 IOMMU，无需用户配置 " +
                          "(learn.microsoft.com: Kernel DMA Protection for Thunderbolt)"
                        : "Hyper-V IOMMU 策略被显式强制开启")
                    + $"\n         {dmaHealthNote}";

                // 协同佐证: 填实 Default(0) 策略下的推断可信度
                var bootDma = Find(wbcl, SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION);
                if (bootDma != null)
                    feat.Detail += $"\n         Boot DMA Protection={(IsTrue(bootDma) ? "Enabled" : "Disabled")} [0x00050030, PCR{bootDma.SourcePcr}]";
                var vbsIommuReq = Find(wbcl, SIPAEVENT_VBS_IOMMU_REQUIRED);
                if (vbsIommuReq != null && IsTrue(vbsIommuReq))
                    feat.Detail += $"\n         VBSIOMMURequired=true [0x000A0003, PCR{vbsIommuReq.SourcePcr}] — VBS 硬件策略强制要求 IOMMU 处于工作状态";
                return feat;
            }

            //  日志中没有 Policy 事件: 仅在 DMA 保护被降级时判 Disabled，否则 NotMeasured 
            if (dmaProtectionDowngraded)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "PCR[7] 存在 EV_EFI_ACTION \"DMA Protection Disabled\" — 引导时 IOMMU/内核 DMA 保护被关闭或降级";
                feat.Detail = "微软 OEM Kernel DMA Protection 规范: IOMMU/内核 DMA 保护被关闭或降级时，" +
                              "固件 MUST 向 PCR[7] 扩展该事件，这会导致 BitLocker TPM 封印失效";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No HypervisorIOMMUPolicy (0x0005000C) measurement found in WBCL";
            feat.Detail = dmaHealthNote;
            return feat;
        }

        // 
        // 4. HVCI / VBS
        //    证据链，wbcl.h 权威 ID:
        //    Chain 1: 0x0005000A HypervisorLaunchType, UInt64 — Hyper-V 是否启动
        //    Chain 2: 0x000A0001 VBS_VSM_REQUIRED, Boolean / 0x00050012 VSM_LAUNCH_TYPE, UInt64 — VBS 是否激活
        //    Chain 3: 0x000A0007 VBS_HVCI_POLICY — HVCI 策略
        //    Hyper-V 启动 ≠ HVCI 开启，三者分开判定。
        //    已删除虚构的 0x00080001 "HypervisorLaunchType" 与 0x00020008，后者实为 MORBIT_NOT_CANCELABLE，
        //    并删除不存在的 VBS 位掩码解释。
        // 
        private static SecurityFeature AnalyzeHvci(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "HVCI / VBS (Hypervisor Code Integrity)" };
            var wbcl = WbclParser.ParseAll(log);
            var evidences = new List<string>();

            //  Chain 1: Hyper-V 是否启动，必须 Auto=1 
            bool hypervisorRunning = false;
            bool hyperOff = false;   // 明确测到 LaunchType=0 即 Off
            bool launchMissing = true;
            var launch = Find(wbcl, SIPAEVENT_HYPERVISOR_LAUNCH_TYPE);
            if (launch != null && TryGetUInt64(launch, out ulong launchType))
            {
                launchMissing = false;
                hypervisorRunning = launchType == 1;
                hyperOff = launchType == 0;
                string ltDesc = launchType switch
                {
                    1 => "Auto，Hyper-V 随系统加载",
                    0 => "Off",
                    _ => $"异常值 {launchType}"
                };
                evidences.Add($"Chain 1: HypervisorLaunchType={ltDesc} [0x0005000A, PCR{launch.SourcePcr}]");
            }
            else
            {
                evidences.Add("Chain 1: HypervisorLaunchType 未找到");
            }

            //  Chain 2: VBS / VSM 是否激活 
            bool vbsOn = false;
            bool vsmOn = false;
            var vbsVsm = Find(wbcl, SIPAEVENT_VBS_VSM_REQUIRED);
            var vsmLaunch = Find(wbcl, SIPAEVENT_VSM_LAUNCH_TYPE);
            if (vbsVsm != null)
            {
                vbsOn = IsTrue(vbsVsm);
                evidences.Add($"Chain 2: VBSVSMRequired={(vbsOn ? "true" : "false")} [0x000A0001, PCR{vbsVsm.SourcePcr}]");
            }
            if (vsmLaunch != null && TryGetUInt64(vsmLaunch, out ulong vsmType))
            {
                vsmOn = vsmType >= 1;
                vbsOn |= vsmOn;
                evidences.Add($"Chain 2: VSMLaunchType={vsmType}，{(vsmOn ? "VSM 已启动" : "未启动")} [0x00050012, PCR{vsmLaunch.SourcePcr}]");
            }
            if (vbsVsm == null && vsmLaunch == null)
            {
                evidences.Add("Chain 2: VBS/VSM 策略事件未找到");
            }
            // VSMLaunchType>=1 本身就证明 Hypervisor 在运行，因为 VSM 只能在 Hyper-V 之上启动
            if (vsmOn) hypervisorRunning = true;

            //  Chain 3: HVCI 策略 
            bool hvciOn = false;
            var hvciPolicy = Find(wbcl, SIPAEVENT_VBS_HVCI_POLICY);
            if (hvciPolicy != null && TryGetUInt64(hvciPolicy, out ulong hvciVal))
            {
                hvciOn = hvciVal != 0;
                evidences.Add($"Chain 3: VBSHVCIPolicy=0x{hvciVal:X}，{(hvciOn ? "HVCI 已启用" : "HVCI 未启用")} [0x000A0007, PCR{hvciPolicy.SourcePcr}]");
            }
            else
            {
                evidences.Add("Chain 3: VBSHVCIPolicy 事件 0x000A0007 未找到 — 无法确认 HVCI 状态");
            }

            bool hasPcr12 = log.Events.Any(e => e.PcrIndex == 12);
            evidences.Add(hasPcr12
                ? "Chain 4: PCR12 events present，PCR 重放校验见 PCR Banks 部分"
                : "Chain 4: No PCR12 events — 无法核对 WBCL 完整性");

            //  木桶判定: Hyper-V 运行 + VSM 启动 + HVCI 策略激活，三者缺一不可 
            if (hvciOn && vbsOn && hypervisorRunning)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI 已启用 — Hyper-V Active, VSM Running, VBS_HVCI_POLICY Enforced";
                if (HasLoadedModule(wbcl, "securekernel.exe"))
                    feat.Evidence += " — 已加载安全内核 securekernel.exe，Trustlet 环境";
                if (HasLoadedModule(wbcl, "skci.dll"))
                    feat.Evidence += " 与 VSM 隔离环境内的代码完整性校验器 skci.dll";

                // VSM 专用身份密钥，由 PCR12 度量
                var idk = Find(wbcl, SIPAEVENT_VSM_IDK_INFO);
                if (idk != null)
                    evidences.Add($"VSMIDKInfo 已测量 [0x00050020, PCR{idk.SourcePcr}] — VSM/SMART 身份公钥，含公钥指数及 Modulus");
                var idks = Find(wbcl, SIPAEVENT_VSM_IDKS_INFO);
                if (idks != null)
                    evidences.Add($"VSMIDKSInfo 已测量 [0x00050023, PCR{idks.SourcePcr}] — VSM/IUM 身份签名公钥");
            }
            else if (hyperOff)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "Hyper-V 未随系统加载，HypervisorLaunchType=Off，HVCI 无法工作";
            }
            else if (launchMissing)
            {
                feat.Status = vbsOn ? FeatureStatus.Unknown : FeatureStatus.NotMeasured;
                feat.Evidence = vbsOn
                    ? "VBS/VSM 已激活但未找到 HypervisorLaunchType 测量，无法闭环确认 HVCI"
                    : "No HVCI/VBS markers found in WBCL";
            }
            else if (!vbsOn)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "VSM / VBS 未启动，HVCI 隔离环境不可用";
            }
            else if (hvciPolicy != null)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "VBS 已激活但 VBS_HVCI_POLICY=0 — HVCI 未启用";
            }
            else
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "VBS 已激活但未发现 HVCI 策略事件";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // 
        // 5. Driver Signature Enforcement
        //    a) 0x00050003 TestSigning, Boolean: 1=测试签名开启 → 强制被削弱
        //    b) 0x00050002 CodeIntegrity, Boolean: 1=启用, 0=禁用
        //    c) 0x0005000E DriverLoadPolicy: 必须 <=1，>1 视为强制被削弱
        //    修复: 之前的顺序覆盖 bug，即后一个证据会覆盖前一个 verdict。
        //    规则: CodeIntegrity=0 → Disabled；TestSigning=1 → 削弱为 Disabled；
        //          DriverLoadPolicy>1 → 削弱为 Disabled；
        //          否则 CodeIntegrity=1 → Enabled。
        // 
        private static SecurityFeature AnalyzeDriverSignature(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Driver Signature Enforcement (Code Integrity)" };
            var wbcl = WbclParser.ParseAll(log);
            var evidences = new List<string>();

            bool? ciEnabled = null;
            bool? testSigning = null;
            uint? driverLoadPolicy = null;

            var ciEvent = Find(wbcl, SIPAEVENT_CODEINTEGRITY);
            if (ciEvent != null && ciEvent.EventData.Length > 0)
            {
                ciEnabled = ciEvent.EventData[0] != 0;
                evidences.Add($"CodeIntegrity={(ciEnabled.Value ? "enabled" : "disabled ⚠")} [0x00050002, PCR{ciEvent.SourcePcr}]");
            }

            var tsEvent = Find(wbcl, SIPAEVENT_TESTSIGNING);
            if (tsEvent != null && tsEvent.EventData.Length > 0)
            {
                testSigning = tsEvent.EventData[0] != 0;
                evidences.Add($"TestSigning={(testSigning.Value ? "ON ⚠" : "OFF")} [0x00050003, PCR{tsEvent.SourcePcr}]");
            }

            //  Driver Load Policy: 必须 <=1，否则强制被削弱 
            var driverPolicyEvent = Find(wbcl, SIPAEVENT_DRIVER_LOAD_POLICY);
            if (driverPolicyEvent != null && TryGetUInt32(driverPolicyEvent, out uint dlpVal))
            {
                driverLoadPolicy = dlpVal;
                evidences.Add($"DriverLoadPolicy={dlpVal} [0x0005000E, PCR{driverPolicyEvent.SourcePcr}]" +
                              (dlpVal > 1 ? " ⚠ >1，签名强制被削弱" : ""));
            }

            //  内核代码签名校验核心 CI.dll 
            if (HasLoadedModule(wbcl, "CI.dll"))
                evidences.Add("已加载内核代码签名校验核心 \\Windows\\system32\\CI.dll");

            //  引导期镜像签名校验汇总，含卡巴斯基 cm_km.sys/klelam.sys 等第三方驱动 
            var validated = wbcl.Where(e => e.EventId == 0x0007000A).ToList();
            if (validated.Count > 0)
            {
                int ok = validated.Count(e => e.EventData.Length > 0 && e.EventData[0] != 0);
                evidences.Add(ok == validated.Count
                    ? $"引导期镜像签名校验: {ok}/{validated.Count} 全部 ImageValidated=true，含第三方驱动，均附带合规签名主体"
                    : $"⚠ 引导期镜像签名校验: 仅 {ok}/{validated.Count} ImageValidated=true，存在未通过校验的镜像");
            }

            //  判定，不受证据顺序影响 
            if (ciEnabled == false)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "CodeIntegrity=disabled — 内核代码完整性检查已关闭";
            }
            else if (testSigning == true)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "TestSigning=ON — 测试签名削弱了驱动签名强制";
            }
            else if (driverLoadPolicy > 1)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = $"DriverLoadPolicy={driverLoadPolicy} > 1 — 驱动加载策略异常，签名强制被削弱";
            }
            else if (ciEnabled == true)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Driver signature enforcement is active (CodeIntegrity=enabled" +
                                (testSigning == false ? ", TestSigning=OFF" : "") +
                                (driverLoadPolicy <= 1 ? $", DriverLoadPolicy={driverLoadPolicy}" : "") + ")";
            }
            else if (evidences.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "WBCL tags found but enforcement status unclear";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No driver signing / code integrity tags found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // 
        // 6. Vulnerable Driver Blocklist
        //    核心证据依据 wbcl.h: 0x0005000F SIPAEVENT_SI_POLICY — System Integrity Policy。
        //    注意: PCR13 通常有多条 SI Policy——第一条往往是系统内置 WDAC 基础策略
        //    即 {GUID}.CIP，易受攻击驱动阻止列表是名为 DriverSiPolicy.p7b 的独立策略。
        //    必须按 PolicyName 匹配 "driversipolicy"，否则 FirstOrDefault 会命中
        //    基础 CIP 策略造成假阳性，阻止列表关闭时仍判 Enabled。
        //    不参与判定: FlightSigning 不查；Boot/OSRevocationList 归 Secure Boot；
        //    DriverLoadPolicy 归驱动签名判定。
        // 
        private static SecurityFeature AnalyzeVulnerableDriverBlocklist(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };
            var wbcl = WbclParser.ParseAll(log);

            // 遍历所有 SI_POLICY 事件，按 PolicyName 定位 DriverSiPolicy.p7b
            var siPolicies = wbcl.Where(e => e.EventId == SIPAEVENT_SI_POLICY).ToList();
            var blocklistPolicy = siPolicies.FirstOrDefault(p =>
                ParseSiPolicyName(p.EventData).Contains("driversipolicy", StringComparison.OrdinalIgnoreCase));

            if (blocklistPolicy != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"DriverSiPolicy.p7b measured [0x0005000F, PCR{blocklistPolicy.SourcePcr}] — 易受攻击驱动阻止列表已载入并测量";
                feat.Detail = DescribeSiPolicy(blocklistPolicy.EventData);

                // 佐证: OS 吊销列表的 SHA-256 摘要度量，说明被吊销组件黑名单完好
                var osRevoc = Find(wbcl, SIPAEVENT_OS_REVOCATION_LIST);
                if (osRevoc != null)
                    feat.Detail += $"\n         OSRevocationList 已测量 ({osRevoc.EventData.Length} bytes) [0x00050013, PCR{osRevoc.SourcePcr}] — 吊销列表有效 SHA-256 摘要度量";
                return feat;
            }

            // 存在其他 SI 策略但缺少 DriverSiPolicy → 阻止列表未开启
            if (siPolicies.Count > 0)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "检测到系统代码完整性策略，但未测量到 DriverSiPolicy.p7b，易受攻击驱动阻止列表未开启";
                feat.Detail = string.Join("\n         ", siPolicies.Select(p => DescribeSiPolicy(p.EventData)));
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No SI Policy (0x0005000F) measurement found in WBCL";
            feat.Detail = "SIPAEVENT_SI_POLICY 未出现 → 阻止列表策略未被测量，可能未启用或该日志不含此项";
            return feat;
        }

        // 
        // 7. Boot Log Integrity (PCR Replay)
        //    注意: 分隔符 + WBCL 终止符只能证明"日志结构完整"，
        //    不能替代 PCR 重放校验，后者在 PCR Banks 部分单独完成。
        // 
        private static SecurityFeature AnalyzeBootIntegrity(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Boot Log Integrity (PCR Replay)" };

            int separatorCount = log.Events.Count(e => e.EventType == 0x00000004);
            bool hasSeparators = separatorCount >= 7;

            bool hasWbclTerminator = log.Events.Any(e =>
                e.EventType == 0x00000004 &&
                e.PcrIndex is 12 or 13 or 14 &&
                e.EventData.Length == 4 &&
                System.Text.Encoding.ASCII.GetString(e.EventData) == "WBCL");

            if (hasSeparators && hasWbclTerminator)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Boot log structure complete ({separatorCount} phase separators, WBCL terminator found)";
                feat.Detail = "日志结构良好；注意：这是结构完整性检查，PCR 重放一致性请以 PCR Banks 部分的校验结果为准";
            }
            else if (hasSeparators)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Phase separators present ({separatorCount}), WBCL terminator absent";
                feat.Detail = "UEFI 启动阶段分隔正常；WBCL 终止符缺失，可能为 Linux/非 Windows 日志";
            }
            else
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"Only {separatorCount} separator events found";
                feat.Detail = "日志结构不完整，无法判断启动序列是否正常";
            }

            return feat;
        }

        // 
        // 8. ELAM (Early Launch Anti-Malware)
        //    SIPA ID (wbcl.h): 0x00090001=ELAM_KEYNAME (Unicode),
        //    0x00090003=ELAM_POLICY, 0x00090004=ELAM_MEASURED。
        //    ELAM_KEYNAME 记录的是 ELAM 厂商注册表键名 → 本次启动有 ELAM 驱动注册。
        // 
        private static SecurityFeature AnalyzeElam(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Early Launch Anti-Malware (ELAM)" };
            var wbcl = WbclParser.ParseAll(log);

            var keyname = Find(wbcl, SIPAEVENT_ELAM_KEYNAME);
            if (keyname != null)
            {
                string name = keyname.InterpretedValue ?? "present";
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"ELAM vendor key measured: '{name}' [0x00090001, PCR{keyname.SourcePcr}]";
                feat.Detail = "本次启动有 ELAM 反恶意软件驱动注册，其注册表键已被测量";
                return feat;
            }

            var policy = Find(wbcl, SIPAEVENT_ELAM_POLICY);
            if (policy != null && policy.EventData.Length > 0)
            {
                uint val = TryGetUInt32(policy, out var v) ? v : policy.EventData[0];
                if (val == 0)
                {
                    feat.Status = FeatureStatus.Disabled;
                    feat.Evidence = $"ELAMPolicy=0 (Disabled) [0x00090003, PCR{policy.SourcePcr}]";
                }
                else
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"ELAMPolicy={val} ({(val == 1 ? "Auto" : "Force")}) [0x00090003, PCR{policy.SourcePcr}]";
                }
                feat.Detail = "ELAM 策略已被测量。策略存在不等于厂商驱动已加载，但策略非零表示 ELAM 已配置";
                return feat;
            }

            var measured = Find(wbcl, SIPAEVENT_ELAM_MEASURED);
            if (measured != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"ELAM driver measurement present [0x00090004, PCR{measured.SourcePcr}]";
                return feat;
            }

            // ELAM 聚合容器，事件 0x40010002 SIPAEVENT_ELAM_AGGREGATION: 存在即 ELAM 相关测量已记录
            var agg = wbcl.Where(e => e.EventId == 0x40010002).ToList();
            if (agg.Count > 0)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "ELAMAggregation present";
                feat.Detail = $"[0x40010002, PCR{agg[0].SourcePcr}, {agg.Count} event(s)] — ELAM 聚合容器";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No ELAM SIPA events found in WBCL";
            feat.Detail = "本次启动未记录 ELAM 驱动测量 → 可能未安装 ELAM 驱动";
            return feat;
        }

        // 
        // Helpers
        // 
        private static WbclTaggedEvent? Find(List<WbclTaggedEvent> events, uint id) =>
            events.FirstOrDefault(e => e.EventId == id);

        private static bool IsTrue(WbclTaggedEvent? e) =>
            e != null && e.EventData.Length > 0 && e.EventData[0] != 0;

        /// <summary>
        /// 检查 LoadedModule 聚合中是否加载了指定模块，
        /// 依据 SIPAEVENT_FILEPATH 0x00070001，其 InterpretedValue 为 Unicode 路径。
        /// </summary>
        private static bool HasLoadedModule(List<WbclTaggedEvent> wbcl, string moduleName) =>
            wbcl.Any(e => e.EventId == 0x00070001 &&
                          (e.InterpretedValue ?? "").Contains(moduleName, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// 检查引导链模块是否签名校验通过: 找到模块的 SIPAEVENT_FILEPATH 事件 0x00070001 后，
        /// 在同一 LoadedImage 子事件序列内最多 12 条范围中查找 SIPAEVENT_IMAGEVALIDATED 事件 0x0007000A。
        /// </summary>
        private static bool IsBootModuleValidated(List<WbclTaggedEvent> wbcl, string moduleName)
        {
            for (int i = 0; i < wbcl.Count; i++)
            {
                var fp = wbcl[i];
                if (fp.EventId != 0x00070001) continue;
                if (!(fp.InterpretedValue ?? "").Contains(moduleName, StringComparison.OrdinalIgnoreCase)) continue;
                for (int j = i + 1; j < Math.Min(wbcl.Count, i + 12); j++)
                {
                    // 遇到下一个模块的路径标签 → 当前模块的属性区间已结束，终止探测
                    // 以防止模块 A 缺 ImageValidated 时误读模块 B 的校验状态
                    if (wbcl[j].EventId == 0x00070001) break;

                    if (wbcl[j].EventId == 0x0007000A)
                        return wbcl[j].EventData.Length > 0 && wbcl[j].EventData[0] != 0;
                }
            }
            return false;
        }

        private static bool TryGetUInt64(WbclTaggedEvent e, out ulong value)
        {
            value = 0;
            if (e.EventData.Length >= 8) { value = BitConverter.ToUInt64(e.EventData, 0); return true; }
            if (e.EventData.Length >= 4) { value = BitConverter.ToUInt32(e.EventData, 0); return true; }
            if (e.EventData.Length >= 1) { value = e.EventData[0]; return true; }
            return false;
        }

        private static bool TryGetUInt32(WbclTaggedEvent e, out uint value)
        {
            value = 0;
            if (e.EventData.Length >= 4) { value = BitConverter.ToUInt32(e.EventData, 0); return true; }
            if (e.EventData.Length >= 1) { value = e.EventData[0]; return true; }
            return false;
        }

        /// <summary>
        /// 从 SI_POLICY payload 中提取 PolicyName，即 UTF-16 字符串。
        /// 用于区分基础 WDAC CIP 策略 {GUID}.CIP 与驱动阻止列表 DriverSiPolicy.p7b。
        /// </summary>
        private static string ParseSiPolicyName(byte[] d)
        {
            if (d.Length < 0x10) return "";
            ushort nameLen = BitConverter.ToUInt16(d, 8);
            int offset = 0x10;
            if (nameLen > 0 && offset + nameLen <= d.Length)
                return Encoding.Unicode.GetString(d, offset, nameLen).TrimEnd('\0');
            return "";
        }

        /// <summary>
        /// 解析 SIPAEVENT_SI_POLICY_PAYLOAD，定义见 wbcl.h:
        /// ULONGLONG PolicyVersion; UINT16 PolicyNameLength; UINT16 HashAlgID;
        /// UINT32 DigestLength; VarLengthData = WCHAR PolicyName[] + BYTE Digest[]。
        /// </summary>
        private static string DescribeSiPolicy(byte[] d)
        {
            if (d.Length < 0x10) return $"raw payload ({d.Length} bytes)";

            ulong ver = BitConverter.ToUInt64(d, 0);
            ushort nameLen = BitConverter.ToUInt16(d, 8);
            ushort algId = BitConverter.ToUInt16(d, 0x0A);
            uint digLen = BitConverter.ToUInt32(d, 0x0C);

            // PolicyVersion 布局与 TCGLogTools.psm1 一致: 4×Int16 = Revision, Build, Minor, Major
            short revision = (short)(ver & 0xFFFF);
            short build = (short)((ver >> 16) & 0xFFFF);
            short minor = (short)((ver >> 32) & 0xFFFF);
            short major = (short)((ver >> 48) & 0xFFFF);

            var parts = new List<string> { $"PolicyVersion={major}.{minor}.{build}.{revision}" };

            int offset = 0x10;
            if (nameLen > 0 && offset + nameLen <= d.Length)
            {
                string name = Encoding.Unicode.GetString(d, offset, nameLen).TrimEnd('\0');
                if (name.Length > 0) parts.Add($"PolicyName='{name}'");
            }
            offset += nameLen;

            parts.Add($"HashAlgID=0x{algId:X4}");

            if (digLen > 0 && digLen <= 64 && offset + digLen <= d.Length)
                parts.Add($"Digest={Convert.ToHexString(d, offset, (int)digLen)}");

            return string.Join(", ", parts);
        }

        private static bool TryParseEfiVariable(byte[] data, out EfiVariableData? result)
        {
            result = null;
            if (data == null || data.Length < 28) return false;
            try
            {
                var guid = new Guid(
                    BitConverter.ToUInt32(data, 0),
                    BitConverter.ToUInt16(data, 4),
                    BitConverter.ToUInt16(data, 6),
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15]);
                ulong nameLen = BitConverter.ToUInt64(data, 16);
                ulong dataLen = BitConverter.ToUInt64(data, 24);
                int nameOffset = 32;
                int nameBytes = (int)nameLen * 2;
                if (nameOffset + nameBytes > data.Length) return false;
                string name = Encoding.Unicode.GetString(data, nameOffset, nameBytes).TrimEnd('\0');
                int dataOffset = nameOffset + nameBytes;
                int dataBytes = (int)Math.Min(dataLen, (ulong)(data.Length - dataOffset));
                byte[] varData = dataBytes > 0 ? data[dataOffset..(dataOffset + dataBytes)] : [];

                result = new EfiVariableData
                {
                    VariableGuid = guid,
                    VariableName = name,
                    VariableData = varData
                };
                return true;
            }
            catch { return false; }
        }

        private static string ParseFirmwareBlobName(byte[] data)
        {
            // EV_EFI_PLATFORM_FIRMWARE_BLOB2 (0x8000000A, wbcl.h):
            // UINT8 BlobDescriptionSize, BlobDescription (UTF-8), UINT64 Base, UINT64 Length
            if (data == null || data.Length < 2) return "";
            int nameLen = data[0];
            if (nameLen == 0 || nameLen + 1 > data.Length) return "";
            return Encoding.UTF8.GetString(data, 1, nameLen).TrimEnd('\0');
        }

        private static bool ContainsMagic(byte[] data, byte[] magic)
        {
            if (data == null || data.Length < magic.Length) return false;
            for (int i = 0; i <= data.Length - magic.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < magic.Length; j++)
                    if (data[i + j] != magic[j]) { match = false; break; }
                if (match) return true;
            }
            return false;
        }
    }
}
