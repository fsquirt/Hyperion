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
    /// 所有 SIPA 事件 ID 均以 Windows SDK wbcl.h (10.0.22621.0) 为权威来源，
    /// 原则：事件 ID 能证明什么，就只让它证明什么；"存在事件"不等于"功能开启"。
    /// </summary>
    public static class SecurityFeatureAnalyzer
    {
        // Well-known GUIDs
        private static readonly Guid EfiGlobalVariableGuid =
            new("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        private static readonly Guid EfiImageSecurityDatabaseGuid =
            new("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

        // ── SIPA 事件 ID（来源: wbcl.h）──
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
        private const uint SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION  = 0x00050030; // Boolean, Win10 VB+
        private const uint SIPAEVENT_ELAM_KEYNAME                    = 0x00090001; // Unicode string
        private const uint SIPAEVENT_ELAM_POLICY                     = 0x00090003;
        private const uint SIPAEVENT_ELAM_MEASURED                   = 0x00090004;
        private const uint SIPAEVENT_VBS_VSM_REQUIRED                = 0x000A0001; // Boolean
        private const uint SIPAEVENT_VBS_IOMMU_REQUIRED              = 0x000A0003; // Boolean
        private const uint SIPAEVENT_VBS_HVCI_POLICY                 = 0x000A0007;
        private const uint SIPAEVENT_DRTM_STATE_AUTH                 = 0x000C0001; // PCR20, TcbLaunch.exe, RS5+
        private const uint SIPAEVENT_DRTM_SMM_LEVEL                  = 0x000C0002; // 1 byte, PCR20
        private const uint SIPAEVENT_DRTM_AMD_SMM_HASH               = 0x000C0003; // PCR19

        public static List<SecurityFeature> Analyze(TcgEventLog log)
        {
            var results = new List<SecurityFeature>();

            results.Add(AnalyzeSecureBoot(log));
            results.Add(AnalyzeVirtualization(log));
            results.Add(AnalyzeIommu(log));
            results.Add(AnalyzeHvci(log));
            results.Add(AnalyzeDriverSignature(log));
            results.Add(AnalyzeVulnerableDriverBlocklist(log));
            results.Add(AnalyzeBootIntegrity(log));
            results.Add(AnalyzeElam(log));
            results.Add(AnalyzeDrtm(log));

            return results;
        }

        // ────────────────────────────────────────────────
        // 1. Secure Boot
        //    核心: PCR7 SecureBoot EFI 变量 (EV_EFI_VARIABLE_DRIVER_CONFIG)
        //    KernelDebug (0x00050001): 必须为 false，ON → 判定不通过
        //    PK/db/dbx 与吊销列表 (BootRevocationList/OSRevocationList) 作为佐证 Detail
        // ────────────────────────────────────────────────
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

            // ── Kernel Debugging (wbcl.h 0x00050001 OSKernelDebug, Boolean) ──
            // 内核调试开启会削弱启动链安全性 → 必须为 false，否则判定不通过
            var wbcl = WbclParser.ParseAll(log);
            var kdEvent = Find(wbcl, SIPAEVENT_OSKERNELDEBUG);
            bool kernelDebugOn = IsTrue(kdEvent);
            details.Add($"KernelDebug={(kernelDebugOn ? "ON ⚠" : "OFF")}" +
                        (kdEvent != null ? $" [0x00050001, PCR{kdEvent.SourcePcr}]" : ""));
            if (kernelDebugOn)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "OSKernelDebug=ON — 内核调试开启，启动链安全被削弱（Secure Boot 判定不通过）";
            }

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

        // ────────────────────────────────────────────────
        // 2. CPU Virtualization (VT-x / AMD-V)
        //    唯一可靠的直接证据: SIPAEVENT_HYPERVISOR_LAUNCH_TYPE (0x0005000A, UInt64)
        //    对应 BCD 的 hypervisorlaunchtype: 1=Auto (开机加载 Hyper-V，VT-x 被占用),
        //    0=Off。必须为 Auto(1) 才算通过。
        //    PCR11 启发式已删除: PCR11 是 Windows/BitLocker 测量 PCR，与 VT-x 无必然联系。
        // ────────────────────────────────────────────────
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
                    feat.Detail = "Hyper-V (Auto) 运行即代表 CPU 虚拟化扩展 (VT-x/AMD-V) 已启用并被 Hypervisor 占用";
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
                    feat.Evidence = $"HypervisorLaunchType={launchType} (异常值) [0x0005000A, PCR{launch.SourcePcr}]";
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

        // ────────────────────────────────────────────────
        // 3. IOMMU (VT-d / AMD-Vi)
        //    权威证据 (wbcl.h):
        //    a) 0x0005000C HypervisorIOMMUPolicy (UInt64): 0=未启用/default, 1=启用, 2=启用(NoForceSnoop)
        //    b) 0x00050030 HypervisorBootDMAProtection (Boolean, Win10 VB+)
        //    c) 0x000A0003 VBSIOMMURequired (Boolean) — 仅表示 VBS 策略"要求" IOMMU，
        //       不等于 IOMMU 实际已启用，只能作为 Unknown 级别的佐证
        //    已删除: 0x00050010 (MMIO NX policy) / 0x00050011 (MSR filter policy) 误判，
        //            以及不存在的 "Win11 V2 Event Aggregation" 叙事 (0x40010001 是 TrustBoundary 容器)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeIommu(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "IOMMU (VT-d/AMD-Vi)" };
            var wbcl = WbclParser.ParseAll(log);
            var aux = new List<string>();

            // ── 核心证据 1: HypervisorIOMMUPolicy ──
            var policy = Find(wbcl, SIPAEVENT_HYPERVISOR_IOMMU_POLICY);
            if (policy != null && TryGetUInt64(policy, out ulong polVal))
            {
                switch (polVal)
                {
                    case 1:
                        feat.Status = FeatureStatus.Enabled;
                        feat.Evidence = $"HypervisorIOMMUPolicy=1 (IOMMU enabled) [0x0005000C, PCR{policy.SourcePcr}]";
                        feat.Detail = "Hyper-V IOMMU 策略已开启，内核 DMA 保护依赖此设置";
                        return feat;
                    case 2:
                        feat.Status = FeatureStatus.Enabled;
                        feat.Evidence = $"HypervisorIOMMUPolicy=2 (IOMMU enabled, NoForceSnoop) [0x0005000C, PCR{policy.SourcePcr}]";
                        feat.Detail = "Hyper-V IOMMU 策略已开启（带 NoForceSnoop 兼容模式）";
                        return feat;
                    default:
                        aux.Add($"HypervisorIOMMUPolicy={polVal} [0x0005000C, PCR{policy.SourcePcr}] — IOMMU 未启用");
                        break;
                }
            }

            // ── 核心证据 2: HypervisorBootDMAProtection (Boolean) ──
            var bootDma = Find(wbcl, SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION);
            if (bootDma != null)
            {
                if (IsTrue(bootDma))
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"HypervisorBootDMAProtection=true [0x00050030, PCR{bootDma.SourcePcr}]";
                    feat.Detail = "Windows 启动 DMA 保护已开启（依赖 IOMMU）";
                    if (aux.Count > 0) feat.Detail += "\n         " + string.Join("\n         ", aux);
                    return feat;
                }
                aux.Add($"HypervisorBootDMAProtection=false [0x00050030, PCR{bootDma.SourcePcr}] — 启动 DMA 保护未开启");
            }

            // ── 佐证: VBSIOMMURequired — "要求"而非"实际启用" ──
            var vbsIommu = Find(wbcl, SIPAEVENT_VBS_IOMMU_REQUIRED);
            if (vbsIommu != null)
            {
                aux.Add($"VBSIOMMURequired={(IsTrue(vbsIommu) ? "true" : "false")} [0x000A0003, PCR{vbsIommu.SourcePcr}] — VBS 策略要求{(IsTrue(vbsIommu) ? "" : "不要求")} IOMMU（要求≠实际启用）");
            }

            // ── 固件级佐证: DMAR (Intel VT-d) / IVRS (AMD-Vi) ACPI 表 ──
            var handoffEvents = log.Events.Where(e =>
                e.PcrIndex == 1 && e.EventType == 0x8000000B).ToList();
            foreach (var hEvent in handoffEvents)
            {
                if (ContainsMagic(hEvent.EventData, "DMAR"u8.ToArray()))
                {
                    aux.Add($"DMAR ACPI table measured in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index}) — IOMMU 硬件存在");
                    break;
                }
                if (ContainsMagic(hEvent.EventData, "IVRS"u8.ToArray()))
                {
                    aux.Add($"IVRS ACPI table measured in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index}) — AMD-Vi 硬件存在");
                    break;
                }
            }

            if (aux.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "存在 IOMMU 相关佐证，但未发现 HypervisorIOMMUPolicy/BootDMAProtection 明确开启的证据";
                feat.Detail = string.Join("\n         ", aux);
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No IOMMU/DMA protection SIPA events found in WBCL";
            feat.Detail = "IOMMU 可能未启用，或本日志缺少相关测量";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 4. HVCI / VBS
        //    证据链（wbcl.h 权威 ID）:
        //    Chain 1: 0x0005000A HypervisorLaunchType (UInt64) — Hyper-V 是否启动
        //    Chain 2: 0x000A0001 VBS_VSM_REQUIRED (Boolean) / 0x00050012 VSM_LAUNCH_TYPE (UInt64) — VBS 是否激活
        //    Chain 3: 0x000A0007 VBS_HVCI_POLICY — HVCI 策略
        //    Hyper-V 启动 ≠ HVCI 开启，三者分开判定。
        //    已删除虚构的 0x00080001 "HypervisorLaunchType"、0x00020008 (实为 MORBIT_NOT_CANCELABLE)
        //    以及不存在的 VBS 位掩码解释。
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeHvci(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "HVCI / VBS (Hypervisor Code Integrity)" };
            var wbcl = WbclParser.ParseAll(log);
            var evidences = new List<string>();

            // ── Chain 1: Hyper-V 是否启动（必须 Auto=1）──
            bool hypervisorRunning = false;
            var launch = Find(wbcl, SIPAEVENT_HYPERVISOR_LAUNCH_TYPE);
            if (launch != null && TryGetUInt64(launch, out ulong launchType))
            {
                hypervisorRunning = launchType == 1;
                string ltDesc = launchType switch
                {
                    1 => "Auto (Hyper-V 随系统加载)",
                    0 => "Off",
                    _ => $"异常值 {launchType}"
                };
                evidences.Add($"Chain 1: HypervisorLaunchType={ltDesc} [0x0005000A, PCR{launch.SourcePcr}]");
            }
            else
            {
                evidences.Add("Chain 1: HypervisorLaunchType 未找到");
            }

            // ── Chain 2: VBS / VSM 是否激活 ──
            bool vbsOn = false;
            var vbsVsm = Find(wbcl, SIPAEVENT_VBS_VSM_REQUIRED);
            var vsmLaunch = Find(wbcl, SIPAEVENT_VSM_LAUNCH_TYPE);
            if (vbsVsm != null)
            {
                vbsOn = IsTrue(vbsVsm);
                evidences.Add($"Chain 2: VBSVSMRequired={(vbsOn ? "true" : "false")} [0x000A0001, PCR{vbsVsm.SourcePcr}]");
            }
            if (vsmLaunch != null && TryGetUInt64(vsmLaunch, out ulong vsmType))
            {
                bool vsmOn = vsmType >= 1;
                vbsOn |= vsmOn;
                evidences.Add($"Chain 2: VSMLaunchType={vsmType} ({(vsmOn ? "VSM 已启动" : "未启动")}) [0x00050012, PCR{vsmLaunch.SourcePcr}]");
            }
            if (vbsVsm == null && vsmLaunch == null)
            {
                evidences.Add("Chain 2: VBS/VSM 策略事件未找到");
            }

            // ── Chain 3: HVCI 策略 ──
            bool hvciOn = false;
            var hvciPolicy = Find(wbcl, SIPAEVENT_VBS_HVCI_POLICY);
            if (hvciPolicy != null && TryGetUInt64(hvciPolicy, out ulong hvciVal))
            {
                hvciOn = hvciVal != 0;
                evidences.Add($"Chain 3: VBSHVCIPolicy=0x{hvciVal:X} ({(hvciOn ? "HVCI 已启用" : "HVCI 未启用")}) [0x000A0007, PCR{hvciPolicy.SourcePcr}]");
            }
            else
            {
                evidences.Add("Chain 3: VBSHVCIPolicy (0x000A0007) 未找到 — 无法确认 HVCI 状态");
            }

            bool hasPcr12 = log.Events.Any(e => e.PcrIndex == 12);
            evidences.Add(hasPcr12
                ? "Chain 4: PCR12 events present（PCR 重放校验见 PCR Banks 部分）"
                : "Chain 4: No PCR12 events — 无法核对 WBCL 完整性");

            // ── 判定: Hyper-V 启动不能证明 HVCI 开启 ──
            if (hvciOn)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI 已启用 (VBS_HVCI_POLICY 非零)";
            }
            else if (vbsOn)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "VBS/VSM 已激活，但未发现 HVCI 策略证据（HVCI 可能未开启）";
            }
            else if (hypervisorRunning)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "Hyper-V 已启动，但未发现 VBS/HVCI 策略事件";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No HVCI/VBS markers found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 5. Driver Signature Enforcement
        //    a) 0x00050003 TestSigning (Boolean): 1=测试签名开启 → 强制被削弱
        //    b) 0x00050002 CodeIntegrity (Boolean): 1=启用, 0=禁用
        //    c) 0x0005000E DriverLoadPolicy: 必须 <=1（>1 视为强制被削弱）
        //    修复: 之前的顺序覆盖 bug（后一个证据会覆盖前一个 verdict）。
        //    规则: CodeIntegrity=0 → Disabled；TestSigning=1 → 削弱(Disabled)；
        //          DriverLoadPolicy>1 → 削弱(Disabled)；
        //          否则 CodeIntegrity=1 → Enabled。
        // ────────────────────────────────────────────────
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

            // ── Driver Load Policy: 必须 <=1，否则强制被削弱 ──
            var driverPolicyEvent = Find(wbcl, SIPAEVENT_DRIVER_LOAD_POLICY);
            if (driverPolicyEvent != null && TryGetUInt32(driverPolicyEvent, out uint dlpVal))
            {
                driverLoadPolicy = dlpVal;
                evidences.Add($"DriverLoadPolicy={dlpVal} [0x0005000E, PCR{driverPolicyEvent.SourcePcr}]" +
                              (dlpVal > 1 ? " ⚠ (>1，签名强制被削弱)" : ""));
            }

            // ── 判定（不受证据顺序影响）──
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

        // ────────────────────────────────────────────────
        // 6. Vulnerable Driver Blocklist
        //    核心证据 (wbcl.h): 0x0005000F SIPAEVENT_SI_POLICY — System Integrity Policy。
        //    微软易受攻击驱动阻止列表以 Code Integrity SI policy (driversipolicy.p7b)
        //    形式存在；该事件测量的是 SIPAEVENT_SI_POLICY_PAYLOAD
        //    (PolicyVersion ULONGLONG + PolicyName + HashAlgID + Digest)。
        //    不参与判定: FlightSigning (0x00050021, 不查)、BootRevocationList/OSRevocationList
        //    (属于 Secure Boot 吊销链，已移至 Secure Boot)、DriverLoadPolicy (归驱动签名判定)。
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeVulnerableDriverBlocklist(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };
            var wbcl = WbclParser.ParseAll(log);

            var siPolicy = Find(wbcl, SIPAEVENT_SI_POLICY);
            if (siPolicy != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"SIPAEVENT_SI_POLICY measured [0x0005000F, PCR{siPolicy.SourcePcr}] — System Integrity Policy 已测量";
                feat.Detail = DescribeSiPolicy(siPolicy.EventData) +
                    "\n         微软易受攻击驱动阻止列表以 SI Policy (driversipolicy.p7b) 形式被测量加载";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No SI Policy (0x0005000F) measurement found in WBCL";
            feat.Detail = "SIPAEVENT_SI_POLICY 未出现 → 阻止列表策略未被测量（可能未启用或该日志不含此项）";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 7. Boot Log Integrity (PCR Replay)
        //    注意: 分隔符 + WBCL 终止符只能证明"日志结构完整"，
        //    不能替代 PCR 重放校验（那在 PCR Banks 部分单独完成）。
        // ────────────────────────────────────────────────
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
                feat.Detail = "UEFI 启动阶段分隔正常；WBCL 终止符缺失（可能为 Linux/非 Windows 日志）";
            }
            else
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"Only {separatorCount} separator events found";
                feat.Detail = "日志结构不完整，无法判断启动序列是否正常";
            }

            return feat;
        }

        // ────────────────────────────────────────────────
        // 8. ELAM (Early Launch Anti-Malware)
        //    SIPA ID (wbcl.h): 0x00090001=ELAM_KEYNAME (Unicode),
        //    0x00090003=ELAM_POLICY, 0x00090004=ELAM_MEASURED。
        //    ELAM_KEYNAME 记录的是 ELAM 厂商注册表键名 → 本次启动有 ELAM 驱动注册。
        // ────────────────────────────────────────────────
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
                feat.Detail = "本次启动有 ELAM 反恶意软件驱动注册（其注册表键被测量）";
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
                feat.Detail = "ELAM 策略已被测量（策略存在≠厂商驱动已加载，但策略非零表示 ELAM 已配置）";
                return feat;
            }

            var measured = Find(wbcl, SIPAEVENT_ELAM_MEASURED);
            if (measured != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"ELAM driver measurement present [0x00090004, PCR{measured.SourcePcr}]";
                return feat;
            }

            // ELAM 聚合容器 (0x40010002 SIPAEVENT_ELAM_AGGREGATION): 存在即 ELAM 相关测量已记录
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

        // ────────────────────────────────────────────────
        // 9. DRTM (Dynamic Root of Trust for Measurement)
        //    wbcl.h (RS5+) 明确定义 SIPAEVENTTYPE_DRTM (0x000C0000):
        //    a) 0x000C0001 SIPAEVENT_DRTM_STATE_AUTH — TcbLaunch.exe 测量到 PCR20，
        //       payload 为 TPM_API_PA_DIRECT_AUTHORIZATION_1（对 DRTM 状态的签名授权）。
        //    b) 0x000C0002 SIPAEVENT_DRTM_SMM_LEVEL — 单字节 SI_DRTM_SMM_LEVEL (PCR20)。
        //    两个事件均由 TcbLaunch.exe 在 DRTM (System Guard Secure Launch) 期间测量
        //    (wbcl.h 原文)，任一存在即证明 DRTM 已执行。
        //    重要: VBS/Hyper-V ≠ DRTM，不能用 VBS 策略推出 "DRTM enabled"。
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeDrtm(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Dynamic Root of Trust for Measurement (DRTM)" };
            var wbcl = WbclParser.ParseAll(log);
            var aux = new List<string>();

            // ── 直接证据 1: DRTM_STATE_AUTH (0x000C0001) ──
            var drtmAuth = Find(wbcl, SIPAEVENT_DRTM_STATE_AUTH);
            if (drtmAuth != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"SIPAEVENT_DRTM_STATE_AUTH present [0x000C0001, PCR{drtmAuth.SourcePcr}] — System Guard Secure Launch 已执行";
                feat.Detail = $"Payload = TPM_API_PA_DIRECT_AUTHORIZATION_1 ({drtmAuth.EventData.Length} bytes, 由 TcbLaunch.exe 测量至 PCR20)";
                var smm1 = Find(wbcl, SIPAEVENT_DRTM_SMM_LEVEL);
                if (smm1 != null && smm1.EventData.Length > 0)
                    feat.Detail += $"\n         SIPAEVENT_DRTM_SMM_LEVEL={smm1.EventData[0]} [0x000C0002, PCR{smm1.SourcePcr}]";
                return feat;
            }

            // ── 直接证据 2: DRTM_SMM_LEVEL (0x000C0002) — 同样由 TcbLaunch.exe 在 DRTM 期间测量 ──
            var smmLevel = Find(wbcl, SIPAEVENT_DRTM_SMM_LEVEL);
            if (smmLevel != null && smmLevel.EventData.Length > 0)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"SIPAEVENT_DRTM_SMM_LEVEL={smmLevel.EventData[0]} [0x000C0002, PCR{smmLevel.SourcePcr}] — System Guard Secure Launch 已执行";
                feat.Detail = "wbcl.h: 该事件由 TcbLaunch.exe 在 DRTM 期间测量到 PCR20，其存在即证明 DRTM 动态启动已发生" +
                             "（本日志未含 0x000C0001 签名授权 payload）";
                return feat;
            }

            // ── 部分证据: AMD SMM hash ──
            var amdSmm = Find(wbcl, SIPAEVENT_DRTM_AMD_SMM_HASH);
            if (amdSmm != null)
            {
                aux.Add($"SIPAEVENT_DRTM_AMD_SMM_HASH present [0x000C0003, PCR{amdSmm.SourcePcr}] — AMD Secure Launch 相关测量");
            }

            // ── VBS/Hyper-V 状态仅作背景信息，绝不据此判定 DRTM ──
            var vbsVsm = Find(wbcl, SIPAEVENT_VBS_VSM_REQUIRED);
            var launch = Find(wbcl, SIPAEVENT_HYPERVISOR_LAUNCH_TYPE);
            if (vbsVsm != null || launch != null)
            {
                string vbsInfo = vbsVsm != null ? $"VBSVSMRequired={(IsTrue(vbsVsm) ? "1" : "0")}" : "";
                string hypInfo = launch != null && TryGetUInt64(launch, out var lt) ? $"HypervisorLaunchType={lt}" : "";
                aux.Add($"背景: {string.Join(", ", new[] { vbsInfo, hypInfo }.Where(s => s != ""))} — 注意: VBS/Hyper-V ≠ DRTM，不能据此判定 System Guard Secure Launch");
            }

            if (aux.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "存在 DRTM 相关测量，但未发现 SIPAEVENT_DRTM_STATE_AUTH (0x000C0001)";
                feat.Detail = string.Join("\n         ", aux);
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No DRTM indicators found in WBCL (0x000C0001-0x000C0003)";
            feat.Detail = "未发现 DRTM 测量事件 → System Guard Secure Launch 大概率未启用（DRTM 日志亦独立于 SRTM，PCR17-22）";
            return feat;
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────
        private static WbclTaggedEvent? Find(List<WbclTaggedEvent> events, uint id) =>
            events.FirstOrDefault(e => e.EventId == id);

        private static bool IsTrue(WbclTaggedEvent? e) =>
            e != null && e.EventData.Length > 0 && e.EventData[0] != 0;

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
        /// 解析 SIPAEVENT_SI_POLICY_PAYLOAD (wbcl.h):
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

            // PolicyVersion 布局 (与 TCGLogTools.psm1 一致): 4×Int16 = Revision, Build, Minor, Major
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
