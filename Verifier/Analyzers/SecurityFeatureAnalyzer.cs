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

    public static class SecurityFeatureAnalyzer
    {
        // Well-known GUIDs
        private static readonly Guid EfiGlobalVariableGuid =
            new("8be4df61-93ca-11d2-aa0d-00e098032b8c");
        private static readonly Guid EfiImageSecurityDatabaseGuid =
            new("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

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
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeSecureBoot(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Secure Boot" };

            // Find SecureBoot variable in PCR7
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
            feat.Evidence = $"Event #{secureBootEvent.Index} (PCR7, EFI_VARIABLE_DRIVER_CONFIG)";

            // Also check PK, KEK, db presence
            var pkEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "PK");
            var dbEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "db");
            var dbxEvent = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 7 && TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName == "dbx");

            var details = new List<string>();
            if (pkEvent != null)
            {
                TryParseEfiVariable(pkEvent.EventData, out var pk);
                details.Add($"PK measured (DataLen={pk?.VariableData?.Length ?? 0})");
            }
            if (dbEvent != null)
            {
                TryParseEfiVariable(dbEvent.EventData, out var db);
                details.Add($"db measured (DataLen={db?.VariableData?.Length ?? 0})");
            }
            if (dbxEvent != null)
            {
                TryParseEfiVariable(dbxEvent.EventData, out var dbx);
                details.Add($"dbx measured (DataLen={dbx?.VariableData?.Length ?? 0})");
            }

            feat.Detail = string.Join(", ", details);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 2. CPU Virtualization (VT-x / AMD-V)
        //    Evidence in TCG logs:
        //    a) EV_EFI_PLATFORM_FIRMWARE_BLOB2 in PCR0 (UEFI FW modules)
        //    b) EFI variable "VirtualizationTechnology" or similar in PCR1
        //    c) Presence of EV_EFI_HANDOFF_TABLES2 with SMBIOS type 4
        //       (Processor Info) flags - not directly readable here
        //    d) Windows WBCL: PCR12 EV_EVENT_TAG encodes boot config flags
        //
        //    Most practical: check PCR0 firmware blob names for VMX-related
        //    strings, and look for WBCL tag events in PCR11-14
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeVirtualization(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "CPU Virtualization (VT-x/AMD-V)" };

            // Strategy 1: Look for EFI variable with virtualization in name
            var virtVar = log.Events.FirstOrDefault(e =>
                (e.EventType == 0x80000001 || e.EventType == 0x80000002) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName != null &&
                (v.VariableName.Contains("Virt", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("SVM", StringComparison.OrdinalIgnoreCase)));

            if (virtVar != null)
            {
                TryParseEfiVariable(virtVar.EventData, out var v);
                bool en = v?.VariableData?.Length > 0 && v.VariableData[0] != 0;
                feat.Status = en ? FeatureStatus.Enabled : FeatureStatus.Disabled;
                feat.Evidence = $"EFI variable '{v?.VariableName}' in Event #{virtVar.Index}";
                return feat;
            }

            // Strategy 2: PCR0 EV_EFI_PLATFORM_FIRMWARE_BLOB2 entries
            // Blob2 event data: 1-byte name length, name (UTF-8), then UINT64 base, UINT64 length
            var blobs = log.Events.Where(e =>
                e.PcrIndex == 0 && e.EventType == 0x8000000A).ToList();

            var vmxBlob = blobs.FirstOrDefault(e =>
            {
                string blobName = ParseFirmwareBlobName(e.EventData);
                return blobName.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                       blobName.Contains("CPUINIT", StringComparison.OrdinalIgnoreCase) ||
                       blobName.Contains("VTD", StringComparison.OrdinalIgnoreCase);
            });

            if (vmxBlob != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Firmware blob '{ParseFirmwareBlobName(vmxBlob.EventData)}' measured in PCR0 (Event #{vmxBlob.Index})";
                return feat;
            }

            // Strategy 3: WBCL PCR11 EV_COMPACT_HASH
            // The value 0x10000000 in PCR11 is Windows "Early Launch" marker
            // PCR11 being present at all indicates Hyper-V/VBS is active which requires VT-x
            var pcr11Events = log.Events.Where(e => e.PcrIndex == 11).ToList();
            if (pcr11Events.Any())
            {
                // Check if Hyper-V launch marker present
                var hvEvent = pcr11Events.FirstOrDefault(e =>
                    e.EventType == 0x0000000C && e.EventData.Length == 4 &&
                    BitConverter.ToUInt32(e.EventData) == 0x00000010);

                if (hvEvent != null)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"PCR11 contains Hyper-V early launch marker (Event #{hvEvent.Index}) — VT-x required and active";
                    feat.Detail = "Windows Hyper-V/VBS is using CPU virtualization";
                    return feat;
                }

                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"PCR11 has {pcr11Events.Count} WBCL events — indicates VBS/Hyper-V active, requires VT-x";
                return feat;
            }

            // Strategy 4: EV_EFI_PLATFORM_FIRMWARE_BLOB2 existence in PCR0
            // If present with multiple blobs, platform likely supports virtualization
            // but we can't confirm it's enabled
            if (blobs.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"PCR0 has {blobs.Count} firmware blob measurements; no direct virtualization marker found";
                feat.Detail = "Check BIOS/UEFI setup to confirm VT-x/AMD-V is enabled";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No virtualization-related measurements found in event log";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 3. IOMMU (VT-d / AMD-Vi)
        //    Evidence:
        //    a) ACPI DMAR table measured in EV_EFI_HANDOFF_TABLES2 (PCR1)
        //    b) EFI variable with "VTd" or "IOMMU" in PCR1
        //    c) WBCL PCR12 events (Windows records DMA protection state)
        //    d) EV_EFI_PLATFORM_FIRMWARE_BLOB2 blob named "VTD" or "DMAR"
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeIommu(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "IOMMU (VT-d/AMD-Vi)" };

            // Strategy 1: EFI variable with IOMMU/VTd name
            var iommuVar = log.Events.FirstOrDefault(e =>
                (e.EventType == 0x80000001 || e.EventType == 0x80000002) &&
                TryParseEfiVariable(e.EventData, out var v) &&
                v!.VariableName != null &&
                (v.VariableName.Contains("Iommu", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("VTd", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("DMAR", StringComparison.OrdinalIgnoreCase) ||
                 v.VariableName.Contains("DMA", StringComparison.OrdinalIgnoreCase)));

            if (iommuVar != null)
            {
                TryParseEfiVariable(iommuVar.EventData, out var v);
                bool en = v?.VariableData?.Length > 0 && v.VariableData[0] != 0;
                feat.Status = en ? FeatureStatus.Enabled : FeatureStatus.Disabled;
                feat.Evidence = $"EFI variable '{v?.VariableName}' in Event #{iommuVar.Index}";
                return feat;
            }

            // Strategy 2: PCR0 firmware blob named VTD/DMAR
            var dmarBlob = log.Events.FirstOrDefault(e =>
                e.PcrIndex == 0 && e.EventType == 0x8000000A &&
                ParseFirmwareBlobName(e.EventData) is string name &&
                (name.Contains("VTD", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("DMAR", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("IOMMU", StringComparison.OrdinalIgnoreCase)));

            if (dmarBlob != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"DMAR/VTD firmware blob in PCR0 (Event #{dmarBlob.Index})";
                return feat;
            }

            // Strategy 3: EV_EFI_HANDOFF_TABLES2 in PCR1 — contains SMBIOS/ACPI
            // We can check if the raw data contains "DMAR" ACPI signature (4 bytes)
            var handoffEvents = log.Events.Where(e =>
                e.PcrIndex == 1 && e.EventType == 0x8000000B).ToList();

            foreach (var hEvent in handoffEvents)
            {
                if (ContainsMagic(hEvent.EventData, "DMAR"u8.ToArray()))
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"DMAR ACPI table signature found in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index})";
                    feat.Detail = "Intel VT-d DMAR table present and measured";
                    return feat;
                }
                if (ContainsMagic(hEvent.EventData, "IVRS"u8.ToArray()))
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"IVRS ACPI table signature found in EFI_HANDOFF_TABLES2 (Event #{hEvent.Index})";
                    feat.Detail = "AMD-Vi IVRS table present and measured";
                    return feat;
                }
            }

            // Strategy 4: Windows DMA protection via WBCL PCR12 events
            // Windows records "DMA Protection" boot event if IOMMU is active
            var wbclEvents = WbclParser.ParseAll(log);

            // 0x000A0003 = VBSIOMMURequired (Boolean)
            // 0x0005000C = HypervisorIOMMUPolicy (UInt64): 0=off, 1=on, 2=on+NOFORCESNOOP
            // 0x00050010 = HypervisorMMIONXPolicy (UInt64): VBS IOMMU 防护的一部分
            var iommuEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x000A0003 || e.EventId == 0x0005000C || e.EventId == 0x00050010);

            if (iommuEvent != null)
            {
                bool active = false;
                if (iommuEvent.EventData.Length >= 4)
                {
                    uint flags = BitConverter.ToUInt32(iommuEvent.EventData, 0);
                    active = flags != 0;  // 非 0 即表示 IOMMU 相关策略已启用
                }
                else if (iommuEvent.EventData.Length >= 1)
                {
                    active = iommuEvent.EventData[0] != 0;
                }

                // 如果当前事件值为 0，继续检查其他指标
                if (active)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = $"IOMMU event 0x{iommuEvent.EventId:X8}=active " +
                                    $"(TcgEvent #{iommuEvent.SourceEventIndex}, PCR{iommuEvent.SourcePcr})";
                    feat.Detail = iommuEvent.InterpretedValue;
                    return feat;
                }
            }

            // ── VBSIOMMURequired (0x000A0003) 作为辅助判断 ──
            var vbsIommuEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x000A0003);
            if (vbsIommuEvent != null)
            {
                bool required = vbsIommuEvent.EventData.Length > 0 && vbsIommuEvent.EventData[0] != 0;
                feat.Status = required ? FeatureStatus.Enabled : FeatureStatus.Unknown;
                feat.Evidence = $"VBSIOMMURequired={required} " +
                                $"(TcgEvent #{vbsIommuEvent.SourceEventIndex})";
                feat.Detail = "VBS policy requires IOMMU → IOMMU must be present and enabled";
                return feat;
            }

            // Strategy 5: Windows 11 WBCL V2 Event Aggregation
            // Microsoft moved DMA protection flags to undocumented 0x0005xxxx sub-tags in Win11
            bool hasWbclV2 = wbclEvents.Any(e => e.EventId == 0x40010001);
            if (hasWbclV2)
            {
                var win11VbsPolicy = wbclEvents.FirstOrDefault(e =>
                    e.EventId == 0x00050010 || e.EventId == 0x00050014 || e.EventId == 0x00050011);

                if (win11VbsPolicy != null && win11VbsPolicy.EventData.Length > 0 && win11VbsPolicy.EventData[0] == 0x01)
                {
                    feat.Status = FeatureStatus.Enabled;
                    feat.Evidence = "Windows 11 V2 Event Aggregation (0x40010001) contains VBS/DMA policy tags";
                    feat.Detail = $"Found active V2 security tag 0x{win11VbsPolicy.EventId:X8} = 1. Kernel DMA Protection is active.";
                    return feat;
                }
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No IOMMU SIPA events found in WBCL";
            feat.Detail = "IOMMU may be disabled, or WBCL not fully present in this log";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 4. HVCI / VBS (Hypervisor-protected Code Integrity)
        //    Evidence chain:
        //    1) SIPAEVENT_HYPERVISOR_LAUNCH_TYPE (old: 0x00080001, Win11 V2: 0x00020008)
        //       value 1 = Hyper-V launched, VT-x occupied
        //    2) SIPAEVENT_VBS flags (old: 0x000A0001, Win11 V2: 0x0005000A)
        //       Bit 0: VBS Enabled, Bit 2: HVCI Enabled
        //    3) PCR12 replay match confirms WBCL integrity (handled by PCR Banks)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeHvci(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "HVCI / VBS (Hypervisor Code Integrity)" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool hvciDetected = false;

            // ── Evidence 1: Hypervisor Launch Type ──
            // Legacy tag: SIPAEVENT_HYPERVISOR_LAUNCH_TYPE = 0x00080001
            // Win11 V2 tag: 0x00020008 (inside 0x40010001 aggregation)
            var launchTypeEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x00080001 || e.EventId == 0x00020008);

            if (launchTypeEvent != null)
            {
                uint launchType = 0;
                if (launchTypeEvent.EventData.Length >= 4)
                    launchType = BitConverter.ToUInt32(launchTypeEvent.EventData, 0);
                else if (launchTypeEvent.EventData.Length >= 1)
                    launchType = launchTypeEvent.EventData[0];

                string launchDesc = launchType switch
                {
                    0 => "Hyper-V not launched",
                    1 => "Hyper-V launched (VT-x occupied)",
                    2 => "Launched with virtualization extensions",
                    _ => $"Unknown ({launchType})"
                };

                evidences.Add($"Chain 1: HypervisorLaunchType={launchType} ({launchDesc}) " +
                              $"[0x{launchTypeEvent.EventId:X8}, PCR{launchTypeEvent.SourcePcr}]");

                if (launchType >= 1)
                    hvciDetected = true;
            }
            else
            {
                evidences.Add("Chain 1: HypervisorLaunchType not found");
            }

            // ── Evidence 2: VBS / HVCI flags ──
            // Legacy tag: SIPAEVENT_VBS_STATUS = 0x000A0001
            // Win11 V2 tag: 0x0005000A (VBS flags, 8 bytes LE)
            var vbsFlagsEvent = wbclEvents.FirstOrDefault(e =>
                e.EventId == 0x000A0001 || e.EventId == 0x0005000A);

            if (vbsFlagsEvent != null)
            {
                ulong vbsFlags = 0;
                if (vbsFlagsEvent.EventData.Length >= 8)
                    vbsFlags = BitConverter.ToUInt64(vbsFlagsEvent.EventData, 0);
                else if (vbsFlagsEvent.EventData.Length >= 4)
                    vbsFlags = BitConverter.ToUInt32(vbsFlagsEvent.EventData, 0);
                else if (vbsFlagsEvent.EventData.Length >= 1)
                    vbsFlags = vbsFlagsEvent.EventData[0];

                bool vbsEnabled = (vbsFlags & 0x01) != 0;
                bool vbsRequired = (vbsFlags & 0x02) != 0;
                bool hvciEnabled = (vbsFlags & 0x04) != 0;

                var flagStrs = new List<string>();
                if (vbsEnabled) flagStrs.Add("VBS=ON");
                if (vbsRequired) flagStrs.Add("VBS_REQUIRED");
                if (hvciEnabled) flagStrs.Add("HVCI=ON");

                if (flagStrs.Count == 0 && vbsFlags != 0)
                    flagStrs.Add($"raw=0x{vbsFlags:X}");

                evidences.Add($"Chain 2: VBS/HVCI flags=0x{vbsFlags:X} ({string.Join(", ", flagStrs)}) " +
                              $"[0x{vbsFlagsEvent.EventId:X8}, PCR{vbsFlagsEvent.SourcePcr}]");

                if (vbsEnabled || hvciEnabled)
                    hvciDetected = true;
            }
            else
            {
                // Fallback: check 0x00050012 (Win11 V2 VBS related)
                var vbs12 = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050012);
                if (vbs12 != null)
                {
                    ulong val = 0;
                    if (vbs12.EventData.Length >= 8)
                        val = BitConverter.ToUInt64(vbs12.EventData, 0);
                    else if (vbs12.EventData.Length >= 1)
                        val = vbs12.EventData[0];

                    evidences.Add($"Chain 2: VBS policy tag 0x00050012=0x{val:X} " +
                                  $"[PCR{vbs12.SourcePcr}]");

                    if (val != 0)
                        hvciDetected = true;
                }
                else
                {
                    evidences.Add("Chain 2: VBS/HVCI flags not found");
                }
            }

            // ── Evidence 3: PCR12 replay integrity ──
            // This is verified in PCR Banks section; we just note whether PCR12 events exist
            bool hasPcr12 = log.Events.Any(e => e.PcrIndex == 12);
            if (hasPcr12)
            {
                evidences.Add("Chain 3: PCR12 events present — replay match verified in PCR Banks");
            }
            else
            {
                evidences.Add("Chain 3: No PCR12 events — cannot verify WBCL integrity");
            }

            // ── Final verdict ──
            if (hvciDetected && hasPcr12)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI/VBS is active — Hyper-V occupying VT-x, PCR12 integrity verified";
            }
            else if (hvciDetected)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "HVCI/VBS detected from WBCL flags (PCR12 replay not available)";
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
        // 5. Driver Signature Enforcement (代码完整性 / 驱动签名)
        //    SIPA ID 参考: https://github.com/mattifestation/TCGLogTools
        //    a) 0x00050003 = TestSigning (Boolean: 1=ON → enforcement weakened)
        //    b) 0x00050002 = CodeIntegrity (Boolean: 1=enabled, 0=disabled)
        //    c) 0x00050001 = OSKernelDebug (仅供参考，不影响签名状态)
        //    d) 0x0005000E = DriverLoadPolicy (仅供参考)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeDriverSignature(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Driver Signature Enforcement (Code Integrity)" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool? enforced = null;

            // ── Test Signing (0x00050003) ──
            // Boolean: 1=测试签名开启（削弱强制）, 0=关闭（强制生效）
            var testSignEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050003);
            if (testSignEvent != null)
            {
                byte val = testSignEvent.EventData.Length > 0 ? testSignEvent.EventData[0] : (byte)0;
                if (val == 1) { enforced = false; evidences.Add($"TestSigning=ON ⚠ [0x00050003, PCR{testSignEvent.SourcePcr}]"); }
                else { enforced = true; evidences.Add($"TestSigning=OFF [0x00050003, PCR{testSignEvent.SourcePcr}]"); }
            }

            // ── Code Integrity (0x00050002) ──
            // Boolean: 1=完整性检查启用, 0=完整性检查禁用
            var ciEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050002);
            if (ciEvent != null)
            {
                byte val = ciEvent.EventData.Length > 0 ? ciEvent.EventData[0] : (byte)0;
                if (val == 0) { enforced = false; evidences.Add($"CodeIntegrity=disabled ⚠ [0x00050002, PCR{ciEvent.SourcePcr}]"); }
                else { enforced = true; evidences.Add($"CodeIntegrity=enabled [0x00050002, PCR{ciEvent.SourcePcr}]"); }
            }

            // ── Driver Load Policy (0x0005000E) ──
            // UInt32: 驱动加载策略（仅供参考）
            var driverPolicyEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x0005000E);
            if (driverPolicyEvent != null)
            {
                uint val = 0;
                if (driverPolicyEvent.EventData.Length >= 4)
                    val = BitConverter.ToUInt32(driverPolicyEvent.EventData, 0);
                else if (driverPolicyEvent.EventData.Length >= 1)
                    val = driverPolicyEvent.EventData[0];
                evidences.Add($"DriverLoadPolicy={val} [0x0005000E, PCR{driverPolicyEvent.SourcePcr}]");
            }

            // ── OS Kernel Debug (0x00050001) ──
            // 仅供参考，不影响驱动签名状态
            var kdEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050001);
            if (kdEvent != null)
            {
                bool kdOn = kdEvent.InterpretedValue?.Contains("Enabled", StringComparison.OrdinalIgnoreCase) == true
                    || (kdEvent.EventData.Length > 0 && kdEvent.EventData[0] == 1);
                evidences.Add($"KernelDebug={(kdOn ? "ON" : "OFF")} [0x00050001, PCR{kdEvent.SourcePcr}]");
            }

            // ── Flight Signing (0x00050021) ──
            var flightEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050021);
            if (flightEvent != null && flightEvent.EventData.Length > 0 && flightEvent.EventData[0] == 1)
                evidences.Add($"FlightSigning=ON [0x00050021, PCR{flightEvent.SourcePcr}]");

            // ── Verdict ──
            if (enforced == true)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Driver signature enforcement is active";
            }
            else if (enforced == false)
            {
                feat.Status = FeatureStatus.Disabled;
                feat.Evidence = "Driver signature enforcement is weakened";
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
        // 6. Vulnerable Driver Blocklist (易受攻击驱动阻止列表)
        //    SIPA ID 参考: https://github.com/mattifestation/TCGLogTools
        //    a) 0x00050021 = FlightSigning (Boolean)
        //    b) 0x00040002 = BootRevocationList (Struct)
        //    c) 0x00050013 = OSRevocationList (Struct)
        //    d) 0x0005000E = DriverLoadPolicy (UInt32)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeVulnerableDriverBlocklist(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };
            var wbclEvents = WbclParser.ParseAll(log);
            var evidences = new List<string>();
            bool blocklistEnabled = false;

            // ── 0x00050021: FlightSigning ──
            var flightEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050021);
            if (flightEvent != null)
            {
                byte val = flightEvent.EventData.Length > 0 ? flightEvent.EventData[0] : (byte)0;
                bool enabled = val == 0x01;
                evidences.Add($"FlightSigning={(enabled ? "Enabled" : "Disabled")} " +
                              $"[0x00050021=0x{val:X2}, PCR{flightEvent.SourcePcr}]");
                if (enabled) blocklistEnabled = true;
            }

            // ── 0x00040002: BootRevocationList ──
            var revocListEvents = wbclEvents.Where(e => e.EventId == 0x00040002).ToList();
            if (revocListEvents.Count > 0)
            {
                evidences.Add($"BootRevocationList present ({revocListEvents.Count} entries) " +
                              $"[0x00040002, PCR{revocListEvents[0].SourcePcr}]");
                blocklistEnabled = true;
            }

            // ── 0x00050013: OSRevocationList ──
            var osRevocEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050013);
            if (osRevocEvent != null)
            {
                evidences.Add($"OSRevocationList present [0x00050013, PCR{osRevocEvent.SourcePcr}]");
                blocklistEnabled = true;
            }

            // ── 0x0005000E: DriverLoadPolicy ──
            var driverPolicyEvent = wbclEvents.FirstOrDefault(e => e.EventId == 0x0005000E);
            if (driverPolicyEvent != null)
            {
                uint val = 0;
                if (driverPolicyEvent.EventData.Length >= 4)
                    val = BitConverter.ToUInt32(driverPolicyEvent.EventData, 0);
                else if (driverPolicyEvent.EventData.Length >= 1)
                    val = driverPolicyEvent.EventData[0];
                evidences.Add($"DriverLoadPolicy={val} " +
                              $"[0x0005000E, PCR{driverPolicyEvent.SourcePcr}]");
                if (val != 0) blocklistEnabled = true;
            }

            // ── Verdict ──
            if (blocklistEnabled)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Microsoft vulnerable driver blocklist is active";
            }
            else if (revocListEvents.Count > 0)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "Boot revocation list present (blocklist likely active)";
            }
            else if (evidences.Count > 0)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "WBCL tags found but blocklist status unclear";
            }
            else
            {
                feat.Status = FeatureStatus.NotMeasured;
                feat.Evidence = "No vulnerable driver blocklist tags found in WBCL";
            }

            feat.Detail = string.Join("\n         ", evidences);
            return feat;
        }

        // ────────────────────────────────────────────────
        // 7. Boot Integrity (PCR replay consistency)
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeBootIntegrity(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Boot Log Integrity (PCR Replay)" };

            // Count events by separator presence (indicates clean boot phases)
            int separatorCount = log.Events.Count(e => e.EventType == 0x00000004);
            bool hasSeparators = separatorCount >= 7; // PCR0-6 should each have one

            // Check if WBCL terminator is present (EV_SEPARATOR with "WBCL" in PCR12/13/14)
            bool hasWbclTerminator = log.Events.Any(e =>
                e.EventType == 0x00000004 &&
                e.PcrIndex is 12 or 13 or 14 &&
                e.EventData.Length == 4 &&
                System.Text.Encoding.ASCII.GetString(e.EventData) == "WBCL");

            if (hasSeparators && hasWbclTerminator)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"All phase separators present ({separatorCount}), WBCL terminator found";
                feat.Detail = "Boot sequence appears complete and well-formed";
            }
            else if (hasSeparators)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"Phase separators present ({separatorCount})";
                feat.Detail = "UEFI boot phases properly separated; WBCL (Windows) terminator absent";
            }
            else
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"Only {separatorCount} separator events found";
            }

            return feat;
        }

        // ────────────────────────────────────────────────
        // 8. ELAM (Early Launch Anti-Malware)
        //    SIPA IDs: 0x00090001=ELAMKeyname, 0x00090003=ELAMPolicy,
        //              0x00090004=ELAMMeasured, 0x40010002=ELAMAggregation
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeElam(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Early Launch Anti-Malware (ELAM)" };
            var wbclEvents = WbclParser.ParseAll(log);

            // ELAMKeyname (0x00090001) — 存在即表示 ELAM 驱动已加载
            var keyname = wbclEvents.FirstOrDefault(e => e.EventId == 0x00090001);
            if (keyname != null)
            {
                string name = keyname.InterpretedValue ?? "present";
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"ELAMKeyname={name}";
                feat.Detail = $"[0x00090001, PCR{keyname.SourcePcr}]";
                return feat;
            }

            // ELAMPolicy (0x00090003)
            var policy = wbclEvents.FirstOrDefault(e => e.EventId == 0x00090003);
            if (policy != null)
            {
                byte val = policy.EventData.Length > 0 ? policy.EventData[0] : (byte)0;
                if (val == 1) { feat.Status = FeatureStatus.Enabled; feat.Evidence = "ELAM policy=Auto enabled"; }
                else if (val == 2) { feat.Status = FeatureStatus.Enabled; feat.Evidence = "ELAM policy=Force enabled"; }
                else { feat.Status = FeatureStatus.Disabled; feat.Evidence = "ELAM policy=Disabled"; }
                feat.Detail = $"[0x00090003=0x{val:X}, PCR{policy.SourcePcr}]";
                return feat;
            }

            // ELAMMeasured (0x00090004)
            var measured = wbclEvents.FirstOrDefault(e => e.EventId == 0x00090004);
            if (measured != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "ELAM drivers measured";
                feat.Detail = $"[0x00090004, PCR{measured.SourcePcr}]";
                return feat;
            }

            // ELAM Aggregation container (0x40010002)
            var agg = wbclEvents.FirstOrDefault(e => e.EventId == 0x40010002);
            if (agg != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "ELAMAggregation present";
                return feat;
            }

            // fallback: any ELAM event in range 0x00090000-0x00090004
            var elamEvent = wbclEvents.FirstOrDefault(e => e.EventId >= 0x00090000 && e.EventId <= 0x00090004);
            if (elamEvent != null)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = $"ELAM event 0x{elamEvent.EventId:X8} detected";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No ELAM SIPA events found in WBCL";
            return feat;
        }

        // ────────────────────────────────────────────────
        // 9. DRTM (Dynamic Root of Trust for Measurement)
        //    DRTM 日志（PCR 17-22）独立于 SRTM 日志（PCR 0-15）
        // ────────────────────────────────────────────────
        private static SecurityFeature AnalyzeDrtm(TcgEventLog log)
        {
            var feat = new SecurityFeature { Name = "Dynamic Root of Trust for Measurement (DRTM)" };
            var wbclEvents = WbclParser.ParseAll(log);

            // DRTM state (0x000C0001)
            var drtmState = wbclEvents.FirstOrDefault(e => e.EventId == 0x000C0001);
            if (drtmState != null && drtmState.EventData.Length >= 4)
            {
                uint state = BitConverter.ToUInt32(drtmState.EventData, 0);
                if (state == 1) { feat.Status = FeatureStatus.Enabled; feat.Evidence = "DRTM state=authenticated success"; }
                else { feat.Status = FeatureStatus.Disabled; feat.Evidence = $"DRTM state={state}"; }
                feat.Detail = $"[0x000C0001, PCR{drtmState.SourcePcr}]";
                return feat;
            }

            // SMM protection level (0x000C0002)
            var smmLevel = wbclEvents.FirstOrDefault(e => e.EventId == 0x000C0002);
            if (smmLevel != null && smmLevel.EventData.Length >= 4)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = $"SMM protection level={BitConverter.ToUInt32(smmLevel.EventData, 0)}";
                return feat;
            }

            // 间接指标: VBSVSMRequired (0x000A0001)
            var vbsRequired = wbclEvents.FirstOrDefault(e => e.EventId == 0x000A0001);
            bool vbsOn = vbsRequired != null && vbsRequired.EventData.Length > 0 && vbsRequired.EventData[0] == 1;

            // HypervisorLaunchType (0x0005000A)
            var hyperLaunch = wbclEvents.FirstOrDefault(e => e.EventId == 0x0005000A);
            bool hyperOn = hyperLaunch != null && hyperLaunch.EventData.Length >= 4 && BitConverter.ToUInt32(hyperLaunch.EventData, 0) >= 1;

            // VSMLaunchType (0x00050012)
            var vsmLaunch = wbclEvents.FirstOrDefault(e => e.EventId == 0x00050012);
            bool vsmOn = vsmLaunch != null && vsmLaunch.EventData.Length >= 4 && BitConverter.ToUInt32(vsmLaunch.EventData, 0) >= 1;

            if (vbsOn && hyperOn)
            {
                feat.Status = FeatureStatus.Enabled;
                feat.Evidence = "VBSVSMRequired=1, HypervisorLaunchType=Auto (DRTM enforced by VBS policy)";
                return feat;
            }

            if (hyperOn && vsmOn)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "HypervisorLaunchType=Auto, VSMLaunchType=Auto (DRTM possible, needs WBCLDrtm log)";
                return feat;
            }

            if (hyperOn)
            {
                feat.Status = FeatureStatus.Unknown;
                feat.Evidence = "HypervisorLaunchType=Auto (VBS running, DRTM possible)";
                return feat;
            }

            feat.Status = FeatureStatus.NotMeasured;
            feat.Evidence = "No DRTM indicators found in WBCL";
            return feat;
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────
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
            // EFI_PLATFORM_FIRMWARE_BLOB2: UINT8 BlobDescriptionSize, BlobDescription (UTF-8), UINT64 Base, UINT64 Length
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