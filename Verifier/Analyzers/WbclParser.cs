using MeasuredBootParser.Models;
using System.Text;

namespace MeasuredBootParser.Analyzers
{
    public class WbclTaggedEvent
    {
        public uint EventId { get; set; }
        public string EventName => WbclEventIds.GetName(EventId);
        public uint EventSize { get; set; }
        public byte[] EventData { get; set; } = [];
        public string? InterpretedValue { get; set; }
        public int SourceEventIndex { get; set; }  // 对应 TcgEvent.Index
        public uint SourcePcr { get; set; }
    }

    public static class WbclEventIds
    {
        private static readonly Dictionary<uint, string> Names = new()
        {
            // ── SIPAEVENTTYPE_INFORMATION (0x0002xxxx) ──
            [0x00020001] = "SIPAEVENT_INFORMATION",
            [0x00020002] = "SIPAEVENT_BOOTCOUNTER",
            [0x00020003] = "SIPAEVENT_TRANSFER_CONTROL",
            [0x00020004] = "SIPAEVENT_APPLICATION_RETURN",
            [0x00020005] = "SIPAEVENT_BITLOCKER_UNLOCK",
            [0x00020006] = "SIPAEVENT_EVENTCOUNTER",
            [0x00020007] = "SIPAEVENT_COUNTERID",
            [0x00020008] = "SIPAEVENT_MORBIT_NOT_CANCELABLE",
            [0x00020009] = "SIPAEVENT_APPLICATION_SVN",
            [0x0002000A] = "SIPAEVENT_SVN_CHAIN_STATUS",
            [0x0002000B] = "SIPAEVENT_MORBIT_API_STATUS",
            [0x0002000C] = "SIPAEVENT_IDK_GENERATION_STATUS",

            // ── SIPAEVENTTYPE_PREOSPARAMETER (0x0004xxxx) ──
            // 参考: https://github.com/mattifestation/TCGLogTools
            [0x00040001] = "SIPAEVENT_BOOTDEBUGGING",
            [0x00040002] = "SIPAEVENT_BOOTREVOCATIONLIST",

            // ── SIPAEVENTTYPE_OSPARAMETER (0x0005xxxx) ──
            // 参考: https://github.com/mattifestation/TCGLogTools
            [0x00050001] = "SIPAEVENT_OSKERNELDEBUG",
            [0x00050002] = "SIPAEVENT_CODEINTEGRITY",
            [0x00050003] = "SIPAEVENT_TESTSIGNING",
            [0x00050004] = "SIPAEVENT_DATAEXECUTIONPREVENTION",
            [0x00050005] = "SIPAEVENT_SAFEMODE",
            [0x00050006] = "SIPAEVENT_WINPE",
            [0x00050007] = "SIPAEVENT_PHYSICALADDRESSEXTENSION",
            [0x00050008] = "SIPAEVENT_OSDEVICE",
            [0x00050009] = "SIPAEVENT_SYSTEMROOT",
            [0x0005000A] = "SIPAEVENT_HYPERVISOR_LAUNCH_TYPE",
            [0x0005000B] = "SIPAEVENT_HYPERVISOR_PATH",
            [0x0005000C] = "SIPAEVENT_HYPERVISOR_IOMMU_POLICY",
            [0x0005000D] = "SIPAEVENT_HYPERVISOR_DEBUG",
            [0x0005000E] = "SIPAEVENT_DRIVER_LOAD_POLICY",
            [0x0005000F] = "SIPAEVENT_SI_POLICY",
            [0x00050010] = "SIPAEVENT_HYPERVISOR_MMIO_NX_POLICY",
            [0x00050011] = "SIPAEVENT_HYPERVISOR_MSR_FILTER_POLICY",
            [0x00050012] = "SIPAEVENT_VSM_LAUNCH_TYPE",
            [0x00050013] = "SIPAEVENT_OS_REVOCATION_LIST",
            [0x00050014] = "SIPAEVENT_SMT_STATUS",
            [0x00050020] = "SIPAEVENT_VSM_IDK_INFO",
            [0x00050021] = "SIPAEVENT_FLIGHTSIGNING",
            [0x00050022] = "SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED",
            [0x00050023] = "SIPAEVENT_VSM_IDKS_INFO",
            [0x00050024] = "SIPAEVENT_HIBERNATION_DISABLED",
            [0x00050025] = "SIPAEVENT_DUMPS_DISABLED",
            [0x00050026] = "SIPAEVENT_DUMP_ENCRYPTION_ENABLED",
            [0x00050027] = "SIPAEVENT_DUMP_ENCRYPTION_KEY_DIGEST",
            [0x00050028] = "SIPAEVENT_LSAISO_CONFIG",
            [0x00050029] = "SIPAEVENT_SBCP_INFO",
            [0x00050030] = "SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION",
            [0x00050031] = "SIPAEVENT_SI_POLICY_SIGNER",
            [0x00050032] = "SIPAEVENT_SI_POLICY_UPDATE_SIGNER",
            [0x00050033] = "SIPAEVENT_REFS_VOLUME_CHECKPOINT_RECORD_CHECKSUM",
            [0x00050034] = "SIPAEVENT_REFS_ROLLBACK_PROTECTION_FROZEN_VOLUME_CHECKSUM",
            [0x00050035] = "SIPAEVENT_REFS_ROLLBACK_PROTECTION_USER_PAYLOAD_HASH",
            [0x00050036] = "SIPAEVENT_REFS_ROLLBACK_PROTECTION_VERIFICATION_SUCCEEDED",
            [0x00050037] = "SIPAEVENT_REFS_ROLLBACK_PROTECTION_VOLUME_FIRST_EVER_MOUNT",
            [0x0005003A] = "SIPAEVENT_VSM_SEALED_SI_POLICY",
            [0x0005003B] = "SIPAEVENT_VSM_DRTM_KEYROLL_DETECTED",
            [0x0005003C] = "SIPAEVENT_VSM_SRTM_UNSEAL_POLICY",
            [0x0005003D] = "SIPAEVENT_VSM_SRTM_ANTI_ROLLBACK_COUNTER",
            [0x00050040] = "SIPAEVENT_VTL1_DUMP_CONFIG",

            // ── SIPAEVENTTYPE_AUTHORITY (0x0006xxxx) ──
            [0x00060001] = "SIPAEVENT_NOAUTHORITY",
            [0x00060002] = "SIPAEVENT_AUTHORITYPUBKEY",

            // ── SIPAEVENTTYPE_LOADEDMODULE (0x0007xxxx) ──
            [0x00070001] = "SIPAEVENT_FILEPATH",
            [0x00070002] = "SIPAEVENT_IMAGESIZE",
            [0x00070003] = "SIPAEVENT_HASHALGORITHMID",
            [0x00070004] = "SIPAEVENT_AUTHENTICODEHASH",
            [0x00070005] = "SIPAEVENT_AUTHORITYISSUER",
            [0x00070006] = "SIPAEVENT_AUTHORITYSERIAL",
            [0x00070007] = "SIPAEVENT_IMAGEBASE",
            [0x00070008] = "SIPAEVENT_AUTHORITYPUBLISHER",
            [0x00070009] = "SIPAEVENT_AUTHORITYSHA1THUMBPRINT",
            [0x0007000A] = "SIPAEVENT_IMAGEVALIDATED",
            [0x0007000B] = "SIPAEVENT_MODULE_SVN",
            [0x0007000C] = "SIPAEVENT_MODULE_HSP",   // wbcl.h (NTDDI_WIN10_NI)

            // ── SIPAEVENTTYPE_VBS (0x000Axxxx) ──
            [0x000A0001] = "SIPAEVENT_VBS_VSM_REQUIRED",
            [0x000A0002] = "SIPAEVENT_VBS_SECUREBOOT_REQUIRED",
            [0x000A0003] = "SIPAEVENT_VBS_IOMMU_REQUIRED",
            [0x000A0004] = "SIPAEVENT_VBS_MMIO_NX_REQUIRED",
            [0x000A0005] = "SIPAEVENT_VBS_MSR_FILTERING_REQUIRED",
            [0x000A0006] = "SIPAEVENT_VBS_MANDATORY_ENFORCEMENT",
            [0x000A0007] = "SIPAEVENT_VBS_HVCI_POLICY",
            [0x000A0008] = "SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED",
            [0x000A0009] = "SIPAEVENT_VBS_DUMP_USES_AMEROOT",
            [0x000A000A] = "SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED",

            // ── SIPAEVENTTYPE_TRUSTPOINT (0x8008xxxx, 带 NONMEASURED 标志位, wbcl.h) ──
            [0x80080001] = "SIPAEVENT_QUOTE",
            [0x80080002] = "SIPAEVENT_QUOTESIGNATURE",
            [0x80080003] = "SIPAEVENT_AIKID",
            [0x80080004] = "SIPAEVENT_AIKPUBDIGEST",

            // ── SIPAEVENTTYPE_ELAM (0x0009xxxx) ──
            [0x00090001] = "SIPAEVENT_ELAM_KEYNAME",
            [0x00090002] = "SIPAEVENT_ELAM_CONFIGURATION",
            [0x00090003] = "SIPAEVENT_ELAM_POLICY",
            [0x00090004] = "SIPAEVENT_ELAM_MEASURED",

            // ── SIPAEVENTTYPE_DRTM (0x000Cxxxx, wbcl.h RS5+) ──
            // DRTM_STATE_AUTH 由 TcbLaunch.exe 测量到 PCR20; SMM_LEVEL 为单字节 (PCR20)
            [0x000C0001] = "SIPAEVENT_DRTM_STATE_AUTH",
            [0x000C0002] = "SIPAEVENT_DRTM_SMM_LEVEL",
            [0x000C0003] = "SIPAEVENT_DRTM_AMD_SMM_HASH",
            [0x000C0004] = "SIPAEVENT_DRTM_AMD_SMM_SIGNER_KEY",

            // ── SIPAEVENTTYPE_KSR (0x000Bxxxx, wbcl.h RS3+) ──
            [0x000B0001] = "SIPAEVENT_KSR_SIGNATURE",

            // 注意: 旧版映射中的 0x00080001(QUOTE), 0x00090001(IOMMU_DMA_PROTECTION),
            // 0x000C0001(BITLOCKER_UNLOCK) 以及 0x000E0001-0x001B0001 "Legacy" ID 均为虚构，
            // wbcl.h 中不存在，已按 wbcl.h 全部移除。
            // BitLocker unlock = 0x00020005, TrustPoint = 0x8008xxxx。

            // ── SIPAEVENTTYPE_CONTAINER (0x4001xxxx / 0xC0010004, wbcl.h) ──
            // TRUSTPOINT_AGGREGATION 带 NONMEASURED 标志 → 0x80000000+0x40000000+0x00010000+4 = 0xC0010004
            [0x40010001] = "SIPAEVENT_TRUSTBOUNDARY",
            [0x40010002] = "SIPAEVENT_ELAM_AGGREGATION",
            [0x40010003] = "SIPAEVENT_LOADEDMODULE_AGGREGATION",
            [0xC0010004] = "SIPAEVENT_TRUSTPOINT_AGGREGATION",
            [0x40010005] = "SIPAEVENT_KSR_AGGREGATION",
            [0x40010006] = "SIPAEVENT_KSR_SIGNED_MEASUREMENT_AGGREGATION",
        };
        public static string GetName(uint id) =>
            Names.TryGetValue(id, out var n) ? n : $"SIPAEVENT_UNKNOWN(0x{id:X8})";
    }

    public static class WbclParser
    {
        public static List<WbclTaggedEvent> ParseAll(TcgEventLog log)
        {
            var results = new List<WbclTaggedEvent>();

            foreach (var evt in log.Events)
            {
                // EV_EVENT_TAG (0x06) tagged events:
                // PCR 11-14 = WBCL (Windows); PCR 19/20 = DRTM tagged events
                // (SIPAEVENT_DRTM_STATE_AUTH / SMM_LEVEL 由 TcbLaunch.exe 测量, wbcl.h)
                if (evt.EventType != 0x00000006) continue;
                if (evt.PcrIndex < 11 || evt.PcrIndex > 22) continue;

                var tagged = ParseTaggedEvents(evt.EventData, evt.Index, evt.PcrIndex);
                results.AddRange(tagged);
            }

            // Recursively expand aggregation containers:
            // TrustBoundary(0x40010001) 内部还嵌套 LoadedModuleAggregation(0x40010003)、
            // ELAMAggregation(0x40010002) 等子容器 (psm1 Get-SIPAEventData 同样递归展开)
            var expanded = new List<WbclTaggedEvent>();
            var toProcess = new Queue<WbclTaggedEvent>(results);
            while (toProcess.Count > 0)
            {
                var r = toProcess.Dequeue();
                expanded.Add(r);
                if (r.EventId is 0x40010001 or 0x40010002 or 0x40010003 or 0x40010005 or 0x40010006 or 0xC0010004)
                {
                    foreach (var nested in ParseTaggedEvents(r.EventData, r.SourceEventIndex, r.SourcePcr))
                        toProcess.Enqueue(nested);
                }
            }

            return expanded;
        }

        private static List<WbclTaggedEvent> ParseTaggedEvents(
            byte[] data, int sourceIndex, uint sourcePcr)
        {
            var list = new List<WbclTaggedEvent>();
            if (data == null || data.Length < 8) return list;

            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms);

            while (ms.Position + 8 <= ms.Length)
            {
                uint eventId = br.ReadUInt32();
                uint eventSize = br.ReadUInt32();

                if (ms.Position + eventSize > ms.Length) break;
                byte[] eventData = br.ReadBytes((int)eventSize);

                var tag = new WbclTaggedEvent
                {
                    EventId = eventId,
                    EventSize = eventSize,
                    EventData = eventData,
                    SourceEventIndex = sourceIndex,
                    SourcePcr = sourcePcr,
                    InterpretedValue = InterpretEvent(eventId, eventData),
                };
                list.Add(tag);
            }

            return list;
        }

        private static string? InterpretEvent(uint eventId, byte[] data)
        {
            try
            {
                switch (eventId)
                {
                    // ── Boolean flags (1 byte: 0=false, 1=true) ──
                    case 0x00040001: // BOOTDEBUGGING
                    case 0x00050001: // OSKERNELDEBUG
                    case 0x00050002: // CODEINTEGRITY
                    case 0x00050003: // TESTSIGNING
                    case 0x00050005: // SAFEMODE
                    case 0x00050006: // WINPE
                    case 0x0005000D: // HYPERVISOR_DEBUG
                    case 0x00050021: // FLIGHTSIGNING
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Disabled/Off" : "Enabled/On";
                        break;

                    // ── SIPAEVENT_ELAM_KEYNAME (0x00090001, wbcl.h) — Unicode 字符串 ──
                    case 0x00090001:
                        // UTF-16LE: 不能用"第一个 0x00 字节"截断（每个 ASCII 字符低字节就是 0x00），
                        // 整段解码后去掉结尾的 NUL
                        if (data.Length >= 2)
                            return DecodeUtf16(data);
                        break;

                    // ── Hypervisor Launch Type ──
                    case 0x0005000A: // SIPAEVENT_HYPERVISOR_LAUNCH_TYPE
                        if (data.Length >= 4)
                        {
                            uint launchType = BitConverter.ToUInt32(data, 0);
                            return launchType switch
                            {
                                0 => "NotLaunched",
                                1 => "Launched (Hyper-V active)",
                                2 => "LaunchedWithVirtualization",
                                _ => $"Unknown(0x{launchType:X8})"
                            };
                        }
                        break;

                    // ── VBS (Virtualization Based Security) ──
                    // 注意: wbcl.h 中不存在 0x00110001/0x00120001/0x00150001 等 "Legacy" ID，
                    // 相关解释 case 已随虚构 ID 一并删除。

                    // ── Transfer Control (boot loader handoff) ──
                    case 0x00060001:
                        if (data.Length >= 16)
                        {
                            // GUID identifying the component receiving control
                            var guid = new Guid(
                                BitConverter.ToUInt32(data, 0),
                                BitConverter.ToUInt16(data, 4),
                                BitConverter.ToUInt16(data, 6),
                                data[8], data[9], data[10], data[11],
                                data[12], data[13], data[14], data[15]);
                            return $"HandoffTo={guid}";
                        }
                        break;

                    // ── String types ──
                    case 0x000A0001: // PLATFORM_FIRMWARE_BLOB / VBS_VSM_REQUIRED (overlap)
                        if (data.Length > 0)
                        {
                            // If it's 1 byte, it's VBS_VSM_REQUIRED (boolean), otherwise it's string
                            if (data.Length == 1)
                                return data[0] == 0 ? "VBS VSM: Not Required/Disabled" : "VBS VSM: Required/Enabled";

                            int nullPos = Array.IndexOf(data, (byte)0);
                            int len = nullPos >= 0 ? nullPos : data.Length;
                            return Encoding.UTF8.GetString(data, 0, Math.Min(len, 64));
                        }
                        break;

                    // ── SIPAEVENTTYPE_INFORMATION (0x0002xxxx) ──
                    case 0x00020002: // SIPAEVENT_BOOTCOUNTER
                        if (data.Length >= 4)
                        {
                            uint counter = BitConverter.ToUInt32(data, 0);
                            return $"BootCounter={counter}";
                        }
                        break;
                    case 0x00020006: // SIPAEVENT_EVENTCOUNTER
                        if (data.Length >= 8)
                        {
                            ulong counter = BitConverter.ToUInt64(data, 0);
                            return $"EventCounter={counter}";
                        }
                        break;
                    case 0x00020007: // SIPAEVENT_COUNTERID
                        if (data.Length >= 8)
                        {
                            ulong counterId = BitConverter.ToUInt64(data, 0);
                            return $"CounterId=0x{counterId:X16}";
                        }
                        break;
                    case 0x00020008: // SIPAEVENT_MORBIT_NOT_CANCELABLE
                        if (data.Length >= 1)
                            return data[0] == 0 ? "MOR: Cancelable" : "MOR: Not Cancelable";
                        break;
                    case 0x00020009: // SIPAEVENT_APPLICATION_SVN
                        if (data.Length >= 4)
                        {
                            uint svn = BitConverter.ToUInt32(data, 0);
                            return $"SVN={svn}";
                        }
                        break;
                    case 0x00020005: // SIPAEVENT_BITLOCKER_UNLOCK
                        if (data.Length >= 1)
                            return data[0] == 0 ? "BitLocker: Not Unlocked" : "BitLocker: Unlocked";
                        break;

                    // ── SIPAEVENTTYPE_OSPARAMETER (0x0005xxxx) ──
                    case 0x00050004: // SIPAEVENT_DATAEXECUTIONPREVENTION
                        if (data.Length >= 4)
                        {
                            uint dep = BitConverter.ToUInt32(data, 0);
                            return dep switch
                            {
                                0 => "DEP: Disabled",
                                1 => "DEP: Enabled (OptIn)",
                                2 => "DEP: Enabled (OptOut)",
                                3 => "DEP: AlwaysOn",
                                _ => $"DEP=0x{dep:X8}"
                            };
                        }
                        break;
                    case 0x00050022: // SIPAEVENT_PAGEFILE_ENCRYPTION_ENABLED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Pagefile Encryption: Disabled" : "Pagefile Encryption: Enabled";
                        break;
                    case 0x00050024: // SIPAEVENT_HIBERNATION_DISABLED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Hibernation: Enabled" : "Hibernation: Disabled";
                        break;
                    case 0x00050025: // SIPAEVENT_DUMPS_DISABLED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Crash Dumps: Enabled" : "Crash Dumps: Disabled";
                        break;
                    case 0x00050026: // SIPAEVENT_DUMP_ENCRYPTION_ENABLED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Dump Encryption: Disabled" : "Dump Encryption: Enabled";
                        break;
                    case 0x00050030: // SIPAEVENT_HYPERVISOR_BOOT_DMA_PROTECTION (wbcl.h: BOOLEAN)
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Boot DMA Protection: Disabled" : "Boot DMA Protection: Enabled";
                        break;
                    case 0x0005000E: // SIPAEVENT_DRIVER_LOAD_POLICY
                        // 值语义 (learn.microsoft.com elam-driver-requirements, PNP_INITIALIZE_*):
                        // 0=Good only, 1=Good+Unknown, 3=Good+Unknown+Bad Critical, 7=All
                        // 判定规则 (SecurityFeatureAnalyzer): 必须 <=1，>=2 允许带毒驱动启动 → 削弱
                        if (data.Length >= 4)
                        {
                            uint policy = BitConverter.ToUInt32(data, 0);
                            return policy switch
                            {
                                0 => "Good only (PNP_INITIALIZE_DRIVERS_DEFAULT)",
                                1 => "Good + Unknown (PNP_INITIALIZE_UNKNOWN_DRIVERS)",
                                3 => "Good + Unknown + Bad Critical (PNP_INITIALIZE_BAD_CRITICAL_DRIVERS)",
                                7 => "All (PNP_INITIALIZE_BAD_DRIVERS)",
                                _ => $"Policy=0x{policy:X8}"
                            };
                        }
                        break;

                    // ── SIPAEVENTTYPE_LOADEDMODULE (0x0007xxxx) ──
                    case 0x00070001: // SIPAEVENT_FILEPATH
                    case 0x00070008: // SIPAEVENT_AUTHORITYPUBLISHER
                        // UTF-16LE: 整段解码后去掉结尾 NUL（不能用"第一个 0x00 字节"截断）
                        if (data.Length > 0)
                            return DecodeUtf16(data);
                        break;
                    case 0x00070002: // SIPAEVENT_IMAGESIZE
                        if (data.Length >= 4)
                        {
                            uint size = BitConverter.ToUInt32(data, 0);
                            return $"Size={size:N0} bytes";
                        }
                        break;
                    case 0x00070003: // SIPAEVENT_HASHALGORITHMID
                        if (data.Length >= 2)
                        {
                            ushort algId = BitConverter.ToUInt16(data, 0);
                            return $"HashAlg={TcgAlgorithmId.GetName(algId)}";
                        }
                        break;
                    case 0x00070007: // SIPAEVENT_IMAGEBASE
                        if (data.Length >= 8)
                        {
                            ulong baseAddr = BitConverter.ToUInt64(data, 0);
                            return $"ImageBase=0x{baseAddr:X16}";
                        }
                        break;
                    case 0x0007000A: // SIPAEVENT_IMAGEVALIDATED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Not Validated" : "Successfully Validated";
                        break;
                    case 0x0007000B: // SIPAEVENT_MODULE_SVN
                        if (data.Length >= 4)
                        {
                            uint svn = BitConverter.ToUInt32(data, 0);
                            return $"Module SVN={svn}";
                        }
                        break;
                    case 0x0007000C: // SIPAEVENT_MODULE_HSP (wbcl.h NTDDI_WIN10_NI)
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Not Validated by HSP" : "Validated by HSP";
                        break;

                    // ── SIPAEVENTTYPE_VBS (0x000Axxxx except 000A0001 which handled above) ──
                    case 0x000A0002: // SIPAEVENT_VBS_SECUREBOOT_REQUIRED
                    case 0x000A0003: // SIPAEVENT_VBS_IOMMU_REQUIRED
                    case 0x000A0004: // SIPAEVENT_VBS_MMIO_NX_REQUIRED
                    case 0x000A0005: // SIPAEVENT_VBS_MSR_FILTERING_REQUIRED
                    case 0x000A0006: // SIPAEVENT_VBS_MANDATORY_ENFORCEMENT
                    case 0x000A0007: // SIPAEVENT_VBS_HVCI_POLICY
                    case 0x000A0008: // SIPAEVENT_VBS_MICROSOFT_BOOT_CHAIN_REQUIRED
                    case 0x000A0009: // SIPAEVENT_VBS_DUMP_USES_AMEROOT
                    case 0x000A000A: // SIPAEVENT_VBS_VSM_NOSECRETS_ENFORCED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Not Required/Disabled" : "Required/Enabled";
                        break;

                    // ── SIPAEVENTTYPE_ELAM (0x0009xxxx except 00090001 handled above) ──
                    case 0x00090003: // SIPAEVENT_ELAM_POLICY
                        if (data.Length >= 4)
                        {
                            uint policy = BitConverter.ToUInt32(data, 0);
                            return policy switch
                            {
                                0 => "Disabled",
                                1 => "Enabled (Auto)",
                                2 => "Enabled (Force)",
                                _ => $"Policy=0x{policy:X8}"
                            };
                        }
                        break;
                    case 0x00090004: // SIPAEVENT_ELAM_MEASURED
                        if (data.Length >= 1)
                            return data[0] == 0 ? "Not Measured" : "Measured by ELAM";
                        break;

                    // ── SIPAEVENTTYPE_DRTM (0x000Cxxxx, wbcl.h RS5+) ──
                    case 0x000C0001: // SIPAEVENT_DRTM_STATE_AUTH (PCR20, TcbLaunch.exe)
                        // payload 为 TPM_API_PA_DIRECT_AUTHORIZATION_1（含对 DRTM 状态的签名），
                        // 不是简单的状态枚举 → 只描述结构，不做状态解读
                        return $"DRTM state authorization payload ({data.Length} bytes)";
                    case 0x000C0002: // SIPAEVENT_DRTM_SMM_LEVEL (单字节 SI_DRTM_SMM_LEVEL, PCR20)
                        if (data.Length >= 1)
                            return $"SMM Protection Level={data[0]} (SI_DRTM_SMM_LEVEL)";
                        break;

                    // ── Windows WBCL 聚合容器 (0x4001xxxx, wbcl.h) ──
                    case 0x40010001: // SIPAEVENT_TRUSTBOUNDARY
                        return $"TrustBoundary container, {data.Length / 8} nested events";
                    case 0x40010003: // SIPAEVENT_LOADEDMODULE_AGGREGATION
                        return $"Loaded Module Aggregation: {data.Length} bytes of aggregated measurements";
                    case 0x40010004: // SIPAEVENT_LOADEDMODULE_AGGREGATION_V2
                        return $"Loaded Module Aggregation V2: {data.Length} bytes";
                    case 0x40010002: // SIPAEVENT_TRUSTBOUNDARY
                        if (data.Length >= 4)
                        {
                            uint boundary = BitConverter.ToUInt32(data, 0);
                            return boundary == 0 ? "TrustBoundary: Exit" : "TrustBoundary: Enter";
                        }
                        break;

                    // ── Authority Public Key ──
                    case 0x00060002: // SIPAEVENT_AUTHORITYPUBKEY
                        if (data.Length >= 32)
                        {
                            return $"SHA256={Convert.ToHexString(data.AsSpan(0, 32)).ToLowerInvariant()}";
                        }
                        else if (data.Length >= 20)
                        {
                            return $"SHA1={Convert.ToHexString(data.AsSpan(0, 20)).ToLowerInvariant()}";
                        }
                        break;

                    // ── OSPARAMETER common 32-bit value cases ──
                    case 0x00050012: // SIPAEVENT_VSM_LAUNCH_TYPE
                        if (data.Length >= 4)
                        {
                            uint type = BitConverter.ToUInt32(data, 0);
                            return type switch
                            {
                                0 => "VSM: Not Launched",
                                1 => "VSM: Launched (Early)",
                                2 => "VSM: Launched (Late)",
                                _ => $"VSM LaunchType=0x{type:X8}"
                            };
                        }
                        break;
                    case 0x00050014: // SIPAEVENT_SMT_STATUS
                        if (data.Length >= 1)
                            return data[0] == 0 ? "SMT: Disabled" : "SMT: Enabled";
                        break;
                    case 0x0005003D: // SIPAEVENT_VSM_SRTM_ANTI_ROLLBACK_COUNTER
                        if (data.Length >= 4)
                        {
                            uint counter = BitConverter.ToUInt32(data, 0);
                            return $"Anti-Rollback Counter={counter}";
                        }
                        break;
                }
            }
            catch { /* ignore parse errors in individual events */ }

            // Fallback: hex dump (first 16 bytes)
            if (data.Length == 0) return "(empty)";
            int dumpLen = Math.Min(data.Length, 16);
            return $"0x{Convert.ToHexString(data, 0, dumpLen)}{(data.Length > 16 ? "..." : "")}";
        }

        /// <summary>
        /// 解码 UTF-16LE 字符串（FilePath / ELAM Keyname / SystemRoot 等）。
        /// 整段解码后去掉结尾的 NUL——不能用"第一个 0x00 字节"截断，
        /// 因为 UTF-16LE 中每个 ASCII 字符的低字节就是 0x00。
        /// </summary>
        private static string DecodeUtf16(byte[] data)
        {
            int len = data.Length & ~1; // 对齐到 2 字节
            return Encoding.Unicode.GetString(data, 0, len).TrimEnd('\0');
        }
    }
}