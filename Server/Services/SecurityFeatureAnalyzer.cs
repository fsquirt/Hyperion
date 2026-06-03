using System.Buffers.Binary;
using System.Text;
using SEWindows.Server.Models;

namespace SEWindows.Server.Services;

/// <summary>
/// 安全特性分析器（9 项分析：SecureBoot / 虚拟化 / IOMMU / HVCI-VBS / 驱动签名 / 阻断列表 / 启动完整性 / ELAM / DRTM）
/// </summary>
public static class SecurityFeatureAnalyzer
{
    // ═══════════════════════════════════════════════════════════════
    //  事件类型常量
    // ═══════════════════════════════════════════════════════════════

    private const uint EV_NO_ACTION     = 0x00000003;
    private const uint EV_SEPARATOR     = 0x00000004;
    private const uint EV_COMPACT_HASH  = 0x0000000C;
    private const uint EV_EVENT_TAG     = 0x00000006;
    private const uint EV_EFI_VAR_CFG   = 0x80000001;
    private const uint EV_EFI_VAR_BOOT  = 0x80000002;
    private const uint EV_EFI_VAR_AUTH  = 0x800000E0;
    private const uint EV_EFI_BLOB      = 0x80000008;
    private const uint EV_EFI_BLOB2     = 0x8000000A;
    private const uint EV_EFI_HANDOFF   = 0x80000009;
    private const uint EV_EFI_HANDOFF2  = 0x8000000B;
    private const uint EV_EFI_GPT_EVENT = 0x80000006;

    private static readonly Guid EFI_GLOBAL_GUID = new("8BE4DF61-93CA-11D2-AA0D-00E098032B8C");

    // 聚合容器 ID
    private static readonly HashSet<uint> AggregationIds =
    [
        0x40010001, 0x40010003, 0x40010004, 0x40010005, 0x40010006, 0x000F0001
    ];

    // ═══════════════════════════════════════════════════════════════
    //  主入口
    // ═══════════════════════════════════════════════════════════════

    public static List<SecurityFeature> Analyze(ParseResult pr)
    {
        var sipa = ParseSipa(pr);
        return
        [
            FeatSecureBoot(pr, sipa),
            FeatVirtualization(pr, sipa),
            FeatIommu(pr, sipa),
            FeatHvci(pr, sipa),
            FeatDriverSig(pr, sipa),
            FeatBlocklist(pr, sipa),
            FeatBootIntegrity(pr, sipa),
            FeatElam(pr, sipa),
            FeatDrtm(pr, sipa),
        ];
    }

    // ═══════════════════════════════════════════════════════════════
    //  SIPA 事件解析
    // ═══════════════════════════════════════════════════════════════

    internal static List<SipaEv> ParseSipa(ParseResult pr)
    {
        var result = new List<SipaEv>();
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr is < 12 or > 14) continue;
            if (ev.Data.Length < 8) continue;
            if (ev.EType != EV_EVENT_TAG) continue;
            result.AddRange(ParseSipaTlvs(ev.Data, ev.Pcr, ev.Index));
        }
        return result;
    }

    private static List<SipaEv> ParseSipaTlvs(byte[] raw, uint pcr, int idx)
    {
        var result = new List<SipaEv>();
        var pos = 0;
        while (pos + 8 <= raw.Length)
        {
            var eid = BitConverter.ToUInt32(raw, pos); pos += 4;
            var dsz = BitConverter.ToUInt32(raw, pos); pos += 4;
            if (pos + (int)dsz > raw.Length) break;
            var data = raw[pos..(pos + (int)dsz)]; pos += (int)dsz;

            var sipa = new SipaEv { Eid = eid, Data = data, Pcr = pcr, Idx = idx };
            result.Add(sipa);

            // 递归解析聚合容器
            if (AggregationIds.Contains(eid) && data.Length >= 8)
                result.AddRange(ParseSipaTlvs(data, pcr, idx));
        }
        return result;
    }

    private static SipaEv? S1(List<SipaEv> sipa, params uint[] ids)
    {
        var idSet = new HashSet<uint>(ids);
        return sipa.FirstOrDefault(s => idSet.Contains(s.Eid));
    }

    private static List<SipaEv> SAll(List<SipaEv> sipa, params uint[] ids)
    {
        var idSet = new HashSet<uint>(ids);
        return sipa.Where(s => idSet.Contains(s.Eid)).ToList();
    }

    // ═══════════════════════════════════════════════════════════════
    //  EFI 变量解析
    // ═══════════════════════════════════════════════════════════════

    private static (Guid guid, string name, byte[] data)? ParseEfiVar(byte[] raw)
    {
        if (raw.Length < 32) return null;
        try
        {
            var d1 = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(0));
            var d2 = BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(4));
            var d3 = BinaryPrimitives.ReadUInt16LittleEndian(raw.AsSpan(6));
            var d4 = raw[8..16];
            var guid = new Guid((int)d1, (short)d2, (short)d3, d4);

            var nameLen = (int)BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(16));
            var dataLen = (int)BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(24));
            if (raw.Length < 32 + nameLen * 2 + dataLen) return null;

            var name = Encoding.Unicode.GetString(raw, 32, nameLen * 2).TrimEnd('\0');
            var data = raw[(32 + nameLen * 2)..(32 + nameLen * 2 + dataLen)];
            return (guid, name, data);
        }
        catch { return null; }
    }

    private static (EvRec ev, Guid guid, string name, byte[] data)? FindEfiVar(
        ParseResult pr, uint[]? pcrs = null, string? exact = null,
        string[]? kw = null, bool needGlobal = false)
    {
        foreach (var ev in pr.Events)
        {
            if (ev.EType is not (EV_EFI_VAR_CFG or EV_EFI_VAR_BOOT or EV_EFI_VAR_AUTH))
                continue;
            if (pcrs != null && !pcrs.Contains(ev.Pcr)) continue;

            var parsed = ParseEfiVar(ev.Data);
            if (parsed == null) continue;

            var (guid, name, data) = parsed.Value;
            if (needGlobal && guid != EFI_GLOBAL_GUID) continue;
            if (exact != null && !name.Equals(exact, StringComparison.OrdinalIgnoreCase)) continue;
            if (kw != null && !kw.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase))) continue;

            return (ev, guid, name, data);
        }
        return null;
    }

    // ═══════════════════════════════════════════════════════════════
    //  事件数据解码辅助
    // ═══════════════════════════════════════════════════════════════

    private static string Blob2Name(byte[] raw)
    {
        if (raw.Length < 1) return "";
        var nameLen = raw[0];
        if (raw.Length < 1 + nameLen) return "";
        return Encoding.UTF8.GetString(raw, 1, nameLen);
    }

    private static string BlobName(byte[] raw)
    {
        if (raw.Length < 16) return "";
        var addr = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(0));
        var len = BinaryPrimitives.ReadUInt64LittleEndian(raw.AsSpan(8));
        return $"blob@0x{addr:X}:0x{len:X}";
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 1: Secure Boot
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatSecureBoot(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Secure Boot" };
        var found = FindEfiVar(pr, pcrs: [7], exact: "SecureBoot", needGlobal: true);
        if (found == null)
            return result with { Status = FeatureStatus.NotMeasured };

        var data = found.Value.data;
        var enabled = data.Length > 0 && data[0] == 1;

        // 检查 PK/KEK/db/dbx
        var details = new List<string>();
        foreach (var name in new[] { "PK", "KEK", "db", "dbx" })
        {
            var v = FindEfiVar(pr, pcrs: [7], exact: name);
            if (v != null)
                details.Add($"{name}={v.Value.data.Length}B");
        }

        return result with
        {
            Status = enabled ? FeatureStatus.Enabled : FeatureStatus.Disabled,
            Evidence = $"SecureBoot byte={data[0]}",
            Detail = details.Count > 0 ? string.Join(", ", details) : ""
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 2: CPU Virtualization
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatVirtualization(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "CPU Virtualization (VT-x / AMD-V)" };

        // 策略 1: EFI 变量
        var virtVar = FindEfiVar(pr, kw: ["Virt", "VMX", "SVM"]);
        if (virtVar != null)
        {
            var enabled = virtVar.Value.data.Length > 0 && virtVar.Value.data[0] != 0;
            return result with
            {
                Status = enabled ? FeatureStatus.Enabled : FeatureStatus.Disabled,
                Evidence = $"EFI var: {virtVar.Value.name}"
            };
        }

        // 策略 2: PCR0 中的 BLOB2 事件
        bool hasBlobs = false;
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr != 0 || ev.EType != EV_EFI_BLOB2) continue;
            var name = Blob2Name(ev.Data);
            hasBlobs = true;
            if (name.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("CPUINIT", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("VTD", StringComparison.OrdinalIgnoreCase))
            {
                return result with
                {
                    Status = FeatureStatus.Enabled,
                    Evidence = $"PCR0 BLOB2: {name}"
                };
            }
        }

        // 策略 3: PCR11 Hyper-V 启动标记
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr != 11 || ev.EType != EV_COMPACT_HASH) continue;
            if (ev.Data.Length >= 4 && BitConverter.ToUInt32(ev.Data, 0) == 0x10)
            {
                return result with
                {
                    Status = FeatureStatus.Enabled,
                    Evidence = "PCR11 Hyper-V launch marker (0x10)"
                };
            }
        }

        // PCR11 有事件说明 VBS 活动（需要 VT-x）
        bool pcr11HasEvents = pr.Events.Any(e => e.Pcr == 11 && e.EType != EV_NO_ACTION);
        if (pcr11HasEvents)
        {
            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = "PCR11 has events (VBS active, requires VT-x)"
            };
        }

        if (hasBlobs)
            return result with { Status = FeatureStatus.Unknown, Evidence = "PCR0 BLOB2 present but no VT-x marker" };

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 3: IOMMU
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatIommu(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "IOMMU (VT-d / AMD-Vi)" };

        // 策略 1: EFI 变量
        var iommuVar = FindEfiVar(pr, kw: ["Iommu", "VTd", "DMAR", "DMA"]);
        if (iommuVar != null)
        {
            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = $"EFI var: {iommuVar.Value.name}"
            };
        }

        // 策略 2: PCR0 BLOB2
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr != 0 || ev.EType != EV_EFI_BLOB2) continue;
            var name = Blob2Name(ev.Data);
            if (name.Contains("VTD", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("DMAR", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("IOMMU", StringComparison.OrdinalIgnoreCase))
            {
                return result with { Status = FeatureStatus.Enabled, Evidence = $"PCR0 BLOB2: {name}" };
            }
        }

        // 策略 3: Handoff tables 中的 DMAR/IVRS
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr != 1) continue;
            if (ev.EType is not (EV_EFI_HANDOFF or EV_EFI_HANDOFF2)) continue;
            var sig = Encoding.ASCII.GetString(ev.Data, 0, Math.Min(4, ev.Data.Length));
            if (sig == "DMAR")
                return result with { Status = FeatureStatus.Enabled, Evidence = "PCR1 handoff: DMAR (Intel VT-d)" };
            if (sig == "IVRS")
                return result with { Status = FeatureStatus.Enabled, Evidence = "PCR1 handoff: IVRS (AMD-Vi)" };
        }

        // 策略 4: SIPA IOMMU_DMA_PROTECTION (0x00090001)
        var dma = S1(sipa, 0x00090001);
        if (dma != null && (dma.U8 & 1) != 0)
            return result with { Status = FeatureStatus.Enabled, Evidence = "WBCL IOMMU_DMA_PROTECTION=1" };

        // 策略 5: VBS_IOMMU_REQUIRED (0x00150001)
        var vbsIommu = S1(sipa, 0x00150001);
        if (vbsIommu != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = "WBCL VBS_IOMMU_REQUIRED" };

        // 策略 6: Win11 V2 标签
        foreach (var id in new uint[] { 0x00050010, 0x00050011, 0x00050014 })
        {
            var ev = S1(sipa, id);
            if (ev != null && ev.U8 == 1)
                return result with { Status = FeatureStatus.Enabled, Evidence = $"WBCL 0x{id:X8}=1" };
        }

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 4: HVCI / VBS
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatHvci(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "HVCI / VBS" };

        // 链 1: HypervisorLaunchType (0x00080001 or 0x00020008)
        var hyperLaunch = S1(sipa, 0x00080001, 0x00020008);
        if (hyperLaunch != null)
        {
            var val = hyperLaunch.U32;
            if (val >= 1)
                return result with
                {
                    Status = FeatureStatus.Enabled,
                    Evidence = $"HypervisorLaunchType={val}"
                };
        }

        // 链 2: VBS flags (0x000A0001 or 0x0005000A)
        var vbsFlags = S1(sipa, 0x000A0001, 0x0005000A);
        if (vbsFlags != null)
        {
            var flags = vbsFlags.U32;
            if ((flags & 0x05) != 0)
                return result with
                {
                    Status = FeatureStatus.Enabled,
                    Evidence = $"VBS flags=0x{flags:X} (VBS={(flags & 1) != 0}, HVCI={(flags & 4) != 0})"
                };
        }

        // fallback: VSM launch type (0x00050012)
        var vsmLaunch = S1(sipa, 0x00050012);
        if (vsmLaunch != null && vsmLaunch.U32 >= 1)
            return result with { Status = FeatureStatus.Enabled, Evidence = $"VSM launch type={vsmLaunch.U32}" };

        // 链 3: PCR12 有事件 = VBS 活动
        bool pcr12HasEvents = pr.Events.Any(e => e.Pcr == 12 && e.EType != EV_NO_ACTION && e.EType != EV_SEPARATOR);
        if (pcr12HasEvents)
            return result with { Status = FeatureStatus.Enabled, Evidence = "PCR12 has events (VBS activity)" };

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 5: Driver Signature Enforcement
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatDriverSig(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Driver Signature Enforcement" };
        var evidence = new List<string>();
        bool? enforced = null;

        // TestSigning (0x00050002)
        var testSign = S1(sipa, 0x00050002);
        if (testSign != null)
        {
            if (testSign.U8 == 1) { enforced = false; evidence.Add("TestSigning=ON"); }
            else { enforced = true; evidence.Add("TestSigning=OFF"); }
        }

        // Code Integrity enforcement (0x0005000E)
        var ciEnforce = S1(sipa, 0x0005000E);
        if (ciEnforce != null)
        {
            if (ciEnforce.U32 != 0) { enforced = true; evidence.Add($"CI enforcement={ciEnforce.U32}"); }
        }

        // OS Kernel Debug (0x00040002)
        var kernDbg = S1(sipa, 0x00040002);
        if (kernDbg != null)
        {
            if (kernDbg.U8 == 0) evidence.Add("KernelDebug=disabled");
            else { enforced = false; evidence.Add("KernelDebug=enabled"); }
        }

        // Legacy CI (0x00070001)
        var legacyCi = S1(sipa, 0x00070001);
        if (legacyCi != null && legacyCi.U8 != 0)
        {
            enforced = true;
            evidence.Add("LegacyCI enforced");
        }

        if (evidence.Count == 0) return result;
        return result with
        {
            Status = enforced == true ? FeatureStatus.Enabled :
                     enforced == false ? FeatureStatus.Disabled : FeatureStatus.Unknown,
            Evidence = string.Join("; ", evidence)
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 6: Vulnerable Driver Blocklist
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatBlocklist(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };

        // SIPA 0x00050021
        var blEnabled = S1(sipa, 0x00050021);
        if (blEnabled != null && blEnabled.U8 == 1)
            return result with { Status = FeatureStatus.Enabled, Evidence = "BlocklistEnabled=1" };

        // SIPA 0x00040001 (BootRevocationList)
        var revList = S1(sipa, 0x00040001);
        if (revList != null && revList.Data.Length > 0)
            return result with { Status = FeatureStatus.Enabled, Evidence = "BootRevocationList present" };

        // SIPA 0x00050003 (BootRevocationPolicy)
        var revPolicy = S1(sipa, 0x00050003);
        if (revPolicy != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = "BootRevocationPolicy present" };

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 7: Boot Log Integrity
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatBootIntegrity(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Boot Log Integrity" };

        // 统计 EV_SEPARATOR 事件
        int sepCount = pr.Events.Count(e => e.EType == EV_SEPARATOR);

        // 检查 WBCL terminator (EV_SEPARATOR in PCR 12/13/14 with data == "WBCL")
        bool hasTerminator = pr.Events.Any(e =>
            e.EType == EV_SEPARATOR &&
            e.Pcr is >= 12 and <= 14 &&
            e.Data.Length >= 4 &&
            e.Data.AsSpan(0, 4).SequenceEqual("WBCL"u8));

        var detail = sepCount >= 7 ? "Well-formed" :
                     sepCount >= 4 ? "Partial" : "Incomplete";

        return result with
        {
            Status = sepCount >= 7 ? FeatureStatus.Enabled : FeatureStatus.Unknown,
            Evidence = $"Separators={sepCount}, Terminator={hasTerminator}",
            Detail = detail
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 8: ELAM
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatElam(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Early Launch Anti-Malware (ELAM)" };

        // ELAM policy (0x00090003)
        var policy = S1(sipa, 0x00090003);
        if (policy != null)
        {
            var val = policy.U8;
            if (val == 1)
                return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM policy=Auto enabled" };
            if (val == 2)
                return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM policy=Force enabled" };
            if (val == 0)
                return result with { Status = FeatureStatus.Disabled, Evidence = "ELAM policy=Disabled" };
        }

        // ELAM measured (0x00090004)
        var measured = S1(sipa, 0x00090004);
        if (measured != null && measured.U8 == 1)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM drivers measured" };

        // ELAM Aggregation V2 container (0x40010003)
        var agg = S1(sipa, 0x40010003);
        if (agg != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM Aggregation V2 present" };

        // fallback: any ELAM event in range 0x00090000-0x00090004
        bool hasElamEvents = sipa.Any(s => s.Eid >= 0x00090000 && s.Eid <= 0x00090004);
        if (hasElamEvents)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM events detected" };

        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 9: DRTM
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatDrtm(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Dynamic Root of Trust for Measurement (DRTM)" };

        // DRTM state (0x000C0001)
        var drtmState = S1(sipa, 0x000C0001);
        if (drtmState != null)
        {
            var val = drtmState.U32;
            if (val == 1)
                return result with { Status = FeatureStatus.Enabled, Evidence = "DRTM state=authenticated success" };
            if (val == 0)
                return result with { Status = FeatureStatus.Disabled, Evidence = "DRTM state=not authenticated" };
            return result with { Status = FeatureStatus.Disabled, Evidence = $"DRTM state=failed ({val})" };
        }

        // SMM protection level (0x000C0002)
        var smmLevel = S1(sipa, 0x000C0002);
        if (smmLevel != null)
            return result with { Status = FeatureStatus.Unknown, Evidence = $"SMM protection level={smmLevel.U32}" };

        // VSM DRTM 相关事件
        var vsmDrtm = S1(sipa, 0x0005003B, 0x0005003C, 0x0005003D);
        if (vsmDrtm != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = $"VSM DRTM event 0x{vsmDrtm.Eid:X8}" };

        return result;
    }
}
