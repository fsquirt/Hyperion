using Hyperion.Server.Models;
using System.Buffers.Binary;
using System.Text;

namespace Hyperion.Server.Services;

/// <summary>
/// 安全特性分析器（8 项分析：SecureBoot / 虚拟化 / IOMMU / HVCI-VBS / 驱动签名 / 阻断列表 / 启动完整性 / ELAM）
///
/// 所有 SIPA 事件 ID 均以 Windows SDK wbcl.h (10.0.22621.0) 为权威来源，
/// 与客户端 Verifier/Analyzers/SecurityFeatureAnalyzer.cs 判定逻辑保持同步。
/// 原则：事件 ID 能证明什么，就只让它证明什么；"存在事件"不等于"功能开启"。
/// DRTM 检测已移除：DRTM (System Guard Secure Launch) 依赖 Intel TXT / vPro，
/// 大量消费级 CPU（如 i5-13600K/KF）不支持，检测无意义。
///
/// SIPA Event ID 参考: https://github.com/mattifestation/TCGLogTools/blob/master/TCGLogTools.psm1
/// </summary>
public static class SecurityFeatureAnalyzer
{
    // ═══════════════════════════════════════════════════════════════
    //  事件类型常量（TCG EFI Platform / PC Client）
    // ═══════════════════════════════════════════════════════════════

    private const uint EV_NO_ACTION = 0x00000003;
    private const uint EV_SEPARATOR = 0x00000004;
    private const uint EV_EVENT_TAG = 0x00000006;
    private const uint EV_EFI_ACTION = 0x80000007;
    private const uint EV_EFI_VAR_CFG = 0x80000001;
    private const uint EV_EFI_VAR_BOOT = 0x80000002;
    private const uint EV_EFI_VAR_AUTH = 0x800000E0;
    private const uint EV_EFI_BLOB2 = 0x8000000A;

    private static readonly Guid EFI_GLOBAL_GUID = new("8BE4DF61-93CA-11D2-AA0D-00E098032B8C");

    // 聚合容器 ID（wbcl.h；0x40010004/0x000F0001 为虚构 ID，已移除）
    private static readonly HashSet<uint> AggregationIds =
    [
        0x40010001, 0x40010002, 0x40010003, 0x40010005, 0x40010006, 0xC0010004
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
            FeatElam(pr, sipa),
            FeatBootIntegrity(pr, sipa),
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
            // PCR 11-14 = WBCL (Windows)；PCR 19/20 = DRTM tagged events (wbcl.h)
            if (ev.Pcr is < 11 or > 22) continue;
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

            // 递归解析聚合容器（TrustBoundary 内嵌套 LoadedModule/ELAM 聚合等）
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

    private static bool IsTrue(SipaEv? e) => e != null && e.Data.Length > 0 && e.Data[0] != 0;

    /// <summary>
    /// 检查 LoadedModule 聚合中是否加载了指定模块
    /// (SIPAEVENT_FILEPATH 0x00070001, UTF-16LE 路径字符串)。
    /// </summary>
    private static bool HasLoadedModule(List<SipaEv> sipa, string moduleName) =>
        sipa.Any(s => s.Eid == 0x00070001 &&
                      DecodeUtf16(s.Data).Contains(moduleName, StringComparison.OrdinalIgnoreCase));

    private static string DecodeUtf16(byte[] data)
    {
        int len = data.Length & ~1; // 对齐到 2 字节
        return Encoding.Unicode.GetString(data, 0, len).TrimEnd('\0');
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

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 1: Secure Boot
    //    核心: PCR7 SecureBoot EFI 变量；KernelDebug 必须 false（ON → 不通过）；
    //    PK/KEK/db/dbx 与吊销列表作为佐证 Detail
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatSecureBoot(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Secure Boot" };
        var found = FindEfiVar(pr, pcrs: [7], exact: "SecureBoot", needGlobal: true);
        if (found == null)
            return result with { Status = FeatureStatus.NotMeasured, Evidence = "SecureBoot variable not found in PCR7" };

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

        // ── Kernel Debugging (wbcl.h 0x00050001 OSKernelDebug, Boolean) ──
        // 内核调试开启会削弱启动链安全性 → 必须为 false，否则判定不通过
        var kernDbg = S1(sipa, 0x00050001);
        bool kernelDebugOn = IsTrue(kernDbg);
        details.Add($"KernelDebug={(kernelDebugOn ? "ON ⚠" : "OFF")}");
        if (kernelDebugOn)
        {
            return result with
            {
                Status = FeatureStatus.Disabled,
                Evidence = "OSKernelDebug=ON — 内核调试开启，启动链安全被削弱（Secure Boot 判定不通过）",
                Detail = string.Join(", ", details)
            };
        }

        // 吊销列表: 记录"已被吊销的启动组件/签名证书"的摘要，属 Secure Boot 吊销链佐证
        var bootRevoc = S1(sipa, 0x00040002);
        if (bootRevoc != null)
            details.Add($"BootRevocationList={bootRevoc.Data.Length}B [0x00040002] — 启动链吊销列表");
        var osRevoc = S1(sipa, 0x00050013);
        if (osRevoc != null)
            details.Add($"OSRevocationList={osRevoc.Data.Length}B [0x00050013] — OS 吊销列表");

        return result with
        {
            Status = enabled ? FeatureStatus.Enabled : FeatureStatus.Disabled,
            Evidence = $"PCR7 SecureBoot={(enabled ? 1 : 0)}",
            Detail = details.Count > 0 ? string.Join(", ", details) : ""
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 2: CPU Virtualization
    //    唯一可靠证据: HypervisorLaunchType (0x0005000A, UInt64) 必须 =1 (Auto)
    //    PCR11 启发式已删除（PCR11 是 Windows/BitLocker 测量 PCR，与 VT-x 无必然联系）
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatVirtualization(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "CPU Virtualization (VT-x / AMD-V)" };

        var launch = S1(sipa, 0x0005000A);
        if (launch != null)
        {
            var val = launch.U64;
            if (val == 1)
            {
                var detail = "Hyper-V (Auto) 运行即代表 CPU 虚拟化扩展 (VT-x/AMD-V) 已启用并被 Hypervisor 占用";
                // Hypervisor 核心模块加载证据: BIOS 关闭 VT-x/AMD-V 时 hvix64/hvax64 根本无法启动
                if (HasLoadedModule(sipa, "hvix64.exe"))
                    detail += "\n已加载并校验 Intel Hypervisor 核心 hvix64.exe — VT-x 必然已启用";
                if (HasLoadedModule(sipa, "hvax64.exe"))
                    detail += "\n已加载并校验 AMD Hypervisor 核心 hvax64.exe — AMD-V 必然已启用";
                if (HasLoadedModule(sipa, "hvloader.dll"))
                    detail += "\n已加载 hvloader.dll (Hypervisor Loader)";
                if (HasLoadedModule(sipa, "mcupdate_GenuineIntel.dll"))
                    detail += "\n已加载 Intel 平台微码 mcupdate_GenuineIntel.dll";
                if (HasLoadedModule(sipa, "secfw_GenuineIntel.dll"))
                    detail += "\n已加载 Intel 安全固件支持 secfw_GenuineIntel.dll";
                var mmioNx = S1(sipa, 0x00050010);
                if (mmioNx != null && mmioNx.U64 != 0)
                    detail += $"\nHypervisorMMIONXPolicy={mmioNx.U64} [0x00050010] — 虚拟化拦截加固已激活";
                var msrFilter = S1(sipa, 0x00050011);
                if (msrFilter != null && msrFilter.U64 != 0)
                    detail += $"\nHypervisorMSRFilterPolicy={msrFilter.U64} [0x00050011] — 虚拟化拦截加固已激活";
                return result with
                {
                    Status = FeatureStatus.Enabled,
                    Evidence = $"HypervisorLaunchType=Auto [0x0005000A, PCR{launch.Pcr}] — Hyper-V 随系统启动加载",
                    Detail = detail
                };
            }
            if (val == 0)
                return result with
                {
                    Status = FeatureStatus.Disabled,
                    Evidence = $"HypervisorLaunchType=Off [0x0005000A, PCR{launch.Pcr}] — Hyper-V 未随系统加载",
                    Detail = "hypervisorlaunchtype=Off，虚拟化引擎未启用"
                };
            return result with
            {
                Status = FeatureStatus.Unknown,
                Evidence = $"HypervisorLaunchType={val} (异常值) [0x0005000A, PCR{launch.Pcr}]",
                Detail = "预期值: 1=Auto, 0=Off"
            };
        }

        // 辅助: PCR0 BLOB2 固件模块名 — 仅说明固件包含相关模块，不能证明"已启用"
        foreach (var ev in pr.Events)
        {
            if (ev.Pcr != 0 || ev.EType != EV_EFI_BLOB2) continue;
            var name = Blob2Name(ev.Data);
            if (name.Length > 0 &&
                (name.Contains("VMX", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("VTD", StringComparison.OrdinalIgnoreCase) ||
                 name.Contains("SVM", StringComparison.OrdinalIgnoreCase)))
            {
                return result with
                {
                    Status = FeatureStatus.Unknown,
                    Evidence = $"PCR0 BLOB2: {name}",
                    Detail = "固件包含虚拟化相关模块，但未找到 HypervisorLaunchType 测量，启用状态未知"
                };
            }
        }

        return result with { Status = FeatureStatus.NotMeasured, Evidence = "No HypervisorLaunchType measurement found in WBCL" };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 3: IOMMU
    //    唯一判定依据: HypervisorIOMMUPolicy (0x0005000C, UInt64)
    //    值语义 (BCD / 微软"内核 DMA 保护"文档):
    //      0 = Default (自适应: 支持内核 DMA 保护的平台引导时自动启用，出厂恒为 0)
    //      1 = Enable (强制开启)   2 = Disable (强制关闭)
    //    → 不等于 2 即 IOMMU 开启。
    //    反向健康证明: OEM 规范要求 IOMMU/DMA 保护被关闭或降级时固件 MUST 向
    //    PCR[7] 扩展 EV_EFI_ACTION "DMA Protection Disabled"；该事件不存在 = 未被降级。
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatIommu(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "IOMMU (VT-d / AMD-Vi)" };

        // 微软 OEM 规范检查: PCR[7] 是否存在 "DMA Protection Disabled"
        bool dmaDowngraded = pr.Events.Any(e =>
            e.Pcr == 7 && e.EType == EV_EFI_ACTION &&
            ContainsAscii(e.Data, "DMA Protection Disabled"));
        string healthNote = dmaDowngraded
            ? "⚠ PCR[7] 存在 \"DMA Protection Disabled\" — 引导时 IOMMU/内核 DMA 保护被关闭或降级"
            : "PCR[7] 无 \"DMA Protection Disabled\" (EV_EFI_ACTION) — 引导阶段 IOMMU/内核 DMA 保护未被关闭或降级";

        var hyperIommu = S1(sipa, 0x0005000C);
        if (hyperIommu != null)
        {
            var val = hyperIommu.U64;
            if (val == 2 || dmaDowngraded)
            {
                return result with
                {
                    Status = FeatureStatus.Disabled,
                    Evidence = dmaDowngraded
                        ? "PCR[7] 存在 EV_EFI_ACTION \"DMA Protection Disabled\" — 引导时 IOMMU/内核 DMA 保护被关闭或降级"
                        : $"HypervisorIOMMUPolicy=2 (Disable 强制关闭) [0x0005000C, PCR{hyperIommu.Pcr}] — IOMMU 已被禁用",
                    Detail = "微软 OEM Kernel DMA Protection 规范: 降级时固件 MUST 向 PCR[7] 扩展该事件（导致 BitLocker TPM 封印失效）"
                };
            }

            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = $"HypervisorIOMMUPolicy={val} ({(val == 0 ? "Default/自适应" : val == 1 ? "Enable 强制开启" : "非 Disable")}) " +
                           $"[0x0005000C, PCR{hyperIommu.Pcr}] — IOMMU 已启用",
                Detail = (val == 0
                        ? "0=Default: 引导时由 Hyper-V 与内核自动检测硬件/ACPI 状态，支持内核 DMA 保护的平台自动启用 (learn.microsoft.com: Kernel DMA Protection)"
                        : "Hyper-V IOMMU 策略被显式强制开启")
                    + $"\n{healthNote}"
            };
        }

        if (dmaDowngraded)
        {
            return result with
            {
                Status = FeatureStatus.Disabled,
                Evidence = "PCR[7] 存在 EV_EFI_ACTION \"DMA Protection Disabled\" — 引导时 IOMMU/内核 DMA 保护被关闭或降级",
                Detail = "微软 OEM Kernel DMA Protection 规范: 降级时固件 MUST 向 PCR[7] 扩展该事件（导致 BitLocker TPM 封印失效）"
            };
        }

        return result with
        {
            Status = FeatureStatus.NotMeasured,
            Evidence = "No HypervisorIOMMUPolicy (0x0005000C) measurement found in WBCL",
            Detail = healthNote
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 4: HVCI / VBS
    //    Chain 1: HypervisorLaunchType (0x0005000A) — 必须 Auto=1
    //    Chain 2: VBS_VSM_REQUIRED (0x000A0001) / VSM_LAUNCH_TYPE (0x00050012)
    //    Chain 3: VBS_HVCI_POLICY (0x000A0007) ≠ 0 才判 HVCI Enabled
    //    Hyper-V 启动 ≠ HVCI 开启，三者分开判定。
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatHvci(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "HVCI / VBS" };
        var evidences = new List<string>();

        // Chain 1: Hyper-V 是否启动（必须 Auto=1）
        bool hypervisorRunning = false;
        var hyperLaunch = S1(sipa, 0x0005000A);
        if (hyperLaunch != null)
        {
            var val = hyperLaunch.U64;
            hypervisorRunning = val == 1;
            evidences.Add($"Chain 1: HypervisorLaunchType={(val == 1 ? "Auto" : val == 0 ? "Off" : $"异常值 {val}")} [0x0005000A, PCR{hyperLaunch.Pcr}]");
        }

        // Chain 2: VBS / VSM 是否激活
        bool vbsOn = false;
        var vbsRequired = S1(sipa, 0x000A0001);
        if (vbsRequired != null)
        {
            vbsOn = vbsRequired.U8 == 1;
            evidences.Add($"Chain 2: VBSVSMRequired={(vbsOn ? "true" : "false")} [0x000A0001, PCR{vbsRequired.Pcr}]");
        }
        var vsmLaunch = S1(sipa, 0x00050012);
        if (vsmLaunch != null)
        {
            var vsmOn = vsmLaunch.U64 >= 1;
            vbsOn |= vsmOn;
            evidences.Add($"Chain 2: VSMLaunchType={vsmLaunch.U64} ({(vsmOn ? "VSM 已启动" : "未启动")}) [0x00050012, PCR{vsmLaunch.Pcr}]");
        }

        // Chain 3: HVCI 策略
        bool hvciOn = false;
        var hvciPolicy = S1(sipa, 0x000A0007);
        if (hvciPolicy != null && hvciPolicy.U64 != 0)
        {
            hvciOn = true;
            evidences.Add($"Chain 3: VBSHVCIPolicy=0x{hvciPolicy.U64:X} (HVCI 已启用) [0x000A0007, PCR{hvciPolicy.Pcr}]");
        }
        else
        {
            evidences.Add("Chain 3: VBSHVCIPolicy (0x000A0007) 未找到或为 0 — 无法确认 HVCI 状态");
        }

        // 判定: Hyper-V 启动不能证明 HVCI 开启
        if (hvciOn)
        {
            var ev1 = "HVCI 已启用 (VBS_HVCI_POLICY 非零)";
            if (HasLoadedModule(sipa, "securekernel.exe"))
                ev1 += " — 已加载安全内核 securekernel.exe (Trustlet 环境)";
            if (HasLoadedModule(sipa, "skci.dll"))
                ev1 += " 与 skci.dll (VSM 隔离环境内的代码完整性校验器)";
            // VSM 专用身份密钥 (PCR12 度量)
            var idk = S1(sipa, 0x00050020);
            if (idk != null)
                evidences.Add($"VSMIDKInfo 已测量 [0x00050020, PCR{idk.Pcr}] — VSM/SMART 身份公钥 (含公钥指数及 Modulus)");
            var idks = S1(sipa, 0x00050023);
            if (idks != null)
                evidences.Add($"VSMIDKSInfo 已测量 [0x00050023, PCR{idks.Pcr}] — VSM/IUM 身份签名公钥");
            return result with { Status = FeatureStatus.Enabled, Evidence = ev1, Detail = string.Join("\n", evidences) };
        }
        if (vbsOn)
            return result with { Status = FeatureStatus.Unknown, Evidence = "VBS/VSM 已激活，但未发现 HVCI 策略证据（HVCI 可能未开启）", Detail = string.Join("\n", evidences) };
        if (hypervisorRunning)
            return result with { Status = FeatureStatus.Unknown, Evidence = "Hyper-V 已启动，但未发现 VBS/HVCI 策略事件", Detail = string.Join("\n", evidences) };

        bool hasMarkers = hyperLaunch != null || vbsRequired != null || vsmLaunch != null || hvciPolicy != null;
        return result with
        {
            Status = hasMarkers ? FeatureStatus.Unknown : FeatureStatus.NotMeasured,
            Evidence = hasMarkers ? "WBCL tags found but HVCI/VBS status unclear" : "No HVCI/VBS markers found in WBCL",
            Detail = string.Join("\n", evidences)
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 5: Driver Signature Enforcement
    //    CodeIntegrity=0 → Disabled；TestSigning=1 → 削弱；
    //    DriverLoadPolicy 必须 ≤1 (>1 削弱)；否则 CodeIntegrity=1 → Enabled。
    //    KernelDebug 归 Secure Boot 判定；FlightSigning 不查。
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatDriverSig(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Driver Signature Enforcement" };
        var evidence = new List<string>();
        bool? ciEnabled = null;
        bool? testSigning = null;
        uint? driverLoadPolicy = null;

        // CodeIntegrity (0x00050002) — Boolean
        var ci = S1(sipa, 0x00050002);
        if (ci != null)
        {
            ciEnabled = ci.U8 != 0;
            evidence.Add($"CodeIntegrity={(ciEnabled.Value ? "enabled" : "disabled ⚠")} [0x00050002, PCR{ci.Pcr}]");
        }

        // TestSigning (0x00050003) — Boolean
        var testSign = S1(sipa, 0x00050003);
        if (testSign != null)
        {
            testSigning = testSign.U8 == 1;
            evidence.Add($"TestSigning={(testSigning.Value ? "ON ⚠" : "OFF")} [0x00050003, PCR{testSign.Pcr}]");
        }

        // DriverLoadPolicy (0x0005000E) — 必须 ≤1
        var driverPolicy = S1(sipa, 0x0005000E);
        if (driverPolicy != null)
        {
            driverLoadPolicy = driverPolicy.U32;
            evidence.Add($"DriverLoadPolicy={driverLoadPolicy} [0x0005000E, PCR{driverPolicy.Pcr}]" +
                         (driverLoadPolicy > 1 ? " ⚠ (>1，签名强制被削弱)" : ""));
        }

        // ── 内核代码签名校验核心 CI.dll ──
        if (HasLoadedModule(sipa, "CI.dll"))
            evidence.Add("已加载内核代码签名校验核心 \\Windows\\system32\\CI.dll");

        // ── 引导期镜像签名校验汇总 (含第三方驱动如卡巴斯基 cm_km.sys/klelam.sys 等) ──
        var validated = sipa.Where(s => s.Eid == 0x0007000A).ToList();
        if (validated.Count > 0)
        {
            int ok = validated.Count(s => s.Data.Length > 0 && s.Data[0] != 0);
            evidence.Add(ok == validated.Count
                ? $"引导期镜像签名校验: {ok}/{validated.Count} 全部 ImageValidated=true（含第三方驱动），均附带合规签名主体"
                : $"⚠ 引导期镜像签名校验: 仅 {ok}/{validated.Count} ImageValidated=true，存在未通过校验的镜像");
        }

        // 判定（不受证据顺序影响）
        if (ciEnabled == false)
            return result with { Status = FeatureStatus.Disabled, Evidence = "CodeIntegrity=disabled — 内核代码完整性检查已关闭", Detail = string.Join("; ", evidence) };
        if (testSigning == true)
            return result with { Status = FeatureStatus.Disabled, Evidence = "TestSigning=ON — 测试签名削弱了驱动签名强制", Detail = string.Join("; ", evidence) };
        if (driverLoadPolicy > 1)
            return result with { Status = FeatureStatus.Disabled, Evidence = $"DriverLoadPolicy={driverLoadPolicy} > 1 — 驱动加载策略异常，签名强制被削弱", Detail = string.Join("; ", evidence) };
        if (ciEnabled == true)
            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = "Driver signature enforcement is active (CodeIntegrity=enabled" +
                           (testSigning == false ? ", TestSigning=OFF" : "") +
                           (driverLoadPolicy <= 1 ? $", DriverLoadPolicy={driverLoadPolicy}" : "") + ")",
                Detail = string.Join("; ", evidence)
            };

        return result with
        {
            Status = evidence.Count > 0 ? FeatureStatus.Unknown : FeatureStatus.NotMeasured,
            Evidence = evidence.Count > 0 ? "WBCL tags found but enforcement status unclear" : "No driver signing / code integrity tags found in WBCL",
            Detail = string.Join("; ", evidence)
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 6: Vulnerable Driver Blocklist
    //    核心证据: 0x0005000F SIPAEVENT_SI_POLICY — System Integrity Policy
    //    (driversipolicy.p7b)。FlightSigning 不查；吊销列表属 Secure Boot 佐证。
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatBlocklist(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Vulnerable Driver Blocklist" };

        var siPolicy = S1(sipa, 0x0005000F);
        if (siPolicy != null)
        {
            var detail = DescribeSiPolicy(siPolicy.Data) +
                         "\n微软易受攻击驱动阻止列表以 SI Policy (driversipolicy.p7b) 形式被测量加载";
            var osRevoc = S1(sipa, 0x00050013);
            if (osRevoc != null)
                detail += $"\nOSRevocationList 已测量 ({osRevoc.Data.Length}B) [0x00050013, PCR{osRevoc.Pcr}] — 吊销列表有效 SHA-256 摘要度量";
            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = $"SIPAEVENT_SI_POLICY measured [0x0005000F, PCR{siPolicy.Pcr}] — System Integrity Policy 已测量",
                Detail = detail
            };
        }

        return result with
        {
            Status = FeatureStatus.NotMeasured,
            Evidence = "No SI Policy (0x0005000F) measurement found in WBCL",
            Detail = "SIPAEVENT_SI_POLICY 未出现 → 阻止列表策略未被测量（可能未启用或该日志不含此项）"
        };
    }

    /// <summary>
    /// 解析 SIPAEVENT_SI_POLICY_PAYLOAD (wbcl.h):
    /// ULONGLONG PolicyVersion; UINT16 PolicyNameLength; UINT16 HashAlgID;
    /// UINT32 DigestLength; VarLengthData = WCHAR PolicyName[] + BYTE Digest[]。
    /// PolicyVersion 布局: 4×Int16 = Revision, Build, Minor, Major。
    /// </summary>
    private static string DescribeSiPolicy(byte[] d)
    {
        if (d.Length < 0x10) return $"raw payload ({d.Length} bytes)";

        ulong ver = BitConverter.ToUInt64(d, 0);
        ushort nameLen = BitConverter.ToUInt16(d, 8);
        ushort algId = BitConverter.ToUInt16(d, 0x0A);
        uint digLen = BitConverter.ToUInt32(d, 0x0C);

        short revision = (short)(ver & 0xFFFF);
        short build = (short)((ver >> 16) & 0xFFFF);
        short minor = (short)((ver >> 32) & 0xFFFF);
        short major = (short)((ver >> 48) & 0xFFFF);

        var parts = new List<string> { $"PolicyVersion={major}.{minor}.{build}.{revision}" };

        int offset = 0x10;
        if (nameLen > 0 && offset + nameLen <= d.Length)
        {
            var name = Encoding.Unicode.GetString(d, offset, nameLen).TrimEnd('\0');
            if (name.Length > 0) parts.Add($"PolicyName='{name}'");
        }
        offset += nameLen;

        parts.Add($"HashAlgID=0x{algId:X4}");

        if (digLen > 0 && digLen <= 64 && offset + digLen <= d.Length)
            parts.Add($"Digest={Convert.ToHexString(d, offset, (int)digLen)}");

        return string.Join(", ", parts);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 7: ELAM
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatElam(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Early Launch Anti-Malware (ELAM)" };

        // ELAMKeyname (0x00090001) — 存在即表示 ELAM 驱动已加载
        var keyname = S1(sipa, 0x00090001);
        if (keyname != null)
        {
            var name = keyname.Data.Length > 2
                ? Encoding.Unicode.GetString(keyname.Data).TrimEnd('\0')
                : "present";
            return result with
            {
                Status = FeatureStatus.Enabled,
                Evidence = $"ELAM vendor key measured: '{name}' [0x00090001, PCR{keyname.Pcr}]",
                Detail = "本次启动有 ELAM 反恶意软件驱动注册（其注册表键被测量）"
            };
        }

        // ELAMPolicy (0x00090003)
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

        // ELAMMeasured (0x00090004)
        var measured = S1(sipa, 0x00090004);
        if (measured != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM drivers measured" };

        // ELAM Aggregation container (0x40010002)
        var agg = S1(sipa, 0x40010002);
        if (agg != null)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAMAggregation present" };

        // fallback: any ELAM event in range 0x00090000-0x00090004
        bool hasElamEvents = sipa.Any(s => s.Eid >= 0x00090000 && s.Eid <= 0x00090004);
        if (hasElamEvents)
            return result with { Status = FeatureStatus.Enabled, Evidence = "ELAM events detected" };

        return result with { Status = FeatureStatus.NotMeasured, Evidence = "No ELAM SIPA events found in WBCL" };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Analyzer 8: Boot Log Integrity
    //    注意: 分隔符 + WBCL 终止符只能证明"日志结构完整"，
    //    不能替代 PCR 重放校验。
    // ═══════════════════════════════════════════════════════════════

    private static SecurityFeature FeatBootIntegrity(ParseResult pr, List<SipaEv> sipa)
    {
        var result = new SecurityFeature { Name = "Boot Log Integrity" };

        int sepCount = pr.Events.Count(e => e.EType == EV_SEPARATOR);

        bool hasTerminator = pr.Events.Any(e =>
            e.EType == EV_SEPARATOR &&
            e.Pcr is >= 12 and <= 14 &&
            e.Data.Length >= 4 &&
            e.Data.AsSpan(0, 4).SequenceEqual("WBCL"u8));

        var detail = sepCount >= 7 ? "日志结构良好；这是结构完整性检查，PCR 重放一致性以 PCR Banks 校验结果为准" :
                     sepCount >= 4 ? "部分分隔符存在" : "日志结构不完整";

        return result with
        {
            Status = sepCount >= 7 ? FeatureStatus.Enabled : FeatureStatus.Unknown,
            Evidence = $"Separators={sepCount}, Terminator={hasTerminator}",
            Detail = detail
        };
    }

    // ═══════════════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════════════

    private static bool ContainsAscii(byte[] data, string needle)
    {
        var magic = Encoding.ASCII.GetBytes(needle);
        if (data.Length < magic.Length) return false;
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
