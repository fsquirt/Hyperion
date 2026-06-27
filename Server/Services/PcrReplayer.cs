using SEWindows.Server.Models;
using System.Security.Cryptography;
using System.Text;

namespace SEWindows.Server.Services;

/// <summary>
/// PCR 值回放器：从事件日志重新计算 PCR 值
/// </summary>
public static class PcrReplayer
{
    // ═══════════════════════════════════════════════════════════════
    //  回放事件日志，计算期望的 PCR 值
    //  返回: algId -> PCR bank (24个 PCR 值)
    // ═══════════════════════════════════════════════════════════════

    public static Dictionary<ushort, PcrBank> Replay(ParseResult pr)
    {
        var banks = new Dictionary<ushort, PcrBank>();
        foreach (var algId in pr.AlgIds)
            banks[algId] = new PcrBank(algId);

        // 检测 StartupLocality（PCR0 非零初始化）
        DetectStartupLocality(pr, banks);

        foreach (var ev in pr.Events)
        {
            // 跳过 EV_NO_ACTION 和 PCR 0xFFFFFFFF
            if (ev.EType == 0x00000003 || ev.Pcr == 0xFFFFFFFF)
                continue;

            foreach (var (algId, digest) in ev.Digests)
            {
                if (banks.TryGetValue(algId, out var bank))
                    bank.Extend(ev.Pcr, digest);
            }
        }

        return banks;
    }

    // ═══════════════════════════════════════════════════════════════
    //  计算 pcrDigest = Hash(PCR[i0] || PCR[i1] || ...)
    //  用于与 TPMS_ATTEST 中的 pcrDigest 对比
    // ═══════════════════════════════════════════════════════════════

    public static byte[]? ComputePcrDigest(
        Dictionary<ushort, PcrBank> banks,
        List<PcrSelection> selections)
    {
        if (selections.Count == 0) return null;

        var sel = selections[0];
        if (!banks.TryGetValue(sel.HashAlg, out var bank)) return null;

        // 连接选中 PCR 的值
        var pcrIndices = sel.PcrIndices.OrderBy(i => i).ToList();
        var concatenated = new List<byte>();
        foreach (var idx in pcrIndices)
        {
            if (idx < 24)
                concatenated.AddRange(bank.Pcrs[idx]);
        }

        // 哈希
        return HashValue(sel.HashAlg, concatenated.ToArray());
    }

    // ═══════════════════════════════════════════════════════════════
    //  内部方法
    // ═══════════════════════════════════════════════════════════════

    private static void DetectStartupLocality(ParseResult pr, Dictionary<ushort, PcrBank> banks)
    {
        // 查找 EV_NO_ACTION 事件中的 StartupLocality 标记
        foreach (var ev in pr.Events)
        {
            if (ev.EType != 0x00000003) continue; // EV_NO_ACTION
            if (ev.Data.Length < 16) continue;

            var sig = Encoding.ASCII.GetString(ev.Data, 0, Math.Min(16, ev.Data.Length));
            if (!sig.StartsWith("StartupLocality\0")) continue;

            // 最后一个字节是 locality 值
            if (ev.Data.Length >= 17)
            {
                var locality = ev.Data[^1];
                foreach (var bank in banks.Values)
                {
                    // PCR0 初始化为: 00...00 || locality
                    var init = new byte[bank.DigestSize];
                    init[^1] = locality;
                    bank.Pcrs[0] = init;
                }
            }
            break;
        }
    }

    internal static byte[] HashValue(ushort algId, byte[] data) => algId switch
    {
        0x0004 => SHA1.HashData(data),
        0x000B => SHA256.HashData(data),
        0x000C => SHA384.HashData(data),
        0x000D => SHA512.HashData(data),
        _ => SHA256.HashData(data)
    };
}

/// <summary>
/// 单个算法的 PCR Bank（24 个 PCR 寄存器）
/// </summary>
public sealed class PcrBank
{
    public ushort AlgId { get; }
    public int DigestSize { get; }
    public byte[][] Pcrs { get; }

    public PcrBank(ushort algId)
    {
        AlgId = algId;
        DigestSize = algId switch
        {
            0x0004 => 20,
            0x000B => 32,
            0x000C => 48,
            0x000D => 64,
            _ => 32
        };
        Pcrs = new byte[24][];
        for (int i = 0; i < 24; i++)
            Pcrs[i] = new byte[DigestSize]; // 全零初始化
    }

    /// <summary>
    /// PCR Extend: newPCR = Hash(oldPCR || digest)
    /// </summary>
    public void Extend(uint pcr, byte[] digest)
    {
        if (pcr >= 24) return;
        var input = new byte[DigestSize + digest.Length];
        Buffer.BlockCopy(Pcrs[pcr], 0, input, 0, DigestSize);
        Buffer.BlockCopy(digest, 0, input, DigestSize, digest.Length);
        Pcrs[pcr] = PcrReplayer.HashValue(AlgId, input);
    }
}
