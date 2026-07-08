using Hyperion.Server.Models;
using System.Buffers.Binary;

namespace Hyperion.Server.Services;

/// <summary>
/// TPMS_ATTEST 结构解析器（大端序，TPM2 规范）
/// </summary>
public static class TpmsAttestParser
{
    public const uint TPM_GENERATED_MAGIC = 0xFF544347;
    public const ushort TPM_ST_ATTEST_QUOTE = 0x8018;

    public static TpmsAttest Parse(byte[] data)
    {
        var pos = 0;

        // magic (uint32 BE)
        var magic = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos)); pos += 4;

        // type (uint16 BE)
        var type = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;

        // qualifiedSigner (TPM2B): uint16 BE size + bytes
        var qsLen = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;
        var qualifiedSigner = data[pos..(pos + qsLen)]; pos += qsLen;

        // extraData (TPM2B): uint16 BE size + bytes
        var edLen = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;
        var extraData = data[pos..(pos + edLen)]; pos += edLen;

        // TPMS_CLOCK_INFO: clock(uint64 BE) + resetCount(uint32 BE) + restartCount(uint32 BE) + safe(byte)
        pos += 8 + 4 + 4 + 1; // 跳过 17 字节

        // firmwareVersion (uint64 BE)
        var firmwareVersion = BinaryPrimitives.ReadUInt64BigEndian(data.AsSpan(pos)); pos += 8;

        // TPML_PCR_SELECTION
        var selCount = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos)); pos += 4;
        var selections = new List<PcrSelection>();

        for (int i = 0; i < selCount; i++)
        {
            var hashAlg = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;
            var sizeofSelect = (int)data[pos]; pos += 1;
            var pcrSelect = data[pos..(pos + sizeofSelect)]; pos += sizeofSelect;

            var indices = new List<uint>();
            for (int byteIdx = 0; byteIdx < sizeofSelect; byteIdx++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    if ((pcrSelect[byteIdx] & (1 << bit)) != 0)
                        indices.Add((uint)(byteIdx * 8 + bit));
                }
            }

            selections.Add(new PcrSelection { HashAlg = hashAlg, PcrIndices = indices });
        }

        // pcrDigest (TPM2B): uint16 BE size + bytes
        var pdLen = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos)); pos += 2;
        var pcrDigest = data[pos..(pos + pdLen)];

        return new TpmsAttest
        {
            Magic = magic,
            Type = type,
            QualifiedSigner = qualifiedSigner,
            ExtraData = extraData,
            FirmwareVersion = firmwareVersion,
            PcrSelections = selections,
            PcrDigest = pcrDigest
        };
    }
}
