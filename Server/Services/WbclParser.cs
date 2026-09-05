using Hyperion.Server.Models;
using System.Buffers.Binary;

namespace Hyperion.Server.Services;

/// <summary>
/// TCG 2.0 事件日志解析器，WBCL 格式
/// </summary>
public static class WbclParser
{
    private static ReadOnlySpan<byte> SpecSig => "Spec ID Event03\0"u8;

    //  解析入口
    public static ParseResult Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 32)
            return new ParseResult { Errors = ["data too short"] };

        try
        {
            // 读取第一个事件头，TCG 1.2 格式
            var pos = 0;
            var pcrIndex = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;
            var eventType = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;

            // 第一个事件的 digest 是 20 字节 SHA-1 全零
            pos += 20;

            var eventSize = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;
            var eventData = raw.Slice(pos, (int)eventSize); pos += (int)eventSize;

            if (eventType != 0x00000003) // EV_NO_ACTION
                return new ParseResult { Errors = [$"first event type 0x{eventType:X8}, expected EV_NO_ACTION"] };

            // 解析 SPEC_ID
            var (algIds, dsizes) = ParseSpecId(eventData);
            if (algIds.Count == 0)
                return new ParseResult { Errors = ["no algorithms in SPEC_ID"] };

            // 解析后续事件
            var events = new List<EvRec>();
            var index = 1;
            while (pos + 8 <= raw.Length)
            {
                try
                {
                    var (ev, newPos) = ParseEvent2(raw, pos, index, algIds, dsizes);
                    events.Add(ev);
                    pos = newPos;
                    index++;
                }
                catch (EndOfStreamException) { break; }
                catch (Exception ex)
                {
                    return new ParseResult
                    {
                        AlgIds = algIds,
                        Dsizes = dsizes,
                        Events = events,
                        Errors = [$"event {index} parse error: {ex.Message}"]
                    };
                }
            }

            return new ParseResult { AlgIds = algIds, Dsizes = dsizes, Events = events };
        }
        catch (Exception ex)
        {
            return new ParseResult { Errors = [ex.Message] };
        }
    }

    //  SPEC_ID 事件解析
    private static (List<ushort> algIds, Dictionary<ushort, int> dsizes) ParseSpecId(
        ReadOnlySpan<byte> data)
    {
        if (data.Length < 16 || !data[..16].SequenceEqual(SpecSig))
            throw new FormatException("invalid SPEC_ID signature");

        // offset 24: number of algorithms
        if (data.Length < 28)
            throw new FormatException("SPEC_ID too short");

        var num = BinaryPrimitives.ReadUInt32LittleEndian(data[24..]);
        var algIds = new List<ushort>();
        var dsizes = new Dictionary<ushort, int>();
        var offset = 28;

        for (int i = 0; i < num && offset + 4 <= data.Length; i++)
        {
            var algId = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]); offset += 2;
            var digestSize = BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]); offset += 2;
            algIds.Add(algId);
            dsizes[algId] = digestSize;
        }

        return (algIds, dsizes);
    }

    
    //  TCG2 Event2 解析
    private static (EvRec ev, int newPos) ParseEvent2(
        ReadOnlySpan<byte> raw, int pos, int index,
        List<ushort> algIds, Dictionary<ushort, int> dsizes)
    {
        var start = pos;

        var pcrIndex = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;
        var eventType = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;
        var digestCount = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;

        var digests = new Dictionary<ushort, byte[]>();
        for (int i = 0; i < digestCount; i++)
        {
            var algId = BinaryPrimitives.ReadUInt16LittleEndian(raw[pos..]); pos += 2;
            if (!dsizes.TryGetValue(algId, out var dsz))
                dsz = GetDefaultDigestSize(algId);
            var digest = raw.Slice(pos, dsz).ToArray(); pos += dsz;
            digests[algId] = digest;
        }

        var eventSize = BinaryPrimitives.ReadUInt32LittleEndian(raw[pos..]); pos += 4;
        var eventData = raw.Slice(pos, (int)eventSize).ToArray(); pos += (int)eventSize;

        return (new EvRec
        {
            Index = index,
            Pcr = pcrIndex,
            EType = eventType,
            Digests = digests,
            Data = eventData
        }, pos);
    }

    private static int GetDefaultDigestSize(ushort algId) => algId switch
    {
        0x0004 => 20,  // SHA-1
        0x000B => 32,  // SHA-256
        0x000C => 48,  // SHA-384
        0x000D => 64,  // SHA-512
        _ => 32
    };
}
