using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules.DriverAttach;

/// <summary>
/// 纯托管解析 .sys PE 导入表（对齐 IatScanner.cpp）。仅支持 PE32+（x64 内核驱动）。
/// 命中"危险内核函数列表"视为高危。列表默认内置 4 个,可由服务端策略(<see cref="PolicySync"/>)
/// 下发覆盖(SetDangerousApis)。
/// </summary>
public static class IatScanner
{
    // 默认内置(服务端未连接时回退用)。大小写不敏感匹配(内核函数名本身大小写敏感,
    // 但此处用 OrdinalIgnoreCase 以避免因大小写差异漏判)。
    private static HashSet<string> _dangerousApis = new(StringComparer.OrdinalIgnoreCase)
        { "MmCopyMemory", "MmMapIoSpace", "ZwMapViewOfSection", "MmCopyVirtualMemory" };

    /// <summary>当前生效的危险内核函数集合(只读快照)。</summary>
    public static IReadOnlyCollection<string> DangerousApis => _dangerousApis;

    /// <summary>
    /// 用服务端下发的列表覆盖默认集合。空列表会被忽略(保留当前值,避免空策略导致全部放行)。
    /// </summary>
    public static void SetDangerousApis(IEnumerable<string> funcs)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in funcs)
        {
            var name = (f ?? "").Trim();
            if (name.Length > 0) set.Add(name);
        }
        if (set.Count > 0) _dangerousApis = set;
    }

    public sealed class IatEntry
    {
        public string DllName = "";
        public List<string> Apis = new();
    }

    public static bool ScanIat(string filePath, out List<IatEntry> iat, out string error)
    {
        iat = new List<IatEntry>();
        error = "";

        byte[] data;
        try { data = File.ReadAllBytes(filePath); }
        catch (Exception ex) { error = $"读取失败: {ex.Message}"; return false; }

        if (data.Length < 64) { error = "文件太小"; return false; }
        if (BitConverter.ToUInt16(data, 0) != 0x5A4D) { error = "不是 PE 文件"; return false; }

        int eLfanew = BitConverter.ToInt32(data, 0x3C);
        if (eLfanew + 24 > data.Length) { error = "e_lfanew 越界"; return false; }
        if (BitConverter.ToUInt32(data, eLfanew) != 0x00004550) { error = "PE NT 头签名不对"; return false; }

        int optStart = eLfanew + 24;
        ushort magic = BitConverter.ToUInt16(data, optStart);
        if (magic != 0x20B) { error = "不是 PE32+ (64 位)"; return true; } // 仅支持 64 位驱动

        ushort numRva = BitConverter.ToUInt16(data, optStart + 108); // NumberOfRvaAndSizes
        if (numRva < 2) { error = "无导入表"; return true; }

        int impRva = BitConverter.ToInt32(data, optStart + 120);  // DataDirectory[1].VirtualAddress
        int impSize = BitConverter.ToInt32(data, optStart + 124); // DataDirectory[1].Size
        if (impRva == 0 || impSize == 0) { error = "(无导入表)"; return true; }

        int impOff = RvaToOffset(data, eLfanew, impRva);
        if (impOff < 0) { error = "导入表 RVA 转文件偏移失败"; return false; }

        const int DESC = 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
        for (int idx = 0; idx < 1024; idx++)
        {
            int off = impOff + idx * DESC;
            if (off + DESC > data.Length) { error = "导入表未遇终止符即到文件末尾"; break; }

            uint ilt = BitConverter.ToUInt32(data, off);        // OriginalFirstThunk
            uint nameRva = BitConverter.ToUInt32(data, off + 12);
            uint firstThunk = BitConverter.ToUInt32(data, off + 16);
            if (ilt == 0 && nameRva == 0) break;                // 正常终止符
            if (nameRva == 0) continue;

            int nameOff = RvaToOffset(data, eLfanew, (int)nameRva);
            if (nameOff < 0) continue;
            string dll = ReadAsciiZ(data, nameOff);

            var entry = new IatEntry { DllName = dll };
            uint iltRva = ilt != 0 ? ilt : firstThunk;
            if (iltRva != 0)
            {
                int iltOff = RvaToOffset(data, eLfanew, (int)iltRva);
                if (iltOff >= 0)
                {
                    for (int t = 0; t < 8192; t++)
                    {
                        int thunkOff = iltOff + t * 8;
                        if (thunkOff + 8 > data.Length) break;
                        ulong thunk = BitConverter.ToUInt64(data, thunkOff);
                        if (thunk == 0) break;

                        if ((thunk & 0x8000000000000000UL) != 0)
                        {
                            ushort ord = (ushort)(thunk & 0xFFFF);
                            entry.Apis.Add($"(ordinal {ord})");
                        }
                        else
                        {
                            uint nameRva2 = (uint)(thunk & 0x7FFFFFFF);
                            int nameOff2 = RvaToOffset(data, eLfanew, (int)nameRva2);
                            if (nameOff2 < 0 || nameOff2 + 2 > data.Length)
                                entry.Apis.Add("(invalid name rva)");
                            else
                                entry.Apis.Add(ReadAsciiZ(data, nameOff2 + 2));
                        }
                    }
                }
            }
            iat.Add(entry);
        }
        return true;
    }

    public static bool HasDangerousImports(List<IatEntry> iat, out List<string> foundApis)
    {
        foundApis = new List<string>();
        foreach (var entry in iat)
        {
            foreach (var api in entry.Apis)
            {
                if (api.Length == 0 || api[0] == '(') continue; // 跳过 ordinal / 无效项
                foreach (var danger in DangerousApis)
                {
                    if (api.Equals(danger, StringComparison.OrdinalIgnoreCase))
                        foundApis.Add($"{entry.DllName}!{api}");
                }
            }
        }
        return foundApis.Count > 0;
    }

    // RVA → 文件偏移（遍历 section table，对齐 IatScanner.cpp::RvaToFileOffset）
    private static int RvaToOffset(byte[] data, int eLfanew, int rva)
    {
        int optStart = eLfanew + 24;
        int headerSize = BitConverter.ToInt32(data, optStart + 60); // SizeOfHeaders
        if (rva < headerSize) return rva;

        ushort sizeOpt = BitConverter.ToUInt16(data, eLfanew + 20); // FileHeader.SizeOfOptionalHeader
        int sectionTable = eLfanew + 24 + sizeOpt;
        ushort numSections = BitConverter.ToUInt16(data, eLfanew + 6);
        for (int i = 0; i < numSections; i++)
        {
            int sh = sectionTable + i * 40;
            uint vaStart = BitConverter.ToUInt32(data, sh + 12); // VirtualAddress
            uint vaSize = BitConverter.ToUInt32(data, sh + 8);   // VirtualSize (Misc)
            uint rawStart = BitConverter.ToUInt32(data, sh + 20); // PointerToRawData
            uint rawSize = BitConverter.ToUInt32(data, sh + 16);  // SizeOfRawData
            if (vaSize == 0) vaSize = rawSize;
            if (rva >= vaStart && rva < vaStart + vaSize)
            {
                uint delta = (uint)(rva - vaStart);
                if (delta >= rawSize) return -1;
                int off = (int)(rawStart + delta);
                if (off >= data.Length) return -1;
                return off;
            }
        }
        return -1;
    }

    private static string ReadAsciiZ(byte[] data, int offset)
    {
        var sb = new System.Text.StringBuilder();
        int max = Math.Min(255, data.Length - offset);
        for (int i = 0; i < max; i++)
        {
            byte c = data[offset + i];
            if (c == 0) break;
            sb.Append((char)c);
        }
        return sb.ToString();
    }
}
