using System.Text.Json;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 本地取证统计，不上报。仅记录两项：
///   1. IOCTL 控制码 → 累计交互次数
///   2. 参与交互的模块路径集合，含系统 DLL，供概览
/// 生成 ioctl_stats.json。不做逐次采样 / 时间戳 / 机器标识等冗余记录。
/// 写盘采用临时文件 + 原子替换，并吞掉并发/锁冲突异常，
/// 避免多实例抢同一文件导致进程崩溃。
/// </summary>
public sealed class ForensicJsonLogger
{
    private sealed class StatDoc
    {
        public Dictionary<string, ulong> IoctlCounts { get; set; } = new();
        public List<string> Modules { get; set; } = new();
    }

    private string _lastPath = "";
    public string LastJsonPath => _lastPath;

    /// <summary>写出统计 JSON，不修改传入集合。</summary>
    public string WriteStats(string dir, IReadOnlyDictionary<uint, ulong> counts,
        IReadOnlyCollection<string> modules)
    {
        var doc = new StatDoc();
        foreach (var kv in counts)
            doc.IoctlCounts[$"0x{kv.Key:X8}"] = kv.Value;
        doc.Modules = new List<string>(modules);

        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "ioctl_stats.json");
        string tmp = path + ".tmp";
        var opts = new JsonSerializerOptions { WriteIndented = true };
        try
        {
            File.WriteAllText(tmp, JsonSerializer.Serialize(doc, opts));
            try { File.Delete(path); } catch { /* 被占用时忽略，下一步 Move 覆盖 */ }
            File.Move(tmp, path, true);
            _lastPath = path;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Forensic] 写 ioctl_stats.json 失败，已忽略: {ex.Message}");
        }
        return _lastPath;
    }
}
