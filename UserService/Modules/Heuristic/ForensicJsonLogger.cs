using System.Text.Json;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 取证 JSON 日志（对齐 HeuristicDumper/JsonLogger 的精简版）。
/// 仅记录 "IOCTL 控制码 → 次数"（不再落 InputBuffer），并附带取证元数据，
/// 生成 ioctl_stats.json 供 Upload 模块读取上报。
/// </summary>
public sealed class ForensicJsonLogger
{
    private class Sample
    {
        public long TimestampUtc { get; set; }
        public Dictionary<string, ulong> IoctlCounts { get; set; } = new();
    }

    private class ForensicDoc
    {
        public string Schema { get; set; } = "hyperion.forensic.ioctl.v1";
        public long GeneratedAtUtc { get; set; }
        public string MachineId { get; set; } = "";
        public string SessionId { get; set; } = "";
        public List<Sample> Samples { get; set; } = new();
        public Dictionary<string, ulong> Aggregate { get; set; } = new();
    }

    private readonly string _machineId;
    private readonly string _sessionId;
    private readonly List<Sample> _samples = new();
    private readonly object _lock = new();
    private string _lastPath = "";

    public string LastJsonPath => _lastPath;

    public ForensicJsonLogger()
    {
        _machineId = GetMachineId();
        _sessionId = Guid.NewGuid().ToString("N");
    }

    /// <summary>记录一次 IOCTL 统计采样（仅码+次数）。</summary>
    public void RecordCounts(IReadOnlyDictionary<uint, ulong> counts)
    {
        var sample = new Sample
        {
            TimestampUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        foreach (var kv in counts)
            sample.IoctlCounts[$"0x{kv.Key:X8}"] = kv.Value;

        lock (_lock) _samples.Add(sample);
    }

    /// <summary>落盘 ioctl_stats.json（聚合全部采样 + 累计）。</summary>
    public string Flush(string dir)
    {
        var doc = new ForensicDoc
        {
            GeneratedAtUtc = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            MachineId = _machineId,
            SessionId = _sessionId
        };

        var agg = new Dictionary<string, ulong>();
        lock (_lock)
        {
            doc.Samples = new List<Sample>(_samples);
            foreach (var s in _samples)
                foreach (var kv in s.IoctlCounts)
                    agg[kv.Key] = agg.TryGetValue(kv.Key, out var v) ? v + kv.Value : kv.Value;
        }
        doc.Aggregate = agg;

        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "ioctl_stats.json");
        var opts = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(doc, opts));
        _lastPath = path;
        return path;
    }

    private static string GetMachineId()
    {
        try
        {
            // 优先用 MachineGuid（HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid）
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography");
            var v = key?.GetValue("MachineGuid") as string;
            if (!string.IsNullOrEmpty(v)) return v;
        }
        catch { }
        return Environment.MachineName;
    }
}
