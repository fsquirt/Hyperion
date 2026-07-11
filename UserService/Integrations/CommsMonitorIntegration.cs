using System.Text;
using System.Text.Json;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 通信监控集成: 把 HeuristicDumper 的 CommsMonitor 能力接入 UserService。
///
/// 功能:
///   1. 后台线程运行 FetchComms (duration=86400, 即 24 小时)
///   2. 实时监控被附着驱动设备的 IOCTL 通信
///   3. 从调用栈定位业务文件, dump 内存映像到 dumpfile\, 拷贝磁盘文件到 filecopy\
///   4. 游戏退出时调用 StopComms 主动停止
///   5. 停止后拿到 CbnCommsSummary 汇总, 投递到服务端 /api/tracker/dumps API
///
/// 配置:
///   - dumpMode: raw/mini/full (从服务端配置拉取,默认 mini)
///   - fileCopyEnabled: 是否拷贝磁盘文件 (从服务端配置拉取,默认 true)
/// </summary>
internal sealed class CommsMonitorIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;
    private Thread? _commsThread;
    private volatile bool _started;

    // 监控时长: 24 小时 (游戏运行不会超过, 退出时主动 StopComms 停止)
    private const uint DurationSec = 86400;

    // Dump 模式 + 磁盘拷贝开关 (由服务端配置决定)
    private readonly CommsDumpMode _dumpMode;
    private readonly bool _fileCopyEnabled;

    public CommsMonitorIntegration(NativeHost host, ServerDataClient? server,
        CommsDumpMode dumpMode = CommsDumpMode.Mini, bool fileCopyEnabled = true)
    {
        _host = host;
        _server = server;
        _dumpMode = dumpMode;
        _fileCopyEnabled = fileCopyEnabled;
    }

    /// <summary>
    /// 启动通信监控 (后台线程, 阻塞直到 StopComms 或 duration 到)。
    /// 幂等: 重复调用不会启动多个线程。
    /// </summary>
    public void Start()
    {
        if (_started) return;
        _started = true;

        Console.Error.WriteLine($"[Comms] 启动通信监控 (dump 模式: {_dumpMode}, fileCopy: {_fileCopyEnabled})...");
        _commsThread = new Thread(MonitorLoop)
        {
            Name = "CommsMonitor",
            IsBackground = true,  // 后台线程, 进程退出时自动终止
        };
        _commsThread.Start();
    }

    /// <summary>通信监控主循环 (在后台线程上运行)。</summary>
    private void MonitorLoop()
    {
        try
        {
            // 参数: duration=86400, enableJson=false, dumpMode 由配置决定
            var parameters = new CommsParameters(DurationSec, false, _dumpMode);
            using var result = _host.Service.FetchComms(parameters);

            if (!result.Success)
            {
                _ = _server?.PostDumpAsync(
                    level: "ERR",
                    title: "通信监控失败",
                    detail: result.ErrorMessage,
                    dumpFilesJson: "[]");
                return;
            }

            // 拿到汇总数据
            var summary = result.SingleEntry;
            Console.Error.WriteLine(
                $"[Comms] 监控结束: {summary.PathCount} 个路径, " +
                $"{summary.TotalIoctls} 次 IOCTL, {summary.TotalEvents} 个事件");

            // 投递汇总 + dump 文件路径到服务端 dumps API
            var dumpFiles = BuildDumpFilesJson(summary);
            string detail = BuildSummaryDetail(summary);
            _ = _server?.PostDumpAsync(
                level: "HIGH",
                title: $"通信监控汇总: {summary.PathCount} 个路径",
                detail: detail,
                dumpFilesJson: dumpFiles);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Comms] 监控异常: {ex.Message}");
        }
    }

    /// <summary>构建 dump 文件路径 JSON 数组 [{path, kind, pid, hitCount, abnormal}]。</summary>
    private string BuildDumpFilesJson(CbnCommsSummary summary)
    {
        var files = new List<object>();
        var paths = summary.Paths.Take((int)summary.PathCount);
        foreach (var p in paths)
        {
            if (p.Dumped != 0 && !string.IsNullOrEmpty(p.DumpFile))
            {
                files.Add(new
                {
                    path = p.DumpFile,
                    kind = "dump",
                    pid = p.Pid,
                    hitCount = p.HitCount,
                    abnormal = p.Abnormal,
                });
            }
            if (p.FileCopied != 0 && _fileCopyEnabled && !string.IsNullOrEmpty(p.FileCopyName))
            {
                files.Add(new
                {
                    path = p.FileCopyName,
                    kind = "filecopy",
                    pid = p.Pid,
                    hitCount = p.HitCount,
                    abnormal = p.Abnormal,
                });
            }
        }
        return JsonSerializer.Serialize(files);
    }

    /// <summary>构建汇总详情 (含 dump 文件路径)。</summary>
    private static string BuildSummaryDetail(CbnCommsSummary summary)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"总路径数: {summary.PathCount}");
        sb.AppendLine($"IOCL 总次数: {summary.TotalIoctls}");
        sb.AppendLine($"事件总数: {summary.TotalEvents}");
        sb.AppendLine();

        int dumped = 0, copied = 0, abnormal = 0;
        var paths = summary.Paths.Take((int)summary.PathCount);
        foreach (var p in paths)
        {
            if (p.Dumped != 0) dumped++;
            if (p.FileCopied != 0) copied++;
            if (p.Abnormal != 0) abnormal++;

            sb.AppendLine($"  {p.Path}");
            sb.AppendLine($"    PID={p.Pid}, Hits={p.HitCount}, Abnormal={p.Abnormal}");
            if (p.Dumped != 0)
                sb.AppendLine($"    → dumpfile\\{p.DumpFile}");
            if (p.FileCopied != 0)
                sb.AppendLine($"    → filecopy\\{p.FileCopyName}");
        }

        sb.AppendLine();
        sb.AppendLine($"已 dump: {dumped} (→ dumpfile)");
        sb.AppendLine($"已拷贝: {copied} (→ filecopy)");
        sb.AppendLine($"异常路径: {abnormal}");
        return sb.ToString();
    }

    /// <summary>
    /// 停止通信监控 (非阻塞)。
    /// 调用 CombinationNative 的 StopComms 设置内部停止标志,
    /// 后台线程会在 ~200ms 内退出并返回汇总数据。
    /// </summary>
    public void Stop()
    {
        if (!_started) return;
        _started = false;

        Console.Error.WriteLine("[Comms] 请求停止通信监控...");
        _host.Service.StopComms();

        // 等待后台线程退出 (最多 5 秒, 防止卡死)
        if (_commsThread != null && _commsThread.IsAlive)
        {
            if (!_commsThread.Join(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[Comms] 后台线程未在 5 秒内退出");
            }
        }
        Console.Error.WriteLine("[Comms] 通信监控已停止");
    }

    public void Dispose()
    {
        Stop();
    }
}
