using System.IO;
using System.Text.Json;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// 通信监控集成: 把 HeuristicDumper 的 CommsMonitor 能力接入 UserService。
///
/// 功能:
///   1. 后台线程运行 FetchCommsLive (duration=86400, 即 24 小时)
///   2. 实时监控被附着驱动设备的 IOCTL 通信
///   3. 每收到一个 CbnCommsEvent, 投递到服务端 kernel-comms API (kind="comms-event")
///      含全部 per-event 维度: timestamp/ioctl/major/method/pid/attachId/exe/stackModules/payload
///   4. 从调用栈定位业务文件, dump 内存映像到 dumpfile\, 拷贝磁盘文件到 filecopy\
///   5. 游戏退出时调用 StopComms 主动停止
///   6. 停止后:
///      a) 拿到 CbnCommsSummary 汇总 + per-path 列表
///      b) 调用 FetchDriverDumpInfo 拿到驱动 dump 元数据
///      c) 整体投递到服务端 /api/tracker/dumps API (含 per-path JSON + driver-dumps JSON)
///
/// 数据上报 (结构化):
///   - 每事件: KernelCommPayload{kind="comms-event"} 含 per-event 维度 + 索引列
///   - 汇总: DumpPayload 含 6 个汇总列 + per-path JSON + driver-dumps JSON + 路径目录
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
            // 使用 FetchCommsLive: per-event 回调实时投递 (不再等结束才出数据)
            var parameters = new CommsParameters(DurationSec, false, _dumpMode);
            int ret = _host.Service.FetchCommsLive(parameters, OnCommsEvent);

            Console.Error.WriteLine($"[Comms] 实时订阅结束, ret={ret}, 开始上报汇总...");

            // 订阅结束后, 拿 CbnCommsSummary 汇总 + DriverDumpInfo 元数据
            ReportSummary();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Comms] 监控异常: {ex.Message}");
            _ = _server?.PostDumpAsync(new ServerDataClient.DumpPayload
            {
                Level = "ERR",
                Title = $"通信监控异常: {ex.Message}",
                DumpFilesJson = "[]",
                DriverDumpsJson = "[]",
            });
        }
    }

    /// <summary>
    /// 通信事件回调 (由 C++ 通过 CommsLiveCollector 调用)。
    /// 每收到一个 IOCTL 通信事件, 投递到服务端 kind="comms-event"。
    /// </summary>
    private void OnCommsEvent(CbnCommsEvent evt)
    {
        // 取 payload 原始字节 (最多 256, 16 进制字符串用于服务端检索)
        int payloadLen = (int)Math.Min(evt.PayloadSize, (uint)(evt.Payload?.Length ?? 0));
        string payloadHex = payloadLen > 0
            ? Convert.ToHexString(evt.Payload!, 0, payloadLen)
            : "";

        // 序列化完整 CbnCommsEvent (含 stackModules 数组 + payload)
        var evtObj = new
        {
            timestamp = evt.Timestamp,
            ioControlCode = evt.IoControlCode,
            majorFunction = evt.MajorFunction,
            method = evt.Method,
            requestorPid = evt.RequestorPid,
            attachId = evt.AttachId,
            processExe = evt.ProcessExe,
            stackModuleCount = evt.StackModuleCount,
            stackModules = evt.StackModules.Take((int)evt.StackModuleCount).Select(m => new
            {
                path = m.Path,
                baseAddr = m.Base,
                size = m.Size,
            }).ToArray(),
            payloadSize = evt.PayloadSize,
            payloadHex = payloadHex,
        };

        _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
        {
            Kind = "comms-event",
            Level = "HIGH",
            Source = "CommsMonitor",
            Title = $"通信事件: PID={evt.RequestorPid}, IOCTL=0x{evt.IoControlCode:X8}, AttachId={evt.AttachId}",
            DataJson = JsonSerializer.Serialize(evtObj),
            // 索引列 (Category A: per-event comms data 之前丢失)
            IoControlCode = evt.IoControlCode,
            MajorFunction = evt.MajorFunction,
            Method = evt.Method,
            RequestorPid = evt.RequestorPid,
            AttachId = (uint)evt.AttachId,
            StackModuleCount = evt.StackModuleCount,
            PayloadSize = evt.PayloadSize,
            PayloadHex = string.IsNullOrEmpty(payloadHex) ? null : payloadHex,
        });
    }

    /// <summary>
    /// 监控结束后上报汇总数据:
    ///   1. CbnCommsSummary 汇总统计 (TotalIoctls/TotalEvents/PathCount)
    ///   2. per-path JSON (CbnPathEntry 全维度)
    ///   3. driver dump 元数据 JSON (CbnDriverDumpInfo 全维度, Category D 之前只写磁盘)
    /// </summary>
    private void ReportSummary()
    {
        // 1. 拿 CbnCommsSummary 汇总
        var commsParams = new CommsParameters(0, false, _dumpMode);
        using var commsResult = _host.Service.FetchComms(commsParams);

        if (!commsResult.Success)
        {
            _ = _server?.PostDumpAsync(new ServerDataClient.DumpPayload
            {
                Level = "ERR",
                Title = $"通信监控汇总获取失败: {commsResult.ErrorMessage}",
                DumpFilesJson = "[]",
                DriverDumpsJson = "[]",
            });
            return;
        }

        var summary = commsResult.SingleEntry;
        var paths = summary.Paths.Take((int)summary.PathCount).ToList();

        int abnormalCount = paths.Count(p => p.Abnormal != 0);
        int dumpedCount = paths.Count(p => p.Dumped != 0);
        int copiedCount = paths.Count(p => p.FileCopied != 0);

        Console.Error.WriteLine(
            $"[Comms] 汇总: {summary.PathCount} 路径, " +
            $"{summary.TotalIoctls} IOCTL, {summary.TotalEvents} 事件, " +
            $"{abnormalCount} 异常, {dumpedCount} dump, {copiedCount} 拷贝");

        string pathsJson = BuildPathsJson(paths);

        // 2. 拿驱动 dump 元数据 (Category D: 之前 C++ 只写磁盘)
        string driverDumpsJson = "[]";
        int driverDumpCount = 0;
        try
        {
            using var dumpResult = _host.Service.FetchDriverDumpInfo();
            if (dumpResult.Success)
            {
                driverDumpCount = dumpResult.Count;
                driverDumpsJson = BuildDriverDumpsJson(dumpResult.Entries);
                Console.Error.WriteLine($"[Comms] 驱动 dump 元数据: {driverDumpCount} 条");
            }
            else
            {
                Console.Error.WriteLine($"[Comms] 驱动 dump 元数据获取失败: {dumpResult.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Comms] 驱动 dump 元数据异常: {ex.Message}");
        }

        // 3. 从 per-path 数据派生路径目录 (Category D: 之前 C++ 只写磁盘, 现在导出到服务端)
        //     - DumpFileDir: 第一个有 dumpFile 的路径所在目录
        //     - FileCopyDir: 第一个有 fileCopyName 的路径所在目录
        //     - JsonLogPath: enableJson=false 时不生成, 设为 null
        string? dumpFileDir = paths
            .Where(p => !string.IsNullOrEmpty(p.DumpFile))
            .Select(p => Path.GetDirectoryName(p.DumpFile))
            .FirstOrDefault();
        string? fileCopyDir = paths
            .Where(p => !string.IsNullOrEmpty(p.FileCopyName))
            .Select(p => Path.GetDirectoryName(p.FileCopyName))
            .FirstOrDefault();

        // 4. 整体投递到 dumps API
        _ = _server?.PostDumpAsync(new ServerDataClient.DumpPayload
        {
            Level = "HIGH",
            Title = $"通信监控汇总: {summary.PathCount} 路径, {abnormalCount} 异常, {driverDumpCount} 驱动 dump",
            TotalIoctls = summary.TotalIoctls,
            TotalEvents = summary.TotalEvents,
            PathCount = summary.PathCount,
            AbnormalCount = abnormalCount,
            DumpedCount = dumpedCount,
            CopiedCount = copiedCount,
            DumpFilesJson = pathsJson,
            DriverDumpsJson = driverDumpsJson,
            DriverDumpCount = driverDumpCount,
            // 路径目录 (Category D)
            JsonLogPath = null,  // enableJson=false, 无 JSON 日志
            DumpFileDir = dumpFileDir,
            FileCopyDir = fileCopyDir,
        });
    }

    /// <summary>
    /// 构建完整 per-path JSON 数组。
    /// 每个路径一个完整对象, 包含全部维度:
    /// {path, tag, pid, abnormal, note, hitCount, dumped, dumpFile, fileCopied, fileCopyName}
    /// </summary>
    private string BuildPathsJson(List<CbnPathEntry> paths)
    {
        var objs = paths.Select(p => new
        {
            path = p.Path,
            tag = p.Tag,
            pid = p.Pid,
            abnormal = p.Abnormal,
            note = p.Note,
            hitCount = p.HitCount,
            dumped = p.Dumped,
            dumpFile = p.DumpFile,
            fileCopied = p.FileCopied,
            fileCopyName = p.FileCopyName,
        }).ToArray();

        return JsonSerializer.Serialize(objs);
    }

    /// <summary>
    /// 构建驱动 dump 元数据 JSON 数组 (Category D: 之前只写磁盘, 现在导出到服务端)。
    /// 每条记录包含: status/attachId/driverObjectAddr/imageBase/imageSize/bytesDumped/fullPath/baseName/dumpFile
    /// </summary>
    private string BuildDriverDumpsJson(CbnDriverDumpInfo[] dumps)
    {
        var objs = dumps.Select(d => new
        {
            status = d.Status,
            attachId = d.AttachId,
            driverObjectAddr = d.DriverObjectAddr,
            imageBase = d.ImageBase,
            imageSize = d.ImageSize,
            bytesDumped = d.BytesDumped,
            fullPath = d.FullPath,
            baseName = d.BaseName,
            dumpFile = d.DumpFile,
        }).ToArray();

        return JsonSerializer.Serialize(objs);
    }

    /// <summary>
    /// 停止通信监控 (非阻塞)。
    /// 调用 CombinationNative 的 StopComms 设置内部停止标志,
    /// 后台线程会在 ~200ms 内退出并上报汇总数据。
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
