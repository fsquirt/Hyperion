using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using UserService.Native;

namespace Hyperion.UserService;

/// <summary>
/// 通信监控集成: 把 HeuristicDumper 的 CommsMonitor 能力接入 UserService。
///
/// 功能:
///   1. 后台线程运行 FetchCommsLive (duration=86400, 即 24 小时)
///   2. 实时监控被附着驱动设备的 IOCTL 通信
///   3. 每收到一个 CbnCommsEvent:
///      a) 按 (attachId, ioctlCode) 聚合 {count, firstSeen, lastSeen, requestorPids}
///         不再 per-event HTTP POST, 由周期定时器 (60s) 统一上报 kind="ioctl-aggregate"
///      b) 对调用栈中每个 stackModule 调 ModuleSignatureVerifier.Verify 验签,
///         命中未签名模块立即投递告警 kind="unsigned-module-alert" + 触发定向深扫
///   4. 从调用栈定位业务文件, dump 内存映像到 dumpfile\, 拷贝磁盘文件到 filecopy\
///   5. 游戏退出时调用 StopComms 主动停止
///   6. 停止后:
///      a) 先 FlushAggregates 上报剩余聚合数据
///      b) 拿到 CbnCommsSummary 汇总 + per-path 列表
///      c) 调用 FetchDriverDumpInfo 拿到驱动 dump 元数据
///      d) 整体投递到服务端 /api/tracker/dumps API (含 per-path JSON + driver-dumps JSON)
///
/// 数据上报 (结构化):
///   - 聚合: KernelCommPayload{kind="ioctl-aggregate"} 周期上报, 含聚合记录数组
///   - 告警: KernelCommPayload{kind="unsigned-module-alert"} 命中未签名模块时立即投递
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

    // 定向深扫 (可空, 由构造函数注入)
    private readonly TargetedProcessScanIntegration? _targetedScan;

    // ══════════════════════════════════════════════════════════════════
    //  IOCTL 聚合: per-event 不再 HTTP POST, 按 (attachId, ioctlCode) 聚合
    //  周期 60s 上报一次 kind="ioctl-aggregate"
    // ══════════════════════════════════════════════════════════════════

    /// <summary>IOCTL 聚合记录: 同一 (attachId, ioctlCode) 的多次调用合并为一条。</summary>
    private sealed class IoctlAggregate
    {
        public uint IoctlCode;
        public ulong AttachId;
        public long Count;
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public HashSet<ulong> RequestorPids = new();
    }

    // 聚合表: (attachId, ioctlCode) -> aggregate
    private readonly ConcurrentDictionary<(ulong attachId, uint ioctlCode), IoctlAggregate> _aggregator = new();

    // 聚合表锁: 保护 IoctlAggregate 字段修改 (HashSet/Count/LastSeen 非线程安全)
    // ConcurrentDictionary.AddOrUpdate 的 update 委托不在外部锁下执行, 可能并发,
    // 因此 OnCommsEvent 和 FlushAggregates 都通过此锁串行化对 aggregate 字段的访问。
    private readonly object _aggregatorLock = new();

    // 周期上报定时器
    private System.Threading.Timer? _flushTimer;
    private const int FlushIntervalSec = 60;

    public CommsMonitorIntegration(NativeHost host, ServerDataClient? server,
        CommsDumpMode dumpMode = CommsDumpMode.Mini, bool fileCopyEnabled = true,
        TargetedProcessScanIntegration? targetedScan = null)
    {
        _host = host;
        _server = server;
        _dumpMode = dumpMode;
        _fileCopyEnabled = fileCopyEnabled;
        _targetedScan = targetedScan;
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

        // 启动周期上报定时器 (60s)
        _flushTimer = new System.Threading.Timer(
            _ => FlushAggregates(),
            null,
            FlushIntervalSec * 1000,
            FlushIntervalSec * 1000);
        Console.Error.WriteLine($"[Comms] IOCTL 聚合上报定时器已启动 ({FlushIntervalSec}s)");
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

            // H4: Stop() 超时返回后, AntiCheatService.Cleanup 可能已调 _nativeHost.Dispose(),
            //     此时 _host.Service 会抛 ObjectDisposedException。在调 ReportSummary 前检查 host
            //     是否还活着, 若已 dispose 则跳过汇总 (数据已实时上报, 汇总缺失可接受)。
            if (_host.IsDisposed)
            {
                Console.Error.WriteLine("[Comms] NativeHost 已释放, 跳过汇总上报 (shutdown race)");
                return;
            }

            // 订阅结束后, 拿 CbnCommsSummary 汇总 + DriverDumpInfo 元数据
            ReportSummary();
        }
        catch (Exception ex)
        {
            // H4: 区分 shutdown race 与真实异常
            //     M5 修复后 NativeHost.Service getter 在 _disposed 时统一抛 ObjectDisposedException,
            //     不再用 InvalidOperationException + Message 字符串匹配。
            //     Stop() 超时后 NativeHost 被 dispose 导致的 ODE 不是真实故障, 不上报异常 dump。
            if (ex is ObjectDisposedException)
            {
                Console.Error.WriteLine($"[Comms] 监控退出 (NativeHost 已释放): {ex.Message}");
                return;
            }
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
    /// 通信事件回调 (由 C++ 通过 CommsLiveCollector 调用, 可能多线程并发)。
    /// 不再 per-event HTTP POST, 改为:
    ///   1. 聚合到 _aggregator (按 (attachId, ioctlCode) 合并)
    ///   2. 对调用栈中每个 stackModule 验签, 命中未签名立即告警 + 触发定向深扫
    /// </summary>
    private void OnCommsEvent(CbnCommsEvent evt)
    {
        var now = DateTime.UtcNow;

        // 1. 聚合到 _aggregator (加锁保护 IoctlAggregate 字段)
        var key = (evt.AttachId, evt.IoControlCode);
        lock (_aggregatorLock)
        {
            if (_aggregator.TryGetValue(key, out var existing))
            {
                existing.Count++;
                existing.LastSeen = now;
                existing.RequestorPids.Add(evt.RequestorPid);
            }
            else
            {
                _aggregator[key] = new IoctlAggregate
                {
                    IoctlCode = evt.IoControlCode,
                    AttachId = evt.AttachId,
                    Count = 1,
                    FirstSeen = now,
                    LastSeen = now,
                    RequestorPids = { evt.RequestorPid }
                };
            }
        }

        // 2. 对调用栈中的模块验签, 命中未签名立即告警 + 触发深扫
        for (int i = 0; i < (int)evt.StackModuleCount; i++)
        {
            var module = evt.StackModules[i];
            if (string.IsNullOrEmpty(module.Path)) continue;

            bool signed = ModuleSignatureVerifier.Verify(module.Path);
            if (!signed)
            {
                // 立即投递告警 (不走聚合, 直接 HTTP POST)
                var alertObj = new
                {
                    timestamp = now,
                    modulePath = module.Path,
                    moduleBase = module.Base,
                    moduleSize = module.Size,
                    requestorPid = evt.RequestorPid,
                    attachId = evt.AttachId,
                    ioControlCode = evt.IoControlCode,
                    processExe = evt.ProcessExe,
                };

                _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
                {
                    Kind = "unsigned-module-alert",
                    Level = "HIGH",
                    Source = "CommsMonitor",
                    Title = $"未签名模块与驱动交互: {Path.GetFileName(module.Path)} (PID={evt.RequestorPid})",
                    DataJson = JsonSerializer.Serialize(alertObj),
                    RequestorPid = evt.RequestorPid,
                    AttachId = (uint)evt.AttachId,
                    IoControlCode = evt.IoControlCode,
                });

                // 触发定向深扫
                _targetedScan?.Scan((uint)evt.RequestorPid, module.Path, evt.AttachId, evt.IoControlCode);
            }
        }
    }

    /// <summary>
    /// 上报并清空 IOCTL 聚合数据。
    /// 由周期定时器 (60s) 和 ReportSummary 调用。
    /// </summary>
    private void FlushAggregates()
    {
        List<IoctlAggregate> aggregates;
        lock (_aggregatorLock)
        {
            if (_aggregator.IsEmpty) return;

            // 取出当前所有聚合记录并清空
            aggregates = new List<IoctlAggregate>(_aggregator.Count);
            foreach (var kvp in _aggregator)
            {
                aggregates.Add(kvp.Value);
            }
            _aggregator.Clear();
        }

        if (aggregates.Count == 0) return;

        var dataObj = new
        {
            flushedAt = DateTime.UtcNow,
            aggregateCount = aggregates.Count,
            aggregates = aggregates.Select(a => new
            {
                ioctlCode = a.IoctlCode,
                attachId = a.AttachId,
                count = a.Count,
                firstSeen = a.FirstSeen,
                lastSeen = a.LastSeen,
                requestorPids = a.RequestorPids.ToList(),
            }).ToArray(),
        };

        long totalIoctls = aggregates.Sum(a => a.Count);

        _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
        {
            Kind = "ioctl-aggregate",
            Level = "INFO",
            Source = "CommsMonitor",
            Title = $"IOCTL 聚合上报: {aggregates.Count} 条聚合, {totalIoctls} 次调用",
            DataJson = JsonSerializer.Serialize(dataObj),
        });

        Console.Error.WriteLine($"[Comms] 聚合上报: {aggregates.Count} 条, {totalIoctls} 次调用");
    }

    /// <summary>
    /// 监控结束后上报汇总数据:
    ///   1. 先 FlushAggregates 上报剩余 IOCTL 聚合数据
    ///   2. CbnCommsSummary 汇总统计 (TotalIoctls/TotalEvents/PathCount)
    ///   3. per-path JSON (CbnPathEntry 全维度)
    ///   4. driver dump 元数据 JSON (CbnDriverDumpInfo 全维度, Category D 之前只写磁盘)
    /// </summary>
    private void ReportSummary()
    {
        // 先上报未刷新的 IOCTL 聚合数据
        try { FlushAggregates(); }
        catch (Exception ex) { Console.Error.WriteLine($"[Comms] FlushAggregates 异常: {ex.Message}"); }

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

        // 停止聚合上报定时器
        _flushTimer?.Dispose();
        _flushTimer = null;

        // H4: NativeHost 可能已被 Cleanup 路径 dispose, 此时 _host.Service 抛异常,
        //     用 try/catch 兜住, 仍等待后台线程退出
        try
        {
            _host.Service.StopComms();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Comms] StopComms 调用异常 (host 可能已释放): {ex.Message}");
        }

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
