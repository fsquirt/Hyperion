using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Hyperion.UserService.Modules.DriverAttach;
using Hyperion.UserService.Modules.Heuristic;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Hyperion.UserService.Modules.ProcTree;

/// <summary>
/// 事件触发器（移植自 ProcessTreeSnapshot 的事件触发式快照策略）。
/// 1. 订阅 Windows 代码完整性 Provider（Microsoft-Windows-CodeIntegrity）→ 本地提示（全量快照上报已停用）。
/// 2. 订阅 IoctlCommsMonitor 的拦截事件（来自附着驱动的通信）→ 对每个请求方进程只拍一次
///    单进程快照（含其子树），落本地 snapshots\ 目录。去重按请求方 PID，保证高频通信下不重复拍照。
/// </summary>
public sealed class EventTrigger : IDisposable
{
    private static readonly Guid CiProviderGuid =
        new(0x4f407aad, 0x13ed, 0x43cf, 0x92, 0x15, 0xd8, 0xdd, 0xf3, 0xf6, 0xa2, 0x97);

    private readonly ProcessTreeCollector _collector;
    private readonly IoctlCommsMonitor _comms;
    private readonly string _baseDir;

    // 已拍照的请求方 PID 集合：每个与被附着驱动通信的进程只拍一次单进程快照（含其子树）。
    private readonly HashSet<ulong> _snappedPids = new();
    private readonly object _pidLock = new();

    private TraceEventSession? _ciSession;
    private Thread? _ciThread;
    private volatile bool _stopCi;

    /// <summary>快照采集完成（落盘后）回调，参数为原始 JSON 字符串，供实时上报。</summary>
    public Action<string>? OnSnapshot { get; set; }

    public EventTrigger(ProcessTreeCollector collector, IoctlCommsMonitor comms, string baseDir)
    {
        _collector = collector;
        _comms = comms;
        _baseDir = baseDir;
    }

    public void Start()
    {
        _comms.OnIntercept += OnCommsIntercept;
        StartCodeIntegritySession();
    }

    public void Stop()
    {
        _comms.OnIntercept -= OnCommsIntercept;
        StopCodeIntegritySession();
    }

    // ─────────────────────────────────────────────────────────────
    //  代码完整性事件：全量快照
    // ─────────────────────────────────────────────────────────────

    private void StartCodeIntegritySession()
    {
        try
        {
            _ciSession = new TraceEventSession("HyperionCiTrace");
            _ciSession.EnableProvider(CiProviderGuid);
            _ciThread = new Thread(RunCiPump) { IsBackground = true, Name = "CiEtwPump" };
            _ciThread.Start();
            Console.WriteLine("[ET] 已订阅代码完整性事件（全量快照触发）");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] 代码完整性订阅失败（需管理员/ETW 权限）: {ex.Message}");
        }
    }

    private void RunCiPump()
    {
        if (_ciSession == null) return;
        try
        {
            _ciSession.Source.AllEvents += _ =>
            {
                if (_stopCi) return;
                // 代码完整性事件 → 全系统进程树快照（重活投递线程池，避免阻塞 CI ETW 会话丢事件）
                Task.Run(CaptureFullSnapshotOnCi);
            };
            _ciSession.Source.Process();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] CI 泵异常: {ex.Message}");
        }
    }

    /// <summary>代码完整性事件触发：采集全系统进程树快照，落盘并实时上报。</summary>
    private void CaptureFullSnapshotOnCi()
    {
        try
        {
            var snap = _collector.SnapshotFull();
            snap.Trigger = "code_integrity";
            string json = JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true });
            WriteSnapshot(json, 0);
            OnSnapshot?.Invoke(json);
            Console.WriteLine($"[ET] 代码完整性事件触发全系统进程树快照(进程数={snap.Processes.Count}, 连接数={snap.Connections.Count})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] CI 全量快照异常: {ex.Message}");
        }
    }

    private void StopCodeIntegritySession()
    {
        _stopCi = true;
        try { _ciSession?.Stop(); } catch { }
        try { _ciSession?.Dispose(); } catch { }
        _ciThread?.Join(TimeSpan.FromSeconds(3));
        _ciSession = null;
    }

    // ─────────────────────────────────────────────────────────────
    //  附着驱动通信：对每个请求方进程只拍一次单进程快照（含其子树）
    // ─────────────────────────────────────────────────────────────

    private void OnCommsIntercept(IoctlInterceptEvent evt)
    {
        ulong pid = evt.RequestorPid;
        if (pid == 0) return;

        // 每个与被附着驱动通信的进程，只拍一次单进程快照（含其子树）。
        // 去重在 ETW 线程上同步完成，保证并发下也只触发一次；重活（枚举进程/句柄/内存扫描）
        // 投递线程池，避免阻塞 ETW 会话丢事件。
        bool first;
        lock (_pidLock) first = _snappedPids.Add(pid);
        if (!first) return;

        var captured = evt;
        Task.Run(() => TakeProcessSnapshot(captured));
    }

    private void TakeProcessSnapshot(IoctlInterceptEvent evt)
    {
        try
        {
            var snap = _collector.SnapshotProcessTree(evt.RequestorPid);
            snap.Trigger = "driver_interaction";
            string json = JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true });
            WriteSnapshot(json, evt.RequestorPid);
            OnSnapshot?.Invoke(json);
            Console.WriteLine($"[ET] 单进程快照已保存并上报: PID={evt.RequestorPid} " +
                              $"进程数={snap.Processes.Count} 连接数={snap.Connections.Count}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] 单进程快照异常 PID={evt.RequestorPid}: {ex.Message}");
        }
    }

    private void WriteSnapshot(string json, ulong pid)
    {
        try
        {
            string dir = Path.Combine(_baseDir, "snapshots");
            Directory.CreateDirectory(dir);
            string name = $"snap_pid{pid}_{DateTime.UtcNow:yyyyMMddHHmmssfff}.json";
            string path = Path.Combine(dir, name);
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, path, true); // 原子覆盖，避免半截文件
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] 写快照失败 PID={pid}: {ex.Message}");
        }
    }

    public void Dispose() => Stop();
}
