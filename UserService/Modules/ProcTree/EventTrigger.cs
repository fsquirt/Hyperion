using System.Text.Json;
using Hyperion.UserService.Modules.DriverAttach;
using Hyperion.UserService.Modules.Heuristic;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace Hyperion.UserService.Modules.ProcTree;

/// <summary>
/// 事件触发器（移植自 ProcessTreeSnapshot 的事件触发式快照策略）。
/// 1. 订阅 Windows 代码完整性 Provider（Microsoft-Windows-CodeIntegrity）→ 全量进程树快照提示。
/// 2. 订阅 IoctlCommsMonitor 的拦截事件（来自附着驱动的通信）→ 若发起方 exe 或调用栈模块
///    未签名，打印本地提示。服务端上报已停用（服务端未就绪），
///    模块 dump 与交互统计由 IoctlCommsMonitor 负责。
/// </summary>
public sealed class EventTrigger : IDisposable
{
    private static readonly Guid CiProviderGuid =
        new(0x4f407aad, 0x13ed, 0x43cf, 0x92, 0x15, 0xd8, 0xdd, 0xf3, 0xf6, 0xa2, 0x97);

    private readonly ProcessTreeCollector _collector;
    private readonly IoctlCommsMonitor _comms;
    private readonly object _lock = new();

    private TraceEventSession? _ciSession;
    private Thread? _ciThread;
    private volatile bool _stopCi;

    public EventTrigger(ProcessTreeCollector collector, IoctlCommsMonitor comms)
    {
        _collector = collector;
        _comms = comms;
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
                // 服务端上报已停用（服务端未就绪），全量进程树快照无消费方，此处仅本地提示。
                Console.WriteLine("[ET] 收到代码完整性事件");
            };
            _ciSession.Source.Process();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ET] CI 泵异常: {ex.Message}");
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
    //  附着驱动通信：未签名发起方 → 单进程快照
    // ─────────────────────────────────────────────────────────────

    private void OnCommsIntercept(IoctlInterceptEvent evt)
    {
        // 校验签名较耗时，投递线程池避免阻塞 ETW 线程
        var captured = evt;
        Task.Run(() =>
        {
            try
            {
                bool unsigned = false;
                string? offender = null;

                if (!string.IsNullOrEmpty(captured.ExePath) && DriverClassifier.IsUntrusted(captured.ExePath))
                {
                    unsigned = true;
                    offender = captured.ExePath;
                }
                else if (captured.Frames.Length > 0)
                {
                    var modules = StackResolver.ResolveCallerModules(captured.RequestorPid, captured.Frames);
                    foreach (var m in modules)
                    {
                        if (DriverClassifier.IsUntrusted(m)) { unsigned = true; offender = m; break; }
                    }
                }

                if (!unsigned) return;

                // 服务端上报已停用（服务端未就绪），进程树快照无消费方；
                // 模块 dump 与交互统计由 IoctlCommsMonitor 负责。此处仅做本地提示。
                Console.WriteLine($"[ET] 未签名模块↔附着驱动交互: {offender} (PID={captured.RequestorPid})");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ET] 交互判定异常: {ex.Message}");
            }
        });
    }

    public void Dispose() => Stop();
}
