using System.Text;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// ETW 实时事件集成: 把 DriverAttachSelector 的 EtwLive 能力接入 UserService。
///
/// 功能:
///   1. 后台线程运行 FetchEtwLive (duration=86400, 即 24 小时)
///   2. 订阅 KernelService 驱动的 ETW Provider (IOCL 拦截事件)
///   3. 每收到一个 CbnEtwEvent, 转成 TrackedEvent 投递到 ITrackerSink
///      Type="ioctl", Level="HIGH" (所有 IOCTL 拦截都是高危)
///   4. 游戏退出时调用 StopEtwLive 主动停止 (无需 Ctrl+C)
///
/// 与 CommsMonitorIntegration 的区别:
///   - 本组件: 实时事件流 (每个 IOCTL 立即投递到 sink)
///   - CommsMonitorIntegration: dump-to-file (监控结束时返回汇总)
/// 两者用不同的 ETW Session 名, 不会冲突。
/// </summary>
internal sealed class EtwLiveIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ITrackerSink _sink;
    private Thread? _etwThread;
    private volatile bool _started;

    // 订阅时长: 24 小时 (游戏运行不会超过, 退出时主动 StopEtwLive 停止)
    private const uint DurationSec = 86400;

    public EtwLiveIntegration(NativeHost host, ITrackerSink sink)
    {
        _host = host;
        _sink = sink;
    }

    /// <summary>
    /// 启动 ETW 实时订阅 (后台线程, 阻塞直到 StopEtwLive 或 duration 到)。
    /// 幂等: 重复调用不会启动多个线程。
    /// </summary>
    public void Start()
    {
        if (_started) return;
        _started = true;

        Console.Error.WriteLine("[EtwLive] 启动 ETW 实时订阅 (IOCL 拦截事件)...");
        _etwThread = new Thread(EtwLoop)
        {
            Name = "EtwLiveMonitor",
            IsBackground = true,
        };
        _etwThread.Start();
    }

    /// <summary>ETW 订阅主循环 (在后台线程上运行)。</summary>
    private void EtwLoop()
    {
        try
        {
            var parameters = new EtwParameters(DurationSec, null);
            int ret = _host.Service.FetchEtwLive(parameters, OnEtwEvent);

            Console.Error.WriteLine($"[EtwLive] 订阅结束, ret={ret}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[EtwLive] 订阅异常: {ex.Message}");
        }
    }

    /// <summary>ETW 事件回调 (由 C++ 通过 EtwLiveCollector 调用)。</summary>
    private void OnEtwEvent(CbnEtwEvent evt)
    {
        // 每个 IOCTL 拦截事件都投递到 sink
        _sink.Post(new TrackedEvent
        {
            Type = "ioctl",
            Timestamp = DateTime.UtcNow,
            Level = "HIGH",
            Source = "EtwLive",
            Title = $"IOCL 拦截: PID={evt.RequestorPid}, Code=0x{evt.IoControlCode:X8}",
            Detail = BuildEventDetail(evt),
        });
    }

    /// <summary>构建事件详情 (含调用栈帧)。</summary>
    private static string BuildEventDetail(CbnEtwEvent evt)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"IoControlCode: 0x{evt.IoControlCode:X8}");
        sb.AppendLine($"InputBufferLength: {evt.InputBufferLength}");
        sb.AppendLine($"CaptureSize: {evt.CaptureSize}");
        sb.AppendLine($"RequestorPid: {evt.RequestorPid}");
        sb.AppendLine($"TargetDevice: 0x{evt.TargetDeviceAddr:X}");
        sb.AppendLine($"FilterDevice: 0x{evt.FilterDeviceAddr:X}");
        sb.AppendLine($"AttachId: {evt.AttachId}");
        sb.AppendLine($"MajorFunction: 0x{evt.MajorFunction:X} (IRP_MJ_DEVICE_CONTROL=0x0E)");
        sb.AppendLine($"Method: {evt.Method}");

        if (evt.StackFrameCount > 0)
        {
            sb.AppendLine($"调用栈 ({evt.StackFrameCount} 帧):");
            int frames = Math.Min(evt.StackFrameCount, evt.StackFrames.Length);
            for (int i = 0; i < frames; i++)
            {
                if (evt.StackFrames[i] != 0)
                    sb.AppendLine($"  [{i}] 0x{evt.StackFrames[i]:X}");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// 停止 ETW 订阅 (非阻塞)。
    /// 调用 CombinationNative 的 StopEtwLive 设置内部停止标志,
    /// 后台线程会在 ~200ms 内退出。
    /// </summary>
    public void Stop()
    {
        if (!_started) return;
        _started = false;

        Console.Error.WriteLine("[EtwLive] 请求停止 ETW 订阅...");
        _host.Service.StopEtwLive();

        // 等待后台线程退出 (最多 5 秒)
        if (_etwThread != null && _etwThread.IsAlive)
        {
            if (!_etwThread.Join(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[EtwLive] 后台线程未在 5 秒内退出");
            }
        }
        Console.Error.WriteLine("[EtwLive] ETW 订阅已停止");
    }

    public void Dispose()
    {
        Stop();
    }
}
