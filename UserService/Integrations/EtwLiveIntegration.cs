using System.Text.Json;
using SuperUserService.Models;

namespace Hyperion.UserService;

/// <summary>
/// ETW 实时事件集成: 把 DriverAttachSelector 的 EtwLive 能力接入 UserService。
///
/// 功能:
///   1. 后台线程运行 FetchEtwLive (duration=86400, 即 24 小时)
///   2. 订阅 KernelService 驱动的 ETW Provider (IOCL 拦截事件)
///   3. 每收到一个 CbnEtwEvent, 投递到服务端 kernel-comms API (kind=ioctl)
///   4. 游戏退出时调用 StopEtwLive 主动停止
///
/// IOCTL 监听开关:
///   - 由服务端配置决定(ioctlEnabled),默认关闭
///   - 关闭时此组件不启动
/// </summary>
internal sealed class EtwLiveIntegration : IDisposable
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;
    private Thread? _etwThread;
    private volatile bool _started;

    // 订阅时长: 24 小时 (游戏运行不会超过, 退出时主动 StopEtwLive 停止)
    private const uint DurationSec = 86400;

    public EtwLiveIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
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
            // H4: 区分 shutdown race (NativeHost 已释放) 与真实异常
            //     M5 修复后 NativeHost.Service getter 在 _disposed 时统一抛 ObjectDisposedException,
            //     不再用 InvalidOperationException + Message 字符串匹配。
            if (ex is ObjectDisposedException)
            {
                Console.Error.WriteLine($"[EtwLive] 订阅退出 (NativeHost 已释放): {ex.Message}");
                return;
            }
            Console.Error.WriteLine($"[EtwLive] 订阅异常: {ex.Message}");
        }
    }

    /// <summary>ETW 事件回调 (由 C++ 通过 EtwLiveCollector 调用)。</summary>
    private void OnEtwEvent(CbnEtwEvent evt)
    {
        // 取 payload 原始字节 (最多 256, 16 进制字符串用于服务端检索)
        int payloadLen = (int)Math.Min(evt.PayloadSize, (uint)(evt.Payload?.Length ?? 0));
        string payloadHex = payloadLen > 0
            ? Convert.ToHexString(evt.Payload!, 0, payloadLen)
            : "";

        // 序列化完整 CbnEtwEvent 到 DataJson (含调用栈帧 + 时间戳 + payload)
        var evtObj = new
        {
            version = evt.Version,
            ioControlCode = evt.IoControlCode,
            inputBufferLength = evt.InputBufferLength,
            captureSize = evt.CaptureSize,
            requestorPid = evt.RequestorPid,
            targetDeviceAddr = evt.TargetDeviceAddr,
            filterDeviceAddr = evt.FilterDeviceAddr,
            attachId = evt.AttachId,
            majorFunction = evt.MajorFunction,
            method = evt.Method,
            stackFrameCount = evt.StackFrameCount,
            stackFrames = evt.StackFrames.Take(evt.StackFrameCount).ToArray(),
            // Category A: 之前 FFI 丢失的字段, 现已补齐
            timestamp = evt.Timestamp,
            payloadSize = evt.PayloadSize,
            payloadHex = payloadHex,
        };

        // 每个 IOCTL 拦截事件投递到服务端 kernel-comms API (kind=ioctl)
        _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
        {
            Kind = "ioctl",
            Level = "HIGH",
            Source = "EtwLive",
            Title = $"IOCTL 拦截: PID={evt.RequestorPid}, Code=0x{evt.IoControlCode:X8}",
            DataJson = JsonSerializer.Serialize(evtObj),
            IoControlCode = evt.IoControlCode,
            RequestorPid = evt.RequestorPid,
            AttachId = (uint)evt.AttachId,
            MajorFunction = evt.MajorFunction,
            Method = evt.Method,
            FilterDeviceAddr = evt.FilterDeviceAddr,
            TargetDeviceAddr = evt.TargetDeviceAddr,
            PayloadSize = evt.PayloadSize,
            PayloadHex = string.IsNullOrEmpty(payloadHex) ? null : payloadHex,
        });
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
        // H4: NativeHost 可能已被 Cleanup 路径 dispose, 此时 _host.Service 抛异常,
        //     用 try/catch 兜住, 仍等待后台线程退出
        try
        {
            _host.Service.StopEtwLive();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[EtwLive] StopEtwLive 调用异常 (host 可能已释放): {ex.Message}");
        }

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
