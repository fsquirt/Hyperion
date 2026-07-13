using SuperUserService.Logging;
using SuperUserService.NativeInterop;
using SuperUserService.Services;

namespace Hyperion.UserService;

/// <summary>
/// CombinationNative 的宿主端封装。
/// 持有 <see cref="CombinationNativeService"/> 的单例, 负责初始化、生命周期管理。
/// 所有需要调用 CombinationNative.dll 的集成组件都通过此类获取服务实例。
/// </summary>
internal sealed class NativeHost : IDisposable
{
    private readonly ServiceLogger _logger = new();
    private readonly NativeBridge _bridge = new();
    private CombinationNativeService? _service;
    private volatile bool _initialized;
    // _disposed 跨线程访问: Dispose 在清理线程写, MonitorLoop/EtwLoop 线程通过 IsDisposed/Service getter 读。
    // 不加 volatile 时 CPU 缓存可能导致读取线程看不到 Dispose 的写入 (H4 race 兜底失效)。
    private volatile bool _disposed;

    /// <summary>获取已初始化的服务实例。</summary>
    /// <exception cref="ObjectDisposedException">NativeHost 已 Dispose。</exception>
    /// <exception cref="InvalidOperationException">NativeHost 未初始化, 请先调用 Initialize。</exception>
    public CombinationNativeService Service
    {
        get
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(NativeHost));
            return _service ?? throw new InvalidOperationException(
                "NativeHost 未初始化,请先调用 Initialize");
        }
    }

    /// <summary>是否已初始化 (且未释放)。</summary>
    public bool IsInitialized => _initialized && !_disposed;

    /// <summary>是否已释放。</summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// 初始化 CombinationNative (ntdll API)。
    /// 幂等: 重复调用不会重复初始化。
    /// </summary>
    public bool Initialize()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(NativeHost));
        if (_initialized) return true;

        Console.Error.WriteLine("[NativeHost] 初始化 CombinationNative...");

        // 1. 创建服务实例
        _service = new CombinationNativeService(_bridge, _logger);

        // 2. 初始化 ntdll API (ProcessTreeSnapshot 依赖)
        var initResult = _service.Initialize();
        if (!initResult.Success)
        {
            Console.Error.WriteLine($"[NativeHost] 初始化失败: {initResult}");
            _service = null;
            return false;
        }

        _initialized = true;
        Console.Error.WriteLine("[NativeHost] 初始化完成");
        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _initialized = false;

        // M5: 主动停止 Comms 后台线程
        //     原 Dispose 直接 _service=null, 若 Comms 线程还在运行 (理论上不该发生,
        //     因为 Cleanup 会先 StopCommsMonitor), 再访问 _service 会抛异常。
        //     这里主动调 Stop 确保后台线程退出, 且后续 Service getter 抛 ObjectDisposedException
        //     而非 InvalidOperationException, 调用方可区分。
        if (_service != null)
        {
            try { _service.StopComms(); } catch (Exception ex)
            { Console.Error.WriteLine($"[NativeHost] Dispose 时 StopComms 异常: {ex.Message}"); }
        }

        // NativeBridge 和 CombinationNativeService 没有需要释放的非托管资源
        // (所有 Fetch* 返回的 NativeDataResult 由调用方 using 释放)
        _service = null;
    }
}
