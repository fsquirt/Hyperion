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
    private bool _initialized;

    /// <summary>获取已初始化的服务实例 (未初始化时抛异常)。</summary>
    public CombinationNativeService Service
        => _service ?? throw new InvalidOperationException("NativeHost 未初始化,请先调用 Initialize");

    /// <summary>是否已初始化。</summary>
    public bool IsInitialized => _initialized;

    /// <summary>
    /// 初始化 CombinationNative (ntdll API)。
    /// 幂等: 重复调用不会重复初始化。
    /// </summary>
    public bool Initialize()
    {
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
        // NativeBridge 和 CombinationNativeService 没有需要释放的非托管资源
        // (所有 Fetch* 返回的 NativeDataResult 由调用方 using 释放)
        _service = null;
        _initialized = false;
    }
}
