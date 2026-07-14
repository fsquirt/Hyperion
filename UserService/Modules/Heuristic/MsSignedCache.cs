using System.Collections.Concurrent;
using Hyperion.UserService.Modules.DriverAttach;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// 微软签名缓存：把"模块路径 → 是否带微软签名"缓存下来，避免高频 IOCTL 事件下对每个
/// 调用栈模块反复调用 WinVerifyTrust / Catalog 验证（后者既慢又会刷屏 [WVT]/[CAT] 日志）。
///
/// 判定口径与 DriverClassifier 一致：
///   - 内嵌签名归属 Microsoft  → 算微软签名
///   - 仅 Windows 目录签名 Inbox → 算微软签名（系统 DLL 多由 Microsoft 目录保护）
///   - WHQL 第三方签名          → 不算（第三方厂商，仍应取证）
///
/// 容量有界（默认 2000 条），超出后按 FIFO 淘汰最旧项。高频场景下系统 DLL 路径跨进程一致，
/// 命中率极高，首次验签后基本不再走 WinVerifyTrust。
/// </summary>
public static class MsSignedCache
{
    private const int Capacity = 2000;
    private static readonly ConcurrentDictionary<string, bool> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentQueue<string> _order = new();
    private static readonly object _gate = new();

    /// <summary>
    /// 模块是否带微软签名。命中缓存直接返回；未命中则调用 DriverClassifier 验签并回填。
    /// 文件不存在/无法判定一律按"非微软签名"处理（保留取证）。
    /// </summary>
    public static bool IsMicrosoftSigned(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return false;

        if (_cache.TryGetValue(filePath, out bool cached))
            return cached;

        bool ms;
        try
        {
            var cls = DriverClassifier.ClassifyDriver(filePath).Class;
            ms = cls == DriverClass.Microsoft || cls == DriverClass.Inbox;
        }
        catch
        {
            ms = false; // 验签异常按可疑处理，不排除
        }

        // 回填缓存 + FIFO 容量管理（单锁保护字典与顺序队列的一致性）
        lock (_gate)
        {
            if (!_cache.ContainsKey(filePath))
            {
                _cache[filePath] = ms;
                _order.Enqueue(filePath);
                while (_cache.Count > Capacity && _order.TryDequeue(out var old))
                {
                    _cache.TryRemove(old, out _);
                }
            }
        }
        return ms;
    }
}
