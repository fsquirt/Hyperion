namespace Hyperion.UserService.Tracking.SysmonEventTracker;

/// <summary>
/// 签名验证结果 LRU 缓存，容量 1000。
/// 减少重复文件的磁盘读取和 WinVerifyTrust 调用。
/// </summary>
public sealed class CacheVerify
{
    private readonly int _capacity;
    private readonly Dictionary<string, LinkedListNode<(string Path, bool Trusted, string Info)>> _map;
    private readonly LinkedList<(string Path, bool Trusted, string Info)> _lru;

    public CacheVerify(int capacity = 1000)
    {
        _capacity = capacity;
        _map = new Dictionary<string, LinkedListNode<(string, bool, string)>>(capacity, StringComparer.OrdinalIgnoreCase);
        _lru = new LinkedList<(string, bool, string)>();
    }

    /// <summary>
    /// 查询缓存，命中返回 true 并输出结果；未命中返回 false。
    /// </summary>
    public bool TryGet(string filePath, out bool trusted, out string info)
    {
        if (_map.TryGetValue(filePath, out var node))
        {
            // 命中 → 移到链表头部（最近使用）
            _lru.Remove(node);
            _lru.AddFirst(node);
            trusted = node.Value.Trusted;
            info = node.Value.Info;
            return true;
        }

        trusted = false;
        info = "";
        return false;
    }

    /// <summary>写入缓存，超出容量时淘汰最久未使用的条目。</summary>
    public void Set(string filePath, bool trusted, string info)
    {
        if (_map.TryGetValue(filePath, out var existing))
        {
            // 更新已有条目
            _lru.Remove(existing);
            existing.Value = (filePath, trusted, info);
            _lru.AddFirst(existing);
            return;
        }

        // 淘汰最久未使用
        if (_map.Count >= _capacity)
        {
            var evict = _lru.Last!;
            _lru.RemoveLast();
            _map.Remove(evict.Value.Path);
        }

        // 插入新条目
        var node = new LinkedListNode<(string, bool, string)>((filePath, trusted, info));
        _lru.AddFirst(node);
        _map[filePath] = node;
    }

    /// <summary>当前缓存条目数。</summary>
    public int Count => _map.Count;
}
