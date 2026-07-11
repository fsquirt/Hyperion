using Hyperion.Tracker.Services;

namespace Hyperion.UserService;

/// <summary>
/// 服务端 Sink: 把事件通过 HTTP 上报到 Hyperion.Server 的 /api/tracker/* API。
///
/// 内部包装 <see cref="ServerConnection"/> (复用 Tracker 项目现成的):
///   - Channel 缓冲 (4096 容量, DropOldest)
///   - 后台 SendLoop (每秒批量发 50 条)
///   - 后台 HeartbeatLoop (每 30 秒心跳)
///   - StartSessionAsync 建立会话, EndSessionAsync 结束
///
/// 会话建立前的事件会缓存在 Channel 里, 建立后自动发出。
/// </summary>
public sealed class ServerTrackerSink : ITrackerSink, IDisposable
{
    private readonly ServerConnection _conn;
    private bool _ended;

    public ServerTrackerSink(string serverBaseUrl)
    {
        _conn = new ServerConnection(serverBaseUrl);

        // fire-and-forget 建立会话 (构造函数不能 await)
        // 会话建立前的事件缓存在 Channel, 建立后自动发
        _ = _conn.StartSessionAsync().ContinueWith(t =>
        {
            if (!t.Result)
            {
                Console.Error.WriteLine(
                    "[ServerSink] 会话建立失败, 事件将丢失 (Server 未启动?)");
            }
            else
            {
                Console.Error.WriteLine(
                    $"[ServerSink] 会话已建立: {_conn.SessionId?[..8]}...");
            }
        });
    }

    public void Post(TrackedEvent evt)
    {
        // TrackedEvent → TrackedEventDto (timestamp 转 ISO 8601 字符串)
        _conn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = evt.Type,
            timestamp = evt.Timestamp.ToString("o"),
            level = evt.Level,
            source = evt.Source,
            title = evt.Title,
            detail = evt.Detail,
            xml = evt.Xml,
        });
    }

    public async Task FlushAsync()
    {
        // 1. 等待 Channel 里的事件全部发出 (SendLoop 每秒一轮)
        await _conn.FlushAsync();

        // 2. 通知服务端会话结束 (会触发持久化到 SQLite)
        if (!_ended)
        {
            _ended = true;
            await _conn.EndSessionAsync();
        }
    }

    public void Dispose()
    {
        // EndSession 已在 FlushAsync 里调过;这里只释放连接
        _conn.Dispose();
    }
}

/// <summary>
/// 复合 Sink: 把事件同时投递到多个 sink (双写)。
///
/// 当前用法: 本地 LocalLogTrackerSink (Console 日志) + ServerTrackerSink (HTTP 上报)。
/// Post 同步调所有 sink; FlushAsync 并行等所有 sink。
/// </summary>
public sealed class CompositeTrackerSink : ITrackerSink, IDisposable
{
    private readonly ITrackerSink[] _sinks;
    private bool _disposed;

    public CompositeTrackerSink(params ITrackerSink[] sinks)
    {
        _sinks = sinks;
    }

    public void Post(TrackedEvent evt)
    {
        if (_disposed) return;
        foreach (var sink in _sinks)
        {
            try { sink.Post(evt); }
            catch (Exception ex)
            {
                // 单个 sink 异常不影响其他 sink
                Console.Error.WriteLine($"[Composite] sink {sink.GetType().Name} Post 异常: {ex.Message}");
            }
        }
    }

    public async Task FlushAsync()
    {
        if (_disposed) return;
        // 并行等所有 sink 刷完
        await Task.WhenAll(_sinks.Select(async sink =>
        {
            try { await sink.FlushAsync(); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Composite] sink {sink.GetType().Name} Flush 异常: {ex.Message}");
            }
        }));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var sink in _sinks)
        {
            if (sink is IDisposable d)
            {
                try { d.Dispose(); }
                catch { }
            }
        }
    }
}
