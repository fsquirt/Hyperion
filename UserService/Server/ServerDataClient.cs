using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace Hyperion.UserService;

/// <summary>
/// 服务端数据上报客户端 — 4 种独立 API。
///
/// 设计:
///   - events (winevent + etw)  → /api/tracker/events (批量, 走 Channel)
///   - snapshots (security/tree) → /api/tracker/snapshots (每条独立 POST)
///   - kernel-comms (driver/attach/ioctl) → /api/tracker/kernel-comms (每条独立 POST)
///   - dumps                    → /api/tracker/dumps (每条独立 POST)
///
/// 会话建立:
///   - 启动时调 /api/tracker/start 拿 sessionId
///   - 关闭时调 /api/tracker/end
///
/// events 用 Channel 缓冲 + 后台 SendLoop 批量发(高频率)
/// snapshots/kernel-comms/dumps 直接同步 POST(低频率,不阻塞监控线程则用 Task.Run)
/// </summary>
public sealed class ServerDataClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly Channel<TrackedEvent> _eventChan;
    private readonly Task _sendLoop;
    private readonly CancellationTokenSource _cts = new();

    /// <summary>当前会话 ID(建立后可用)。</summary>
    public string? SessionId { get; private set; }

    public ServerDataClient(string baseUrl)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _eventChan = Channel.CreateBounded<TrackedEvent>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });
        _sendLoop = Task.Run(EventSendLoop);
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    /// <summary>启动会话(异步,失败不抛异常,后续 PostEvents 会缓存在 Channel)。</summary>
    public async Task StartSessionAsync(string machineName, int pid)
    {
        Console.Error.WriteLine($"[ServerClient] [STEP] StartSession: POST {_baseUrl}/api/tracker/start (machine={machineName}, pid={pid})");
        try
        {
            var res = await _http.PostAsJsonAsync(
                _baseUrl + "/api/tracker/start",
                new { machineName, pid });
            Console.Error.WriteLine($"[ServerClient] [STEP] StartSession 响应: {res.StatusCode}");
            if (res.IsSuccessStatusCode)
            {
                var raw = await res.Content.ReadAsStringAsync();
                Console.Error.WriteLine($"[ServerClient] [STEP] StartSession body: {raw}");
                var body = await res.Content.ReadFromJsonAsync<StartSessionResponse>();
                SessionId = body?.id;
                if (SessionId != null)
                    Console.Error.WriteLine($"[ServerClient] [STEP] 会话建立成功: sid={SessionId[..Math.Min(8, SessionId.Length)]}... (len={SessionId.Length})");
                else
                    Console.Error.WriteLine("[ServerClient] [STEP] 会话建立警告: sessionId 为 null (反序列化失败?)");
            }
            else
            {
                Console.Error.WriteLine($"[ServerClient] [STEP] 会话建立失败: {res.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] [STEP] 会话建立异常: {ex.Message}");
        }
    }

    /// <summary>结束会话(等 Channel 排空后调 end)。</summary>
    public async Task EndSessionAsync()
    {
        _cts.Cancel();
        await _sendLoop;

        if (SessionId == null) return;
        try
        {
            await _http.PostAsJsonAsync(
                _baseUrl + "/api/tracker/end",
                new { sessionId = SessionId });
            Console.Error.WriteLine("[ServerClient] 会话已结束");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 结束会话异常: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  1. 事件 (winevent + etw) — 走 Channel 批量发
    // ═══════════════════════════════════════════════════════════════

    /// <summary>投递 winevent/etw 事件到 Channel(非阻塞)。</summary>
    public void PostEvent(TrackedEvent evt)
    {
        _eventChan.Writer.TryWrite(evt);
    }

    private async Task EventSendLoop()
    {
        const int BatchSize = 50;
        const int IntervalMs = 1000;
        var batch = new List<TrackedEvent>(BatchSize);

        while (!_cts.IsCancellationRequested)
        {
            batch.Clear();
            try
            {
                // 等 Channel 里来数据
                if (await _eventChan.Reader.WaitToReadAsync(_cts.Token))
                {
                    while (batch.Count < BatchSize && _eventChan.Reader.TryRead(out var evt))
                    {
                        batch.Add(evt);
                    }
                }
            }
            catch (OperationCanceledException) { break; }

            if (batch.Count == 0) continue;

            // 等 SessionId 建立后发
            if (SessionId == null)
            {
                // 还没建立会话,先放回 Channel(等待建立)
                foreach (var e in batch) _eventChan.Writer.TryWrite(e);
                await Task.Delay(IntervalMs);
                continue;
            }

            try
            {
                var req = new
                {
                    sessionId = SessionId,
                    events = batch,
                };
                await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/events", req);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ServerClient] 事件发送失败({batch.Count} 条): {ex.Message}");
                // 失败也丢弃(不重试,避免堆积)
            }
        }

        // 最后再排空一次
        while (_eventChan.Reader.TryRead(out var evt))
        {
            batch.Add(evt);
            if (batch.Count >= BatchSize)
            {
                await FlushBatchAsync(batch);
                batch.Clear();
            }
        }
        if (batch.Count > 0) await FlushBatchAsync(batch);
    }

    private async Task FlushBatchAsync(List<TrackedEvent> batch)
    {
        if (SessionId == null || batch.Count == 0) return;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/events",
                new { sessionId = SessionId, events = batch });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 最终批次发送失败: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  2. 进程树快照 — 每次独立 POST
    // ═══════════════════════════════════════════════════════════════

    public async Task PostSnapshotAsync(string kind, int processCount, string processesJson)
    {
        if (SessionId == null)
        {
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({kind}) 跳过: SessionId 未建立");
            return;
        }
        Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({kind}) 发送中... (sid={SessionId[..8]}, count={processCount}, json={processesJson.Length}B)");
        try
        {
            var resp = await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/snapshots", new
            {
                sessionId = SessionId,
                kind,  // "security" | "tree"
                processCount,
                processesJson,
            });
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({kind}) 响应: {resp.StatusCode}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({kind}) 异常: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  3. 内核通信 — 驱动扫描 / 附着 / IOCTL
    // ═══════════════════════════════════════════════════════════════

    public async Task PostKernelCommAsync(string kind, string level, string source, string title, string detail)
    {
        if (SessionId == null) return;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/kernel-comms", new
            {
                sessionId = SessionId,
                kind,  // "driver" | "attach" | "ioctl"
                level, source, title, detail,
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 内核通信发送失败: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  4. Dump 触发
    // ═══════════════════════════════════════════════════════════════

    public async Task PostDumpAsync(string level, string title, string detail, string dumpFilesJson)
    {
        if (SessionId == null) return;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/dumps", new
            {
                sessionId = SessionId,
                level, title, detail, dumpFilesJson,
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] dump 发送失败: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  配置拉取
    // ═══════════════════════════════════════════════════════════════

    public async Task<TrackerConfig?> FetchConfigAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<TrackerConfig>(_baseUrl + "/api/tracker/config");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 拉取配置失败: {ex.Message}");
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════

    public void Dispose()
    {
        _cts.Cancel();
        _http.Dispose();
    }

    // 响应模型
    private sealed class StartSessionResponse
    {
        public string? id { get; set; }
    }

    public sealed class TrackerConfig
    {
        public int TreePollIntervalSec { get; set; } = 10;
        public bool IoctlEnabled { get; set; } = false;
        public string DumpMode { get; set; } = "mini";
        public bool FileCopyEnabled { get; set; } = true;

        // 转 CommsDumpMode 枚举
        public SuperUserService.Models.CommsDumpMode DumpModeEnum =>
            DumpMode.ToLowerInvariant() switch
            {
                "raw" => SuperUserService.Models.CommsDumpMode.Raw,
                "full" => SuperUserService.Models.CommsDumpMode.Full,
                _ => SuperUserService.Models.CommsDumpMode.Mini,
            };
    }
}
