using System.Collections.Generic;
using System.Net.Http.Json;
using System.Threading.Channels;

namespace Hyperion.Tracker.Services;

/// <summary>
/// Tracker 与 Server 的 HTTP 连接管理。
/// 事件通过 Channel 缓冲，后台 Task 批量发送；另有心跳线程保活。
/// </summary>
public sealed class ServerConnection : IDisposable
{
    private readonly HttpClient _http;
    private readonly Channel<TrackedEventDto> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _sendTask;
    private readonly Task _heartbeatTask;

    public string? SessionId { get; private set; }
    public bool IsConnected => SessionId != null;

    public ServerConnection(string serverBase)
    {
        _http = new HttpClient { BaseAddress = new Uri(serverBase), Timeout = TimeSpan.FromSeconds(10) };
        _channel = Channel.CreateBounded<TrackedEventDto>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        _sendTask = Task.Run(() => SendLoop(_cts.Token));
        _heartbeatTask = Task.Run(() => HeartbeatLoop(_cts.Token));
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    /// <summary>向 Server 创建会话（可选携带会话建立时采纳的策略）。</summary>
    public async Task<bool> StartSessionAsync(PolicyInfoDto? policy = null)
    {
        try
        {
            var machine = Environment.MachineName;
            var pid = Environment.ProcessId;

            var resp = await _http.PostAsJsonAsync("/api/tracker/start", new
            {
                machineName = machine,
                pid = pid,
                policy = policy,
            }).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"[ServerConnection] start 失败: {resp.StatusCode}");
                return false;
            }

            var body = await resp.Content.ReadFromJsonAsync<StartResponse>().ConfigureAwait(false);
            SessionId = body?.id;
            if (SessionId == null) return false;

            Console.WriteLine($"[ServerConnection] 会话已创建: {SessionId[..8]}...");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerConnection] 连接失败: {ex.Message}");
            return false;
        }
    }

    /// <summary>通知 Server 会话结束。</summary>
    public async Task EndSessionAsync()
    {
        if (SessionId == null) return;
        try
        {
            await _http.PostAsJsonAsync("/api/tracker/end", new { sessionId = SessionId })
                .ConfigureAwait(false);
            Console.WriteLine("[ServerConnection] 会话已结束");
        }
        catch { }
    }

    /// <summary>向服务端 POST 一段 JSON（非阻塞，失败仅记日志）。用于策略 / IOCTL 统计 / 设备 / 文件 / 快照等产物上报。</summary>
    public void PostJson(string relativePath, object payload)
    {
        if (SessionId == null) return;
        _ = Task.Run(async () =>
        {
            try
            {
                await _http.PostAsJsonAsync(relativePath, payload, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ServerConnection] POST {relativePath} 失败: {ex.Message}");
            }
        });
    }

    /// <summary>向服务端 multipart 上传一个取证文件（非阻塞，失败仅记日志）。用于 FileCopy / DebugDump 文件内容落地。</summary>
    public void UploadFile(string relativePath, Dictionary<string, string> fields, string localFilePath)
    {
        if (SessionId == null) return;
        _ = Task.Run(async () =>
        {
            try
            {
                using var content = new MultipartFormDataContent();
                foreach (var kv in fields)
                    content.Add(new StringContent(kv.Value), kv.Key);
                var bytes = await File.ReadAllBytesAsync(localFilePath).ConfigureAwait(false);
                content.Add(new ByteArrayContent(bytes), "file", Path.GetFileName(localFilePath));
                var resp = await _http.PostAsync(relativePath, content).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    Console.Error.WriteLine($"[ServerConnection] 上传文件失败: {resp.StatusCode} {localFilePath}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ServerConnection] 上传文件异常 {localFilePath}: {ex.Message}");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  事件投递（非阻塞，由事件回调线程调用）
    // ═══════════════════════════════════════════════════════════════

    /// <summary>投递事件到发送队列（非阻塞）。</summary>
    public void PostEvent(TrackedEventDto evt)
    {
        _channel.Writer.TryWrite(evt);
    }

    // ═══════════════════════════════════════════════════════════════
    //  后台发送循环（每 1 秒批量发送最多 50 条）
    // ═══════════════════════════════════════════════════════════════

    private async Task SendLoop(CancellationToken ct)
    {
        var batch = new List<TrackedEventDto>(50);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(1000, ct);

                // drain channel
                batch.Clear();
                while (batch.Count < 50 && _channel.Reader.TryRead(out var evt))
                    batch.Add(evt);

                if (batch.Count == 0 || SessionId == null) continue;

                await _http.PostAsJsonAsync("/api/tracker/events", new
                {
                    sessionId = SessionId,
                    events = batch,
                }, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ServerConnection] 发送异常: {ex.Message}");
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  心跳循环（每 30 秒）
    // ═══════════════════════════════════════════════════════════════

    private async Task HeartbeatLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(30_000, ct);
                if (SessionId == null) continue;

                await _http.PostAsJsonAsync("/api/tracker/heartbeat", new
                {
                    sessionId = SessionId,
                }, ct);
            }
            catch (OperationCanceledException) { break; }
            catch { }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  释放
    // ═══════════════════════════════════════════════════════════════

    public void Dispose()
    {
        _cts.Cancel();
        _channel.Writer.TryComplete();
        try { _sendTask.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _heartbeatTask.Wait(TimeSpan.FromSeconds(3)); } catch { }
        _cts.Dispose();
        _http.Dispose();
    }

    // ═══════════════════════════════════════════════════════════════
    //  DTO
    // ═══════════════════════════════════════════════════════════════

    public sealed record TrackedEventDto
    {
        public string type { get; init; } = "";
        public string timestamp { get; init; } = "";
        public string level { get; init; } = "INFO";
        public string source { get; init; } = "";
        public string title { get; init; } = "";
        public string? detail { get; init; }
        public string? xml { get; init; }
    }

    private sealed record StartResponse
    {
        public string id { get; init; } = "";
    }

    /// <summary>会话建立时采纳的策略快照（与 Server 端 PolicyInfo 对应）。</summary>
    public sealed record PolicyInfoDto
    {
        public List<string> kernelFuncs { get; init; } = new();
        public List<string> whitelistCertSubjects { get; init; } = new();
        public List<string> whitelistHashes { get; init; } = new();
    }
}
