using System.Collections.Generic;
using System.IO;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Channels;

namespace Hyperion.Tracker.Services;

/// <summary>
/// Tracker 与 Server 的 HTTP 连接管理。
/// 事件通过 Channel 缓冲，后台 Task 批量发送；另有心跳线程保活。
/// 取证文件上传走独立有界 Channel：流式发送、串行限并发、失败持久化重试。
/// </summary>
public sealed class ServerConnection : IDisposable
{
    private readonly HttpClient _http;
    private readonly Channel<TrackedEventDto> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _sendTask;
    private readonly Task _heartbeatTask;

    // 上传：有界队列 + 单 worker（流式发送，避免整文件读入内存）
    private readonly Channel<UploadJob> _uploadChannel;
    private readonly Task _uploadTask;
    private const int MaxUploadAttempts = 3;

    // 失败上传的持久化重试队列（跨进程重启存活）
    private readonly string _pendingQueueFile;
    private readonly object _pendingLock = new();
    private int _disposed;

    public string? SessionId { get; private set; }
    public bool IsConnected => SessionId != null;

    // 会话写凭据：start 时由服务端下发，通过 HttpClient 默认头随所有写请求携带
    private string? _sessionToken;

    public ServerConnection(string serverBase)
    {
        _http = CertPinning.CreatePinnedClient(serverBase, TimeSpan.FromSeconds(10));
        _channel = Channel.CreateBounded<TrackedEventDto>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        _uploadChannel = Channel.CreateBounded<UploadJob>(new BoundedChannelOptions(64)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false,
        });

        _pendingQueueFile = Path.Combine(AppContext.BaseDirectory, "pending_uploads.json");

        _sendTask = Task.Run(() => SendLoop(_cts.Token));
        _heartbeatTask = Task.Run(() => HeartbeatLoop(_cts.Token));
        _uploadTask = Task.Run(() => UploadLoop(_cts.Token));
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    /// <summary>向 Server 创建会话（可选携带会话建立时采纳的策略），成功后重放上次失败的上传任务。</summary>
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
            _sessionToken = body?.token;
            if (SessionId == null || string.IsNullOrEmpty(_sessionToken)) return false;

            // 会话凭据设为默认头：所有写请求（事件/心跳/产物/上传）自动携带
            _http.DefaultRequestHeaders.Remove("X-Session-Token");
            _http.DefaultRequestHeaders.Add("X-Session-Token", _sessionToken);

            Console.WriteLine($"[ServerConnection] 会话已创建: {SessionId[..8]}...");
            ReplayPendingUploads();
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerConnection] 连接失败: {ex}");
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
        finally
        {
            // 会话凭据随会话结束失效
            _http.DefaultRequestHeaders.Remove("X-Session-Token");
            _sessionToken = null;
        }
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
                Console.Error.WriteLine($"[ServerConnection] POST {relativePath} 失败: {ex}");
            }
        });
    }

    /// <summary>向服务端 multipart 上传一个取证文件（非阻塞，流式发送）。队列满或重试耗尽时落入持久化重试队列。</summary>
    public void UploadFile(string relativePath, Dictionary<string, string> fields, string localFilePath)
    {
        if (SessionId == null) return;
        var job = new UploadJob(relativePath, fields, localFilePath);
        if (!_uploadChannel.Writer.TryWrite(job))
            PersistPendingUpload(job);
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
                Console.Error.WriteLine($"[ServerConnection] 发送异常: {ex}");
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
    //  上传 worker（单读者串行，流式发送 + 重试 + 落盘）
    // ═══════════════════════════════════════════════════════════════

    private async Task UploadLoop(CancellationToken ct)
    {
        while (true)
        {
            UploadJob job;
            try
            {
                if (!await _uploadChannel.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
                    break;
                if (!_uploadChannel.Reader.TryRead(out job!))
                    continue;
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                await UploadOneAsync(job, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task UploadOneAsync(UploadJob job, CancellationToken ct)
    {
        for (var attempt = 1; attempt <= MaxUploadAttempts; attempt++)
        {
            try
            {
                // 流式发送：StreamContent 直接包装文件流，不再整文件读入内存
                await using var fs = File.OpenRead(job.LocalFilePath);
                using var content = new MultipartFormDataContent();
                foreach (var kv in job.Fields)
                    content.Add(new StringContent(kv.Value), kv.Key);
                var streamContent = new StreamContent(fs);
                streamContent.Headers.ContentLength = fs.Length;
                content.Add(streamContent, "file", Path.GetFileName(job.LocalFilePath));

                var resp = await _http.PostAsync(job.RelativePath, content, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[ServerConnection] 上传成功: {job.LocalFilePath}");
                    return;
                }
                Console.Error.WriteLine($"[ServerConnection] 上传失败: {resp.StatusCode} {job.LocalFilePath}");
            }
            catch (OperationCanceledException)
            {
                // 服务停止取消：任务未被服务端确认，落盘避免丢失
                PersistPendingUpload(job);
                throw;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ServerConnection] 上传异常 {job.LocalFilePath}: {ex.Message}");
            }

            if (attempt < MaxUploadAttempts)
                await Task.Delay(TimeSpan.FromSeconds(2 * attempt), ct);
        }

        // 重试耗尽仍未成功 → 持久化，等下次会话重放
        PersistPendingUpload(job);
    }

    // ═══════════════════════════════════════════════════════════════
    //  失败上传持久化重试队列
    // ═══════════════════════════════════════════════════════════════

    private void PersistPendingUpload(UploadJob job)
    {
        try
        {
            lock (_pendingLock)
            {
                var list = LoadPendingUploads();
                list.Add(new PendingUploadRecord
                {
                    Path = job.RelativePath,
                    Fields = job.Fields,
                    LocalFilePath = job.LocalFilePath,
                });
                WritePendingUploads(list);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerConnection] 写入重试队列失败 {job.LocalFilePath}: {ex.Message}");
        }
    }

    private List<PendingUploadRecord> LoadPendingUploads()
    {
        try
        {
            if (!File.Exists(_pendingQueueFile)) return new();
            var json = File.ReadAllText(_pendingQueueFile);
            return JsonSerializer.Deserialize<List<PendingUploadRecord>>(json) ?? new();
        }
        catch
        {
            return new();
        }
    }

    private void WritePendingUploads(List<PendingUploadRecord> list)
    {
        File.WriteAllText(_pendingQueueFile, JsonSerializer.Serialize(list));
    }

    /// <summary>会话建立成功后重放上次失败的上传任务（乐观清空，失败自动回写队列）。</summary>
    private void ReplayPendingUploads()
    {
        List<PendingUploadRecord> list;
        lock (_pendingLock)
        {
            list = LoadPendingUploads();
            if (list.Count == 0) return;
            WritePendingUploads(new());
        }

        foreach (var rec in list)
        {
            if (!File.Exists(rec.LocalFilePath))
            {
                Console.Error.WriteLine($"[ServerConnection] 重放跳过（文件已不存在）: {rec.LocalFilePath}");
                continue;
            }
            UploadFile(rec.Path, rec.Fields, rec.LocalFilePath);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  释放（幂等）
    // ═══════════════════════════════════════════════════════════════

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        _cts.Cancel();
        _channel.Writer.TryComplete();
        _uploadChannel.Writer.TryComplete();
        try { _sendTask.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _heartbeatTask.Wait(TimeSpan.FromSeconds(3)); } catch { }
        try { _uploadTask.Wait(TimeSpan.FromSeconds(5)); } catch { }

        // 记录停止时未发送的数量（事件 + 上传）
        var queuedEvents = _channel.Reader.Count;
        var queuedUploads = _uploadChannel.Reader.Count;
        if (queuedEvents > 0 || queuedUploads > 0)
            Console.Error.WriteLine($"[ServerConnection] 停止时未发送: {queuedEvents} 事件, {queuedUploads} 上传");

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
        public string token { get; init; } = "";
    }

    /// <summary>会话建立时采纳的策略快照（与 Server 端 PolicyInfo 对应）。</summary>
    public sealed record PolicyInfoDto
    {
        public List<string> kernelFuncs { get; init; } = new();
        public List<string> whitelistCertSubjects { get; init; } = new();
        public List<string> whitelistHashes { get; init; } = new();
    }

    private sealed record UploadJob(string RelativePath, Dictionary<string, string> Fields, string LocalFilePath);

    private sealed class PendingUploadRecord
    {
        public string Path { get; set; } = "";
        public Dictionary<string, string> Fields { get; set; } = new();
        public string LocalFilePath { get; set; } = "";
    }
}
