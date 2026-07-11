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

    public async Task PostSnapshotAsync(SnapshotPayload payload)
    {
        if (SessionId == null)
        {
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({payload.Kind}) 跳过: SessionId 未建立");
            return;
        }
        payload.SessionId = SessionId;
        Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({payload.Kind}) 发送中... (sid={SessionId[..8]}, count={payload.ProcessCount}, json={payload.ProcessesJson?.Length ?? 0}B)");
        try
        {
            var resp = await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/snapshots", payload);
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({payload.Kind}) 响应: {resp.StatusCode}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] [STEP] PostSnapshot({payload.Kind}) 异常: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  3. 内核通信 — 驱动扫描 / IAT / 设备 / 附着 / IOCTL
    // ═══════════════════════════════════════════════════════════════

    public async Task PostKernelCommAsync(KernelCommPayload payload)
    {
        if (SessionId == null) return;
        payload.SessionId = SessionId;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/kernel-comms", payload);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 内核通信发送失败: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  4. Dump 触发
    // ═══════════════════════════════════════════════════════════════

    public async Task PostDumpAsync(DumpPayload payload)
    {
        if (SessionId == null) return;
        payload.SessionId = SessionId;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/dumps", payload);
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

    // ═══════════════════════════════════════════════════════════════
    //  结构化 Payload 类 (与 Server 端 Request DTO 字段对齐)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>进程树快照上传载荷。</summary>
    public sealed class SnapshotPayload
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        public string Kind { get; set; } = "tree";
        public int ProcessCount { get; set; }
        public string? ProcessesJson { get; set; }
        // Security 模式统计
        public int PplBrokenCount { get; set; }
        public int SuspiciousMemCount { get; set; }
        public int HighRiskHandleCount { get; set; }
        public int UntrustedCount { get; set; }
        // Tree 模式汇总统计 (Category C: 之前 UI 拿不到, 现在索引化)
        public int TotalThreads { get; set; }
        public int MaxThreadsInSingleProc { get; set; }
        public ulong TopPidByThreads { get; set; }
        public ulong TotalWorkingSet { get; set; }
        public ulong TotalPrivatePages { get; set; }
        public int TotalHandles { get; set; }
    }

    /// <summary>内核通信记录上传载荷 (driver/iat/device/attach/ioctl/comms-event/object-scan/handle-scan/attach-summary)。</summary>
    public sealed class KernelCommPayload
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        public string Kind { get; set; } = "driver";
        public string Level { get; set; } = "INFO";
        public string Source { get; set; } = "";
        public string Title { get; set; } = "";
        public string? DataJson { get; set; }
        // 驱动扫描索引列
        public string? DriverFileName { get; set; }
        public int? DriverClass { get; set; }
        public string? VendorName { get; set; }
        public int? HasCatalog { get; set; }
        public int? HasEmbedded { get; set; }
        // 驱动映像信息索引列 (Category A: 之前丢失)
        public ulong? ImageBase { get; set; }
        public uint? ImageSize { get; set; }
        public ushort? LoadOrderIndex { get; set; }
        // IAT 索引列
        public int? DangerousApiCount { get; set; }
        // 附着索引列
        public uint? AttachId { get; set; }
        public string? DeviceName { get; set; }
        public ulong? FilterDeviceAddr { get; set; }
        // IOCTL 索引列
        public uint? IoControlCode { get; set; }
        public ulong? RequestorPid { get; set; }
        public uint? MajorFunction { get; set; }
        // 通信事件索引列 (Category A: per-event comms data)
        public uint? Method { get; set; }
        public ulong? TargetDeviceAddr { get; set; }
        public uint? StackModuleCount { get; set; }
        public uint? PayloadSize { get; set; }
        // 通信事件 payload 原始字节 (16 进制字符串, 用于服务端过滤/检索)
        public string? PayloadHex { get; set; }
        // 对象扫描 / 句柄扫描索引列
        public string? TypeName { get; set; }
        public int? HighRiskCount { get; set; }
    }

    /// <summary>Dump 记录上传载荷。</summary>
    public sealed class DumpPayload
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        public string Level { get; set; } = "INFO";
        public string Title { get; set; } = "";
        // 通信监控汇总统计 (CbnCommsSummary 索引列)
        public uint TotalIoctls { get; set; }
        public uint TotalEvents { get; set; }
        public uint PathCount { get; set; }
        public int AbnormalCount { get; set; }
        public int DumpedCount { get; set; }
        public int CopiedCount { get; set; }
        // 完整 per-path JSON 数组 (CbnPathEntry 全维度)
        public string? DumpFilesJson { get; set; }
        // 驱动 dump 元数据 JSON 数组 (Category D: 之前 C++ 只写磁盘, 现在导出到服务端)
        public string? DriverDumpsJson { get; set; }
        // 驱动 dump 数量 (索引列, 用于过滤)
        public int DriverDumpCount { get; set; }
        // JSON 日志路径 / dumpfile 目录 / filecopy 目录 (Category D: 之前只 C++ 本地)
        public string? JsonLogPath { get; set; }
        public string? DumpFileDir { get; set; }
        public string? FileCopyDir { get; set; }
    }
}
