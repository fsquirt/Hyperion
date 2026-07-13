using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using UserService.Native;

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

    // H7-v2: SessionId 有界等待已超时标记。
    //   StartSessionAsync 是 fire-and-forget, 网络抖动可能 200ms 后才建立 SessionId。
    //   EventSendLoop 首个 batch 会等待最多 5s; 超时后置此标记, 后续 batch 不再重复等待。
    //   若 StartSession 后续成功 (SessionId != null), 此标记不影响发送 (仅跳过等待)。
    private volatile bool _sessionWaitExpired;

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
        Console.Error.WriteLine($"[ServerClient] StartSession: POST {_baseUrl}/api/tracker/start (machine={machineName}, pid={pid})");
        try
        {
            var res = await _http.PostAsJsonAsync(
                _baseUrl + "/api/tracker/start",
                new { machineName, pid });
            if (res.IsSuccessStatusCode)
            {
                var body = await res.Content.ReadFromJsonAsync<StartSessionResponse>();
                SessionId = body?.id;
                if (SessionId != null)
                    Console.Error.WriteLine($"[ServerClient] 会话建立成功: sid={SessionId[..Math.Min(8, SessionId.Length)]}...");
                else
                    Console.Error.WriteLine("[ServerClient] 会话建立警告: sessionId 为 null");
            }
            else
            {
                Console.Error.WriteLine($"[ServerClient] 会话建立失败: {res.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 会话建立异常: {ex.Message}");
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

            // H7-v2: 等 SessionId 建立后发 (有界等待, 覆盖网络抖动)
            //   原 H7 直接丢弃 batch: StartSession 慢建立 (网络抖动 200ms 后成功) 场景下,
            //     这 200ms 内的所有事件全部丢失。AntiCheatService.cs:111 是 fire-and-forget,
            //     慢建立是真实场景。
            //   v2 改进: 首个 batch 等待最多 5s (HttpClient 超时 15s, 5s 覆盖大部分抖动),
            //     每 100ms 轮询 SessionId。建立后立即发送; 超时则丢弃并置 _sessionWaitExpired,
            //     后续 batch 不再等待 (避免每个 batch 都阻塞 5s)。
            //     等待期间 Channel 继续缓冲新事件 (DropOldest), 不会全部丢失。
            if (SessionId == null)
            {
                if (_sessionWaitExpired)
                {
                    // 已等待过一次, StartSession 仍未成功 — 丢弃
                    Console.Error.WriteLine($"[ServerClient] SessionId 仍未建立, 丢弃 {batch.Count} 条事件 " +
                                            "(StartSession 失败或超时, 请检查服务端连通性)");
                    batch.Clear();
                    await Task.Delay(IntervalMs);
                    continue;
                }

                // 首次等待: 最多 5s, 每 100ms 轮询
                Console.Error.WriteLine($"[ServerClient] SessionId 未建立, 等待 StartSession (batch={batch.Count}, 最多 5s)...");
                for (int i = 0; i < 50 && !_cts.IsCancellationRequested; i++)
                {
                    if (SessionId != null) break;
                    await Task.Delay(100);
                }

                if (SessionId == null)
                {
                    // 5s 超时, 标记不再等待
                    _sessionWaitExpired = true;
                    Console.Error.WriteLine($"[ServerClient] SessionId 等待 5s 超时, 丢弃 {batch.Count} 条事件 " +
                                            "(StartSession 失败或超时, 后续 batch 不再等待)");
                    batch.Clear();
                    await Task.Delay(IntervalMs);
                    continue;
                }

                Console.Error.WriteLine($"[ServerClient] SessionId 已建立 (sid={SessionId[..Math.Min(8, SessionId.Length)]}...), 继续发送");
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
            Console.Error.WriteLine($"[ServerClient] PostSnapshot({payload.Kind}) 跳过: SessionId 未建立");
            return;
        }
        payload.SessionId = SessionId;
        try
        {
            await _http.PostAsJsonAsync(_baseUrl + "/api/tracker/snapshots", payload);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] PostSnapshot({payload.Kind}) 异常: {ex.Message}");
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

    /// <summary>
    /// 拉取完整运行时策略: dumpMode + fileCopyEnabled + 全量白名单 + 启用中的危险内核函数。
    /// 一次性返回客户端启动所需的全部策略, 不需要 admin 鉴权。
    /// </summary>
    public async Task<TrackerPolicy?> FetchPolicyAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<TrackerPolicy>(_baseUrl + "/api/tracker/policy");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] 拉取策略失败: {ex.Message}");
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════

    public void Dispose()
    {
        // H6: 之前 _cts.Cancel() 后立即 _http.Dispose(), 但 _sendLoop 可能正在
        //     await _http.PostAsJsonAsync(...), 会抛 ObjectDisposedException 变成
        //     unobserved exception。现在先 Cancel, 等 _sendLoop 退出 (最多 5 秒),
        //     再 dispose HttpClient。
        _cts.Cancel();
        try
        {
            if (!_sendLoop.Wait(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[ServerClient] Dispose: _sendLoop 未在 5 秒内退出");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ServerClient] Dispose: 等待 _sendLoop 异常: {ex.Message}");
        }
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
        public CommsDumpMode DumpModeEnum =>
            DumpMode.ToLowerInvariant() switch
            {
                "raw" => CommsDumpMode.Raw,
                "full" => CommsDumpMode.Full,
                _ => CommsDumpMode.Mini,
            };
    }

    /// <summary>
    /// 完整运行时策略 (GET /api/tracker/policy 响应)。
    /// 包含 dumpMode + fileCopyEnabled + 全量白名单 + 启用中的危险内核函数。
    /// 客户端启动时拉取一次并输出到本地日志。
    /// </summary>
    public sealed class TrackerPolicy
    {
        public string DumpMode { get; set; } = "mini";
        public bool FileCopyEnabled { get; set; } = true;
        public List<PolicyWhitelistEntry> Whitelist { get; set; } = new();
        public List<PolicyDangerousFunc> DangerousFunctions { get; set; } = new();

        // 转 CommsDumpMode 枚举 (与 TrackerConfig 对齐)
        public CommsDumpMode DumpModeEnum =>
            DumpMode.ToLowerInvariant() switch
            {
                "raw" => CommsDumpMode.Raw,
                "full" => CommsDumpMode.Full,
                _ => CommsDumpMode.Mini,
            };
    }

    /// <summary>策略中的白名单条目 (与 Server WhitelistEntry 字段对齐, snake_case)。</summary>
    public sealed class PolicyWhitelistEntry
    {
        public string Id { get; set; } = "";
        /// <summary>"hash" 或 "cert"</summary>
        public string Type { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string? Sha256 { get; set; }
        public string? Md5 { get; set; }
        public string? Sha1 { get; set; }
        public string? CertSubject { get; set; }
        public string? CertIssuer { get; set; }
        public string AddedAt { get; set; } = "";
        public string? Notes { get; set; }
    }

    /// <summary>策略中的危险内核函数条目 (仅 enabled, 与 Server KernelFuncEntry 字段对齐, snake_case)。</summary>
    public sealed class PolicyDangerousFunc
    {
        public string Id { get; set; } = "";
        public string FuncName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public string Category { get; set; } = "";
        /// <summary>"high" / "medium" / "low"</summary>
        public string Severity { get; set; } = "high";
        public bool Enabled { get; set; } = true;
        public string AddedAt { get; set; } = "";
        public string? Notes { get; set; }
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

    /// <summary>内核通信记录上传载荷 (driver/iat/device/attach/ioctl/ioctl-aggregate/unsigned-module-alert/targeted-scan/object-scan/handle-scan/attach-summary)。</summary>
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
        // 运行时检测索引列 (kind=ioctl-aggregate / unsigned-module-alert / targeted-scan)
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
