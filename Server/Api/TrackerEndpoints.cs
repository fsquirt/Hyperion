using Hyperion.Server.Data;
using Hyperion.Server.Models;
using Hyperion.Server.Services;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace Hyperion.Server.Api;

/// <summary>
/// 运行时追踪 API — 4 种独立数据流 + 配置 + 会话管理。
/// 4 种数据流:
///   1. events:    Tracker 的 Windows 事件 + ETW 事件
///   2. snapshots: 进程树快照(全量 baseline + tree 轮询)
///   3. kernel-comms: 驱动扫描 + 附着 + IOCTL 拦截
///   4. dumps:     通信 dump 文件记录
/// </summary>
public static class TrackerEndpoints
{
    public static void MapTrackerApi(this WebApplication app)
    {
        // ═══ 会话生命周期 ═══
        app.MapPost("/api/tracker/start", HandleStart);
        app.MapPost("/api/tracker/heartbeat", HandleHeartbeat);
        app.MapPost("/api/tracker/end", HandleEnd);

        // ═══ 会话管理(管理员) ═══
        app.MapGet("/api/tracker/sessions", HandleGetSessions);
        app.MapGet("/api/tracker/sessions/{id}", HandleGetSessionDetail);
        app.MapDelete("/api/tracker/sessions/{id}", HandleDeleteSession);

        // ═══ 1. 事件(winevent + etw) ═══
        app.MapPost("/api/tracker/events", HandlePostEvents);
        app.MapGet("/api/tracker/sessions/{id}/events", HandleGetEvents);

        // ═══ 2. 进程树快照 ═══
        app.MapPost("/api/tracker/snapshots", HandlePostSnapshot);
        app.MapGet("/api/tracker/sessions/{id}/snapshots", HandleGetSnapshots);

        // ═══ 3. 内核通信(驱动+附着+IOCTL) ═══
        app.MapPost("/api/tracker/kernel-comms", HandlePostKernelComm);
        app.MapGet("/api/tracker/sessions/{id}/kernel-comms", HandleGetKernelComms);

        // ═══ 4. Dump 触发 ═══
        app.MapPost("/api/tracker/dumps", HandlePostDump);
        app.MapGet("/api/tracker/sessions/{id}/dumps", HandleGetDumps);

        // ═══ 配置 ═══
        app.MapGet("/api/tracker/config", HandleGetConfig);
        app.MapPost("/api/tracker/config", HandleSetConfig);
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话生命周期
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandleStart(
        TrackerStartRequest req,
        TrackerSessionStore store,
        ILogger<Program> logger)
    {
        logger.LogDebug("[Tracker] HandleStart 入口: machine={Machine}, pid={Pid} @ {Ts}",
            req.MachineName, req.Pid, DateTime.Now.ToString("HH:mm:ss.fff"));
        if (string.IsNullOrWhiteSpace(req.MachineName))
            return Results.BadRequest(new { error = "machineName required" });

        var summary = store.CreateSession(req.MachineName, req.Pid);
        logger.LogInformation("[Tracker] 新会话: {Id} from {Machine}",
            summary.Id, summary.MachineName);
        return Results.Json(summary);
    }

    private static IResult HandleHeartbeat(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        var ok = store.Heartbeat(req.SessionId);
        return ok ? Results.Ok() : Results.NotFound();
    }

    private static IResult HandleEnd(
        TrackerSessionIdRequest req,
        TrackerSessionStore store)
    {
        store.EndSession(req.SessionId);
        return Results.Ok();
    }

    // ═══════════════════════════════════════════════════════════════
    //  会话管理
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetSessions(HttpContext ctx, TrackerSessionStore store)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        return Results.Json(await store.GetSummariesAsync());
    }

    private static async Task<IResult> HandleGetSessionDetail(
        HttpContext ctx, string id, TrackerSessionStore store)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id);
        return detail is not null ? Results.Json(detail) : Results.NotFound();
    }

    private static async Task<IResult> HandleDeleteSession(
        HttpContext ctx, string id,
        TrackerSessionStore store,
        IDbContextFactory<AttestationDbContext> dbFactory)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        // 内存中活跃会话:先标记结束
        store.EndSession(id);

        // 数据库:删除会话 + 关联的快照/通信/dump 记录
        await using var db = await dbFactory.CreateDbContextAsync();

        // 删除会话本身
        var session = await db.TrackerSessions.FindAsync(id);
        if (session != null) db.TrackerSessions.Remove(session);

        // 删除关联数据
        db.TrackerSnapshots.RemoveRange(db.TrackerSnapshots.Where(s => s.SessionId == id));
        db.TrackerKernelComms.RemoveRange(db.TrackerKernelComms.Where(k => k.SessionId == id));
        db.TrackerDumps.RemoveRange(db.TrackerDumps.Where(d => d.SessionId == id));

        await db.SaveChangesAsync();
        return Results.Ok();
    }

    // ═══════════════════════════════════════════════════════════════
    //  1. 事件(winevent + etw)
    // ═══════════════════════════════════════════════════════════════

    private static IResult HandlePostEvents(
        TrackerEventsRequest req,
        TrackerSessionStore store)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        if (req.Events.Count == 0)
            return Results.Ok(new { added = 0 });

        var added = store.AppendEvents(req.SessionId, req.Events);
        return Results.Ok(new { added });
    }

    private static async Task<IResult> HandleGetEvents(
        HttpContext ctx, string id, TrackerSessionStore store,
        string? level = null, string? type = null, string? search = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();
        var detail = await store.GetDetailAsync(id, level, search, type);
        return detail is not null ? Results.Json(detail) : Results.NotFound();
    }

    // ═══════════════════════════════════════════════════════════════
    //  2. 进程树快照
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostSnapshot(
        SnapshotRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerSnapshots.Add(new TrackerSnapshotEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Kind = req.Kind == "security" ? "security" : "tree",
            ProcessCount = req.ProcessCount,
            ProcessesJson = req.ProcessesJson ?? "[]",
            PplBrokenCount = req.PplBrokenCount,
            SuspiciousMemCount = req.SuspiciousMemCount,
            HighRiskHandleCount = req.HighRiskHandleCount,
            UntrustedCount = req.UntrustedCount,
            // Tree 模式汇总统计 (Category C)
            TotalThreads = req.TotalThreads,
            MaxThreadsInSingleProc = req.MaxThreadsInSingleProc,
            TopPidByThreads = req.TopPidByThreads,
            TotalWorkingSet = req.TotalWorkingSet,
            TotalPrivatePages = req.TotalPrivatePages,
            TotalHandles = req.TotalHandles,
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] 快照入库: {Id} ({Kind}, {Count} 进程, PPL={Ppl}, 可疑内存={Mem}, 高危句柄={Hdl}, 线程={Thr})",
            id, req.Kind, req.ProcessCount, req.PplBrokenCount, req.SuspiciousMemCount, req.HighRiskHandleCount, req.TotalThreads);
        return Results.Json(new { id, count = req.ProcessCount });
    }

    private static async Task<IResult> HandleGetSnapshots(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? kind = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerSnapshots.Where(s => s.SessionId == id);
        if (!string.IsNullOrWhiteSpace(kind))
            q = q.Where(s => s.Kind == kind);

        var list = await q.OrderByDescending(s => s.Timestamp)
            .Select(s => new
            {
                s.Id,
                s.SessionId,
                s.Timestamp,
                s.Kind,
                s.ProcessCount,
                processesJson = s.ProcessesJson,
                s.PplBrokenCount,
                s.SuspiciousMemCount,
                s.HighRiskHandleCount,
                s.UntrustedCount,
                // Tree 模式汇总统计 (Category C)
                s.TotalThreads,
                s.MaxThreadsInSingleProc,
                s.TopPidByThreads,
                s.TotalWorkingSet,
                s.TotalPrivatePages,
                s.TotalHandles,
            })
            .ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  3. 内核通信(驱动+附着+IOCTL)
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostKernelComm(
        KernelCommRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerKernelComms.Add(new TrackerKernelCommEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Kind = req.Kind,
            Level = req.Level,
            Source = req.Source,
            Title = req.Title,
            DataJson = req.DataJson,
            DriverFileName = req.DriverFileName,
            DriverClass = req.DriverClass,
            VendorName = req.VendorName,
            HasCatalog = req.HasCatalog,
            HasEmbedded = req.HasEmbedded,
            // 驱动映像信息索引列 (Category A)
            ImageBase = req.ImageBase,
            ImageSize = req.ImageSize,
            LoadOrderIndex = req.LoadOrderIndex,
            DangerousApiCount = req.DangerousApiCount,
            AttachId = req.AttachId,
            DeviceName = req.DeviceName,
            FilterDeviceAddr = req.FilterDeviceAddr,
            IoControlCode = req.IoControlCode,
            RequestorPid = req.RequestorPid,
            MajorFunction = req.MajorFunction,
            // 通信事件索引列 (kind=comms-event, Category A)
            Method = req.Method,
            TargetDeviceAddr = req.TargetDeviceAddr,
            StackModuleCount = req.StackModuleCount,
            PayloadSize = req.PayloadSize,
            PayloadHex = req.PayloadHex,
            // 对象扫描 / 句柄扫描索引列 (Category B)
            TypeName = req.TypeName,
            HighRiskCount = req.HighRiskCount,
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] 内核通信入库: {Id} ({Kind}) {Title}", id, req.Kind, req.Title);
        return Results.Json(new { id });
    }

    private static async Task<IResult> HandleGetKernelComms(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? kind = null, string? level = null, string? search = null,
        int? driverClass = null, string? vendorName = null,
        uint? attachId = null, uint? ioctlCode = null,
        ulong? requestorPid = null, string? driverFileName = null,
        uint? method = null, string? typeName = null, int? highRiskCount = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerKernelComms.Where(k => k.SessionId == id);

        if (!string.IsNullOrWhiteSpace(kind))
            q = q.Where(k => k.Kind == kind);
        if (!string.IsNullOrWhiteSpace(level))
            q = q.Where(k => k.Level == level);
        if (driverClass.HasValue)
            q = q.Where(k => k.DriverClass == driverClass);
        if (!string.IsNullOrWhiteSpace(vendorName))
            q = q.Where(k => k.VendorName != null && k.VendorName.Contains(vendorName));
        if (attachId.HasValue)
            q = q.Where(k => k.AttachId == attachId);
        if (ioctlCode.HasValue)
            q = q.Where(k => k.IoControlCode == ioctlCode);
        if (requestorPid.HasValue)
            q = q.Where(k => k.RequestorPid == requestorPid);
        if (!string.IsNullOrWhiteSpace(driverFileName))
            q = q.Where(k => k.DriverFileName != null && k.DriverFileName.Contains(driverFileName));
        // 通信事件 / 对象扫描 / 句柄扫描筛选 (Category A/B/C)
        if (method.HasValue)
            q = q.Where(k => k.Method == method);
        if (!string.IsNullOrWhiteSpace(typeName))
            q = q.Where(k => k.TypeName != null && k.TypeName.Contains(typeName));
        if (highRiskCount.HasValue)
            q = q.Where(k => k.HighRiskCount >= highRiskCount);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search;
            q = q.Where(k => k.Title.Contains(kw) || k.Source.Contains(kw) ||
                             (k.DataJson != null && k.DataJson.Contains(kw)) ||
                             (k.PayloadHex != null && k.PayloadHex.Contains(kw)));
        }

        var list = await q.OrderByDescending(k => k.Timestamp).ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  4. Dump 触发
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandlePostDump(
        DumpRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        if (string.IsNullOrWhiteSpace(req.SessionId))
            return Results.BadRequest(new { error = "sessionId required" });

        var id = Guid.NewGuid().ToString("N")[..16];
        var now = DateTime.UtcNow.ToString("o");

        await using var db = await dbFactory.CreateDbContextAsync();
        db.TrackerDumps.Add(new TrackerDumpEntity
        {
            Id = id,
            SessionId = req.SessionId,
            Timestamp = req.Timestamp ?? now,
            Level = req.Level,
            Title = req.Title,
            TotalIoctls = req.TotalIoctls,
            TotalEvents = req.TotalEvents,
            PathCount = req.PathCount,
            AbnormalCount = req.AbnormalCount,
            DumpedCount = req.DumpedCount,
            CopiedCount = req.CopiedCount,
            DumpFilesJson = req.DumpFilesJson ?? "[]",
            // 驱动 dump 元数据 (Category D)
            DriverDumpsJson = req.DriverDumpsJson ?? "[]",
            DriverDumpCount = req.DriverDumpCount,
            // 路径目录 (Category D)
            JsonLogPath = req.JsonLogPath,
            DumpFileDir = req.DumpFileDir,
            FileCopyDir = req.FileCopyDir,
        });
        await db.SaveChangesAsync();

        logger.LogInformation("[Tracker] Dump 入库: {Id} {Title} (路径={Path}, 异常={Abn}, IOCTL={Io}, 驱动dump={Dd})",
            id, req.Title, req.PathCount, req.AbnormalCount, req.TotalIoctls, req.DriverDumpCount);
        return Results.Json(new { id });
    }

    private static async Task<IResult> HandleGetDumps(
        HttpContext ctx, string id,
        IDbContextFactory<AttestationDbContext> dbFactory,
        string? level = null, string? search = null, int? minDriverDumpCount = null)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.TrackerDumps.Where(d => d.SessionId == id);

        if (!string.IsNullOrWhiteSpace(level))
            q = q.Where(d => d.Level == level);
        if (minDriverDumpCount.HasValue)
            q = q.Where(d => d.DriverDumpCount >= minDriverDumpCount);
        if (!string.IsNullOrWhiteSpace(search))
        {
            var kw = search;
            q = q.Where(d => d.Title.Contains(kw) ||
                             (d.DumpFilesJson != null && d.DumpFilesJson.Contains(kw)) ||
                             (d.DriverDumpsJson != null && d.DriverDumpsJson.Contains(kw)));
        }

        var list = await q.OrderByDescending(d => d.Timestamp).ToListAsync();
        return Results.Json(list);
    }

    // ═══════════════════════════════════════════════════════════════
    //  配置
    // ═══════════════════════════════════════════════════════════════

    private static async Task<IResult> HandleGetConfig(
        IDbContextFactory<AttestationDbContext> dbFactory,
        ILogger<Program> logger)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        logger.LogDebug("[Tracker] HandleGetConfig 入口 @ {Ts}", DateTime.Now.ToString("HH:mm:ss.fff"));
        try
        {
            var tCtx = System.Diagnostics.Stopwatch.StartNew();
            await using var db = await dbFactory.CreateDbContextAsync();
            tCtx.Stop();
            logger.LogDebug("[Tracker] HandleGetConfig: CreateDbContext 完成 (耗时 {Ms}ms)", tCtx.ElapsedMilliseconds);

            var tFind = System.Diagnostics.Stopwatch.StartNew();
            var cfg = await db.TrackerConfig.FindAsync("default");
            tFind.Stop();
            logger.LogDebug("[Tracker] HandleGetConfig: FindAsync 完成 (耗时 {Ms}ms, cfg={Cfg})",
                tFind.ElapsedMilliseconds, cfg == null ? "null" : "exists");

            sw.Stop();
            if (cfg == null)
            {
                logger.LogDebug("[Tracker] HandleGetConfig: 返回默认配置 (总耗时 {Ms}ms)", sw.ElapsedMilliseconds);
                return Results.Json(new
                {
                    treePollIntervalSec = 10,
                    ioctlEnabled = false,
                    dumpMode = "mini",
                    fileCopyEnabled = true,
                });
            }
            logger.LogDebug("[Tracker] HandleGetConfig: 返回 DB 配置 (总耗时 {Ms}ms)", sw.ElapsedMilliseconds);
            return Results.Json(new
            {
                treePollIntervalSec = cfg.TreePollIntervalSec,
                ioctlEnabled = cfg.IoctlEnabled != 0,
                dumpMode = cfg.DumpMode,
                fileCopyEnabled = cfg.FileCopyEnabled != 0,
            });
        }
        catch (Exception ex)
        {
            sw.Stop();
            logger.LogError(ex, "[Tracker] HandleGetConfig 异常 (耗时 {Ms}ms): {Msg}",
                sw.ElapsedMilliseconds, ex.Message);
            throw;
        }
    }

    private static async Task<IResult> HandleSetConfig(
        HttpContext ctx,
        TrackerConfigRequest req,
        IDbContextFactory<AttestationDbContext> dbFactory)
    {
        if (!IsAuth(ctx)) return Results.Unauthorized();

        if (req.TreePollIntervalSec < 1 || req.TreePollIntervalSec > 3600)
            return Results.BadRequest(new { error = "treePollIntervalSec must be 1..3600" });

        var validDumpModes = new[] { "raw", "mini", "full" };
        var dumpMode = string.IsNullOrWhiteSpace(req.DumpMode) ? "mini" : req.DumpMode.ToLowerInvariant();
        if (!validDumpModes.Contains(dumpMode))
            return Results.BadRequest(new { error = "dumpMode must be raw/mini/full" });

        await using var db = await dbFactory.CreateDbContextAsync();
        var cfg = await db.TrackerConfig.FindAsync("default");
        if (cfg == null)
        {
            cfg = new TrackerConfigEntity { Id = "default" };
            db.TrackerConfig.Add(cfg);
        }

        cfg.TreePollIntervalSec = req.TreePollIntervalSec;
        cfg.IoctlEnabled = req.IoctlEnabled ? 1 : 0;
        cfg.DumpMode = dumpMode;
        cfg.FileCopyEnabled = req.FileCopyEnabled ? 1 : 0;
        cfg.UpdatedAt = DateTime.UtcNow.ToString("o");

        await db.SaveChangesAsync();
        return Results.Json(new
        {
            treePollIntervalSec = cfg.TreePollIntervalSec,
            ioctlEnabled = cfg.IoctlEnabled != 0,
            dumpMode = cfg.DumpMode,
            fileCopyEnabled = cfg.FileCopyEnabled != 0,
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private static bool IsAuth(HttpContext ctx) =>
        ctx.Session.GetString("authenticated") == "true";

    // ═══════════════════════════════════════════════════════════════
    //  请求模型
    // ═══════════════════════════════════════════════════════════════

    private sealed record TrackerStartRequest
    {
        public string MachineName { get; init; } = "";
        public int Pid { get; init; }
    }

    private sealed record TrackerSessionIdRequest
    {
        public string SessionId { get; init; } = "";
    }

    private sealed record TrackerEventsRequest
    {
        public string SessionId { get; init; } = "";
        public List<TrackedEvent> Events { get; init; } = [];
    }

    /// <summary>进程树快照上传请求。</summary>
    public sealed class SnapshotRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        /// <summary>"security"(初始全量) | "tree"(后续轮询)</summary>
        public string Kind { get; set; } = "tree";
        public int ProcessCount { get; set; }
        /// <summary>完整进程列表 JSON 字符串(含所有结构化维度)</summary>
        public string? ProcessesJson { get; set; }
        // Security 快照汇总列
        public int PplBrokenCount { get; set; }
        public int SuspiciousMemCount { get; set; }
        public int HighRiskHandleCount { get; set; }
        public int UntrustedCount { get; set; }
        // Tree 模式汇总统计 (Category C: 之前 UI 拿不到)
        public int TotalThreads { get; set; }
        public int MaxThreadsInSingleProc { get; set; }
        public ulong TopPidByThreads { get; set; }
        public ulong TotalWorkingSet { get; set; }
        public ulong TotalPrivatePages { get; set; }
        public int TotalHandles { get; set; }
    }

    /// <summary>内核通信记录上传请求。</summary>
    public sealed class KernelCommRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        /// <summary>"driver" | "iat" | "device" | "attach" | "ioctl" | "comms-event" | "object-scan" | "handle-scan" | "attach-summary"</summary>
        public string Kind { get; set; } = "driver";
        public string Level { get; set; } = "INFO";
        public string Source { get; set; } = "";
        public string Title { get; set; } = "";
        /// <summary>完整结构化载荷 (序列化的 native struct JSON)</summary>
        public string? DataJson { get; set; }
        // 驱动扫描索引列
        public string? DriverFileName { get; set; }
        public int? DriverClass { get; set; }
        public string? VendorName { get; set; }
        public int? HasCatalog { get; set; }
        public int? HasEmbedded { get; set; }
        // 驱动映像信息索引列 (Category A)
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
        // 通信事件索引列 (kind=comms-event, Category A)
        public uint? Method { get; set; }
        public ulong? TargetDeviceAddr { get; set; }
        public uint? StackModuleCount { get; set; }
        public uint? PayloadSize { get; set; }
        public string? PayloadHex { get; set; }
        // 对象扫描 / 句柄扫描索引列 (Category B)
        public string? TypeName { get; set; }
        public int? HighRiskCount { get; set; }
    }

    /// <summary>Dump 记录上传请求。</summary>
    public sealed class DumpRequest
    {
        public string SessionId { get; set; } = "";
        public string? Timestamp { get; set; }
        public string Level { get; set; } = "INFO";
        public string Title { get; set; } = "";
        // 汇总统计
        public uint TotalIoctls { get; set; }
        public uint TotalEvents { get; set; }
        public uint PathCount { get; set; }
        public int AbnormalCount { get; set; }
        public int DumpedCount { get; set; }
        public int CopiedCount { get; set; }
        /// <summary>JSON 数组,每路径完整结构: [{path, tag, pid, abnormal, note, hitCount, dumped, dumpFile, fileCopied, fileCopyName}]</summary>
        public string? DumpFilesJson { get; set; }
        // 驱动 dump 元数据 (Category D: 之前 C++ 只写磁盘)
        public string? DriverDumpsJson { get; set; }
        public int DriverDumpCount { get; set; }
        // 路径目录 (Category D: 之前只 C++ 本地)
        public string? JsonLogPath { get; set; }
        public string? DumpFileDir { get; set; }
        public string? FileCopyDir { get; set; }
    }

    private sealed record TrackerConfigRequest
    {
        public int TreePollIntervalSec { get; init; } = 10;
        public bool IoctlEnabled { get; init; } = false;
        public string DumpMode { get; init; } = "mini";
        public bool FileCopyEnabled { get; init; } = true;
    }
}
