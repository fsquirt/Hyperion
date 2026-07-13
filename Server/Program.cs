using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Api;
using Hyperion.Server.Auth;
using Hyperion.Server.Data;
using Hyperion.Server.Services;

var builder = WebApplication.CreateBuilder(args);

// --debug: 启用详细的请求/响应日志和 Debug 级别 (正常生产环境关闭)
var debugMode = Array.Exists(args, a => a.Equals("--debug", StringComparison.OrdinalIgnoreCase));
if (debugMode)
{
    builder.Logging.SetMinimumLevel(LogLevel.Debug);
}

// ═══════════════════════════════════════════════════════════════
//  SQLite 数据库
// ═══════════════════════════════════════════════════════════════

var dbPath = Path.Combine(AppContext.BaseDirectory, "Data", "attestation.db");
Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);

builder.Services.AddDbContextFactory<AttestationDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

// ═══════════════════════════════════════════════════════════════
//  服务注册
// ═══════════════════════════════════════════════════════════════

builder.Services.AddControllersWithViews();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// HttpClient 用于拉黑列表联网更新
builder.Services.AddHttpClient("Blocklist");

builder.Services.AddSingleton<SqliteStore>();
builder.Services.AddSingleton<CertificateVerifier>();
builder.Services.AddSingleton<AttestationSessionStore>();
builder.Services.AddSingleton<AdminCredentialStore>();
builder.Services.AddSingleton<WebAuthnService>();
builder.Services.AddSingleton<CertAllowListService>();
builder.Services.AddSingleton<TrackerSessionStore>();
builder.Services.AddSingleton<BlocklistService>();
builder.Services.AddSingleton<WhitelistService>();
builder.Services.AddSingleton<KernelFuncService>();
builder.Services.AddSingleton<LlmApiService>();

var app = builder.Build();

// ═══════════════════════════════════════════════════════════════
//  自动创建数据库
// ═══════════════════════════════════════════════════════════════

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AttestationDbContext>();
    db.Database.EnsureCreated();

    // 确保 tracker_sessions 表存在（EnsureCreated 不会给已有库加新表）
    var conn = db.Database.GetDbConnection();
    await conn.OpenAsync();
    using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS tracker_sessions (
                id TEXT PRIMARY KEY,
                machine_name TEXT NOT NULL DEFAULT '',
                pid INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL DEFAULT '',
                ended_at TEXT NOT NULL DEFAULT '',
                event_count INTEGER NOT NULL DEFAULT 0,
                events_json TEXT NOT NULL DEFAULT '[]'
            )
            """;
        await cmd.ExecuteNonQueryAsync();

        // 阻止列表表(EnsureCreated 不会给已有库加新表,手动建)
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS blocked_drivers (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL DEFAULT '',
                driver_name TEXT NOT NULL DEFAULT '',
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                added_at TEXT NOT NULL DEFAULT '',
                notes TEXT
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_blocked_sha256 ON blocked_drivers(sha256)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_blocked_source ON blocked_drivers(source)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在则忽略 */ }

        // all_drivers_json 列（兼容旧库升级）
        try
        {
            cmd.CommandText = "ALTER TABLE driver_verify_history ADD COLUMN all_drivers_json TEXT NOT NULL DEFAULT '[]'";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 列已存在则忽略 */ }

        // 附着白名单表
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS whitelist_entries (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                sha256 TEXT,
                md5 TEXT,
                sha1 TEXT,
                cert_subject TEXT,
                cert_issuer TEXT,
                added_at TEXT NOT NULL DEFAULT '',
                notes TEXT
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_whitelist_type ON whitelist_entries(type)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_whitelist_sha256 ON whitelist_entries(sha256)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_whitelist_cert_subject ON whitelist_entries(cert_subject)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在则忽略 */ }

        // 危险内核函数列表表
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS kernel_dangerous_funcs (
                id TEXT PRIMARY KEY,
                func_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT 'High',
                enabled INTEGER NOT NULL DEFAULT 1,
                added_at TEXT NOT NULL DEFAULT '',
                notes TEXT
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE UNIQUE INDEX IF NOT EXISTS ix_kfunc_func_name ON kernel_dangerous_funcs(func_name)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_kfunc_enabled ON kernel_dangerous_funcs(enabled)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_kfunc_severity ON kernel_dangerous_funcs(severity)";
        await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在则忽略 */ }

        // 大模型 API 配置表
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS llm_apis (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT 'custom',
                base_url TEXT NOT NULL DEFAULT '',
                api_key TEXT NOT NULL DEFAULT '',
                model_name TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                max_tokens INTEGER NOT NULL DEFAULT 4096,
                temperature REAL NOT NULL DEFAULT 0.7,
                added_at TEXT NOT NULL DEFAULT '',
                last_used_at TEXT,
                notes TEXT
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_llm_apis_provider ON llm_apis(provider)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_llm_apis_enabled ON llm_apis(enabled)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_llm_apis_priority ON llm_apis(priority)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在则忽略 */ }

        // 大模型 API 访问凭据表
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS llm_api_credentials (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL DEFAULT '',
                token TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT '',
                last_used_at TEXT,
                notes TEXT
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE UNIQUE INDEX IF NOT EXISTS ix_llm_cred_token ON llm_api_credentials(token)";
            await cmd.ExecuteNonQueryAsync();
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_llm_cred_enabled ON llm_api_credentials(enabled)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在则忽略 */ }

        // ═══════════════════════════════════════════════════════════════
        //  运行时追踪 — 4 种独立数据流表
        // ═══════════════════════════════════════════════════════════════

        // 进程树快照(全量 baseline + tree 轮询)
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS tracker_snapshots (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'tree',
                process_count INTEGER NOT NULL DEFAULT 0,
                processes_json TEXT NOT NULL DEFAULT '[]'
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_snapshots_session ON tracker_snapshots(session_id)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }

        // 内核通信记录(驱动扫描 + 附着 + IOCTL)
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS tracker_kernel_comms (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'driver',
                level TEXT NOT NULL DEFAULT 'INFO',
                source TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT ''
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_kcomms_session ON tracker_kernel_comms(session_id)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }

        // Dump 触发记录
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS tracker_dumps (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT '',
                level TEXT NOT NULL DEFAULT 'INFO',
                title TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                dump_files_json TEXT NOT NULL DEFAULT '[]'
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_dumps_session ON tracker_dumps(session_id)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }

        // Tracker 运行配置(全局单行)
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS tracker_config (
                id TEXT PRIMARY KEY,
                tree_poll_interval_sec INTEGER NOT NULL DEFAULT 10,
                ioctl_enabled INTEGER NOT NULL DEFAULT 0,
                dump_mode TEXT NOT NULL DEFAULT 'mini',
                file_copy_enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """;
        await cmd.ExecuteNonQueryAsync();
        // 确保默认配置行存在
        cmd.CommandText = """
            INSERT OR IGNORE INTO tracker_config (id, tree_poll_interval_sec, ioctl_enabled, dump_mode, file_copy_enabled, updated_at)
            VALUES ('default', 10, 0, 'mini', 1, '')
            """;
        await cmd.ExecuteNonQueryAsync();

        // ═══════════════════════════════════════════════════════════════
        //  运行时追踪 — 结构化列迁移 (ALTER TABLE,兼容已有库)
        // ═══════════════════════════════════════════════════════════════

        // tracker_snapshots 新增汇总列
        foreach (var col in new[] {
            "ppl_broken_count INTEGER NOT NULL DEFAULT 0",
            "suspicious_mem_count INTEGER NOT NULL DEFAULT 0",
            "high_risk_handle_count INTEGER NOT NULL DEFAULT 0",
            "untrusted_count INTEGER NOT NULL DEFAULT 0",
            // Tree 模式汇总统计 (Category C: 之前 UI 拿不到, 现在索引化)
            "total_threads INTEGER NOT NULL DEFAULT 0",
            "max_threads_in_single_proc INTEGER NOT NULL DEFAULT 0",
            "top_pid_by_threads INTEGER NOT NULL DEFAULT 0",
            "total_working_set INTEGER NOT NULL DEFAULT 0",
            "total_private_pages INTEGER NOT NULL DEFAULT 0",
            "total_handles INTEGER NOT NULL DEFAULT 0",
        })
        {
            try { cmd.CommandText = $"ALTER TABLE tracker_snapshots ADD COLUMN {col}"; await cmd.ExecuteNonQueryAsync(); }
            catch { /* 列已存在 */ }
        }

        // tracker_kernel_comms 新增结构化列
        foreach (var col in new[] {
            "data_json TEXT",
            "driver_file_name TEXT",
            "driver_class INTEGER",
            "vendor_name TEXT",
            "has_catalog INTEGER",
            "has_embedded INTEGER",
            "dangerous_api_count INTEGER",
            "attach_id INTEGER",
            "device_name TEXT",
            "filter_device_addr INTEGER",
            "ioctl_code INTEGER",
            "requestor_pid INTEGER",
            "major_function INTEGER",
            // 驱动映像信息索引列 (Category A: 之前 FFI 丢失, 现已补齐)
            "image_base INTEGER",
            "image_size INTEGER",
            "load_order_index INTEGER",
            // 通信事件索引列 (kind=ioctl-aggregate / unsigned-module-alert / targeted-scan)
            "method INTEGER",
            "target_device_addr INTEGER",
            "stack_module_count INTEGER",
            "payload_size INTEGER",
            "payload_hex TEXT",
            // 对象扫描 / 句柄扫描索引列 (Category B)
            "type_name TEXT",
            "high_risk_count INTEGER",
        })
        {
            try { cmd.CommandText = $"ALTER TABLE tracker_kernel_comms ADD COLUMN {col}"; await cmd.ExecuteNonQueryAsync(); }
            catch { /* 列已存在 */ }
        }
        // 内核通信结构化筛选索引
        foreach (var idx in new[] {
            "CREATE INDEX IF NOT EXISTS ix_kc_driver_class ON tracker_kernel_comms(driver_class)",
            "CREATE INDEX IF NOT EXISTS ix_kc_attach_id ON tracker_kernel_comms(attach_id)",
            "CREATE INDEX IF NOT EXISTS ix_kc_ioctl_code ON tracker_kernel_comms(ioctl_code)",
            "CREATE INDEX IF NOT EXISTS ix_kc_requestor_pid ON tracker_kernel_comms(requestor_pid)",
            // 通信事件 / 对象扫描 / 句柄扫描索引 (Category A/B/C)
            "CREATE INDEX IF NOT EXISTS ix_kc_method ON tracker_kernel_comms(method)",
            "CREATE INDEX IF NOT EXISTS ix_kc_type_name ON tracker_kernel_comms(type_name)",
            "CREATE INDEX IF NOT EXISTS ix_kc_high_risk_count ON tracker_kernel_comms(high_risk_count)",
        })
        {
            try { cmd.CommandText = idx; await cmd.ExecuteNonQueryAsync(); }
            catch { /* 索引已存在 */ }
        }

        // tracker_dumps 新增汇总列
        foreach (var col in new[] {
            "total_ioctls INTEGER NOT NULL DEFAULT 0",
            "total_events INTEGER NOT NULL DEFAULT 0",
            "path_count INTEGER NOT NULL DEFAULT 0",
            "abnormal_count INTEGER NOT NULL DEFAULT 0",
            "dumped_count INTEGER NOT NULL DEFAULT 0",
            "copied_count INTEGER NOT NULL DEFAULT 0",
            // 驱动 dump 元数据 (Category D: 之前 C++ 只写磁盘, 现在导出到服务端)
            "driver_dumps_json TEXT NOT NULL DEFAULT '[]'",
            "driver_dump_count INTEGER NOT NULL DEFAULT 0",
            // 路径目录 (Category D: 之前只 C++ 本地)
            "json_log_path TEXT",
            "dump_file_dir TEXT",
            "file_copy_dir TEXT",
        })
        {
            try { cmd.CommandText = $"ALTER TABLE tracker_dumps ADD COLUMN {col}"; await cmd.ExecuteNonQueryAsync(); }
            catch { /* 列已存在 */ }
        }
        // Dump:驱动 dump 数量索引
        try
        {
            cmd.CommandText = "CREATE INDEX IF NOT EXISTS ix_td_driver_dump_count ON tracker_dumps(driver_dump_count)";
            await cmd.ExecuteNonQueryAsync();
        }
        catch { /* 索引已存在 */ }
    }
    await conn.CloseAsync();

    app.Logger.LogInformation("SQLite database: {Path}", dbPath);
}

// ═══════════════════════════════════════════════════════════════
//  启动:加载拉黑列表到内存
// ═══════════════════════════════════════════════════════════════

using (var scope = app.Services.CreateScope())
{
    var blocklist = scope.ServiceProvider.GetRequiredService<BlocklistService>();
    await blocklist.LoadAsync();
    var whitelist = scope.ServiceProvider.GetRequiredService<WhitelistService>();
    await whitelist.LoadAsync();
    var kernelFunc = scope.ServiceProvider.GetRequiredService<KernelFuncService>();
    await kernelFunc.LoadAsync();
    var llmApi = scope.ServiceProvider.GetRequiredService<LlmApiService>();
    await llmApi.LoadAsync();
}

// ═══════════════════════════════════════════════════════════════
//  中间件
// ═══════════════════════════════════════════════════════════════

// DEBUG: 记录每个到达服务端的请求 (--debug 启用)
if (debugMode)
{
    app.Use(async (ctx, next) =>
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        app.Logger.LogInformation("[REQ] {Method} {Path}{Query} 从 {Remote} @ {Ts}",
            ctx.Request.Method, ctx.Request.Path, ctx.Request.QueryString,
            ctx.Connection.RemoteIpAddress, DateTime.Now.ToString("HH:mm:ss.fff"));
        try
        {
            await next();
            sw.Stop();
            app.Logger.LogInformation("[REQ] {Method} {Path} → {Status} (耗时 {Ms}ms)",
                ctx.Request.Method, ctx.Request.Path, ctx.Response.StatusCode, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            sw.Stop();
            app.Logger.LogError(ex, "[REQ] {Method} {Path} 异常 (耗时 {Ms}ms): {Msg}",
                ctx.Request.Method, ctx.Request.Path, sw.ElapsedMilliseconds, ex.Message);
            throw;
        }
    });
}

app.UseStaticFiles();
app.UseSession();
app.UseRouting();

// API 端点（远程证明）
app.MapAttestationApi();

// API 端点（Tracker 事件上报）
app.MapTrackerApi();

// API 端点（恶意驱动阻止列表）
app.MapBlocklistApi();

// API 端点（附着白名单）
app.MapWhitelistApi();

// API 端点（危险内核函数列表）
app.MapKernelFuncApi();

// API 端点（大模型 API 配置 + 访问凭据 — 管理端）
app.MapLlmApiApi();

// API 端点（大模型 API 配置 — 集群端,Bearer token 认证）
app.MapLlmClusterApi();

// MVC 控制器（Web 后台）
app.MapControllers();

app.Run();
