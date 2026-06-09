using Microsoft.EntityFrameworkCore;
using SEWindows.Server.Api;
using SEWindows.Server.Auth;
using SEWindows.Server.Data;
using SEWindows.Server.Services;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddSingleton<SqliteStore>();
builder.Services.AddSingleton<CertificateVerifier>();
builder.Services.AddSingleton<AttestationSessionStore>();
builder.Services.AddSingleton<AdminCredentialStore>();
builder.Services.AddSingleton<WebAuthnService>();
builder.Services.AddSingleton<CertAllowListService>();
builder.Services.AddSingleton<TrackerSessionStore>();

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
    }
    await conn.CloseAsync();

    app.Logger.LogInformation("SQLite database: {Path}", dbPath);
}

// ═══════════════════════════════════════════════════════════════
//  中间件
// ═══════════════════════════════════════════════════════════════

app.UseStaticFiles();
app.UseSession();
app.UseRouting();

// API 端点（远程证明）
app.MapAttestationApi();

// API 端点（Tracker 事件上报）
app.MapTrackerApi();

// MVC 控制器（Web 后台）
app.MapControllers();

app.Run();
