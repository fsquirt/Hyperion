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

// 注册 DbContextFactory（供 Singleton 服务使用）
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

var app = builder.Build();

// ═══════════════════════════════════════════════════════════════
//  自动创建数据库
// ═══════════════════════════════════════════════════════════════

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AttestationDbContext>();
    db.Database.EnsureCreated();
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

// MVC 控制器（Web 后台）
app.MapControllers();

app.Run();
