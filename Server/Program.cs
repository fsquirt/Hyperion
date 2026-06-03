using SEWindows.Server.Api;
using SEWindows.Server.Auth;
using SEWindows.Server.Services;
using SEWindows.Server.Storage;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddSingleton<JsonFileStore>();
builder.Services.AddSingleton<CertificateVerifier>();
builder.Services.AddSingleton<AttestationSessionStore>();
builder.Services.AddSingleton<AdminCredentialStore>();
builder.Services.AddSingleton<WebAuthnService>();

var app = builder.Build();

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
