using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SEWindows.Server.Auth;
using SEWindows.Server.Data;
using SEWindows.Server.Models;
using SEWindows.Server.Services;

namespace SEWindows.Server.Controllers;

public class HomeController : Controller
{
    private readonly AdminCredentialStore _adminStore;
    private readonly WebAuthnService _webAuthn;
    private readonly SqliteStore _dataStore;
    private readonly AttestationSessionStore _sessions;
    private readonly CertificateVerifier _certVerifier;
    private readonly IConfiguration _config;

    public HomeController(
        AdminCredentialStore adminStore,
        WebAuthnService webAuthn,
        SqliteStore dataStore,
        AttestationSessionStore sessions,
        CertificateVerifier certVerifier,
        IConfiguration config)
    {
        _adminStore = adminStore;
        _webAuthn = webAuthn;
        _dataStore = dataStore;
        _sessions = sessions;
        _certVerifier = certVerifier;
        _config = config;
    }

    // ═══════════════════════════════════════════════════════════════
    //  页面路由
    // ═══════════════════════════════════════════════════════════════

    [HttpGet("/")]
    public async Task<IActionResult> Index()
    {
        if (!await _adminStore.HasAdminAsync())
            return RedirectToAction("Register");
        if (!IsAuthenticated())
            return RedirectToAction("Login");
        return RedirectToAction("Dashboard");
    }

    [HttpGet("/register")]
    public async Task<IActionResult> Register()
    {
        if (await _adminStore.HasAdminAsync())
            return RedirectToAction("Login");
        return View();
    }

    [HttpGet("/login")]
    public async Task<IActionResult> Login()
    {
        if (!await _adminStore.HasAdminAsync())
            return RedirectToAction("Register");
        if (IsAuthenticated())
            return RedirectToAction("Dashboard");
        return View();
    }

    [HttpGet("/dashboard")]
    public IActionResult Dashboard()
    {
        if (!IsAuthenticated())
            return RedirectToAction("Login");
        return View();
    }

    [HttpGet("/logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Login");
    }

    // ═══════════════════════════════════════════════════════════════
    //  WebAuthn API
    // ═══════════════════════════════════════════════════════════════

    [HttpPost("/api/webauthn/register/begin")]
    public async Task<IActionResult> RegisterBegin()
    {
        var options = await _webAuthn.BeginRegistrationAsync();
        HttpContext.Session.SetString("reg_challenge", Convert.ToBase64String(options.Challenge));
        return Json(options);
    }

    [HttpPost("/api/webauthn/register/complete")]
    public async Task<IActionResult> RegisterComplete([FromBody] JsonElement body)
    {
        var attestation = System.Text.Json.JsonSerializer.Deserialize<Fido2NetLib.AuthenticatorAttestationRawResponse>(
            body.GetRawText());
        if (attestation == null) return BadRequest(new { error = "invalid request" });

        var (success, error) = await _webAuthn.CompleteRegistrationAsync(attestation);
        if (success)
        {
            HttpContext.Session.SetString("authenticated", "true");
            return Json(new { result = "success" });
        }
        return Json(new { result = "fail", reason = error });
    }

    [HttpPost("/api/webauthn/login/begin")]
    public async Task<IActionResult> LoginBegin()
    {
        var options = await _webAuthn.BeginAuthenticationAsync();
        return Json(options);
    }

    [HttpPost("/api/webauthn/login/complete")]
    public async Task<IActionResult> LoginComplete([FromBody] JsonElement body)
    {
        var assertion = System.Text.Json.JsonSerializer.Deserialize<Fido2NetLib.AuthenticatorAssertionRawResponse>(
            body.GetRawText());
        if (assertion == null) return BadRequest(new { error = "invalid request" });

        var (success, error) = await _webAuthn.CompleteAuthenticationAsync(assertion);
        if (success)
        {
            HttpContext.Session.SetString("authenticated", "true");
            return Json(new { result = "success" });
        }
        return Json(new { result = "fail", reason = error });
    }

    // ═══════════════════════════════════════════════════════════════
    //  Dashboard 数据 API
    // ═══════════════════════════════════════════════════════════════

    [HttpGet("/api/admin/ek-list")]
    public async Task<IActionResult> GetEkList()
    {
        if (!IsAuthenticated()) return Unauthorized();
        var records = await _dataStore.LoadEkRecordsAsync();
        return Json(records);
    }

    [HttpGet("/api/admin/ak-list")]
    public async Task<IActionResult> GetAkList()
    {
        if (!IsAuthenticated()) return Unauthorized();
        var records = await _dataStore.LoadAkRecordsAsync();
        return Json(records);
    }

    [HttpGet("/api/admin/history")]
    public async Task<IActionResult> GetHistory()
    {
        if (!IsAuthenticated()) return Unauthorized();
        var history = await _dataStore.LoadHistoryAsync();
        return Json(history);
    }

    [HttpGet("/api/admin/config")]
    public IActionResult GetConfig()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return Json(new
        {
            trustedRootDir = _config["Attestation:TrustedRootDir"],
            serverDomain = _config["WebAuthn:ServerDomain"],
            apiUrl = _config["Kestrel:Endpoints:Http:Url"]
        });
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private bool IsAuthenticated()
    {
        return HttpContext.Session.GetString("authenticated") == "true";
    }
}
