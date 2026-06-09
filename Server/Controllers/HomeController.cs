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

    [HttpGet("/cert-dashboard")]
    public IActionResult CertDashboard()
    {
        if (!IsAuthenticated())
            return RedirectToAction("Login");
        return View();
    }

    [HttpGet("/partials/tpm-dashboard")]
    public IActionResult TpmDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("TpmVerifyDashboard");
    }

    [HttpGet("/partials/cert-dashboard")]
    public IActionResult CertDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("CertDashboard");
    }

    [HttpGet("/partials/tracker-dashboard")]
    public IActionResult TrackerDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("TrackerDashboard");
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
    public async Task<IActionResult> GetHistory([FromQuery] string? q)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var history = await _dataStore.LoadHistoryAsync();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var query = q.ToLowerInvariant();
            history = history.Where(h =>
                (h.Id ?? "").ToLowerInvariant().Contains(query) ||
                (h.Timestamp ?? "").ToLowerInvariant().Contains(query) ||
                (h.EkFingerprint ?? "").ToLowerInvariant().Contains(query) ||
                (h.Result ?? "").ToLowerInvariant().Contains(query)
            ).ToList();
        }
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

    [HttpGet("/api/admin/cert-history")]
    public async Task<IActionResult> GetCertHistory([FromQuery] string? q)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var history = await _dataStore.LoadCertVerifyHistoryAsync();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var query = q.ToLowerInvariant();
            history = history.Where(h =>
                (h.Id ?? "").ToLowerInvariant().Contains(query) ||
                (h.Timestamp ?? "").ToLowerInvariant().Contains(query) ||
                (h.Result ?? "").ToLowerInvariant().Contains(query)
            ).ToList();
        }
        return Json(history);
    }

    [HttpGet("/api/admin/cert-csv")]
    public IActionResult GetCertCsv()
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var csvPath = Path.Combine(AppContext.BaseDirectory, "IncludedCACertificateReportForMSFT.csv");
            if (!System.IO.File.Exists(csvPath))
                return Json(new { error = "CSV 文件不存在", path = csvPath });

            var lines = System.IO.File.ReadAllLines(csvPath);
            var lastWrite = System.IO.File.GetLastWriteTimeUtc(csvPath);

            // 跳过表头
            var rows = new List<string[]>();
            for (int i = 1; i < lines.Length; i++)
            {
                var fields = ParseCsvLine(lines[i]);
                if (fields.Count >= 6)
                    rows.Add([fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]]);
            }

            return Json(new
            {
                path = csvPath,
                last_modified = lastWrite.ToString("o"),
                total = rows.Count,
                headers = new[] { "Microsoft Status", "CA Owner", "Common Name", "Subject", "SHA-1", "SHA-256" },
                rows
            });
        }
        catch (Exception ex)
        {
            return Json(new { error = ex.Message });
        }
    }

    [HttpPost("/api/admin/cert-csv-sync")]
    public async Task<IActionResult> SyncCertCsv([FromServices] CertAllowListService certAllowList)
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var csvPath = Path.Combine(AppContext.BaseDirectory, "IncludedCACertificateReportForMSFT.csv");
            var oldFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (System.IO.File.Exists(csvPath))
            {
                foreach (var line in System.IO.File.ReadLines(csvPath))
                {
                    var fields = ParseCsvLine(line);
                    if (fields.Count > 5 && !string.IsNullOrWhiteSpace(fields[5]))
                        oldFingerprints.Add(fields[5].Trim());
                }
            }

            // 下载最新 CSV
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            var csvContent = await http.GetStringAsync("https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV");

            // 解析新 CSV
            var newFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var newLines = csvContent.Split('\n');
            foreach (var line in newLines)
            {
                var fields = ParseCsvLine(line);
                if (fields.Count > 5 && !string.IsNullOrWhiteSpace(fields[5]))
                    newFingerprints.Add(fields[5].Trim());
            }

            var added = newFingerprints.Except(oldFingerprints).Count();
            var removed = oldFingerprints.Except(newFingerprints).Count();

            return Json(new
            {
                success = true,
                added,
                removed,
                old_count = oldFingerprints.Count,
                new_count = newFingerprints.Count,
                content = csvContent
            });
        }
        catch (Exception ex)
        {
            return Json(new { success = false, error = ex.Message });
        }
    }

    [HttpPost("/api/admin/cert-csv-apply")]
    public IActionResult ApplyCertCsv([FromBody] System.Text.Json.JsonElement body)
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var content = body.GetProperty("content").GetString() ?? "";
            var csvPath = Path.Combine(AppContext.BaseDirectory, "IncludedCACertificateReportForMSFT.csv");
            System.IO.File.WriteAllText(csvPath, content);
            return Json(new { success = true, path = csvPath });
        }
        catch (Exception ex)
        {
            return Json(new { success = false, error = ex.Message });
        }
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                { current.Append('"'); i++; }
                else if (c == '"') inQuotes = false;
                else current.Append(c);
            }
            else
            {
                if (c == '"') inQuotes = true;
                else if (c == ',') { fields.Add(current.ToString()); current.Clear(); }
                else current.Append(c);
            }
        }
        fields.Add(current.ToString());
        return fields;
    }

    // ═══════════════════════════════════════════════════════════════
    //  辅助
    // ═══════════════════════════════════════════════════════════════

    private bool IsAuthenticated()
    {
        return HttpContext.Session.GetString("authenticated") == "true";
    }
}
