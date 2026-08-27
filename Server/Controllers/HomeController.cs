using Microsoft.AspNetCore.Mvc;
using Hyperion.Server.Auth;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using Hyperion.Server.Services;
using System.Text.Json;

namespace Hyperion.Server.Controllers;

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

    [HttpGet("/partials/blocklist-dashboard")]
    public IActionResult BlocklistDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("BlocklistDashboard");
    }

    [HttpGet("/partials/whitelist-dashboard")]
    public IActionResult WhitelistDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("WhitelistDashboard");
    }

    [HttpGet("/partials/kernel-func-dashboard")]
    public IActionResult KernelFuncDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("KernelFuncDashboard");
    }

    [HttpGet("/partials/sipolicy-dashboard")]
    public IActionResult SiPolicyDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("SiPolicyDashboard");
    }

    [HttpGet("/partials/mock-input-dashboard")]
    public IActionResult MockInputDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("MockInputDashboard");
    }

    [HttpGet("/partials/llm-api-dashboard")]
    public IActionResult LlmApiDashboardPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("LlmApiDashboard");
    }

    // ═══════════════════════════════════════════════════════════════
    //  运行时检测 — 占位(进程树快照 / 内核通信记录 / dump 内容触发)
    // ═══════════════════════════════════════════════════════════════

    [HttpGet("/partials/process-tree")]
    public IActionResult ProcessTreePartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        ViewBag.PlaceholderTitle = "进程树快照";
        ViewBag.PlaceholderDesc = "游戏运行时进程树快照采集与展示,用于发现可疑派生进程、注入链。";
        ViewBag.PlaceholderIcon = "bi-diagram-3";
        ViewBag.PlaceholderCategory = "运行时检测";
        return PartialView("_Placeholder");
    }

    [HttpGet("/partials/kernel-comm")]
    public IActionResult KernelCommPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        ViewBag.PlaceholderTitle = "内核通信记录";
        ViewBag.PlaceholderDesc = "UserService ↔ KernelService 驱动的反向调用通信记录(驱动加载通知等)。";
        ViewBag.PlaceholderIcon = "bi-hdd-network";
        ViewBag.PlaceholderCategory = "运行时检测";
        return PartialView("_Placeholder");
    }

    [HttpGet("/partials/dump-trigger")]
    public IActionResult DumpTriggerPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        ViewBag.PlaceholderTitle = "Dump 内容触发";
        ViewBag.PlaceholderDesc = "命中注入特征后触发的 MiniDump / shellcode 内存页导出列表,供 AI Agent 逆向分析。";
        ViewBag.PlaceholderIcon = "bi-bug";
        ViewBag.PlaceholderCategory = "运行时检测";
        return PartialView("_Placeholder");
    }

    // ═══════════════════════════════════════════════════════════════
    //  秋后查证 — 占位(Agent 配置 / 研判队列 / 报告管理)
    // ═══════════════════════════════════════════════════════════════

    [HttpGet("/partials/agent-config")]
    public IActionResult AgentConfigPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("AgentConfig");
    }

    [HttpGet("/partials/analysis-queue")]
    public IActionResult AnalysisQueuePartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("AnalysisQueue");
    }

    [HttpGet("/partials/report-management")]
    public IActionResult ReportManagementPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        return PartialView("ReportManagement");
    }

    // ═══════════════════════════════════════════════════════════════
    //  系统配置 — 占位(第三方登录配置)
    // ═══════════════════════════════════════════════════════════════

    [HttpGet("/partials/oauth-config")]
    public IActionResult OAuthConfigPartial()
    {
        if (!IsAuthenticated()) return Unauthorized();
        ViewBag.PlaceholderTitle = "第三方登录配置";
        ViewBag.PlaceholderDesc = "QQ / Microsoft 等 OAuth 第三方登录的 AppID、Secret、回调地址配置。";
        ViewBag.PlaceholderIcon = "bi-box-arrow-in-right";
        ViewBag.PlaceholderCategory = "系统配置";
        return PartialView("_Placeholder");
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

    [HttpGet("/api/admin/driver-history")]
    public async Task<IActionResult> GetDriverHistory([FromQuery] string? q)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var history = await _dataStore.LoadDriverVerifyHistoryAsync();
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
    public IActionResult GetCertCsv([FromServices] CertAllowListService certAllowList, [FromQuery] string? q)
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var rows = certAllowList.List(q);
            var lastWrite = System.IO.File.Exists(certAllowList.CsvPath)
                ? System.IO.File.GetLastWriteTimeUtc(certAllowList.CsvPath)
                : DateTime.MinValue;

            return Json(new
            {
                path = certAllowList.CsvPath,
                last_modified = lastWrite.ToString("o"),
                total = rows.Count,
                headers = new[] { "Microsoft Status", "CA Owner", "Common Name", "Subject", "SHA-1", "SHA-256" },
                rows = rows.Select(r => new[] {
                    r.MicrosoftStatus ?? "",
                    r.CaOwner ?? "",
                    r.CommonName ?? "",
                    r.Subject ?? "",
                    r.Sha1 ?? "",
                    r.Sha256 ?? "",
                }).ToList()
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
            var csvPath = certAllowList.CsvPath;
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
    public IActionResult ApplyCertCsv([FromBody] System.Text.Json.JsonElement body,
                                       [FromServices] CertAllowListService certAllowList)
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var content = body.GetProperty("content").GetString() ?? "";
            System.IO.File.WriteAllText(certAllowList.CsvPath, content);
            certAllowList.Reload();   // 即时生效
            return Json(new { success = true, path = certAllowList.CsvPath });
        }
        catch (Exception ex)
        {
            return Json(new { success = false, error = ex.Message });
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  证书白名单 CRUD (即时生效)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>手动添加一条受信任证书。</summary>
    [HttpPost("/api/admin/cert")]
    public IActionResult AddCert([FromBody] CertUpsertRequest req,
                                  [FromServices] CertAllowListService svc)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var row = ToRow(req);
        var (ok, err) = svc.Add(row);
        return Json(new CertOpResult { Success = ok, Error = err, Row = ok ? svc.FindBySha256(row.Sha256!) : null });
    }

    /// <summary>编辑已有证书。originalSha256 由 URL 路径传入用于定位原记录。</summary>
    [HttpPut("/api/admin/cert/{originalSha256}")]
    public IActionResult UpdateCert(string originalSha256,
                                     [FromBody] CertUpsertRequest req,
                                     [FromServices] CertAllowListService svc)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var row = ToRow(req);
        var (ok, err) = svc.Update(originalSha256, row);
        return Json(new CertOpResult { Success = ok, Error = err, Row = ok ? svc.FindBySha256(row.Sha256!) : null });
    }

    /// <summary>按 SHA-256 删除证书。</summary>
    [HttpDelete("/api/admin/cert/{sha256}")]
    public IActionResult DeleteCert(string sha256,
                                     [FromServices] CertAllowListService svc)
    {
        if (!IsAuthenticated()) return Unauthorized();
        var (ok, err) = svc.Delete(sha256);
        return Json(new CertOpResult { Success = ok, Error = err });
    }

    /// <summary>
    /// 上传证书文件(.cer/.crt/.pem),解析出 Subject / Issuer / SHA-1 / SHA-256 等信息。
    /// 仅返回解析结果,不直接入库——前端可基于此结果预填表单后再调用 AddCert。
    /// </summary>
    [HttpPost("/api/admin/cert/parse")]
    public async Task<IActionResult> ParseCertFile([FromServices] CertAllowListService svc)
    {
        if (!IsAuthenticated()) return Unauthorized();
        try
        {
            var form = await Request.ReadFormAsync();
            var file = form.Files.FirstOrDefault();
            if (file == null || file.Length == 0)
                return Json(new { success = false, error = "未上传文件" });
            if (file.Length > 5 * 1024 * 1024)
                return Json(new { success = false, error = "文件过大 (>5MB)" });

            using var ms = new MemoryStream();
            await file.CopyToAsync(ms);
            var bytes = ms.ToArray();

            // 解析 PEM 或 DER
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert;
            try
            {
                // 处理 PEM(可能含 "-----BEGIN CERTIFICATE-----")
                var text = System.Text.Encoding.ASCII.GetString(bytes);
                if (text.Contains("BEGIN CERTIFICATE", StringComparison.OrdinalIgnoreCase))
                {
                    cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(text);
                }
                else
                {
                    // .NET 9+ 推荐 X509CertificateLoader,避免 X509Certificate2(byte[]) 弃用警告
                    cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(bytes);
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, error = "证书解析失败: " + ex.Message });
            }

            var sha1 = cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA1).ToLowerInvariant();
            var sha256 = cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256).ToLowerInvariant();
            var subject = cert.Subject ?? "";
            var issuer = cert.Issuer ?? "";

            // 从 Subject 中提取 CN 作为 CommonName
            var cn = ExtractRdn(subject, "CN");

            return Json(new
            {
                success = true,
                row = new
                {
                    microsoft_status = "Manual",
                    ca_owner = ExtractRdn(issuer, "O") ?? "",
                    common_name = cn ?? "",
                    subject = subject,
                    sha1 = sha1,
                    sha256 = sha256,
                },
                not_before = cert.NotBefore.ToString("o"),
                not_after = cert.NotAfter.ToString("o"),
                serial = cert.SerialNumber ?? "",
                thumbprint = cert.Thumbprint ?? "",
            });
        }
        catch (Exception ex)
        {
            return Json(new { success = false, error = ex.Message });
        }
    }

    private static CertRow ToRow(CertUpsertRequest req) => new()
    {
        MicrosoftStatus = req.MicrosoftStatus,
        CaOwner = req.CaOwner,
        CommonName = req.CommonName,
        Subject = req.Subject,
        Sha1 = req.Sha1,
        Sha256 = req.Sha256,
    };

    /// <summary>从 X500 DN 字符串中提取指定 RDN(如 "CN" "O")的值。</summary>
    private static string? ExtractRdn(string dn, string rdnType)
    {
        if (string.IsNullOrEmpty(dn)) return null;
        var parts = dn.Split(',', StringSplitOptions.TrimEntries);
        var prefix = rdnType.ToUpperInvariant() + "=";
        foreach (var p in parts)
        {
            if (p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return p.Substring(prefix.Length).Trim('"');
        }
        return null;
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
