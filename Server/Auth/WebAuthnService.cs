using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using SEWindows.Server.Storage;

namespace SEWindows.Server.Auth;

/// <summary>
/// WebAuthn (Passkey) 认证服务
/// </summary>
public sealed class WebAuthnService
{
    private readonly IFido2 _fido2;
    private readonly AdminCredentialStore _adminStore;
    private readonly ILogger<WebAuthnService> _logger;

    // 临时存储注册/认证的 options（内存中，按 challenge 索引）
    private readonly Dictionary<string, CredentialCreateOptions> _pendingRegistrations = new();
    private readonly Dictionary<string, AssertionOptions> _pendingAssertions = new();
    private readonly object _lock = new();

    public WebAuthnService(IConfiguration config, AdminCredentialStore adminStore, ILogger<WebAuthnService> logger)
    {
        _adminStore = adminStore;
        _logger = logger;

        var section = config.GetSection("WebAuthn");
        var fidoConfig = new Fido2Configuration
        {
            ServerName = section["ServerName"] ?? "SEWindows",
            ServerDomain = section["ServerDomain"] ?? "localhost",
            Origins = new HashSet<string> { section["Origin"] ?? "http://localhost:5000" }
        };
        _fido2 = new Fido2(fidoConfig);
    }

    /// <summary>标准 base64 转 base64url（WebAuthn clientData.challenge 使用 base64url）</summary>
    private static string ToBase64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ═══════════════════════════════════════════════════════════════
    //  注册流程
    // ═══════════════════════════════════════════════════════════════

    public async Task<CredentialCreateOptions> BeginRegistrationAsync()
    {
        var admin = await _adminStore.LoadAsync();
        var existingCreds = admin.Credentials.Select(c =>
            new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.CredentialId))).ToList();

        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Name = admin.Username,
                DisplayName = "Administrator",
                Id = Encoding.UTF8.GetBytes(admin.Username)
            },
            ExcludeCredentials = existingCreds,
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.None
        });

        // 存储 pending options（用 challenge 的 base64url 作为 key，与 clientData 一致）
        lock (_lock)
        {
            _pendingRegistrations[ToBase64Url(options.Challenge)] = options;
        }

        return options;
    }

    public async Task<(bool success, string error)> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse)
    {
        // 从 clientData 中取出 challenge
        var clientDataJson = Encoding.UTF8.GetString(attestationResponse.Response.ClientDataJson);
        var clientData = JsonSerializer.Deserialize<ClientData>(clientDataJson);
        if (clientData == null) return (false, "invalid client data");

        CredentialCreateOptions? options;
        lock (_lock)
        {
            _pendingRegistrations.TryGetValue(clientData.Challenge, out options);
            _pendingRegistrations.Remove(clientData.Challenge);
        }

        if (options == null) return (false, "no pending registration");

        try
        {
            var result = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true)
            });

            if (result == null) return (false, "registration failed");

            // 保存凭据
            var admin = await _adminStore.LoadAsync();
            admin.Credentials.Add(new AdminCredentialStore.CredentialEntry
            {
                CredentialId = Convert.ToBase64String(result.Id),
                PublicKey = Convert.ToBase64String(result.PublicKey),
                SignCount = result.SignCount,
                Created = DateTime.UtcNow.ToString("o")
            });
            await _adminStore.SaveAsync(admin);

            _logger.LogInformation("Admin passkey registered successfully");
            return (true, "");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed");
            return (false, ex.Message);
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  认证流程
    // ═══════════════════════════════════════════════════════════════

    public async Task<AssertionOptions> BeginAuthenticationAsync()
    {
        var admin = await _adminStore.LoadAsync();
        var allowedCreds = admin.Credentials.Select(c =>
            new PublicKeyCredentialDescriptor(Convert.FromBase64String(c.CredentialId))).ToList();

        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCreds,
            UserVerification = UserVerificationRequirement.Preferred
        });

        lock (_lock)
        {
            _pendingAssertions[ToBase64Url(options.Challenge)] = options;
        }

        return options;
    }

    public async Task<(bool success, string error)> CompleteAuthenticationAsync(
        AuthenticatorAssertionRawResponse assertionResponse)
    {
        var clientDataJson = Encoding.UTF8.GetString(assertionResponse.Response.ClientDataJson);
        var clientData = JsonSerializer.Deserialize<ClientData>(clientDataJson);
        if (clientData == null) return (false, "invalid client data");

        AssertionOptions? options;
        lock (_lock)
        {
            _pendingAssertions.TryGetValue(clientData.Challenge, out options);
            _pendingAssertions.Remove(clientData.Challenge);
        }

        if (options == null) return (false, "no pending assertion");

        var admin = await _adminStore.LoadAsync();
        var cred = admin.Credentials.FirstOrDefault(c =>
            Convert.FromBase64String(c.CredentialId).AsSpan().SequenceEqual(assertionResponse.RawId));
        if (cred == null) return (false, "credential not found");

        try
        {
            var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = options,
                StoredPublicKey = Convert.FromBase64String(cred.PublicKey),
                StoredSignatureCounter = cred.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (_, _) => Task.FromResult(true)
            });

            if (result == null) return (false, "assertion failed");

            // 更新 sign count
            cred.SignCount = result.SignCount;
            await _adminStore.SaveAsync(admin);

            _logger.LogInformation("Admin authenticated successfully");
            return (true, "");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed");
            return (false, ex.Message);
        }
    }

    private sealed class ClientData
    {
        [System.Text.Json.Serialization.JsonPropertyName("challenge")]
        public string Challenge { get; set; } = "";
    }
}
