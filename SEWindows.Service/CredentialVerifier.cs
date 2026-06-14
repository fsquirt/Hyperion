using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SEWindows.Service;

/// <summary>
/// 验证 Server 签发的 HMAC-SHA256 凭证
/// </summary>
public static class CredentialVerifier
{
    public class CredentialPayload
    {
        [JsonPropertyName("machine_id")] public string MachineId { get; set; } = "";
        [JsonPropertyName("issued_at")] public string IssuedAt { get; set; } = "";
        [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
        [JsonPropertyName("test_mode")] public bool TestMode { get; set; }
    }

    public class CredentialEnvelope
    {
        [JsonPropertyName("credential")] public CredentialPayload Credential { get; set; } = new();
        [JsonPropertyName("signature")] public string Signature { get; set; } = "";
    }

    /// <summary>
    /// 验证凭证签名
    /// </summary>
    /// <param name="envelopeJson">凭证 JSON（包含 credential + signature）</param>
    /// <param name="secretHex">Server 共享密钥（64 字符十六进制）</param>
    /// <returns>验证结果</returns>
    public static (bool valid, bool testMode, string reason) Verify(string envelopeJson, string secretHex)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<CredentialEnvelope>(envelopeJson);
            if (envelope == null || envelope.Credential == null)
                return (false, false, "invalid envelope format");

            return Verify(envelope.Credential, envelope.Signature, secretHex);
        }
        catch (Exception ex)
        {
            return (false, false, $"parse error: {ex.Message}");
        }
    }

    /// <summary>
    /// 验证凭证签名
    /// </summary>
    public static (bool valid, bool testMode, string reason) Verify(
        CredentialPayload credential, string signatureHex, string secretHex)
    {
        try
        {
            if (string.IsNullOrEmpty(secretHex))
                return (false, false, "credential secret not configured");

            var secretBytes = Convert.FromHexString(secretHex);

            // Canonicalize the credential payload (same as server)
            var payloadJson = JsonSerializer.Serialize(credential);
            var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

            // Compute expected HMAC-SHA256
            using var hmac = new HMACSHA256(secretBytes);
            var expectedSig = hmac.ComputeHash(payloadBytes);

            // Compare with provided signature (constant-time)
            var providedSig = Convert.FromHexString(signatureHex);
            bool valid = CryptographicOperations.FixedTimeEquals(expectedSig, providedSig);

            return valid
                ? (true, credential.TestMode, "ok")
                : (false, credential.TestMode, "signature mismatch");
        }
        catch (Exception ex)
        {
            return (false, false, $"verification error: {ex.Message}");
        }
    }
}
