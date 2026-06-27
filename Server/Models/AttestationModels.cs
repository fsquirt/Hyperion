using System.Text.Json.Serialization;

namespace SEWindows.Server.Models;

// ═══════════════════════════════════════════════════════════════
// EK / AK 存储记录
// ═══════════════════════════════════════════════════════════════

public sealed record EkRecord
{
    [JsonPropertyName("fingerprint")] public string Fingerprint { get; init; } = "";
    [JsonPropertyName("subject")] public string Subject { get; init; } = "";
    [JsonPropertyName("ts")] public string Timestamp { get; init; } = "";
}

public sealed record AkRecord
{
    [JsonPropertyName("ak_name")] public string AkName { get; init; } = "";
    [JsonPropertyName("ak_pub")] public string AkPub { get; init; } = "";
    [JsonPropertyName("ek_fingerprint")] public string EkFingerprint { get; init; } = "";
    [JsonPropertyName("ts")] public string Timestamp { get; init; } = "";
}

// ═══════════════════════════════════════════════════════════════
// 安全特性分析结果
// ═══════════════════════════════════════════════════════════════

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FeatureStatus
{
    Enabled,
    Disabled,
    Unknown,
    NotMeasured
}

public sealed record SecurityFeature
{
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("status")] public FeatureStatus Status { get; init; } = FeatureStatus.NotMeasured;
    [JsonPropertyName("evidence")] public string Evidence { get; init; } = "";
    [JsonPropertyName("detail")] public string Detail { get; init; } = "";
}

// ═══════════════════════════════════════════════════════════════
// TPMS_ATTEST 解析结果
// ═══════════════════════════════════════════════════════════════

public sealed record PcrSelection
{
    [JsonPropertyName("hash_alg")] public ushort HashAlg { get; init; }
    [JsonPropertyName("pcr_indices")] public List<uint> PcrIndices { get; init; } = [];
}

public sealed record TpmsAttest
{
    [JsonPropertyName("magic")] public uint Magic { get; init; }
    [JsonPropertyName("type")] public ushort Type { get; init; }
    [JsonPropertyName("qualified_signer")] public byte[] QualifiedSigner { get; init; } = [];
    [JsonPropertyName("extra_data")] public byte[] ExtraData { get; init; } = [];
    [JsonPropertyName("firmware_version")] public ulong FirmwareVersion { get; init; }
    [JsonPropertyName("pcr_selections")] public List<PcrSelection> PcrSelections { get; init; } = [];
    [JsonPropertyName("pcr_digest")] public byte[] PcrDigest { get; init; } = [];
}

// ═══════════════════════════════════════════════════════════════
// API 请求 / 响应模型
// ═══════════════════════════════════════════════════════════════

public sealed record VerifyChainRequest
{
    [JsonPropertyName("certs")] public List<string> Certs { get; init; } = [];
}

public sealed record VerifyChainResponse
{
    [JsonPropertyName("result")] public string Result { get; init; } = "fail";
    [JsonPropertyName("chain")] public List<string> Chain { get; init; } = [];
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
    [JsonPropertyName("ek_fingerprint")] public string? EkFingerprint { get; init; }
}

public sealed record MakeCredentialRequest
{
    [JsonPropertyName("ek_pub")] public string EkPub { get; init; } = "";
    [JsonPropertyName("ak_name")] public string AkName { get; init; } = "";
}

public sealed record MakeCredentialResponse
{
    [JsonPropertyName("session_id")] public string SessionId { get; init; } = "";
    [JsonPropertyName("credential_blob")] public string CredentialBlob { get; init; } = "";
    [JsonPropertyName("encrypted_secret")] public string EncryptedSecret { get; init; } = "";
}

public sealed record VerifyRequest
{
    [JsonPropertyName("session_id")] public string SessionId { get; init; } = "";
    [JsonPropertyName("secret")] public string Secret { get; init; } = "";
    [JsonPropertyName("ak_pub")] public string? AkPub { get; init; }
}

public sealed record RequestNonceRequest
{
    [JsonPropertyName("ak_name")] public string AkName { get; init; } = "";
}

public sealed record RequestNonceResponse
{
    [JsonPropertyName("quote_sid")] public string QuoteSid { get; init; } = "";
    [JsonPropertyName("nonce")] public string Nonce { get; init; } = "";
}

public sealed record VerifyQuoteRequest
{
    [JsonPropertyName("quote_sid")] public string QuoteSid { get; init; } = "";
    [JsonPropertyName("attest")] public string Attest { get; init; } = "";
    [JsonPropertyName("sig")] public string Sig { get; init; } = "";
    [JsonPropertyName("wbcl")] public string Wbcl { get; init; } = "";
}

public sealed record VerifyQuoteResponse
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("result")] public string Result { get; init; } = "fail";
    [JsonPropertyName("sig_valid")] public bool SigValid { get; init; }
    [JsonPropertyName("magic_ok")] public bool MagicOk { get; init; }
    [JsonPropertyName("nonce_ok")] public bool NonceOk { get; init; }
    [JsonPropertyName("pcr_match")] public bool PcrMatch { get; init; }
    [JsonPropertyName("security_features")] public List<SecurityFeature> SecurityFeatures { get; init; } = [];
    [JsonPropertyName("reason")] public string Reason { get; init; } = "";
}

// ═══════════════════════════════════════════════════════════════
// 证书存储验证
// ═══════════════════════════════════════════════════════════════

public sealed record CertInfo
{
    [JsonPropertyName("sha256")] public string Sha256 { get; init; } = "";
    [JsonPropertyName("subject")] public string Subject { get; init; } = "";
    [JsonPropertyName("issuer")] public string Issuer { get; init; } = "";
    [JsonPropertyName("store")] public string Store { get; init; } = "";
    [JsonPropertyName("not_before")] public string NotBefore { get; init; } = "";
    [JsonPropertyName("not_after")] public string NotAfter { get; init; } = "";
    [JsonPropertyName("serial")] public string Serial { get; init; } = "";
    [JsonPropertyName("thumbprint")] public string Thumbprint { get; init; } = "";
}

public sealed record VerifyCertsRequest
{
    [JsonPropertyName("certs")] public List<CertInfo> Certs { get; init; } = [];
}

public sealed record VerifyCertsResponse
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("suspicious")] public List<CertInfo> Suspicious { get; init; } = [];
    [JsonPropertyName("trusted_count")] public int TrustedCount { get; init; }
    [JsonPropertyName("client_count")] public int ClientCount { get; init; }
}

public sealed record CertVerifyHistoryEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    [JsonPropertyName("timestamp")] public string Timestamp { get; init; } = DateTime.UtcNow.ToString("o");
    [JsonPropertyName("client_cert_count")] public int ClientCertCount { get; init; }
    [JsonPropertyName("trusted_count")] public int TrustedCount { get; init; }
    [JsonPropertyName("suspicious_count")] public int SuspiciousCount { get; init; }
    [JsonPropertyName("suspicious_certs")] public List<CertInfo> SuspiciousCerts { get; init; } = [];
    [JsonPropertyName("result")] public string Result { get; init; } = "pass";
}

// ═══════════════════════════════════════════════════════════════
// 驱动拉黑验证
// ═══════════════════════════════════════════════════════════════

/// <summary>客户端上传的单个已加载驱动信息。</summary>
public sealed record DriverInfo
{
    [JsonPropertyName("file_name")] public string FileName { get; init; } = "";
    [JsonPropertyName("file_path")] public string FilePath { get; init; } = "";
    [JsonPropertyName("md5")] public string? Md5 { get; init; }
    [JsonPropertyName("sha1")] public string? Sha1 { get; init; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; init; }
    [JsonPropertyName("base_addr")] public ulong BaseAddr { get; init; }
    [JsonPropertyName("size")] public uint Size { get; init; }
}

public sealed record VerifyDriversRequest
{
    [JsonPropertyName("drivers")] public List<DriverInfo> Drivers { get; init; } = [];
}

public sealed record VerifyDriversResponse
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("suspicious")] public List<DriverInfo> Suspicious { get; init; } = [];
    [JsonPropertyName("blocked_count")] public int BlockedCount { get; init; }
    [JsonPropertyName("client_count")] public int ClientCount { get; init; }
}

public sealed record DriverVerifyHistoryEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    [JsonPropertyName("timestamp")] public string Timestamp { get; init; } = DateTime.UtcNow.ToString("o");
    [JsonPropertyName("client_driver_count")] public int ClientDriverCount { get; init; }
    [JsonPropertyName("blocked_count")] public int BlockedCount { get; init; }
    [JsonPropertyName("suspicious_drivers")] public List<DriverInfo> SuspiciousDrivers { get; init; } = [];
    [JsonPropertyName("result")] public string Result { get; init; } = "pass";
}

// ═══════════════════════════════════════════════════════════════
// 验证历史记录
// ═══════════════════════════════════════════════════════════════

public sealed record AttestationHistoryEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    [JsonPropertyName("timestamp")] public string Timestamp { get; init; } = DateTime.UtcNow.ToString("o");
    [JsonPropertyName("ek_fingerprint")] public string EkFingerprint { get; init; } = "";
    [JsonPropertyName("ak_name")] public string AkName { get; init; } = "";
    [JsonPropertyName("sig_valid")] public bool SigValid { get; init; }
    [JsonPropertyName("magic_ok")] public bool MagicOk { get; init; }
    [JsonPropertyName("nonce_ok")] public bool NonceOk { get; init; }
    [JsonPropertyName("pcr_match")] public bool PcrMatch { get; init; }
    [JsonPropertyName("security_features")] public List<SecurityFeature> SecurityFeatures { get; init; } = [];
    [JsonPropertyName("result")] public string Result { get; init; } = "fail";
}

// ═══════════════════════════════════════════════════════════════
// 内部数据结构（事件日志解析）
// ═══════════════════════════════════════════════════════════════

public sealed class EvRec
{
    public int Index { get; init; }
    public uint Pcr { get; init; }
    public uint EType { get; init; }
    public Dictionary<ushort, byte[]> Digests { get; init; } = [];
    public byte[] Data { get; init; } = [];
}

public sealed class ParseResult
{
    public List<ushort> AlgIds { get; init; } = [];
    public Dictionary<ushort, int> Dsizes { get; init; } = [];
    public List<EvRec> Events { get; init; } = [];
    public List<string> Errors { get; init; } = [];
}

public sealed class SipaEv
{
    public uint Eid { get; init; }
    public byte[] Data { get; init; } = [];
    public uint Pcr { get; init; }
    public int Idx { get; init; }

    public byte U8 => Data.Length > 0 ? Data[0] : (byte)0;
    public uint U32 => Data.Length >= 4
        ? BitConverter.ToUInt32(Data, 0)
        : U8;
    public ulong U64 => Data.Length >= 8
        ? BitConverter.ToUInt64(Data, 0)
        : U32;
}
