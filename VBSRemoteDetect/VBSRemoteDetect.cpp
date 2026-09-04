// VBSRemoteDetect — 远程验证 VBS/HVCI 运行态（客户端）
//
// 方案组合 (A+C+D):
//   A. NCrypt 密钥证明链: NCRYPT_REQUIRE_VBS_FLAG 创建 VTL1 隔离密钥
//      → NCryptCreateClaim(NCRYPT_CLAIM_VBS_ROOT) 由 IDKS(VBS 根签名密钥, 仅存在于
//        Secure Kernel) 签发 claim → 服务器 NCryptVerifyClaim 远程验证签名链
//   C. GetRuntimeAttestationReport: Secure Kernel 签发的运行时报告
//      (Driver Report + Code Integrity Report), 只有 HVCI 正在运行才能生成
//   D. Azure Attestation 式协议绑定: 服务器 challenge 作为 claim nonce 与
//      runtime report nonce → 客户端用 VTL1 密钥对 canonical payload 签名
//      (proof-of-possession) → 服务器验证签名 + claim + 报告

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <stdio.h>
#include <clocale>
#include <string>
#include <vector>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

#ifndef NCRYPT_REQUIRE_VBS_FLAG
#define NCRYPT_REQUIRE_VBS_FLAG 0x00020000
#endif
#ifndef NCRYPT_ALLOW_KEY_ATTESTATION_FLAG
#define NCRYPT_ALLOW_KEY_ATTESTATION_FLAG 0x00000010
#endif
#ifndef NCRYPT_CLAIM_VBS_ROOT
#define NCRYPT_CLAIM_VBS_ROOT 0x00000005
#endif
#ifndef NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE
#define NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE 49
#endif
#ifndef NCRYPTBUFFER_ATTESTATION_STATEMENT_SIGNATURE_HASH
#define NCRYPTBUFFER_ATTESTATION_STATEMENT_SIGNATURE_HASH 90
#endif
#ifndef NCRYPT_ALLOW_SIGNING_FLAG
#define NCRYPT_ALLOW_SIGNING_FLAG 0x00000002
#endif

static const wchar_t* K_PROBE_KEY_NAME = L"VBSRemoteDetect_AttestKey";
static const char*     K_CANONICAL_PREFIX = "VBSRemoteDetect-v1";

// ═══════════════════════════════════════════════════════════════
//  工具: base64 / hex / UTF 转换
// ═══════════════════════════════════════════════════════════════

static std::string B64Encode(const BYTE* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        UINT32 v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out += tbl[(v >> 18) & 0x3F];
        out += tbl[(v >> 12) & 0x3F];
        out += (i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? tbl[v & 0x3F] : '=';
    }
    return out;
}

static std::string HexEncode(const BYTE* data, size_t len) {
    static const char* tbl = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out += tbl[data[i] >> 4];
        out += tbl[data[i] & 0xF];
    }
    return out;
}

static std::string WideToUtf8(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// SHA-256 via BCrypt
static bool Sha256(const BYTE* data, size_t len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    bool ok = false;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        BYTE buf[8192]; size_t off = 0;
        while (off < len) {
            size_t chunk = min(len - off, sizeof(buf));
            memcpy(buf, data + off, chunk);
            if (BCryptHashData(hHash, buf, (ULONG)chunk, 0) != 0) break;
            off += chunk;
        }
        if (off == len && BCryptFinishHash(hHash, out, 32, 0) == 0) ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// 通用 SHA via BCrypt (SHA-512 用于运行时报告 digest 校验)
static bool ShaHash(const wchar_t* algId, const BYTE* data, size_t len, BYTE* out, ULONG outLen) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, algId, nullptr, 0) != 0) return false;
    bool ok = false;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    ULONG hashLen = 0, cb = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLen, sizeof(hashLen), &cb, 0) == 0 &&
        hashLen == outLen &&
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) == 0) {
        BYTE buf[8192]; size_t off = 0;
        bool fed = true;
        while (off < len) {
            size_t chunk = min(len - off, sizeof(buf));
            memcpy(buf, data + off, chunk);
            if (BCryptHashData(hHash, buf, (ULONG)chunk, 0) != 0) { fed = false; break; }
            off += chunk;
        }
        if (fed && BCryptFinishHash(hHash, out, outLen, 0) == 0) ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ═══════════════════════════════════════════════════════════════
//  本地分析运行时报告 (布局: winnt.h RUNTIME_REPORT_PACKAGE + 实测偏移)
//    [包头 40B(含对齐填充)] [Nonce 32B @40] [Digest 头 ×N @72 每个 68B]
//    [Signature Blob] [Authenticated Reports: 8B 头 + payload]
// ═══════════════════════════════════════════════════════════════
static void AnalyzeRuntimeReport(const std::vector<BYTE>& r, const BYTE* expectedNonce) {
    if (r.size() < 72) { wprintf(L"    [分析] 报告过短\n"); return; }
    UINT32 magic = *(const UINT32*)r.data();
    UINT16 ver = *(const UINT16*)(r.data() + 4);
    UINT16 numReports = *(const UINT16*)(r.data() + 6);
    UINT64 bitmap = *(const UINT64*)(r.data() + 8);
    UINT32 pkgSize = *(const UINT32*)(r.data() + 16);
    UINT16 digestsSize = *(const UINT16*)(r.data() + 22);
    UINT16 sigScheme = *(const UINT16*)(r.data() + 26);
    UINT32 sigSize = *(const UINT32*)(r.data() + 28);
    UINT32 authSize = *(const UINT32*)(r.data() + 32);

    wprintf(L"    [分析] Magic=0x%08X 版本=%u 报告数=%u 掩码=0x%llX 签名方案=%u\n",
            magic, ver, numReports, (unsigned long long)bitmap, sigScheme);
    if (magic != 0x52545250) { wprintf(L"    [分析] ✗ Magic 非法 (应为 0x52545250)\n"); return; }

    bool nonceOk = r.size() >= 72 && memcmp(r.data() + 40, expectedNonce, 32) == 0;
    wprintf(L"    [分析] Nonce 绑定(与 challenge 一致): %s\n", nonceOk ? L"✓" : L"✗");

    // Digest 头 @72, 每个 68B
    struct DigestEntry { UINT16 type; BYTE digest[64]; };
    std::vector<std::pair<UINT16, const BYTE*>> digests;
    size_t off = 72, digestsEnd = 72 + digestsSize;
    while (off + 68 <= digestsEnd && off + 68 <= r.size()) {
        digests.push_back({ *(const UINT16*)(r.data() + off), r.data() + off + 4 });
        off += 68;
    }

    size_t sigOff = digestsEnd;
    size_t reportsOff = sigOff + sigSize;
    size_t reportsEnd = min(reportsOff + authSize, r.size());

    // 遍历认证报告: 校验 SHA-512 digest + 统计驱动
    size_t p = reportsOff;
    int digestOk = 0, reportCount = 0;
    UINT16 totalDrivers = 0, bootDrivers = 0, unloadedDrivers = 0;
    while (p + 8 <= reportsEnd) {
        UINT16 rtype = *(const UINT16*)(r.data() + p);
        UINT32 rsize = *(const UINT32*)(r.data() + p + 4);
        if (rsize < 8 || p + rsize > reportsEnd) break;
        BYTE calc[64];
        bool dOk = false;
        if (ShaHash(L"SHA512", r.data() + p, rsize, calc, 64))
            for (auto& d : digests)
                if (d.first == rtype && memcmp(calc, d.second, 64) == 0) { dOk = true; break; }
        if (dOk) digestOk++;
        reportCount++;

        if (rtype == 0) {  // Driver Report
            UINT16 n = *(const UINT16*)(r.data() + p + 8);
            UINT16 flags = *(const UINT16*)(r.data() + p + 10);
            totalDrivers = n;
            unloadedDrivers = 0; bootDrivers = 0;
            wprintf(L"    [分析] Driver 报告: %u 个驱动 (溢出=%u 部分=%u 含Boot=%u)\n",
                    n, flags & 1, (flags >> 1) & 1, (flags >> 2) & 1);
            wprintf(L"    [分析] 驱动明细 (前 12 个):\n");
            for (UINT16 i = 0; i < n && i < 12; i++) {
                size_t e = p + 12 + (size_t)i * 56;
                if (e + 56 > r.size()) break;
                char name[33] = {};
                memcpy(name, r.data() + e, 32);
                UINT16 dflags = *(const UINT16*)(r.data() + e + 52);
                UINT16 loadTimes = *(const UINT16*)(r.data() + e + 44);
                if (dflags & 2) bootDrivers++;
                if (dflags & 1) unloadedDrivers++;
                wprintf(L"      %-20hs %s 次数=%u\n", name,
                        (dflags & 2) ? L"Boot " : (dflags & 1) ? L"Unloaded" : L"Runtime", loadTimes);
            }
            if (n > 12) wprintf(L"      ... 其余 %u 个见服务器完整解析\n", n - 12);
        }
        p += rsize;
    }
    wprintf(L"    [分析] Digest 校验: %d/%d OK   Boot驱动=%u Unloaded=%u\n",
            digestOk, reportCount, bootDrivers, unloadedDrivers);
    wprintf(L"    [分析] 微软签名信任链: 服务器侧验证 (本报告已提交)\n");
}

// ═══════════════════════════════════════════════════════════════
//  HTTP (WinHTTP)
// ═══════════════════════════════════════════════════════════════

static std::string HttpCall(const std::wstring& serverUrl, const wchar_t* verb,
                            const std::string& body, DWORD* statusCode) {
    *statusCode = 0;
    // 拆 URL: http://host:port/path
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    uc.dwHostNameLength = (DWORD)-1;
    uc.dwUrlPathLength = (DWORD)-1;
    if (!WinHttpCrackUrl(serverUrl.c_str(), 0, 0, &uc)) return "";

    std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring path = (wcscmp(verb, L"GET") == 0) ? L"/api/vbs/challenge" : L"/api/vbs/verify";

    HINTERNET hSession = WinHttpOpen(L"VBSRemoteDetect/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), uc.nPort, 0);
    HINTERNET hRequest = nullptr;
    std::string response;
    if (hConnect) {
        hRequest = WinHttpOpenRequest(hConnect, verb, path.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hRequest) {
            if (wcscmp(verb, L"POST") == 0) {
                std::wstring hdr = L"Content-Type: application/json\r\n";
                WinHttpAddRequestHeaders(hRequest, hdr.c_str(), (DWORD)hdr.size(),
                                         WINHTTP_ADDREQ_FLAG_ADD);
                WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   (LPVOID)body.data(), (DWORD)body.size(),
                                   (DWORD)body.size(), 0);
            } else {
                WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            }
            WinHttpReceiveResponse(hRequest, nullptr);

            DWORD st = 0, sz = sizeof(st);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX);
            *statusCode = st;

            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
                std::vector<char> chunk(avail);
                DWORD read = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), avail, &read)) break;
                response.append(chunk.data(), read);
            }
        }
    }
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

// Java/JSON 风格 \uXXXX 反转义（System.Text.Json 默认会把 '+' 转义成 \u002B）
static std::string UnescapeJson(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size();) {
        if (in[i] == '\\' && i + 5 < in.size() && in[i + 1] == 'u') {
            unsigned cp = 0;
            bool ok = true;
            for (int k = 0; k < 4; k++) {
                char c = in[i + 2 + k];
                cp <<= 4;
                if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
                else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
                else { ok = false; break; }
            }
            if (ok) {
                // base64 字符都是 ASCII，直接按 UTF-8 追加
                if (cp < 0x80) out += (char)cp;
                else if (cp < 0x800) {
                    out += (char)(0xC0 | (cp >> 6));
                    out += (char)(0x80 | (cp & 0x3F));
                } else {
                    out += (char)(0xE0 | (cp >> 12));
                    out += (char)(0x80 | ((cp >> 6) & 0x3F));
                    out += (char)(0x80 | (cp & 0x3F));
                }
                i += 6;
                continue;
            }
        }
        out += in[i++];
    }
    return out;
}

// base64 → 字节（容忍 padding 缺失，忽略非法字符）
static std::vector<BYTE> B64Decode(const std::string& in) {
    static int rev[256]; static bool init = false;
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!init) { for (int i = 0; i < 256; i++) rev[i] = -1; for (int i = 0; i < 64; i++) rev[(BYTE)tbl[i]] = i; init = true; }
    std::vector<BYTE> out;
    UINT32 acc = 0; int bits = 0;
    for (char c : in) {
        if (c == '=') break;
        int v = rev[(BYTE)c];
        if (v < 0) continue;           // 忽略换行/其他无关字符
        acc = (acc << 6) | (UINT32)v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((BYTE)((acc >> bits) & 0xFF)); }
    }
    return out;
}

// 简易 JSON 字段提取（值都是无转义的 base64/hex 字符串）
static std::string JsonGetString(const std::string& json, const char* key) {
    std::string needle = std::string("\"") + key + "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    auto end = json.find('"', pos);
    if (end == std::string::npos) return "";
    return UnescapeJson(json.substr(pos, end - pos));
}

// ═══════════════════════════════════════════════════════════════
//  方案 A: NCrypt 密钥证明链
// ═══════════════════════════════════════════════════════════════

struct ClaimResult {
    SECURITY_STATUS status = 0;
    bool localVerifyOk = false;
    std::vector<BYTE> claimBlob;
    std::vector<BYTE> attestPub;
    std::vector<BYTE> signature;   // proof-of-possession 签名
};

// canonical payload: K_CANONICAL_PREFIX\n{sessionId}\n{nonceB64}\n{claimSha256Hex}
static std::string BuildCanonical(const std::string& sessionId, const std::string& nonceB64,
                                  const std::string& claimHashHex) {
    std::string s = K_CANONICAL_PREFIX;
    s += "\n";  s += sessionId;
    s += "\n";  s += nonceB64;
    s += "\n";  s += claimHashHex;
    return s;
}

static ClaimResult CreateClaimAndSign(const BYTE* nonce, size_t nonceLen,
                                      const std::string& sessionId, const std::string& nonceB64) {
    ClaimResult r;
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;

    SECURITY_STATUS st = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) { r.status = st; return r; }

    // 1. 创建强制 VTL1 隔离的 RSA 密钥（覆盖式，方便重复运行）
    st = NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_RSA_ALGORITHM, K_PROBE_KEY_NAME,
                                  0, NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_REQUIRE_VBS_FLAG);
    if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }

    {
        // 2. 密钥用途: 签名 (实测: ATTESTATION 位会导致 NTE_INVALID_PARAMETER,
        //    只设 SIGNING 且 flags=0 成功; NCRYPT_PERSIST_FLAG 也不能带)
        DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
        st = NCryptSetProperty(hKey, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage,
                               sizeof(usage), 0);
        if (st != ERROR_SUCCESS)
            wprintf(L"[A] 注: 设置 KeyUsage 失败: 0x%08lX (非致命, 继续执行)\n", st);

        st = NCryptFinalizeKey(hKey, 0);
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }
        wprintf(L"[A] VTL1 隔离密钥已创建 (REQUIRE_VBS) — Secure Kernel 正在运行\n");

        // 3. 导出公钥 (BCRYPT_RSAPUBLIC_BLOB)
        DWORD cbPub = 0;
        st = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &cbPub, 0);
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }
        r.attestPub.resize(cbPub);
        st = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr,
                             r.attestPub.data(), cbPub, &cbPub, 0);
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }

        // 4. 创建 VBS Root Claim（由 IDKS — Secure Kernel 根签名密钥 — 签发）
        //    实测: KeyUsage=SIGNING(仅) 设置成功后, 带 nonce 参数的 claim 可用,
        //    nonce = 服务器 challenge → 服务器 NCryptVerifyClaim 时校验 nonce 绑定
        NCryptBuffer nonceBuf = {};
        nonceBuf.cbBuffer = (ULONG)nonceLen;
        nonceBuf.BufferType = NCRYPTBUFFER_CLAIM_KEYATTESTATION_NONCE;
        nonceBuf.pvBuffer = (PVOID)nonce;
        NCryptBufferDesc params = {};
        params.ulVersion = 0;
        params.cBuffers = 1;
        params.pBuffers = &nonceBuf;

        DWORD cbClaim = 0;
        st = NCryptCreateClaim(hKey, 0, NCRYPT_CLAIM_VBS_ROOT, &params,
                               nullptr, 0, &cbClaim, 0);
        if (st == ERROR_SUCCESS) {
            r.claimBlob.resize(cbClaim);
            st = NCryptCreateClaim(hKey, 0, NCRYPT_CLAIM_VBS_ROOT, &params,
                                   r.claimBlob.data(), cbClaim, &cbClaim, 0);
        }
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }
        wprintf(L"[A] VBS Root Claim 创建成功 (%lu bytes, 由 IDKS 在 VTL1 内签发)\n", cbClaim);

        // 5. 本地验证 claim
        //    注意: pOutput 不能传 nullptr（否则 NTE_INVALID_PARAMETER 0x80090027），
        //    且要带 NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG —— 与 C# 探针的已验证调用一致
        NCryptBufferDesc outDesc = {};
        st = NCryptVerifyClaim(hKey, 0, NCRYPT_CLAIM_VBS_ROOT, &params,
                               r.claimBlob.data(), (DWORD)r.claimBlob.size(),
                               &outDesc, NCRYPT_VBS_RETURN_CLAIM_DETAILS_FLAG);
        r.localVerifyOk = (st == ERROR_SUCCESS);
        wprintf(L"[A] 本地 NCryptVerifyClaim = 0x%08lX %s\n", st,
                r.localVerifyOk ? L"→ 验证通过 (签名链锚定 IDKS)" : L"");
        if (outDesc.pBuffers) NCryptFreeBuffer(outDesc.pBuffers);

        // 6. proof-of-possession: 用 VTL1 密钥对 canonical payload 签名
        //    实测: VTL1 密钥使用 PKCS1/SHA256（PSS padding info 会被忽略）
        BYTE claimHash[32];
        if (!Sha256(r.claimBlob.data(), r.claimBlob.size(), claimHash)) { r.status = NTE_FAIL; goto cleanup; }
        std::string canonical = BuildCanonical(sessionId, nonceB64, HexEncode(claimHash, 32));
        BYTE canonHash[32];
        if (!Sha256((const BYTE*)canonical.data(), canonical.size(), canonHash)) { r.status = NTE_FAIL; goto cleanup; }

        BCRYPT_PKCS1_PADDING_INFO pkcs1Info = { L"SHA256" };
        DWORD cbSig = 0;
        st = NCryptSignHash(hKey, &pkcs1Info, canonHash, 32,
                            nullptr, 0, &cbSig, BCRYPT_PAD_PKCS1);
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }
        r.signature.resize(cbSig);
        st = NCryptSignHash(hKey, &pkcs1Info, canonHash, 32,
                            r.signature.data(), cbSig, &cbSig, BCRYPT_PAD_PKCS1);
        if (st != ERROR_SUCCESS) { r.status = st; goto cleanup; }
        wprintf(L"[A] proof-of-possession 签名完成 (%lu bytes, RSA PKCS1/SHA256)\n", cbSig);
        r.status = ERROR_SUCCESS;
    }

cleanup:
    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return r;
}

// ═══════════════════════════════════════════════════════════════
//  方案 C: GetRuntimeAttestationReport (Secure Kernel 签名的运行时报告)
// ═══════════════════════════════════════════════════════════════

static std::vector<BYTE> GetRuntimeReport(const BYTE* nonce, bool& available) {
    available = false;
    // 实测: API 导出在 kernelbase.dll（文档写 kernel32.dll 是错的）
    typedef BOOL(WINAPI * PFN_GetRuntimeAttestationReport)(UCHAR*, UINT16, UINT64, PVOID, PUINT32);
    PFN_GetRuntimeAttestationReport pfn = nullptr;
    for (auto dll : { L"kernelbase.dll", L"kernel32.dll" }) {
        if (HMODULE h = GetModuleHandleW(dll)) {
            pfn = (PFN_GetRuntimeAttestationReport)GetProcAddress(h, "GetRuntimeAttestationReport");
            if (pfn) { wprintf(L"[C] %s: 找到 GetRuntimeAttestationReport 导出\n", dll); break; }
        }
    }
    if (!pfn) {
        wprintf(L"[C] GetRuntimeAttestationReport 不存在（需要支持该 API 的 Windows 版本）\n");
        return {};
    }

    // 实测: PackageVersion=1；只能请求 Driver 报告 (1<<RuntimeReportTypeDriver = 1)，
    // 请求 CodeIntegrity 报告会返回 ERROR_INVALID_PARAMETER
    const UINT64 kMask = RUNTIME_REPORT_TYPE_TO_MASK(RuntimeReportTypeDriver);

    UINT32 cb = 0;
    SetLastError(0);
    if (!pfn((UCHAR*)nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT, kMask, nullptr, &cb) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        wprintf(L"[C] 报告大小查询失败: gle=0x%08lX（可能 HVCI 未运行 / 系统不支持）\n", GetLastError());
        return {};
    }
    std::vector<BYTE> report(cb);
    if (!pfn((UCHAR*)nonce, RUNTIME_REPORT_PACKAGE_VERSION_CURRENT, kMask, report.data(), &cb)) {
        wprintf(L"[C] 报告获取失败: gle=0x%08lX\n", GetLastError());
        return {};
    }
    available = true;
    wprintf(L"[C] 运行时报告获取成功 (%zu bytes) — Secure Kernel 运行时报告已生成 (nonce/digest 可供后端验证)\n", report.size());
    wprintf(L"[C] 注: 报告的微软签名信任链由服务器侧验证\n");
    return report;
}

// ═══════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════

int wmain(int argc, wchar_t** argv) {
    // UTF-8 输出链: CRT locale 用 .UTF8 → wprintf %hs 把服务器返回的 UTF-8 JSON
    // 原样输出（不再按系统 GBK 转换出乱码）；SetConsoleOutputCP 让控制台按 UTF-8 解释
    setlocale(LC_ALL, ".UTF8");
    SetConsoleOutputCP(CP_UTF8);
    std::wstring serverUrl = (argc > 1) ? argv[1] : L"http://192.168.31.207:5000";
    wprintf(L"=== VBS 远程验证客户端 ===\n服务器: %s\n\n", serverUrl.c_str());

    // ── D: 获取服务器 challenge ──
    DWORD status = 0;
    std::string challengeResp = HttpCall(serverUrl, L"GET", "", &status);
    if (status != 200 || challengeResp.empty()) {
        wprintf(L"[-] 获取 challenge 失败 (HTTP %lu)。服务器未启动? %hs\n", status, challengeResp.c_str());
        return 1;
    }
    // Hyperion.Server 的 /api/vbs/challenge 返回 snake_case: { session_id, nonce }
    std::string sessionId = JsonGetString(challengeResp, "session_id");
    std::string nonceB64 = JsonGetString(challengeResp, "nonce");
    wprintf(L"[D] sessionId=%hs\n[D] challenge nonce=%hs\n\n", sessionId.c_str(), nonceB64.c_str());
    if (sessionId.empty() || nonceB64.empty()) {
        wprintf(L"[-] challenge 格式异常 (缺少字段)\n");
        return 1;
    }
    std::vector<BYTE> nonceBytes = B64Decode(nonceB64);
    if (nonceBytes.size() != 32) {
        wprintf(L"[-] challenge 格式异常 (nonce 解码后 %zu 字节, 期望 32)\n", nonceBytes.size());
        return 1;
    }
    const BYTE* nonce = nonceBytes.data();

    // ── A: NCrypt 证明链 ──
    wprintf(L"── 方案 A: NCrypt 密钥证明链 ──\n");
    ClaimResult claim = CreateClaimAndSign(nonceBytes.data(), nonceBytes.size(), sessionId, nonceB64);
    if (claim.status != ERROR_SUCCESS || claim.claimBlob.empty()) {
        wprintf(L"[-] NCrypt 证明链失败: 0x%08lX\n", claim.status);
        if (claim.status == NTE_NOT_SUPPORTED)
            wprintf(L"    → NTE_NOT_SUPPORTED: Secure Kernel 未运行（VBS 未启动/不支持）\n");
        // 继续尝试 C 部分
    }
    wprintf(L"\n");

    // ── C: 运行时报告 ──
    wprintf(L"── 方案 C: GetRuntimeAttestationReport ──\n");
    bool reportAvail = false;
    std::vector<BYTE> runtimeReport = GetRuntimeReport(nonce, reportAvail);
    if (reportAvail) {
        FILE* f = nullptr;
        _wfopen_s(&f, L"runtime_report.bin", L"wb");
        if (f) { fwrite(runtimeReport.data(), 1, runtimeReport.size(), f); fclose(f); }
        wprintf(L"    已保存 runtime_report.bin 供离线分析\n");
        // ── 本地分析: 结构校验 + nonce 绑定 + digest 校验 + 驱动清单摘要 ──
        AnalyzeRuntimeReport(runtimeReport, nonce);
    }
    wprintf(L"\n");

    // ── D: 提交验证 ──
    wprintf(L"── 方案 D: 提交服务器验证 ──\n");
    std::string claimB64 = claim.claimBlob.empty() ? "" : B64Encode(claim.claimBlob.data(), claim.claimBlob.size());
    std::string pubB64 = claim.attestPub.empty() ? "" : B64Encode(claim.attestPub.data(), claim.attestPub.size());
    std::string sigB64 = claim.signature.empty() ? "" : B64Encode(claim.signature.data(), claim.signature.size());
    std::string reportB64 = runtimeReport.empty() ? "" : B64Encode(runtimeReport.data(), runtimeReport.size());

    std::string body = "{";
    body += "\"session_id\":\"" + sessionId + "\",";
    body += "\"claim_blob\":\"" + claimB64 + "\",";
    body += "\"attest_pub\":\"" + pubB64 + "\",";
    body += "\"signature\":\"" + sigB64 + "\",";
    body += "\"runtime_report\":\"" + reportB64 + "\"";
    body += "}";

    std::string verifyResp = HttpCall(serverUrl, L"POST", body, &status);
    wprintf(L"服务器响应 (HTTP %lu):\n%hs\n", status, verifyResp.c_str());
    return (status == 200) ? 0 : 1;
}
