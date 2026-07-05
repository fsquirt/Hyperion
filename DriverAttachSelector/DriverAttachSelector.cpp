// DriverAttachSelector.cpp : 驱动签名证书链筛选器
// 用法: DriverAttachSelector.exe <path_to_sys_file>
//
// 分类逻辑（按用户指定）:
//   INBOX              - 仅有目录签名(.cat),无内嵌签名 → 放过(inbox 驱动)
//   MICROSOFT          - 内嵌签名 + 厂商是微软 → 放过(微软自家软件驱动)
//   THIRD_PARTY_WHQL   - 内嵌签名 + WHQL + 第三方厂商 → 待附着(漏洞驱动候选)
//   UNTRUSTED          - 无签名或验证失败 → HVCI 下不会存在
//
// 证书链判定:
//   WHQL 签名者 Subject 含 "Microsoft Windows Hardware Compatibility Publisher"
//   厂商签名者 Subject 不含 "Microsoft" (如 "ACEVILLE PTE LTD" / "Realtek Semiconductor Corp")
//   如果签名者全是 Microsoft → MICROSOFT
//   如果存在非 Microsoft 签名者 → THIRD_PARTY_WHQL

// Windows 10 目标,启用 CertEnumCertificateInStore / DRIVER_VERIFY_GUID 等 API
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <imagehlp.h>
#include <psapi.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "psapi.lib")

// DRIVER_VERIFY_GUID = F750E6C3-38EE-11D1-85E5-00C04FC295EE
// 用于驱动 catalog 验证(mscat.h 中声明但部分 SDK 配置下未实例化,这里自行定义)
static const GUID DRIVER_CATALOG_VERIFY_GUID = {
    0xF750E6C3, 0x38EE, 0x11D1, { 0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE }
};

// ═══════════════════════════════════════════════════════════════════════
//  分类结果定义
// ═══════════════════════════════════════════════════════════════════════

enum class DriverClass {
    INBOX,                  // 仅有目录签名(.cat) → 放过
    MICROSOFT,              // 内嵌签名 + 厂商是微软 → 放过
    THIRD_PARTY_WHQL,       // 内嵌签名 + WHQL + 第三方厂商 → 待附着
    UNTRUSTED,              // 无签名或验证失败
};

const wchar_t* ClassToString(DriverClass c) {
    switch (c) {
        case DriverClass::INBOX: return L"INBOX";
        case DriverClass::MICROSOFT: return L"MICROSOFT";
        case DriverClass::THIRD_PARTY_WHQL: return L"THIRD_PARTY_WHQL";
        case DriverClass::UNTRUSTED: return L"UNTRUSTED";
    }
    return L"UNKNOWN";
}

// 单个签名者信息
struct SignerInfo {
    std::wstring subject;       // 证书 Subject (e.g. "Microsoft Windows Hardware Compatibility Publisher")
    std::wstring issuer;        // 证书 Issuer
    bool isMicrosoft;           // 是否微软签名者 (Subject 含 "Microsoft")
    bool isWhql;                // 是否 WHQL 签名者
    bool isVendor;              // 是否第三方厂商签名者
};

// 分类结果
struct ClassifyResult {
    DriverClass klass = DriverClass::UNTRUSTED;
    std::vector<SignerInfo> signers;
    std::wstring vendorName;    // 第三方厂商名 (仅 THIRD_PARTY_WHQL 时有意义)
    std::wstring errorReason;   // 失败原因 (UNTRUSTED 时有意义)
    bool hasCatalog = false;    // 是否有目录签名
    bool hasEmbedded = false;   // 是否有内嵌签名
};

// ═══════════════════════════════════════════════════════════════════════
//  辅助函数
// ═══════════════════════════════════════════════════════════════════════

// 把 CERT_NAME_BLOB 转成可读字符串 (RFC822 形式,易读)
static std::wstring CertNameToString(PCERT_NAME_BLOB pNameBlob) {
    if (!pNameBlob || pNameBlob->cbData == 0) return L"<empty>";

    DWORD dwType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    DWORD cbSize = CertNameToStrW(X509_ASN_ENCODING, pNameBlob, dwType, nullptr, 0);
    if (cbSize == 0) return L"<error>";

    std::wstring result(cbSize, L'\0');
    cbSize = CertNameToStrW(X509_ASN_ENCODING, pNameBlob, dwType, result.data(), cbSize);
    result.resize(cbSize); // 去掉末尾 \0
    return result;
}

// 判断 Subject 是否是 WHQL 签名者
// "Microsoft Windows Hardware Compatibility Publisher"
// 这是微软代签第三方的证书 —— 虽含 "Microsoft",但不视为微软自家
static bool IsWhqlSubject(const std::wstring& subject) {
    return subject.find(L"Hardware Compatibility Publisher") != std::wstring::npos;
}

// 判断 Subject 是否是时间戳服务签名者
// 例如 "Symantec Time Stamping Services Signer - G4" / "DigiCert Timestamp 2021"
// 这些是 RFC 3161 时间戳服务的证书,不是真正的签名者,要过滤掉
static bool IsTimestampSubject(const std::wstring& subject) {
    return subject.find(L"Time Stamping") != std::wstring::npos
        || subject.find(L"Timestamp") != std::wstring::npos;
}

// 判断 Subject 是否是微软自家签名者 (Production PCA 签的 "Microsoft Windows" / "Microsoft Corporation")
// 注意:WHQL 签名者不算微软自家,时间戳签名者不算签名者
static bool IsMicrosoftSubject(const std::wstring& subject) {
    if (IsWhqlSubject(subject)) return false;
    if (IsTimestampSubject(subject)) return false;
    return subject.find(L"Microsoft") != std::wstring::npos;
}

// 判断证书是否是叶子证书 (非 CA),通过 basicConstraints2 扩展
static bool IsLeafCertificate(PCCERT_CONTEXT pCert, DWORD encodingType) {
    if (!pCert || !pCert->pCertInfo) return false;

    PCERT_EXTENSION pExt = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        pCert->pCertInfo->cExtension,
        pCert->pCertInfo->rgExtension);
    if (!pExt) {
        // 没有 basicConstraints 扩展,默认视为叶子(终端实体)
        return true;
    }

    CERT_BASIC_CONSTRAINTS2_INFO constraints = {};
    DWORD cb = sizeof(constraints);
    if (!CryptDecodeObjectEx(encodingType, X509_BASIC_CONSTRAINTS2,
                             pExt->Value.pbData, pExt->Value.cbData,
                             CRYPT_DECODE_NOCOPY_FLAG, nullptr,
                             &constraints, &cb)) {
        return true; // 解码失败,默认视为叶子
    }

    return !constraints.fCA; // fCA=FALSE 是叶子证书
}

// ═══════════════════════════════════════════════════════════════════════
//  1. WinVerifyTrust 验证 Authenticode 内嵌签名
// ═══════════════════════════════════════════════════════════════════════

// 返回值:
//   0                          - 签名有效
//   TRUST_E_NOSIGNATURE        - 无内嵌签名
//   TRUST_E_EXPLICIT_DISTRUST  - 明确不信任(显式拉黑)
//   其他                        - 验证失败(链问题、过期等)
static LONG VerifyAuthenticodeSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // 不做吊销检查(离线环境友好)
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_IGNORE;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG hr = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    // 清理 state data
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    return hr;
}

// ═══════════════════════════════════════════════════════════════════════
//  2. 目录签名 (Catalog) 验证
// ═══════════════════════════════════════════════════════════════════════

// 用 DRIVER_VERIFY_GUID 查驱动 catalog
static bool VerifyCatalogSignature(const std::wstring& filePath) {
    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &DRIVER_CATALOG_VERIFY_GUID, 0)) {
        return false;
    }

    bool result = false;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        // 第一次调用:获取哈希大小
        DWORD hashSize = 0;
        if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0) && hashSize > 0) {
            std::vector<BYTE> hashBuf(hashSize);
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashBuf.data(), 0)) {
                // 在已注册的 catalog 中查找该哈希
                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
                    hCatAdmin, hashBuf.data(), hashSize, 0, nullptr);
                if (hCatInfo) {
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                    result = true;
                }
            }
        }
        CloseHandle(hFile);
    }

    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  3. 提取签名者证书(含嵌套签名递归)
// ═══════════════════════════════════════════════════════════════════════
//
//  PE 签名结构(以 WHQL 第三方驱动为例):
//    外层签名者 = Microsoft Windows Hardware Compatibility Publisher (WHQL)
//    外层签名的 authenticated attributes 里含 szOID_NESTED_SIGNATURE 属性
//    该属性值是另一个 PKCS#7 SignedData,里面是厂商签名者 (如 ACEVILLE)
//
//  必须:
//  1. 从 cert store 遍历外层签名的叶子证书
//  2. 从 hMsg 解析签名者 authenticated attributes,找嵌套签名
//  3. 对嵌套签名用 CryptQueryObject 再解析,递归处理

// 嵌套签名 OID = 1.3.6.1.4.1.311.2.4.1
static const char* SZOID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";

// 前置声明(WriteOut 定义在第 5 节)
static void WriteOut(const std::wstring& s);

// 从 cert store 提取叶子证书(签名者),Subject 去重
static void ExtractSignersFromStore(HCERTSTORE hStore, DWORD encodingType,
                                     std::vector<SignerInfo>& signers) {
    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertFindCertificateInStore(hStore, encodingType, 0,
                                                CERT_FIND_ANY, nullptr, pCert)) != nullptr) {
        if (!IsLeafCertificate(pCert, encodingType)) {
            continue; // 跳过 CA 证书
        }

        std::wstring subject = CertNameToString(&pCert->pCertInfo->Subject);

        // Subject 去重(嵌套签名可能和外层共享某些证书)
        bool dup = false;
        for (const auto& s : signers) {
            if (s.subject == subject) { dup = true; break; }
        }
        if (dup) continue;

        SignerInfo info = {};
        info.subject = subject;
        info.issuer = CertNameToString(&pCert->pCertInfo->Issuer);
        info.isWhql = IsWhqlSubject(subject);
        info.isMicrosoft = IsMicrosoftSubject(subject);
        // 厂商 = 非微软 + 非 WHQL + 非时间戳
        info.isVendor = !info.isMicrosoft && !info.isWhql && !IsTimestampSubject(subject);
        signers.push_back(info);
    }
}

// 从 hMsg 解析嵌套签名,递归提取签名者
static void ExtractNestedSigners(HCRYPTMSG hMsg, DWORD encodingType,
                                  std::vector<SignerInfo>& signers) {
    for (DWORD i = 0; ; i++) {
        DWORD cbSignerInfo = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &cbSignerInfo)) {
            break; // 没有更多签名者
        }

        auto buf = std::make_unique<BYTE[]>(cbSignerInfo);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, buf.get(), &cbSignerInfo)) {
            continue;
        }
        auto pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buf.get());

        // 遍历 authenticated attributes 找嵌套签名
        // 注意:嵌套签名(1.3.6.1.4.1.311.2.4.1)按 RFC 5652 规定是未认证属性,
        //       因为外层签名者无法认证一个包含自己签名的嵌套签名
        //       所以必须同时扫 AuthAttrs 和 UnauthAttrs
        PCRYPT_ATTRIBUTES attrSets[2] = { &pSignerInfo->AuthAttrs, &pSignerInfo->UnauthAttrs };
        for (int attrSetIdx = 0; attrSetIdx < 2; attrSetIdx++) {
            PCRYPT_ATTRIBUTES pAttrs = attrSets[attrSetIdx];
            for (DWORD j = 0; j < pAttrs->cAttr; j++) {
                PCRYPT_ATTRIBUTE pAttr = &pAttrs->rgAttr[j];
                if (strcmp(pAttr->pszObjId, SZOID_NESTED_SIGNATURE) != 0) {
                    continue;
                }

                // 找到嵌套签名,解析每个值
                for (DWORD k = 0; k < pAttr->cValue; k++) {
                    CRYPT_DATA_BLOB blob = {};
                    blob.cbData = pAttr->rgValue[k].cbData;
                    blob.pbData = pAttr->rgValue[k].pbData;

                    HCERTSTORE hNestedStore = nullptr;
                    HCRYPTMSG hNestedMsg = nullptr;
                    DWORD enc = 0, ct = 0, ft = 0;

                    if (CryptQueryObject(
                            CERT_QUERY_OBJECT_BLOB, &blob,
                            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                            CERT_QUERY_FORMAT_FLAG_BINARY,
                            0, &enc, &ct, &ft,
                            &hNestedStore, &hNestedMsg, nullptr)) {
                        // 提取嵌套签名的签名者
                        ExtractSignersFromStore(hNestedStore, enc, signers);
                        // 递归处理(理论上可能有多层嵌套)
                        ExtractNestedSigners(hNestedMsg, enc, signers);

                        CertCloseStore(hNestedStore, 0);
                        CryptMsgClose(hNestedMsg);
                    }
                }
            }
        }
    }
}

// 主入口:用 ImageEnumerateCertificates 遍历 PE 安全目录里的所有签名块,
// 对每个 PKCS#7 用 CryptQueryObject 解析,提取所有签名者(含嵌套)。
//
// 关键:PE 可能有多个独立 WIN_CERTIFICATE 条目(多签名场景),
//       CryptQueryObject 默认只解析第一个,会漏掉其他签名者。
static bool ExtractSigners(const std::wstring& filePath, std::vector<SignerInfo>& signers) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool anyOk = false;

    // 枚举所有签名块
    DWORD certCount = 0;
    if (!ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &certCount, nullptr, 0)) {
        CloseHandle(hFile);
        return false;
    }

    for (DWORD i = 0; i < certCount; i++) {
        // 先取大小
        DWORD cbCert = 0;
        if (!ImageGetCertificateData(hFile, i, nullptr, &cbCert) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            continue;
        }

        auto certBuf = std::make_unique<BYTE[]>(cbCert);
        LPWIN_CERTIFICATE pWinCert = reinterpret_cast<LPWIN_CERTIFICATE>(certBuf.get());
        if (!ImageGetCertificateData(hFile, i, pWinCert, &cbCert)) {
            continue;
        }

        // WIN_CERTIFICATE 结构:dwLength + wRevision + wCertificateType + bCertificate[]
        LPBYTE pPkcs7 = pWinCert->bCertificate;
        DWORD cbPkcs7 = pWinCert->dwLength - offsetof(WIN_CERTIFICATE, bCertificate);

        // 用 CryptQueryObject 解析这个 PKCS#7
        CRYPT_DATA_BLOB blob = {};
        blob.cbData = cbPkcs7;
        blob.pbData = pPkcs7;

        DWORD encodingType = 0, contentType = 0, formatType = 0;
        HCERTSTORE hStore = nullptr;
        HCRYPTMSG hMsg = nullptr;

        if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                              CERT_QUERY_FORMAT_FLAG_BINARY,
                              0, &encodingType, &contentType, &formatType,
                              &hStore, &hMsg, nullptr)) {
            continue;
        }

        // 提取这个签名块的叶子证书
        ExtractSignersFromStore(hStore, encodingType, signers);

        // 提取嵌套签名(在 UnauthAttrs 里,按 RFC 5652)
        ExtractNestedSigners(hMsg, encodingType, signers);

        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        anyOk = true;
    }

    CloseHandle(hFile);
    return anyOk;
}

// ═══════════════════════════════════════════════════════════════════════
//  4. 主分类函数
// ═══════════════════════════════════════════════════════════════════════

static ClassifyResult ClassifyDriver(const std::wstring& filePath) {
    ClassifyResult result;

    // 检查文件存在
    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        result.klass = DriverClass::UNTRUSTED;
        result.errorReason = L"文件不存在或不是文件";
        return result;
    }

    // 1. 先验证 Authenticode 内嵌签名
    LONG hr = VerifyAuthenticodeSignature(filePath);

    if (hr == 0) {
        // 内嵌签名有效,提取签名者
        result.hasEmbedded = true;

        std::vector<SignerInfo> signers;
        if (ExtractSigners(filePath, signers) && !signers.empty()) {
            result.signers = signers;

            bool hasWhql = false;
            bool hasVendor = false;
            std::wstring vendor;

            for (const auto& s : signers) {
                if (s.isWhql)   hasWhql = true;
                if (s.isVendor) { hasVendor = true; vendor = s.subject; }
            }

            // 判定:
            //   有厂商签名者(嵌套签名里的 ACEVILLE 等) → THIRD_PARTY_WHQL, 厂商名已知
            //   有 WHQL 但无厂商签名者 → THIRD_PARTY_WHQL, 厂商名未知
            //   只有 Microsoft 自家签名者 → MICROSOFT
            if (hasVendor) {
                result.klass = DriverClass::THIRD_PARTY_WHQL;
                result.vendorName = vendor;
            } else if (hasWhql) {
                result.klass = DriverClass::THIRD_PARTY_WHQL;
                result.vendorName = L"(仅 WHQL,无嵌套厂商签名)";
            } else {
                result.klass = DriverClass::MICROSOFT;
            }
            return result;
        }

        // 提取失败但 WinVerifyTrust 通过 — 视为微软签名(兜底)
        result.klass = DriverClass::MICROSOFT;
        return result;
    }

    // 2. 内嵌签名无效或不存在 → 试 catalog
    //    (TRUST_E_NOSIGNATURE = 无内嵌签名;其他错误码也可能是签名链问题,但 catalog 可能仍有效)
    if (VerifyCatalogSignature(filePath)) {
        result.hasCatalog = true;
        result.klass = DriverClass::INBOX;
        return result;
    }

    // 3. 都失败
    result.klass = DriverClass::UNTRUSTED;
    wchar_t buf[64];
    swprintf_s(buf, L"0x%08X", static_cast<unsigned int>(hr));
    result.errorReason = std::wstring(L"Authenticode 失败 hr=") + buf + L", 无 Catalog 签名";
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  5. 输出 (UTF-8 输出,控制台和重定向都兼容)
// ═══════════════════════════════════════════════════════════════════════

static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int cb = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                 nullptr, 0, nullptr, nullptr);
    std::string s(cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        s.data(), cb, nullptr, nullptr);
    return s;
}

static void WriteOut(const std::wstring& s) {
    std::string u8 = ToUtf8(s);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, u8.data(), (DWORD)u8.size(), &written, nullptr);
}

static void PrintResult(const std::wstring& filePath, const ClassifyResult& result) {
    std::wostringstream out;
    out << L"═══════════════════════════════════════════════════════\n";
    out << L"文件: " << filePath << L"\n";
    out << L"分类: " << ClassToString(result.klass) << L"\n";
    out << L"签名: ";
    if (result.hasEmbedded) out << L"内嵌签名 ";
    if (result.hasCatalog)  out << L"目录签名 ";
    if (!result.hasEmbedded && !result.hasCatalog) out << L"无";
    out << L"\n";

    if (!result.signers.empty()) {
        out << L"签名者:\n";
        for (const auto& s : result.signers) {
            out << L"  - " << s.subject;
            if (s.isWhql)                   out << L"  [WHQL]";
            if (s.isVendor)                 out << L"  [Vendor]";
            if (s.isMicrosoft && !s.isWhql) out << L"  [Microsoft]";
            out << L"\n";
            out << L"    Issuer: " << s.issuer << L"\n";
        }
    }

    if (!result.vendorName.empty()) {
        out << L"厂商: " << result.vendorName << L"\n";
    }

    if (!result.errorReason.empty()) {
        out << L"原因: " << result.errorReason << L"\n";
    }

    out << L"处置: ";
    switch (result.klass) {
        case DriverClass::INBOX:            out << L"放过(inbox 驱动,目录签名)"; break;
        case DriverClass::MICROSOFT:        out << L"放过(微软自家驱动)"; break;
        case DriverClass::THIRD_PARTY_WHQL: out << L"待附着(第三方 WHQL 漏洞驱动候选)"; break;
        case DriverClass::UNTRUSTED:        out << L"异常(HVCI 下不应存在)"; break;
    }
    out << L"\n═══════════════════════════════════════════════════════\n";

    WriteOut(out.str());
}

// ═══════════════════════════════════════════════════════════════════════
//  PSAPI 枚举已加载驱动
// ═══════════════════════════════════════════════════════════════════════

// 把 PSAPI 返回的内核路径转换为可读的真实文件系统路径
// 常见格式:
//   \SystemRoot\System32\drivers\xxx.sys
//   \??\C:\Windows\System32\drivers\xxx.sys
//   \Device\HarddiskVolumeN\Windows\...
static std::wstring NormalizeDriverPath(const std::wstring& raw) {
    if (raw.empty()) return L"";

    // 已是绝对路径
    if (raw.size() >= 2 && raw[1] == L':') return raw;

    // \??\C:\... 前缀
    if (raw.rfind(L"\\??\\", 0) == 0) return raw.substr(4);

    // \SystemRoot\... → C:\Windows\...
    if (_wcsicmp(raw.c_str(), L"\\SystemRoot") == 0 ||
        raw.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t sysDir[MAX_PATH] = {};
        GetWindowsDirectoryW(sysDir, MAX_PATH);
        return std::wstring(sysDir) + L"\\" + raw.substr(11);
    }

    // \Device\HarddiskVolumeN\... → 用 QueryDosDevice 反查盘符
    if (raw.rfind(L"\\Device\\", 0) == 0) {
        // 提取 \Device\HarddiskVolumeN 部分
        size_t devEnd = raw.find(L'\\', 8); // 跳过 "\Device\"
        if (devEnd == std::wstring::npos) return raw;
        std::wstring devicePrefix = raw.substr(0, devEnd);
        std::wstring remaining = raw.substr(devEnd + 1);

        // 枚举所有盘符,用 QueryDosDevice 匹配
        wchar_t drives[256] = {};
        DWORD len = GetLogicalDriveStringsW(255, drives);
        for (DWORD i = 0; i < len; ) {
            std::wstring drive(drives + i);
            i += drive.size() + 1;
            if (drive.empty()) continue;

            std::wstring driveLetter = drive.substr(0, 2); // "C:"
            wchar_t target[MAX_PATH] = {};
            if (QueryDosDeviceW(driveLetter.c_str(), target, MAX_PATH) > 0) {
                if (_wcsicmp(target, devicePrefix.c_str()) == 0) {
                    return drive + remaining;
                }
            }
        }
    }

    return raw;
}

struct LoadedDriver {
    std::wstring name;
    std::wstring path;
    ULONGLONG baseAddr;
    DWORD size;
};

static bool EnumLoadedDrivers(std::vector<LoadedDriver>& drivers) {
    drivers.clear();

    // 第一次调用获取所需字节数
    DWORD needed = 0;
    if (!EnumDeviceDrivers(nullptr, 0, &needed) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        // 某些情况下第一次调用返回 false 但 needed 有值,继续走
        if (needed == 0) return false;
    }
    if (needed == 0) return false;

    std::vector<LPVOID> bases(needed / sizeof(LPVOID));
    if (!EnumDeviceDrivers(bases.data(), needed, &needed)) {
        return false;
    }

    DWORD count = needed / sizeof(LPVOID);
    drivers.reserve(count);

    wchar_t nameBuf[1024];
    wchar_t pathBuf[MAX_PATH];

    for (DWORD i = 0; i < count; i++) {
        if (!bases[i]) continue;

        nameBuf[0] = 0;
        pathBuf[0] = 0;

        std::wstring name, path;
        if (GetDeviceDriverBaseNameW(bases[i], nameBuf, 1024) > 0) {
            name = nameBuf;
        }
        if (GetDeviceDriverFileNameW(bases[i], pathBuf, MAX_PATH) > 0) {
            path = NormalizeDriverPath(pathBuf);
        }

        // 模块大小(用 GetModuleInformation 拿)
        DWORD size = 0;
        // PSAPI 的 GetModuleInformation 对内核驱动需要 hProcess = GetCurrentProcess()
        // 但驱动基址是内核地址,GetModuleInformation 可能失败
        // 这里不强求 size,失败就 0
        drivers.push_back({name, path, (ULONGLONG)bases[i], size});
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  main — 枚举已加载的内核驱动并分类
// ═══════════════════════════════════════════════════════════════════════

int wmain() {
    SetConsoleOutputCP(CP_UTF8);

    WriteOut(L"枚举已加载的内核驱动模块...\n\n");

    std::vector<LoadedDriver> drivers;
    if (!EnumLoadedDrivers(drivers)) {
        WriteOut(L"EnumDeviceDrivers 失败,错误码: " + std::to_wstring(GetLastError()) + L"\n");
        return 1;
    }

    WriteOut(L"共枚举到 " + std::to_wstring(drivers.size()) + L" 个已加载驱动,开始分类...\n\n");

    // 统计计数
    int countInbox = 0, countMicrosoft = 0, countThirdParty = 0, countUntrusted = 0;
    int total = 0;
    int skipped = 0;

    // 汇总表(只记 THIRD_PARTY_WHQL,其他只计数)
    std::vector<std::pair<std::wstring, std::wstring>> thirdPartyList;

    for (const auto& d : drivers) {
        std::wstring fileName = d.name;
        std::wstring filePath = d.path;

        // 跳过无路径或文件不存在的项(可能是 NT 内核本身等)
        if (filePath.empty() || GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            skipped++;
            std::wostringstream line;
            line << L"[----] " << std::left << std::setw(40) << fileName
                 << L"  (跳过:无文件路径)\n";
            WriteOut(line.str());
            continue;
        }

        ClassifyResult result = ClassifyDriver(filePath);
        total++;

        switch (result.klass) {
            case DriverClass::INBOX:            countInbox++; break;
            case DriverClass::MICROSOFT:        countMicrosoft++; break;
            case DriverClass::THIRD_PARTY_WHQL:
                countThirdParty++;
                thirdPartyList.push_back({fileName, result.vendorName});
                break;
            case DriverClass::UNTRUSTED:        countUntrusted++; break;
        }

        // 单条简要输出
        std::wostringstream line;
        line << L"[" << std::setw(4) << total << L"] "
             << std::left << std::setw(40) << fileName
             << L"  " << ClassToString(result.klass);
        if (result.klass == DriverClass::THIRD_PARTY_WHQL && !result.vendorName.empty()) {
            line << L"  厂商=" << result.vendorName;
        }
        if (result.klass == DriverClass::UNTRUSTED && !result.errorReason.empty()) {
            line << L"  (" << result.errorReason << L")";
        }
        line << L"\n";
        WriteOut(line.str());
    }

    // 汇总
    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"汇总:\n";
    sum << L"  已加载驱动总数:  " << drivers.size() << L"\n";
    sum << L"  分类成功:        " << total << L"\n";
    sum << L"  跳过(无路径):   " << skipped << L"\n";
    sum << L"  INBOX:           " << countInbox << L"  (放过)\n";
    sum << L"  MICROSOFT:       " << countMicrosoft << L"  (放过)\n";
    sum << L"  THIRD_PARTY_WHQL:" << countThirdParty << L"  (待附着)\n";
    sum << L"  UNTRUSTED:       " << countUntrusted << L"  (异常)\n";
    sum << L"═══════════════════════════════════════════════════════\n";

    if (!thirdPartyList.empty()) {
        sum << L"待附着清单(THIRD_PARTY_WHQL):\n";
        for (const auto& [name, vendor] : thirdPartyList) {
            sum << L"  " << std::left << std::setw(40) << name;
            if (!vendor.empty()) sum << L"  " << vendor;
            sum << L"\n";
        }
        sum << L"═══════════════════════════════════════════════════════\n";
    }

    WriteOut(sum.str());
    return 0;
}
