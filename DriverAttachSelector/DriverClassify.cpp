// DriverClassify.cpp — 驱动签名证书链分类实现

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

#include "DriverClassify.h"

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <imagehlp.h>

#include <memory>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")

namespace das {

// DRIVER_VERIFY_GUID = F750E6C3-38EE-11D1-85E5-00C04FC295EE
static const GUID DRIVER_CATALOG_VERIFY_GUID = {
    0xF750E6C3, 0x38EE, 0x11D1, { 0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE }
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

// ═══════════════════════════════════════════════════════════════════════
//  辅助:证书 Subject 解析
// ═══════════════════════════════════════════════════════════════════════

static std::wstring CertNameToString(PCERT_NAME_BLOB pNameBlob) {
    if (!pNameBlob || pNameBlob->cbData == 0) return L"<empty>";

    DWORD dwType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    DWORD cbSize = CertNameToStrW(X509_ASN_ENCODING, pNameBlob, dwType, nullptr, 0);
    if (cbSize == 0) return L"<error>";

    std::wstring result(cbSize, L'\0');
    cbSize = CertNameToStrW(X509_ASN_ENCODING, pNameBlob, dwType, result.data(), cbSize);
    result.resize(cbSize);
    return result;
}

static bool IsWhqlSubject(const std::wstring& subject) {
    return subject.find(L"Hardware Compatibility Publisher") != std::wstring::npos;
}

static bool IsTimestampSubject(const std::wstring& subject) {
    return subject.find(L"Time Stamping") != std::wstring::npos
        || subject.find(L"Timestamp") != std::wstring::npos;
}

static bool IsMicrosoftSubject(const std::wstring& subject) {
    if (IsWhqlSubject(subject)) return false;
    if (IsTimestampSubject(subject)) return false;
    return subject.find(L"Microsoft") != std::wstring::npos;
}

static bool IsLeafCertificate(PCCERT_CONTEXT pCert, DWORD encodingType) {
    if (!pCert || !pCert->pCertInfo) return false;

    PCERT_EXTENSION pExt = CertFindExtension(
        szOID_BASIC_CONSTRAINTS2,
        pCert->pCertInfo->cExtension,
        pCert->pCertInfo->rgExtension);
    if (!pExt) return true;

    CERT_BASIC_CONSTRAINTS2_INFO constraints = {};
    DWORD cb = sizeof(constraints);
    if (!CryptDecodeObjectEx(encodingType, X509_BASIC_CONSTRAINTS2,
                             pExt->Value.pbData, pExt->Value.cbData,
                             CRYPT_DECODE_NOCOPY_FLAG, nullptr,
                             &constraints, &cb)) {
        return true;
    }
    return !constraints.fCA;
}

// ═══════════════════════════════════════════════════════════════════════
//  1. WinVerifyTrust 验证 Authenticode 内嵌签名
// ═══════════════════════════════════════════════════════════════════════

static LONG VerifyAuthenticodeSignature(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_IGNORE;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG hr = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGuid, &trustData);

    return hr;
}

// ═══════════════════════════════════════════════════════════════════════
//  2. 目录签名 (Catalog) 验证
// ═══════════════════════════════════════════════════════════════════════

static bool VerifyCatalogSignature(const std::wstring& filePath) {
    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &DRIVER_CATALOG_VERIFY_GUID, 0)) {
        return false;
    }

    bool result = false;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD hashSize = 0;
        if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0) && hashSize > 0) {
            std::vector<BYTE> hashBuf(hashSize);
            if (CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashBuf.data(), 0)) {
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

// 嵌套签名 OID = 1.3.6.1.4.1.311.2.4.1
static const char* SZOID_NESTED_SIGNATURE_LOCAL = "1.3.6.1.4.1.311.2.4.1";

static void ExtractSignersFromStore(HCERTSTORE hStore, DWORD encodingType,
                                     std::vector<SignerInfo>& signers) {
    PCCERT_CONTEXT pCert = nullptr;
    while ((pCert = CertFindCertificateInStore(hStore, encodingType, 0,
                                                CERT_FIND_ANY, nullptr, pCert)) != nullptr) {
        if (!IsLeafCertificate(pCert, encodingType)) continue;

        std::wstring subject = CertNameToString(&pCert->pCertInfo->Subject);

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
        info.isVendor = !info.isMicrosoft && !info.isWhql && !IsTimestampSubject(subject);
        signers.push_back(info);
    }
}

static void ExtractNestedSigners(HCRYPTMSG hMsg, DWORD encodingType,
                                  std::vector<SignerInfo>& signers) {
    for (DWORD i = 0; ; i++) {
        DWORD cbSignerInfo = 0;
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, nullptr, &cbSignerInfo)) {
            break;
        }

        auto buf = std::make_unique<BYTE[]>(cbSignerInfo);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, i, buf.get(), &cbSignerInfo)) {
            continue;
        }
        auto pSignerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buf.get());

        // 嵌套签名按 RFC 5652 在 UnauthAttrs 里,但两个都扫更稳
        PCRYPT_ATTRIBUTES attrSets[2] = { &pSignerInfo->AuthAttrs, &pSignerInfo->UnauthAttrs };
        for (int attrSetIdx = 0; attrSetIdx < 2; attrSetIdx++) {
            PCRYPT_ATTRIBUTES pAttrs = attrSets[attrSetIdx];
            for (DWORD j = 0; j < pAttrs->cAttr; j++) {
                PCRYPT_ATTRIBUTE pAttr = &pAttrs->rgAttr[j];
                if (strcmp(pAttr->pszObjId, SZOID_NESTED_SIGNATURE_LOCAL) != 0) continue;

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
                        ExtractSignersFromStore(hNestedStore, enc, signers);
                        ExtractNestedSigners(hNestedMsg, enc, signers);

                        CertCloseStore(hNestedStore, 0);
                        CryptMsgClose(hNestedMsg);
                    }
                }
            }
        }
    }
}

// 用 ImageEnumerateCertificates 遍历 PE 安全目录里的所有签名块
// 关键:PE 可能有多个独立 WIN_CERTIFICATE 条目(多签名场景),
//       CryptQueryObject 默认只解析第一个,会漏掉其他签名者。
static bool ExtractSigners(const std::wstring& filePath, std::vector<SignerInfo>& signers) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool anyOk = false;

    DWORD certCount = 0;
    if (!ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &certCount, nullptr, 0)) {
        CloseHandle(hFile);
        return false;
    }

    for (DWORD i = 0; i < certCount; i++) {
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

        LPBYTE pPkcs7 = pWinCert->bCertificate;
        DWORD cbPkcs7 = pWinCert->dwLength - offsetof(WIN_CERTIFICATE, bCertificate);

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

        ExtractSignersFromStore(hStore, encodingType, signers);
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

ClassifyResult ClassifyDriver(const std::wstring& filePath) {
    ClassifyResult result;

    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        result.klass = DriverClass::UNTRUSTED;
        result.errorReason = L"文件不存在或不是文件";
        return result;
    }

    LONG hr = VerifyAuthenticodeSignature(filePath);

    if (hr == 0) {
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

        result.klass = DriverClass::MICROSOFT;
        return result;
    }

    if (VerifyCatalogSignature(filePath)) {
        result.hasCatalog = true;
        result.klass = DriverClass::INBOX;
        return result;
    }

    result.klass = DriverClass::UNTRUSTED;
    wchar_t buf[64];
    swprintf_s(buf, L"0x%08X", static_cast<unsigned int>(hr));
    result.errorReason = std::wstring(L"Authenticode 失败 hr=") + buf + L", 无 Catalog 签名";
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  5. 输出
// ═══════════════════════════════════════════════════════════════════════

void PrintClassifyResult(const std::wstring& filePath, const ClassifyResult& result) {
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

} // namespace das
