// StringUtils.h
//
// 字符串/时间/格式化辅助函数(header-only,全部 inline)
// 包含: 宽字符↔UTF-8 互转、FILETIME 格式化、地址格式化、JSON 转义、
//       内存保护属性字符串化、PPL 保护级别字符串化

#pragma once
#include <Windows.h>
#include <string>
#include <cstdio>

// ───────────────────────────────────────────────────────────────
//  宽字符 → UTF-8
//  之所以不直接用 wprintf + _O_U8TEXT,是因为 MSVC 的 wprintf 在 U8TEXT 模式下
//  遇到 %zu / 某些宽字符序列会静默失败,且一次失败后后续所有 wprintf 都被跳过。
//  改成窄字符串 + printf 输出 UTF-8 字节,稳定可靠。
// ───────────────────────────────────────────────────────────────
inline std::string WToU8(const wchar_t* w)
{
    if (!w || !*w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}
inline std::string WToU8(const std::wstring& w) { return WToU8(w.c_str()); }

inline std::wstring U8ToW(const std::string& s)
{
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

// ───────────────────────────────────────────────────────────────
//  FILETIME → 本地时间字符串(UTF-8)
// ───────────────────────────────────────────────────────────────
inline std::string FormatTime(const LARGE_INTEGER& ft)
{
    if (ft.QuadPart == 0) return "-";
    FILETIME localFt;
    if (!FileTimeToLocalFileTime((const FILETIME*)&ft, &localFt)) return "-";
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&localFt, &st)) return "-";
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ───────────────────────────────────────────────────────────────
//  地址格式化(0x 前缀 + 小写十六进制)
// ───────────────────────────────────────────────────────────────
inline std::string HexAddr(ULONG_PTR addr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    return buf;
}

// ───────────────────────────────────────────────────────────────
//  JSON 字符串转义
// ───────────────────────────────────────────────────────────────
inline std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

// ───────────────────────────────────────────────────────────────
//  PPL 保护级别字符串化
//  PS_PROTECTION 的 Type/Signer 字段直接传入,避免头文件循环依赖
// ───────────────────────────────────────────────────────────────
inline std::string ProtectionLevelToStr(UCHAR level, UCHAR type, UCHAR signer)
{
    if (level == 0) return "None";
    const char* typeStr = "Unknown";
    switch (type)
    {
    case 0: typeStr = "None"; break;
    case 1: typeStr = "Protected"; break;
    case 2: typeStr = "ProtectedLight"; break;
    }
    const char* signerStr = "Unknown";
    switch (signer)
    {
    case 0: signerStr = "None"; break;
    case 1: signerStr = "Authenticode"; break;
    case 2: signerStr = "CodeGen"; break;
    case 3: signerStr = "Antimalware"; break;
    case 4: signerStr = "Lsa"; break;
    case 5: signerStr = "Windows"; break;
    case 6: signerStr = "WinTcb"; break;
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "%s-%s (Level=0x%02x)", typeStr, signerStr, level);
    return buf;
}

// ───────────────────────────────────────────────────────────────
//  内存保护属性字符串化
// ───────────────────────────────────────────────────────────────
inline std::string ProtectToStr(DWORD prot)
{
    std::string s;
    if (prot & PAGE_NOACCESS)          s += "NA|";
    if (prot & PAGE_READONLY)          s += "R|";
    if (prot & PAGE_READWRITE)         s += "RW|";
    if (prot & PAGE_WRITECOPY)         s += "WC|";
    if (prot & PAGE_EXECUTE)           s += "X|";
    if (prot & PAGE_EXECUTE_READ)      s += "RX|";
    if (prot & PAGE_EXECUTE_READWRITE) s += "RWX|";
    if (prot & PAGE_EXECUTE_WRITECOPY) s += "XWC|";
    if (prot & PAGE_GUARD)             s += "Guard|";
    if (prot & PAGE_NOCACHE)           s += "NoCache|";
    if (prot & PAGE_WRITECOMBINE)      s += "WCcombine|";
    if (s.empty()) return "0x" + HexAddr(prot);
    if (s.back() == '|') s.pop_back();
    return s;
}

inline std::string MemTypeToStr(DWORD type)
{
    std::string s;
    if (type & MEM_IMAGE)    s += "Image|";
    if (type & MEM_MAPPED)   s += "Mapped|";
    if (type & MEM_PRIVATE)  s += "Private|";
    if (s.empty()) return "0x" + HexAddr(type);
    if (s.back() == '|') s.pop_back();
    return s;
}
