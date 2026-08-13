// ObjectScanner.cpp — 对象管理器命名空间扫描实现

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include "ObjectScanner.h"

#include <windows.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace das {

// ═══════════════════════════════════════════════════════════════════════
//  NT 结构与常量自定义(避免依赖 subauth.h / winternl.h 在不同 SDK 下的差异)
// ═══════════════════════════════════════════════════════════════════════

typedef struct _NT_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} NT_UNICODE_STRING, *PNT_UNICODE_STRING;

#define UNICODE_STRING       _NT_UNICODE_STRING
#define PUNICODE_STRING      PNT_UNICODE_STRING

typedef struct _NT_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES, *PNT_OBJECT_ATTRIBUTES;

#define OBJECT_ATTRIBUTES    _NT_OBJECT_ATTRIBUTES
#define POBJECT_ATTRIBUTES   PNT_OBJECT_ATTRIBUTES

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY      0x0001
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY  0x0001
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) do { \
    (p)->Length = sizeof(NT_OBJECT_ATTRIBUTES);         \
    (p)->RootDirectory = (r);                            \
    (p)->Attributes = (a);                               \
    (p)->ObjectName = (n);                               \
    (p)->SecurityDescriptor = (s);                       \
    (p)->SecurityQualityOfService = NULL;                \
} while (0)
#endif

// NTAPI 函数指针类型
typedef LONG (NTAPI *PFN_NtOpenDirectoryObject)(
    _Out_ PHANDLE DirectoryHandle,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef LONG (NTAPI *PFN_NtQueryDirectoryObject)(
    _In_      HANDLE DirectoryHandle,
    _Out_opt_ PVOID Buffer,
    _In_      ULONG Length,
    _In_      BOOLEAN ReturnSingleEntry,
    _In_      BOOLEAN RestartScan,
    _Inout_   PULONG Context,
    _Out_opt_ PULONG ReturnLength);

typedef LONG (NTAPI *PFN_NtOpenSymbolicLinkObject)(
    _Out_ PHANDLE LinkHandle,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef LONG (NTAPI *PFN_NtQuerySymbolicLinkObject)(
    _In_      HANDLE LinkHandle,
    _Inout_   PUNICODE_STRING LinkTarget,
    _Out_opt_ PULONG ReturnedLength);

typedef VOID (NTAPI *PFN_RtlInitUnicodeString)(
    _Out_ PUNICODE_STRING DestinationString,
    _In_  PCWSTR SourceString);

typedef LONG (NTAPI *PFN_NtClose)(_In_ HANDLE Handle);

// 全局 NTAPI 函数指针(由 InitNtApi() 填充)
static struct {
    PFN_NtOpenDirectoryObject       NtOpenDirectoryObject;
    PFN_NtQueryDirectoryObject      NtQueryDirectoryObject;
    PFN_NtOpenSymbolicLinkObject    NtOpenSymbolicLinkObject;
    PFN_NtQuerySymbolicLinkObject   NtQuerySymbolicLinkObject;
    PFN_RtlInitUnicodeString        RtlInitUnicodeString;
    PFN_NtClose                     NtClose;
} g_nt;

// ═══════════════════════════════════════════════════════════════════════
//  初始化
// ═══════════════════════════════════════════════════════════════════════

bool InitNtApi() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    g_nt.NtOpenDirectoryObject     = (PFN_NtOpenDirectoryObject)    GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    g_nt.NtQueryDirectoryObject    = (PFN_NtQueryDirectoryObject)   GetProcAddress(hNtdll, "NtQueryDirectoryObject");
    g_nt.NtOpenSymbolicLinkObject  = (PFN_NtOpenSymbolicLinkObject) GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
    g_nt.NtQuerySymbolicLinkObject = (PFN_NtQuerySymbolicLinkObject)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
    g_nt.RtlInitUnicodeString      = (PFN_RtlInitUnicodeString)     GetProcAddress(hNtdll, "RtlInitUnicodeString");
    g_nt.NtClose                   = (PFN_NtClose)                  GetProcAddress(hNtdll, "NtClose");

    return g_nt.NtOpenDirectoryObject && g_nt.NtQueryDirectoryObject &&
           g_nt.NtOpenSymbolicLinkObject && g_nt.NtQuerySymbolicLinkObject &&
           g_nt.RtlInitUnicodeString && g_nt.NtClose;
}

// 把 NTSTATUS 转成可读 hex(如 0xC0000022)
static std::wstring NtStatusHex(LONG status) {
    std::wostringstream ss;
    ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (ULONG)status;
    return ss.str();
}

// ═══════════════════════════════════════════════════════════════════════
//  符号链接目标解析
// ═══════════════════════════════════════════════════════════════════════

// 调用者保证 linkFullPath 以反斜杠开头(如 "\GLOBAL??\C:")
static std::wstring QuerySymbolicLinkTarget(const std::wstring& linkFullPath) {
    if (!g_nt.NtOpenSymbolicLinkObject || !g_nt.NtQuerySymbolicLinkObject) return L"";

    UNICODE_STRING ustr;
    g_nt.RtlInitUnicodeString(&ustr, linkFullPath.c_str());

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hLink = NULL;
    LONG status = g_nt.NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa);
    if (status < 0) {
        return L"<open failed: " + NtStatusHex(status) + L">";
    }

    // 目标缓冲区先开 1024 wide chars,不够再扩
    std::wstring target;
    target.resize(1024);

    UNICODE_STRING targetUs = {};
    targetUs.Buffer = target.data();
    targetUs.Length = 0;
    targetUs.MaximumLength = (USHORT)(target.size() * sizeof(wchar_t));

    ULONG returnedLen = 0;
    status = g_nt.NtQuerySymbolicLinkObject(hLink, &targetUs, &returnedLen);
    if (status == 0) {
        target.resize(targetUs.Length / sizeof(wchar_t));
        g_nt.NtClose(hLink);
        return target;
    }

    // 缓冲区不够,用 returnedLen 重试(returnedLen 是字节数)
    if (status == 0xC0000023L /* STATUS_BUFFER_TOO_SMALL */ && returnedLen > 0) {
        target.resize(returnedLen / sizeof(wchar_t) + 1);
        targetUs.Buffer = target.data();
        targetUs.Length = 0;
        targetUs.MaximumLength = (USHORT)(target.size() * sizeof(wchar_t));

        status = g_nt.NtQuerySymbolicLinkObject(hLink, &targetUs, &returnedLen);
        if (status == 0) {
            target.resize(targetUs.Length / sizeof(wchar_t));
            g_nt.NtClose(hLink);
            return target;
        }
    }

    g_nt.NtClose(hLink);
    return L"<query failed: " + NtStatusHex(status) + L">";
}

// ═══════════════════════════════════════════════════════════════════════
//  目录遍历
// ═══════════════════════════════════════════════════════════════════════

// 枚举一个对象目录下的所有条目
// dirPath 必须以 '\' 开头,如 "\GLOBAL??" / "\Device"
// 对 SymbolicLink 条目自动解析其目标
//
// 实现说明:用 ReturnSingleEntry=TRUE 逐条读取,最稳。
//   - 每次调用返回 1 条 OBJECT_DIRECTORY_INFORMATION
//   - status == 0 (STATUS_SUCCESS):拿到一条,继续
//   - status == 0x8000001a (STATUS_NO_MORE_ENTRIES):遍历结束
//   - 其他:错误
static bool EnumDirectory(const std::wstring& dirPath, std::vector<NtDirEntry>& entries) {
    entries.clear();
    if (!g_nt.NtOpenDirectoryObject || !g_nt.NtQueryDirectoryObject) return false;

    UNICODE_STRING ustr;
    g_nt.RtlInitUnicodeString(&ustr, dirPath.c_str());

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    LONG status = g_nt.NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    if (status < 0) {
        WriteOut(L"[EnumDirectory] NtOpenDirectoryObject(" + dirPath +
                 L") 失败: " + NtStatusHex(status) + L"\n");
        return false;
    }

    // OBJECT_DIRECTORY_INFORMATION = { UNICODE_STRING Name; UNICODE_STRING TypeName; }
    std::vector<BYTE> buffer(4096);
    ULONG context = 0;
    bool firstCall = true;

    while (true) {
        ULONG returnLength = 0;
        status = g_nt.NtQueryDirectoryObject(
            hDir, buffer.data(), (ULONG)buffer.size(),
            TRUE /*ReturnSingleEntry*/, firstCall /*RestartScan*/,
            &context, &returnLength);

        if (status == 0) {
            BYTE* p = buffer.data();
            UNICODE_STRING* pName = (UNICODE_STRING*)p;
            UNICODE_STRING* pType = (UNICODE_STRING*)(p + sizeof(UNICODE_STRING));

            if (pName->Length == 0 || pName->Buffer == NULL) break;

            NtDirEntry e;
            e.name.assign(pName->Buffer, pName->Length / sizeof(wchar_t));
            if (pType->Length > 0 && pType->Buffer) {
                e.typeName.assign(pType->Buffer, pType->Length / sizeof(wchar_t));
            }

            if (_wcsicmp(e.typeName.c_str(), L"SymbolicLink") == 0) {
                std::wstring fullPath = dirPath;
                if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
                fullPath += e.name;
                e.linkTarget = QuerySymbolicLinkTarget(fullPath);
            }

            entries.push_back(std::move(e));
            firstCall = false;
            continue;
        }

        // STATUS_NO_MORE_ENTRIES = 0x8000001a(LONG 为负)
        // 某些 Windows 版本会用 0x105 (STATUS_NOTIFY_ENUM_DIR) 表示相同语义
        if (status == (LONG)0x8000001aL || status == 0x00000105) {
            break;
        }

        // STATUS_BUFFER_TOO_SMALL = 0xC0000023 — 扩容重试
        if (status == (LONG)0xC0000023L) {
            buffer.resize(buffer.size() * 2);
            continue;
        }

        WriteOut(L"[EnumDirectory] NtQueryDirectoryObject(" + dirPath +
                 L") 失败: " + NtStatusHex(status) + L"\n");
        break;
    }

    g_nt.NtClose(hDir);
    return !entries.empty();
}

// 把单条目录项格式化为一行输出
static std::wstring FormatDirEntry(const NtDirEntry& e, size_t nameWidth, size_t typeWidth) {
    std::wostringstream ss;
    ss << L"  " << std::left << std::setw((std::streamsize)nameWidth) << e.name
       << L" " << std::left << std::setw((std::streamsize)typeWidth) << e.typeName;
    if (!e.linkTarget.empty()) {
        ss << L"  -> " << e.linkTarget;
    }
    ss << L"\n";
    return ss.str();
}

// 扫描并打印一个目录,返回总条目数
// 对子目录可选择递归(限制深度避免无限递归)
// depth 是内部递归参数,对外不暴露
static size_t ScanAndPrintDirectoryImpl(const std::wstring& dirPath, int maxDepth, int depth) {
    std::vector<NtDirEntry> entries;
    if (!EnumDirectory(dirPath, entries)) {
        return 0;
    }

    // 计算列宽(最长名字 / 类型名),用于对齐
    size_t nameWidth = 4;  // "Name"
    size_t typeWidth = 4;  // "Type"
    for (const auto& e : entries) {
        if (e.name.size() > nameWidth) nameWidth = e.name.size();
        if (e.typeName.size() > typeWidth) typeWidth = e.typeName.size();
    }
    if (nameWidth > 60) nameWidth = 60;
    if (typeWidth > 20) typeWidth = 20;

    std::wostringstream title;
    title << L"\n━━━ " << dirPath << L" ━━━ (共 " << entries.size() << L" 项)\n";
    WriteOut(title.str());

    WriteOut(FormatDirEntry({L"Name", L"Type", L""}, nameWidth, typeWidth));
    WriteOut(FormatDirEntry({std::wstring(nameWidth, L'-'), std::wstring(typeWidth, L'-'), L""}, nameWidth, typeWidth));

    // 排序:SymbolicLink 优先(用户最关心),再按名字
    std::sort(entries.begin(), entries.end(), [](const NtDirEntry& a, const NtDirEntry& b) {
        bool aSym = _wcsicmp(a.typeName.c_str(), L"SymbolicLink") == 0;
        bool bSym = _wcsicmp(b.typeName.c_str(), L"SymbolicLink") == 0;
        if (aSym != bSym) return aSym;
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    for (const auto& e : entries) {
        WriteOut(FormatDirEntry(e, nameWidth, typeWidth));

        // 递归子目录(限制深度)
        if (depth < maxDepth &&
            _wcsicmp(e.typeName.c_str(), L"Directory") == 0 &&
            _wcsicmp(e.name.c_str(), L".") != 0 &&
            _wcsicmp(e.name.c_str(), L"..") != 0) {
            std::wstring sub = dirPath;
            if (sub.back() != L'\\') sub += L'\\';
            sub += e.name;
            ScanAndPrintDirectoryImpl(sub, maxDepth, depth + 1);
        }
    }

    return entries.size();
}

// 对外的入口:从根目录开始扫
size_t ScanAndPrintDirectory(const std::wstring& dirPath, int maxDepth) {
    return ScanAndPrintDirectoryImpl(dirPath, maxDepth, 0);
}

// ═══════════════════════════════════════════════════════════════════════
//  主入口
// ═══════════════════════════════════════════════════════════════════════

int ScanObjectNamespaces(const std::vector<std::wstring>& dirs) {
    if (!InitNtApi()) {
        WriteOut(L"初始化 NTAPI 失败:无法加载 ntdll.dll 中的函数\n");
        return 1;
    }

    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  对象管理器命名空间扫描(NTAPI 直查,无需驱动)\n");
    WriteOut(L"  用途:识别暴露符号链接的第三方 WHQL 驱动 → 附着候选\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");

    size_t total = 0;
    for (const auto& dir : dirs) {
        total += ScanAndPrintDirectory(dir);
    }

    WriteOut(L"\n═══════════════════════════════════════════════════════\n");
    WriteOut(L"扫描完成,共 " + std::to_wstring(total) + L" 个对象\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    return 0;
}

} // namespace das
