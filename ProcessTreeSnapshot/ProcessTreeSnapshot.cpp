// ProcessTreeSnapshot.cpp
//
// 进程树快照 + 安全采集工具。
//
// 两种工作模式:
//
// 1. 树形打印(默认):
//    ProcessTreeSnapshot.exe                  打印整棵进程树
//    ProcessTreeSnapshot.exe --pid 1234       只打印指定进程的子树
//    ProcessTreeSnapshot.exe --depth 3        限制树深度
//    ProcessTreeSnapshot.exe --json           扁平 JSON(基础信息)
//
// 2. 安全采集模式(--security):
//    采集每个进程的完整安全上下文,输出 JSON 供 Server 端分析。
//    ProcessTreeSnapshot.exe --security                       全系统采集
//    ProcessTreeSnapshot.exe --security --pid 1234            只采集指定进程
//    ProcessTreeSnapshot.exe --security --no-handles          跳过句柄扫描
//    ProcessTreeSnapshot.exe --security --no-mem              跳过内存扫描
//    ProcessTreeSnapshot.exe --security --no-threads          跳过线程采集
//    ProcessTreeSnapshot.exe --security --no-modules          跳过模块采集
//    ProcessTreeSnapshot.exe --security --no-token            跳过 Token/Protection
//    ProcessTreeSnapshot.exe --security --handles-target PID  句柄扫描只看指向 PID 的句柄
//
// 采集维度:
//   进程: PID/PPID/名称/完整路径/命令行/创建时间/Token特权/PPL保护级别
//   线程: TID/StartAddress/Win32StartAddress/SuspendCount/状态/起始地址所属模块
//   模块: 基址/大小/路径(PEB Ldr 链,合法模块)
//   内存: RWX 区域 / RX-unbacked 区域(无文件映射的可执行内存)
//   句柄: 全系统扫指向目标 PID 的强权限句柄(VM_READ/VM_WRITE/CREATE_THREAD)
//
// 参考: https://www.cnblogs.com/priarieNew/p/9756157.html (NtQuerySystemInformation)
//
// 需要管理员权限运行,否则跨进程查询会大量失败。

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <set>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")

// ───────────────────────────────────────────────────────────────
//  ntdll 未文档化 API 常量
// ───────────────────────────────────────────────────────────────
#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif
#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif
#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation 0x3D
#endif
#ifndef ThreadBasicInformation
#define ThreadBasicInformation 0
#endif
#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// ───────────────────────────────────────────────────────────────
//  ntdll 函数指针类型
// ───────────────────────────────────────────────────────────────
typedef NTSTATUS (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *PFN_NtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *PFN_NtQueryObject)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

// 全局 ntdll 函数指针(InitNtdll 初始化)
static PFN_NtQuerySystemInformation      g_NtQuerySystemInformation = nullptr;
static PFN_NtQueryInformationProcess     g_NtQueryInformationProcess = nullptr;
static PFN_NtQueryInformationThread      g_NtQueryInformationThread = nullptr;
static PFN_NtQueryObject                 g_NtQueryObject = nullptr;

static bool InitNtdll()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    g_NtQuerySystemInformation      = (PFN_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_NtQueryInformationProcess     = (PFN_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    g_NtQueryInformationThread      = (PFN_NtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    g_NtQueryObject                 = (PFN_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    return g_NtQuerySystemInformation && g_NtQueryInformationProcess
        && g_NtQueryInformationThread && g_NtQueryObject;
}

// ───────────────────────────────────────────────────────────────
//  未文档化结构体定义
// ───────────────────────────────────────────────────────────────

// SYSTEM_PROCESS_INFORMATION (phnt 完整定义)
// 关键: HardFaultCount / NumberOfThreadsHighWatermark 是 ULONG(4字节),
//       不是 LARGE_INTEGER(8字节),写错会导致后续字段偏移错位崩溃。
//
// 注意: 结构末尾紧跟 NumberOfThreads 个 SYSTEM_THREAD_INFORMATION,
//       这是 NtQuerySystemInformation 原生返回的线程数据,无需再调
//       CreateToolhelp32Snapshot(后者每次都会全系统扫,巨慢)。
typedef struct _SYSTEM_THREAD_INFORMATION_FULL {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_FULL, *PSYSTEM_THREAD_INFORMATION_FULL;

typedef struct _SYSTEM_PROCESS_INFORMATION_FULL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    // 末尾紧跟 NumberOfThreads 个 SYSTEM_THREAD_INFORMATION_FULL
} SYSTEM_PROCESS_INFORMATION_FULL, *PSYSTEM_PROCESS_INFORMATION_FULL;

// PROCESS_BASIC_INFORMATION (已声明但确保可用)
typedef struct _MY_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} MY_PROCESS_BASIC_INFORMATION;

// PS_PROTECTION (PPL 保护级别)
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;  // 0=None, 1=Protected, 2=ProtectedLight
            UCHAR Audit  : 1;
            UCHAR Signer : 4;  // 0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware, 4=Lsa, 5=Windows, 6=WinTcb
        };
    };
} PS_PROTECTION;

// THREAD_BASIC_INFORMATION
typedef struct _MY_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} MY_THREAD_BASIC_INFORMATION;

// SYSTEM_HANDLE_INFORMATION_EX (SystemExtendedHandleInformation)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

// ───────────────────────────────────────────────────────────────
//  辅助函数
// ───────────────────────────────────────────────────────────────

static std::string WToU8(const wchar_t* w)
{
    if (!w || !*w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}
static std::string WToU8(const std::wstring& w) { return WToU8(w.c_str()); }

static std::wstring U8ToW(const std::string& s)
{
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

static std::string FormatTime(const LARGE_INTEGER& ft)
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

static std::string HexAddr(ULONG_PTR addr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    return buf;
}

static std::string JsonEscape(const std::string& s)
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
// ───────────────────────────────────────────────────────────────
static std::string ProtectionToString(const PS_PROTECTION& p)
{
    if (p.Level == 0) return "None";
    const char* typeStr = "Unknown";
    switch (p.Type)
    {
    case 0: typeStr = "None"; break;
    case 1: typeStr = "Protected"; break;
    case 2: typeStr = "ProtectedLight"; break;
    }
    const char* signerStr = "Unknown";
    switch (p.Signer)
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
    snprintf(buf, sizeof(buf), "%s-%s (Level=0x%02x)", typeStr, signerStr, p.Level);
    return buf;
}

// ───────────────────────────────────────────────────────────────
//  内存保护属性字符串化
// ───────────────────────────────────────────────────────────────
static std::string ProtectToStr(DWORD prot)
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

static std::string MemTypeToStr(DWORD type)
{
    std::string s;
    if (type & MEM_IMAGE)    s += "Image|";
    if (type & MEM_MAPPED)   s += "Mapped|";
    if (type & MEM_PRIVATE)  s += "Private|";
    if (s.empty()) return "0x" + HexAddr(type);
    if (s.back() == '|') s.pop_back();
    return s;
}

// ───────────────────────────────────────────────────────────────
//  数据结构定义
// ───────────────────────────────────────────────────────────────

struct ProcBrief {
    ULONG_PTR pid = 0;
    ULONG_PTR ppid = 0;
    std::string name;          // UTF-8,Image 名(如 "explorer.exe")
    ULONG threads = 0;
    LARGE_INTEGER createTime{};
    ULONG session = 0;
    SIZE_T workingSet = 0;
    SIZE_T privatePages = 0;
    ULONG handles = 0;
    LONG basePriority = 0;

    // 线程列表(从 NtQuerySystemInformation 原生拿到,避免每进程调一次
    // CreateToolhelp32Snapshot — 后者每次全系统扫,200 进程 = 200 次全扫)
    struct BriefThread {
        ULONG_PTR tid = 0;
        ULONG_PTR startAddress = 0;   // 内核态记录的 StartAddress
    };
    std::vector<BriefThread> threadList;
};

struct ThreadInfo {
    ULONG_PTR tid = 0;
    ULONG_PTR startAddress = 0;       // NtQueryInformationThread(ThreadBasicInformation)
    ULONG_PTR win32StartAddress = 0;  // NtQueryInformationThread(ThreadQuerySetWin32StartAddress)
    LONG suspendCount = 0;
    std::string startModule;          // StartAddress 所属模块(空 = 匿名内存,可疑)
    bool isSuspended = false;
};

struct ModuleInfo {
    ULONG_PTR base = 0;
    DWORD size = 0;
    std::string name;
    std::string path;
};

struct MemRegion {
    ULONG_PTR base = 0;
    SIZE_T size = 0;
    DWORD protect = 0;
    DWORD type = 0;
    std::string protectStr;
    std::string typeStr;
    std::string reason;  // "RWX" / "RX-unbacked"
};

struct HandleEntry {
    ULONG_PTR ownerPid = 0;
    std::string ownerName;
    ULONG_PTR handleValue = 0;
    ULONG grantedAccess = 0;
    std::string accessStr;
    ULONG_PTR targetPid = 0;
    std::string typeName;
    bool highRisk = false;  // 含 VM_READ/VM_WRITE/CREATE_THREAD
};

struct ProcDetail {
    ProcBrief brief;
    std::string imagePath;             // 完整路径
    std::string commandLine;           // 命令行
    std::vector<std::string> enabledPrivs;   // 启用中的特权
    std::vector<std::string> disabledPrivs;  // 禁用中的特权(只关注高危的)
    std::string protection;            // PPL 保护级别字符串
    bool pplBroken = false;            // Protection == None 但本来应该有保护

    std::vector<ThreadInfo> threads;
    std::vector<ModuleInfo> modules;
    std::vector<MemRegion> suspiciousMem;
    std::vector<HandleEntry> handles;  // 指向本进程的强权限句柄
};

// ───────────────────────────────────────────────────────────────
//  进程枚举(NtQuerySystemInformation)
// ───────────────────────────────────────────────────────────────
static bool EnumProcessesBrief(std::vector<ProcBrief>& out)
{
    if (!g_NtQuerySystemInformation) return false;
    ULONG bufSize = 0x40000;
    std::vector<BYTE> buf(bufSize);
    ULONG retLen = 0;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    for (int retry = 0; retry < 10; ++retry)
    {
        status = g_NtQuerySystemInformation(SystemProcessInformation, buf.data(), bufSize, &retLen);
        if (status == 0) break;
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            bufSize *= 2;
            if (bufSize > 0x2000000) return false;
            buf.resize(bufSize);
            continue;
        }
        return false;
    }
    if (status != 0) return false;

    out.clear();
    auto p = (PSYSTEM_PROCESS_INFORMATION_FULL)buf.data();
    while (true)
    {
        ProcBrief b;
        b.pid = (ULONG_PTR)p->UniqueProcessId;
        b.ppid = (ULONG_PTR)p->InheritedFromUniqueProcessId;
        b.threads = p->NumberOfThreads;
        b.createTime = p->CreateTime;
        b.session = p->SessionId;
        b.workingSet = p->WorkingSetSize;
        b.privatePages = p->PrivatePageCount;
        b.handles = p->HandleCount;
        b.basePriority = p->BasePriority;
        if (p->ImageName.Buffer && p->ImageName.Length > 0)
        {
            std::wstring w(p->ImageName.Buffer, p->ImageName.Length / sizeof(WCHAR));
            b.name = WToU8(w);
        }
        else
        {
            b.name = (b.pid == 0) ? "(Idle)" : "(Unknown)";
        }

        // 紧跟在 SYSTEM_PROCESS_INFORMATION_FULL 后面的是 NumberOfThreads 个
        // SYSTEM_THREAD_INFORMATION_FULL,直接读出来,免去每进程调一次
        // CreateToolhelp32Snapshot(那玩意每次全系统扫,200 进程循环 200 次 = 慢爆)
        if (p->NumberOfThreads > 0)
        {
            auto pThreads = (SYSTEM_THREAD_INFORMATION_FULL*)((BYTE*)p + sizeof(SYSTEM_PROCESS_INFORMATION_FULL));
            b.threadList.reserve(p->NumberOfThreads);
            for (ULONG i = 0; i < p->NumberOfThreads; ++i)
            {
                ProcBrief::BriefThread bt;
                bt.tid = (ULONG_PTR)pThreads[i].ClientId.UniqueThread;
                bt.startAddress = (ULONG_PTR)pThreads[i].StartAddress;
                b.threadList.push_back(bt);
            }
        }

        out.push_back(std::move(b));
        if (p->NextEntryOffset == 0) break;
        p = (PSYSTEM_PROCESS_INFORMATION_FULL)((BYTE*)p + p->NextEntryOffset);
    }
    return true;
}

// ───────────────────────────────────────────────────────────────
//  进程详情采集
// ───────────────────────────────────────────────────────────────

// 采集完整路径 + 命令行 + Token 特权 + PPL 保护级别
static void CollectProcessDetails(HANDLE hProc, ProcDetail& d)
{
    // ── 完整路径 ──
    WCHAR pathBuf[MAX_PATH] = {0};
    DWORD pathLen = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathLen))
    {
        d.imagePath = WToU8(pathBuf);
    }

    // ── 命令行(读 PEB → ProcessParameters → CommandLine)──
    // x64 偏移:PEB+0x20 = ProcessParameters,Params+0x70 = CommandLine(UNICODE_STRING)
    // x86 偏移:PEB+0x10 = ProcessParameters,Params+0x40 = CommandLine
    if (g_NtQueryInformationProcess)
    {
        MY_PROCESS_BASIC_INFORMATION pbi = {};
        ULONG retLen = 0;
        if (g_NtQueryInformationProcess(hProc, ProcessBasicInformation,
            &pbi, sizeof(pbi), &retLen) == 0 && pbi.PebBaseAddress)
        {
#ifdef _WIN64
            const ULONG_PTR offParams = 0x20;
            const ULONG_PTR offCmdLine = 0x70;
#else
            const ULONG_PTR offParams = 0x10;
            const ULONG_PTR offCmdLine = 0x40;
#endif
            ULONG_PTR paramsAddr = 0;
            if (ReadProcessMemory(hProc, (LPCVOID)((ULONG_PTR)pbi.PebBaseAddress + offParams),
                &paramsAddr, sizeof(paramsAddr), nullptr) && paramsAddr)
            {
                UNICODE_STRING cmdLine = {};
                if (ReadProcessMemory(hProc, (LPCVOID)(paramsAddr + offCmdLine),
                    &cmdLine, sizeof(cmdLine), nullptr) && cmdLine.Buffer && cmdLine.Length > 0)
                {
                    std::wstring wcmd(cmdLine.Length / sizeof(WCHAR), L'\0');
                    if (ReadProcessMemory(hProc, cmdLine.Buffer, wcmd.data(), cmdLine.Length, nullptr))
                    {
                        d.commandLine = WToU8(wcmd);
                    }
                }
            }
        }
    }

    // ── Token Privileges ──
    HANDLE hToken = nullptr;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        DWORD retLen = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &retLen);
        if (retLen > 0)
        {
            std::vector<BYTE> tokBuf(retLen);
            if (GetTokenInformation(hToken, TokenPrivileges, tokBuf.data(), retLen, &retLen))
            {
                auto privs = (TOKEN_PRIVILEGES*)tokBuf.data();
                for (DWORD i = 0; i < privs->PrivilegeCount; ++i)
                {
                    LUID luid = privs->Privileges[i].Luid;
                    DWORD attr = privs->Privileges[i].Attributes;
                    bool enabled = (attr & SE_PRIVILEGE_ENABLED) != 0;
                    WCHAR nameBuf[256] = {0};
                    DWORD nameLen = 256;
                    if (LookupPrivilegeNameW(nullptr, &luid, nameBuf, &nameLen))
                    {
                        std::string name = WToU8(nameBuf);
                        // 只记录高危特权:SeDebug / SeLoadDriver / SeAssignPrimaryToken / SeTcb / SeCreateToken
                        if (name.find("SeDebug") != std::string::npos ||
                            name.find("SeLoadDriver") != std::string::npos ||
                            name.find("SeAssignPrimaryToken") != std::string::npos ||
                            name.find("SeTcb") != std::string::npos ||
                            name.find("SeCreateToken") != std::string::npos ||
                            name.find("SeBackup") != std::string::npos ||
                            name.find("SeRestore") != std::string::npos)
                        {
                            if (enabled) d.enabledPrivs.push_back(name);
                            else d.disabledPrivs.push_back(name);
                        }
                    }
                }
            }
        }
        CloseHandle(hToken);
    }

    // ── PPL Protection Level ──
    if (g_NtQueryInformationProcess)
    {
        PS_PROTECTION prot = {};
        ULONG retLen = 0;
        if (g_NtQueryInformationProcess(hProc, ProcessProtectionInformation,
            &prot, sizeof(prot), &retLen) == 0)
        {
            d.protection = ProtectionToString(prot);
            // 判断"应该有保护但实际没有"的关键场景由 Server 端比对白名单
            // 这里只如实上报 Level
        }
        else
        {
            d.protection = "QueryFailed";
        }
    }
}

// ───────────────────────────────────────────────────────────────
//  线程采集
//  直接用 EnumProcessesBrief 已经从 NtQuerySystemInformation 拿到的线程列表,
//  不再调 CreateToolhelp32Snapshot(后者每次全系统扫,200 进程循环 200 次极慢)。
//  内核 StartAddress 已经有了,这里只需补 Win32 StartAddress(抓 shellcode 注入的关键)。
// ───────────────────────────────────────────────────────────────
static void CollectThreads(const ProcBrief& brief, HANDLE hProc,
                           const std::vector<ModuleInfo>& modules,
                           ProcDetail& d)
{
    d.threads.reserve(brief.threadList.size());
    for (const auto& bt : brief.threadList)
    {
        ThreadInfo t;
        t.tid = bt.tid;
        t.startAddress = bt.startAddress;  // 内核态记录的 StartAddress

        // 打开线程拿 Win32 StartAddress(抓 manual map shellcode 的关键字段)
        // ThreadQuerySetWin32StartAddress 需要 THREAD_QUERY_INFORMATION (0x40),
        // LIMITED 不够,先试两个权限组合再降级
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            FALSE, (DWORD)bt.tid);
        if (!hThread)
        {
            hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)bt.tid);
        }
        if (hThread && g_NtQueryInformationThread)
        {
            ULONG_PTR win32Start = 0;
            ULONG retLen = 0;
            if (g_NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
                &win32Start, sizeof(win32Start), &retLen) == 0)
            {
                t.win32StartAddress = win32Start;
            }
            CloseHandle(hThread);
        }

        // 判断 StartAddress 所属模块(基于已采集的模块表)
        // 优先用 Win32 StartAddress(应用层入口),没有就用内核 StartAddress
        ULONG_PTR checkAddr = t.win32StartAddress ? t.win32StartAddress : t.startAddress;
        if (checkAddr && !modules.empty())
        {
            for (const auto& m : modules)
            {
                if (checkAddr >= m.base && checkAddr < m.base + m.size)
                {
                    t.startModule = m.name;
                    break;
                }
            }
            // 没匹配到任何模块 → 匿名内存中的 shellcode,Server 端告警
        }

        d.threads.push_back(std::move(t));
    }
}

// ───────────────────────────────────────────────────────────────
//  模块采集
// ───────────────────────────────────────────────────────────────
static void CollectModules(HANDLE hProc, ProcDetail& d)
{
    // EnumProcessModulesEx + GetModuleFileNameExW(走 PEB Ldr 链)
    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        DWORD count = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i)
        {
            ModuleInfo m;
            MODULEINFO mi = {};
            if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi)))
            {
                m.base = (ULONG_PTR)mi.lpBaseOfDll;
                m.size = mi.SizeOfImage;
            }
            WCHAR nameBuf[MAX_PATH] = {0};
            if (GetModuleBaseNameW(hProc, hMods[i], nameBuf, MAX_PATH))
            {
                m.name = WToU8(nameBuf);
            }
            WCHAR pathBuf[MAX_PATH] = {0};
            if (GetModuleFileNameExW(hProc, hMods[i], pathBuf, MAX_PATH))
            {
                m.path = WToU8(pathBuf);
            }
            d.modules.push_back(std::move(m));
        }
    }
}

// ───────────────────────────────────────────────────────────────
//  可疑内存扫描
// ───────────────────────────────────────────────────────────────
static void CollectSuspiciousMemory(HANDLE hProc,
                                    const std::vector<ModuleInfo>& modules,
                                    ProcDetail& d)
{
    // 遍历整个地址空间,找:
    // 1. PAGE_EXECUTE_READWRITE (RWX) — 极可疑
    // 2. PAGE_EXECUTE_READ (RX) 且 Type != MEM_IMAGE — unbacked 可执行内存
    // 3. PAGE_EXECUTE (X) 且 Type != MEM_IMAGE — 同上
    // 跳过:
    //   - State != MEM_COMMIT 的(未提交)
    //   - 太小的区域(< 4KB,可能是 page header)
    //   - MEM_IMAGE 区域(合法 EXE/DLL 映射,有数字签名)
    //
    // 注意:为了不无限扫描,只扫 0x10000 ~ 0x7FFFFFFFFFFF(x64 用户态范围)
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0x10000;
    const ULONG_PTR maxAddr = 0x7FFFFFFFFFFFULL;

    while (addr < maxAddr)
    {
        if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.RegionSize < 0x1000) continue;

        DWORD prot = mbi.Protect;
        DWORD type = mbi.Type;
        bool isRWX = (prot & PAGE_EXECUTE_READWRITE) != 0;
        bool isExecUnbacked = ((prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ)) != 0) && (type & MEM_IMAGE) == 0;

        if (!isRWX && !isExecUnbacked) continue;

        MemRegion r;
        r.base = (ULONG_PTR)mbi.BaseAddress;
        r.size = mbi.RegionSize;
        r.protect = prot;
        r.type = type;
        r.protectStr = ProtectToStr(prot);
        r.typeStr = MemTypeToStr(type);
        r.reason = isRWX ? "RWX" : "RX-unbacked";

        // 对 RX-unbacked 检查是否落在已知模块内(有些合法 JIT 也会分配 RX)
        // 如果落在已知模块范围内,跳过(已经是模块的子集)
        if (isExecUnbacked && !modules.empty())
        {
            bool inModule = false;
            for (const auto& m : modules)
            {
                if (r.base >= m.base && r.base < m.base + m.size)
                {
                    inModule = true;
                    break;
                }
            }
            if (inModule) continue;
        }

        d.suspiciousMem.push_back(std::move(r));

        // 限制每个进程最多记录 256 个可疑区域,防止恶意进程撑爆 JSON
        if (d.suspiciousMem.size() >= 256) break;
    }
}

// ───────────────────────────────────────────────────────────────
//  句柄表扫描
// ───────────────────────────────────────────────────────────────

// 句柄访问掩码字符串化(只关注高危权限)
static std::string HandleAccessToStr(ULONG access, bool& highRisk)
{
    std::string s;
    // PROCESS 权限
    if (access & 0x0010) { s += "VM_READ|"; highRisk = true; }     // PROCESS_VM_READ
    if (access & 0x0020) { s += "VM_WRITE|"; highRisk = true; }    // PROCESS_VM_WRITE
    if (access & 0x0002) { s += "CREATE_THREAD|"; highRisk = true; } // PROCESS_CREATE_THREAD
    if (access & 0x0040) { s += "DUP_HANDLE|"; highRisk = true; }  // PROCESS_DUP_HANDLE
    if (access & 0x0008) { s += "VM_OP|"; highRisk = true; }       // PROCESS_VM_OPERATION
    if (access & 0x0400) { s += "QUERY_INFO|"; }
    if (access & 0x0800) { s += "SET_INFO|"; }
    if (access & 0x0100) { s += "TERMINATE|"; }
    if (access & 0x0001) { s += "ALL_ACCESS|"; highRisk = true; }
    if (s.empty())
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%08x", access);
        return buf;
    }
    if (s.back() == '|') s.pop_back();
    return s;
}

// 全系统句柄扫描,过滤指向 targetPid 的强权限句柄
// targetPid == 0 表示扫所有进程的所有句柄(数据量大,慎用)
//
// 性能关键优化:
//   系统通常有 10~30 万个句柄,其中 Process 类型只占很小一部分。
//   原版对每个句柄都做 DuplicateHandle + NtQueryObject 查类型,CPU 直接吃满。
//   优化:利用 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 里的 ObjectTypeIndex 字段,
//   先用自己进程的一个已知 Process 句柄,在表里反查出 "Process" 类型的 Index,
//   之后遍历时直接 `if (h.ObjectTypeIndex != procTypeIdx) continue;`
//   在用户态无锁过滤 99% 的非 Process 句柄,绝不进内核。
static void CollectHandles(ULONG_PTR targetPid,
                           const std::unordered_map<ULONG_PTR, std::wstring>& pidToName,
                           std::vector<HandleEntry>& out)
{
    if (!g_NtQuerySystemInformation) return;

    // 拿句柄表(可能很大,翻倍重试)
    ULONG bufSize = 0x100000;  // 1MB 起步
    std::vector<BYTE> buf(bufSize);
    ULONG retLen = 0;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    for (int retry = 0; retry < 8; ++retry)
    {
        status = g_NtQuerySystemInformation(SystemExtendedHandleInformation,
            buf.data(), bufSize, &retLen);
        if (status == 0) break;
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            bufSize *= 2;
            if (bufSize > 0x20000000) return;  // 512MB 上限
            buf.resize(bufSize);
            continue;
        }
        return;
    }
    if (status != 0) return;

    auto info = (SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
    ULONG_PTR count = info->NumberOfHandles;

    // ── 性能优化核心:动态获取 "Process" 对象的 ObjectTypeIndex ──
    // 每次开机 ObjectTypeIndex 是固定的(不同机器/版本可能不同),所以运行时查一次即可。
    // 方法:打开自己进程拿一个 Process 句柄,在句柄表里找到它,读它的 ObjectTypeIndex。
    USHORT procTypeIdx = 0;
    HANDLE hSelf = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    if (hSelf)
    {
        ULONG_PTR selfPid = GetCurrentProcessId();
        ULONG_PTR selfHandleVal = (ULONG_PTR)hSelf;
        for (ULONG_PTR i = 0; i < count; ++i)
        {
            const auto& h = info->Handles[i];
            if (h.UniqueProcessId == selfPid && h.HandleValue == selfHandleVal)
            {
                procTypeIdx = h.ObjectTypeIndex;
                break;
            }
        }
        CloseHandle(hSelf);
    }

    // 遍历每个句柄
    for (ULONG_PTR i = 0; i < count; ++i)
    {
        const auto& h = info->Handles[i];

        // 【优化核心 2】:不是 Process 类型的句柄,直接在用户态抛弃,绝不进内核!
        // 这一过滤砍掉 99% 的 File/Event/Key/Mutant 等无关句柄
        if (procTypeIdx != 0 && h.ObjectTypeIndex != procTypeIdx) continue;

        ULONG_PTR ownerPid = h.UniqueProcessId;

        // 性能优化:如果指定了 targetPid,跳过 ownerPid == targetPid 的句柄(自己引用自己)
        if (targetPid != 0 && ownerPid == targetPid) continue;

        // 从 owner 进程复制句柄到当前进程
        // 需要 owner 进程的 PROCESS_DUP_HANDLE 权限
        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)ownerPid);
        if (!hOwner) continue;

        HANDLE hDup = nullptr;
        if (!DuplicateHandle(hOwner, (HANDLE)h.HandleValue,
            GetCurrentProcess(), &hDup,
            0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            CloseHandle(hOwner);
            continue;
        }
        CloseHandle(hOwner);

        // 拿句柄指向的目标 PID(GetProcessId 极快,远比 NtQueryObject 轻)
        DWORD targetPidForHandle = GetProcessId(hDup);
        CloseHandle(hDup);

        if (targetPidForHandle == 0) continue;

        // 如果指定了 targetPid,只保留指向它的句柄
        if (targetPid != 0 && (ULONG_PTR)targetPidForHandle != targetPid) continue;

        HandleEntry he;
        he.ownerPid = ownerPid;
        he.handleValue = h.HandleValue;
        he.grantedAccess = h.GrantedAccess;
        he.targetPid = targetPidForHandle;
        he.typeName = "Process";  // 已通过 ObjectTypeIndex 过滤,无需再查
        he.accessStr = HandleAccessToStr(h.GrantedAccess, he.highRisk);

        // owner 进程名
        auto it = pidToName.find(ownerPid);
        if (it != pidToName.end())
            he.ownerName = WToU8(it->second);

        out.push_back(std::move(he));
    }
}

// ───────────────────────────────────────────────────────────────
//  树形打印(基础模式,保留)
// ───────────────────────────────────────────────────────────────
struct TreeCtx {
    const std::unordered_map<ULONG_PTR, std::vector<ULONG_PTR>>& children;
    const std::unordered_map<ULONG_PTR, ProcBrief>& byPid;
    int maxDepth;
};

static void PrintNode(const TreeCtx& ctx, ULONG_PTR pid,
                      const std::string& indent, bool isLast,
                      bool isRoot, int depth)
{
    auto itP = ctx.byPid.find(pid);
    if (itP == ctx.byPid.end()) return;
    const auto& info = itP->second;

    const char* branch = isRoot ? "" : (isLast ? "└── " : "├── ");

    std::printf("%s%s%lu %s  [ppid=%lu, t=%u, h=%u, ws=%llu KB, priv=%llu KB, prio=%ld, %s]\n",
        indent.c_str(), branch,
        (unsigned long)info.pid, info.name.c_str(),
        (unsigned long)info.ppid,
        info.threads,
        info.handles,
        (unsigned long long)info.workingSet / 1024,
        (unsigned long long)info.privatePages / 1024,
        info.basePriority,
        FormatTime(info.createTime).c_str());

    if (ctx.maxDepth > 0 && depth >= ctx.maxDepth)
    {
        auto itC = ctx.children.find(pid);
        if (itC != ctx.children.end() && !itC->second.empty())
        {
            std::string ellipsisIndent = indent + (isLast ? "    " : "│   ");
            std::printf("%s└── ... (%zu 个子进程)\n",
                ellipsisIndent.c_str(), itC->second.size());
        }
        return;
    }

    auto itC = ctx.children.find(pid);
    if (itC == ctx.children.end()) return;
    const auto& kids = itC->second;

    std::string childIndent = isRoot ? "" : indent + (isLast ? "    " : "│   ");

    for (size_t i = 0; i < kids.size(); ++i)
    {
        bool last = (i + 1 == kids.size());
        PrintNode(ctx, kids[i], childIndent, last, false, depth + 1);
    }
}

static int RunTreeMode(ULONG_PTR pidFilter, int maxDepth, bool jsonOut)
{
    std::vector<ProcBrief> procs;
    if (!EnumProcessesBrief(procs))
    {
        std::fprintf(stderr, "[错误] NtQuerySystemInformation 调用失败\n");
        return 1;
    }

    if (jsonOut)
    {
        std::printf("{\n");
        std::printf("  \"count\": %zu,\n", procs.size());
        LARGE_INTEGER now;
        GetSystemTimeAsFileTime((FILETIME*)&now);
        std::printf("  \"fetched_at\": \"%s\",\n", FormatTime(now).c_str());
        std::printf("  \"processes\": [\n");
        for (size_t i = 0; i < procs.size(); ++i)
        {
            const auto& p = procs[i];
            std::printf("    {\"pid\": %lu, \"ppid\": %lu, \"name\": \"%s\", \"threads\": %u, \"handles\": %u, \"session\": %u, \"working_set_kb\": %llu, \"private_kb\": %llu, \"create_time\": \"%s\"}%s\n",
                (unsigned long)p.pid, (unsigned long)p.ppid,
                JsonEscape(p.name).c_str(),
                p.threads, p.handles, p.session,
                (unsigned long long)p.workingSet / 1024,
                (unsigned long long)p.privatePages / 1024,
                FormatTime(p.createTime).c_str(),
                (i + 1 < procs.size()) ? "," : "");
        }
        std::printf("  ]\n}\n");
        return 0;
    }

    std::unordered_map<ULONG_PTR, ProcBrief> byPid;
    std::unordered_map<ULONG_PTR, std::vector<ULONG_PTR>> children;
    byPid.reserve(procs.size());
    children.reserve(procs.size());
    for (const auto& p : procs)
    {
        byPid[p.pid] = p;
        if (p.ppid != p.pid)
            children[p.ppid].push_back(p.pid);
    }
    for (auto& kv : children)
        std::sort(kv.second.begin(), kv.second.end());

    ULONG totalThreads = 0;
    SIZE_T totalWs = 0;
    for (const auto& p : procs) { totalThreads += p.threads; totalWs += p.workingSet; }
    std::printf("进程树快照: 共 %zu 个进程, %lu 个线程, 总工作集 %llu KB\n",
        procs.size(), totalThreads, (unsigned long long)totalWs / 1024);
    std::printf("────────────────────────────────────────────────────────────────\n\n");

    TreeCtx ctx{ children, byPid, maxDepth };

    if (pidFilter != 0)
    {
        if (byPid.find(pidFilter) == byPid.end())
        {
            std::fprintf(stderr, "[错误] PID %lu 不存在\n", (unsigned long)pidFilter);
            return 1;
        }
        PrintNode(ctx, pidFilter, "", true, true, 1);
    }
    else
    {
        std::vector<ULONG_PTR> roots;
        for (const auto& p : procs)
        {
            if (p.pid == 0) roots.insert(roots.begin(), 0);
            else if (p.pid != 0 && byPid.find(p.ppid) == byPid.end())
                roots.push_back(p.pid);
        }
        std::sort(roots.begin(), roots.end());
        roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
        for (size_t i = 0; i < roots.size(); ++i)
        {
            PrintNode(ctx, roots[i], "", true, true, 1);
            if (i + 1 < roots.size()) std::printf("\n");
        }
    }
    return 0;
}

// ───────────────────────────────────────────────────────────────
//  安全采集模式 JSON 输出
// ───────────────────────────────────────────────────────────────

struct SecurityArgs {
    ULONG_PTR pid = 0;          // 0 = 全系统
    bool hasPid = false;
    bool noHandles = false;
    bool noMem = false;
    bool noThreads = false;
    bool noModules = false;
    bool noToken = false;
    ULONG_PTR handlesTarget = 0; // 句柄扫描目标 PID(0 = 用 pid 或全系统)
};

static void PrintSecurityJson(const std::vector<ProcDetail>& details,
                              const std::vector<HandleEntry>& handles,
                              const SecurityArgs& args)
{
    LARGE_INTEGER now;
    GetSystemTimeAsFileTime((FILETIME*)&now);
    std::printf("{\n");
    std::printf("  \"mode\": \"security\",\n");
    std::printf("  \"fetched_at\": \"%s\",\n", FormatTime(now).c_str());
    std::printf("  \"process_count\": %zu,\n", details.size());
    std::printf("  \"handle_count\": %zu,\n", handles.size());
    std::printf("  \"processes\": [\n");

    for (size_t i = 0; i < details.size(); ++i)
    {
        const auto& d = details[i];
        const auto& b = d.brief;
        std::printf("    {\n");
        std::printf("      \"pid\": %lu,\n", (unsigned long)b.pid);
        std::printf("      \"ppid\": %lu,\n", (unsigned long)b.ppid);
        std::printf("      \"name\": \"%s\",\n", JsonEscape(b.name).c_str());
        std::printf("      \"image_path\": \"%s\",\n", JsonEscape(d.imagePath).c_str());
        std::printf("      \"command_line\": \"%s\",\n", JsonEscape(d.commandLine).c_str());
        std::printf("      \"threads_count\": %u,\n", b.threads);
        std::printf("      \"handles_count\": %u,\n", b.handles);
        std::printf("      \"session\": %u,\n", b.session);
        std::printf("      \"working_set_kb\": %llu,\n", (unsigned long long)b.workingSet / 1024);
        std::printf("      \"private_kb\": %llu,\n", (unsigned long long)b.privatePages / 1024);
        std::printf("      \"base_priority\": %ld,\n", b.basePriority);
        std::printf("      \"create_time\": \"%s\",\n", FormatTime(b.createTime).c_str());
        std::printf("      \"protection\": \"%s\",\n", JsonEscape(d.protection).c_str());

        // Token 特权
        std::printf("      \"enabled_high_risk_privileges\": [");
        for (size_t j = 0; j < d.enabledPrivs.size(); ++j)
        {
            std::printf("\"%s\"%s", d.enabledPrivs[j].c_str(),
                (j + 1 < d.enabledPrivs.size()) ? ", " : "");
        }
        std::printf("],\n");

        std::printf("      \"disabled_high_risk_privileges\": [");
        for (size_t j = 0; j < d.disabledPrivs.size(); ++j)
        {
            std::printf("\"%s\"%s", d.disabledPrivs[j].c_str(),
                (j + 1 < d.disabledPrivs.size()) ? ", " : "");
        }
        std::printf("],\n");

        // 线程
        if (!args.noThreads && !d.threads.empty())
        {
            std::printf("      \"threads\": [\n");
            for (size_t j = 0; j < d.threads.size(); ++j)
            {
                const auto& t = d.threads[j];
                std::printf("        {\"tid\": %lu, \"start_addr\": \"%s\", \"win32_start\": \"%s\", \"start_module\": \"%s\"}%s\n",
                    (unsigned long)t.tid,
                    HexAddr(t.startAddress).c_str(),
                    HexAddr(t.win32StartAddress).c_str(),
                    JsonEscape(t.startModule).c_str(),
                    (j + 1 < d.threads.size()) ? "," : "");
            }
            std::printf("      ],\n");
        }
        else
        {
            std::printf("      \"threads\": [],\n");
        }

        // 模块
        if (!args.noModules && !d.modules.empty())
        {
            std::printf("      \"modules\": [\n");
            for (size_t j = 0; j < d.modules.size(); ++j)
            {
                const auto& m = d.modules[j];
                std::printf("        {\"base\": \"%s\", \"size\": %lu, \"name\": \"%s\", \"path\": \"%s\"}%s\n",
                    HexAddr(m.base).c_str(),
                    (unsigned long)m.size,
                    JsonEscape(m.name).c_str(),
                    JsonEscape(m.path).c_str(),
                    (j + 1 < d.modules.size()) ? "," : "");
            }
            std::printf("      ],\n");
        }
        else
        {
            std::printf("      \"modules\": [],\n");
        }

        // 可疑内存
        if (!args.noMem && !d.suspiciousMem.empty())
        {
            std::printf("      \"suspicious_memory\": [\n");
            for (size_t j = 0; j < d.suspiciousMem.size(); ++j)
            {
                const auto& r = d.suspiciousMem[j];
                std::printf("        {\"base\": \"%s\", \"size\": %llu, \"protect\": \"%s\", \"type\": \"%s\", \"reason\": \"%s\"}%s\n",
                    HexAddr(r.base).c_str(),
                    (unsigned long long)r.size,
                    r.protectStr.c_str(),
                    r.typeStr.c_str(),
                    r.reason.c_str(),
                    (j + 1 < d.suspiciousMem.size()) ? "," : "");
            }
            std::printf("      ],\n");
        }
        else
        {
            std::printf("      \"suspicious_memory\": [],\n");
        }

        // 指向本进程的句柄
        std::printf("      \"external_handles\": [");
        bool first = true;
        for (const auto& h : handles)
        {
            if (h.targetPid != b.pid) continue;
            if (!first) std::printf(", ");
            first = false;
            std::printf("{\"owner_pid\": %lu, \"owner_name\": \"%s\", \"handle\": %llu, \"access\": \"%s\", \"high_risk\": %s}",
                (unsigned long)h.ownerPid,
                JsonEscape(h.ownerName).c_str(),
                (unsigned long long)h.handleValue,
                h.accessStr.c_str(),
                h.highRisk ? "true" : "false");
        }
        std::printf("]\n");

        std::printf("    }%s\n", (i + 1 < details.size()) ? "," : "");
    }
    std::printf("  ],\n");

    // 全局高危句柄列表(便于 Server 快速检索)
    std::printf("  \"high_risk_handles\": [\n");
    bool first = true;
    for (const auto& h : handles)
    {
        if (!h.highRisk) continue;
        if (!first) std::printf(",\n");
        first = false;
        std::printf("    {\"owner_pid\": %lu, \"owner_name\": \"%s\", \"handle\": %llu, \"target_pid\": %lu, \"access\": \"%s\"}",
            (unsigned long)h.ownerPid,
            JsonEscape(h.ownerName).c_str(),
            (unsigned long long)h.handleValue,
            (unsigned long)h.targetPid,
            h.accessStr.c_str());
    }
    std::printf("\n  ]\n");

    std::printf("}\n");
}

// ───────────────────────────────────────────────────────────────
//  安全采集主流程
// ───────────────────────────────────────────────────────────────
static int RunSecurityMode(const SecurityArgs& args)
{
    SetConsoleOutputCP(CP_UTF8);

    // 1. 枚举所有进程的基础信息
    std::vector<ProcBrief> briefs;
    if (!EnumProcessesBrief(briefs))
    {
        std::fprintf(stderr, "[错误] 进程枚举失败\n");
        return 1;
    }

    // 构建 PID → 名称映射(句柄扫描时用)
    std::unordered_map<ULONG_PTR, std::wstring> pidToName;
    pidToName.reserve(briefs.size());
    for (const auto& b : briefs)
    {
        std::wstring w = U8ToW(b.name);
        pidToName[b.pid] = w;
    }

    // 2. 构建 PID → ProcBrief 映射(O(1) 查找,替代原来的循环)
    std::unordered_map<ULONG_PTR, ProcBrief*> briefByPid;
    for (auto& b : briefs)
    {
        briefByPid[b.pid] = &b;
    }

    // 3. 确定要采集的进程列表
    std::vector<ULONG_PTR> targetPids;
    if (args.hasPid)
    {
        if (briefByPid.find(args.pid) == briefByPid.end())
        {
            std::fprintf(stderr, "[错误] PID %lu 不存在\n", (unsigned long)args.pid);
            return 1;
        }
        targetPids.push_back(args.pid);
    }
    else
    {
        for (const auto& b : briefs)
        {
            // 跳过 Idle (PID 0),它无法 OpenProcess
            if (b.pid == 0) continue;
            targetPids.push_back(b.pid);
        }
    }

    // 4. 逐个采集详情
    std::vector<ProcDetail> details;
    details.reserve(targetPids.size());
    for (ULONG_PTR pid : targetPids)
    {
        ProcDetail d;
        auto itBrief = briefByPid.find(pid);
        if (itBrief != briefByPid.end())
        {
            d.brief = *itBrief->second;
        }

        // 打开进程(用最大权限尝试,失败降级)
        // PROCESS_QUERY_INFORMATION (0x400) | PROCESS_VM_READ (0x10)
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, (DWORD)pid);
        if (!hProc)
        {
            // 降级:PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
        }
        if (!hProc)
        {
            // 打不开就只记录基础信息,详情留空
            details.push_back(std::move(d));
            continue;
        }

        // 采集详情
        CollectProcessDetails(hProc, d);

        if (!args.noModules)
            CollectModules(hProc, d);

        if (!args.noThreads)
            CollectThreads(d.brief, hProc, d.modules, d);

        if (!args.noMem)
            CollectSuspiciousMemory(hProc, d.modules, d);

        CloseHandle(hProc);
        details.push_back(std::move(d));
    }

    // 4. 句柄表扫描
    std::vector<HandleEntry> handles;
    if (!args.noHandles)
    {
        ULONG_PTR handleTarget = args.handlesTarget;
        if (handleTarget == 0 && args.hasPid) handleTarget = args.pid;
        // handleTarget == 0 表示扫所有进程的所有句柄(数据量巨大,慎用)
        CollectHandles(handleTarget, pidToName, handles);
    }

    // 5. 输出 JSON
    PrintSecurityJson(details, handles, args);
    return 0;
}

// ───────────────────────────────────────────────────────────────
//  参数解析 + main
// ───────────────────────────────────────────────────────────────
struct Args {
    ULONG_PTR pid = 0;
    bool hasPid = false;
    int maxDepth = 0;
    bool json = false;
    bool security = false;
    SecurityArgs secArgs;
};

static Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        std::wstring s = argv[i];
        if ((s == L"--pid" || s == L"-p") && i + 1 < argc)
        {
            try {
                a.pid = std::stoull(argv[++i], nullptr, 10);
                a.hasPid = true;
                a.secArgs.pid = a.pid;
                a.secArgs.hasPid = true;
            }
            catch (...) { std::fprintf(stderr, "[警告] 无效的 PID: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if ((s == L"--depth" || s == L"-d") && i + 1 < argc)
        {
            try { a.maxDepth = std::stoi(argv[++i]); if (a.maxDepth < 0) a.maxDepth = 0; }
            catch (...) { std::fprintf(stderr, "[警告] 无效的深度: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if (s == L"--json" || s == L"-j")
        {
            a.json = true;
        }
        else if (s == L"--security")
        {
            a.security = true;
        }
        else if (s == L"--no-handles") { a.secArgs.noHandles = true; }
        else if (s == L"--no-mem")     { a.secArgs.noMem = true; }
        else if (s == L"--no-threads") { a.secArgs.noThreads = true; }
        else if (s == L"--no-modules") { a.secArgs.noModules = true; }
        else if (s == L"--no-token")   { a.secArgs.noToken = true; }
        else if (s == L"--handles-target" && i + 1 < argc)
        {
            try { a.secArgs.handlesTarget = std::stoull(argv[++i], nullptr, 10); }
            catch (...) {}
        }
        else if (s == L"--help" || s == L"-h")
        {
            std::printf("用法: ProcessTreeSnapshot [选项]\n\n");
            std::printf("树形打印模式(默认):\n");
            std::printf("  --pid <N>     只打印指定进程及其子树\n");
            std::printf("  --depth <N>   限制树深度(0=不限制)\n");
            std::printf("  --json        输出扁平 JSON(基础信息)\n\n");
            std::printf("安全采集模式:\n");
            std::printf("  --security              完整安全采集,输出 JSON\n");
            std::printf("  --pid <N>               只采集指定进程(默认全系统)\n");
            std::printf("  --no-handles            跳过句柄表扫描\n");
            std::printf("  --no-mem                跳过可疑内存扫描\n");
            std::printf("  --no-threads            跳过线程采集\n");
            std::printf("  --no-modules            跳过模块采集\n");
            std::printf("  --no-token              跳过 Token/Protection 采集\n");
            std::printf("  --handles-target <PID>  句柄扫描只看指向 PID 的句柄\n\n");
            std::printf("  --help                   显示帮助\n");
            exit(0);
        }
    }
    return a;
}

int wmain(int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (!InitNtdll())
    {
        std::fprintf(stderr, "[错误] 无法加载 ntdll API\n");
        return 1;
    }

    Args args = ParseArgs(argc, argv);

    if (args.security)
    {
        return RunSecurityMode(args.secArgs);
    }
    return RunTreeMode(args.pid, args.maxDepth, args.json);
}
