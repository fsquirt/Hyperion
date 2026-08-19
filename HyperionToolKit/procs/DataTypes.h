// DataTypes.h — procs 模块数据结构
//
// 进程/线程/模块/内存区域/句柄/详情/命令行参数。统一收进 das 命名空间。

#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace das {

// ───────────────────────────────────────────────────────────────
//  基础进程信息(来自 NtQuerySystemInformation,一次调用拿到所有进程)
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

// ───────────────────────────────────────────────────────────────
//  线程详情(补 Win32 StartAddress,用于抓 manual map shellcode)
// ───────────────────────────────────────────────────────────────
struct ThreadInfo {
    ULONG_PTR tid = 0;
    ULONG_PTR startAddress = 0;       // 内核态 StartAddress(来自 NtQuerySystemInformation)
    ULONG_PTR win32StartAddress = 0;  // 应用层 CreateThread 入口(NtQueryInformationThread)
    LONG suspendCount = 0;
    std::string startModule;          // StartAddress 所属模块(空 = 匿名内存,可疑)
    bool isSuspended = false;
};

// ───────────────────────────────────────────────────────────────
//  模块信息(来自 PEB Ldr 链 — 合法加载的 DLL)
// ───────────────────────────────────────────────────────────────
struct ModuleInfo {
    ULONG_PTR base = 0;
    DWORD size = 0;
    std::string name;
    std::string path;
};

// ───────────────────────────────────────────────────────────────
//  可疑内存区域(RWX / RX-unbacked)
// ───────────────────────────────────────────────────────────────
struct MemRegion {
    ULONG_PTR base = 0;
    SIZE_T size = 0;
    DWORD protect = 0;
    DWORD type = 0;
    std::string protectStr;
    std::string typeStr;
    std::string reason;  // "RWX" / "RX-unbacked"
};

// ───────────────────────────────────────────────────────────────
//  句柄表条目(指向某 PID 的强权限句柄)
// ───────────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────────
//  进程完整详情(5 大采集维度的聚合)
// ───────────────────────────────────────────────────────────────
struct ProcDetail {
    ProcBrief brief;
    std::string imagePath;             // 完整路径
    std::string commandLine;           // 命令行
    std::vector<std::string> enabledPrivs;   // 启用中的高危特权
    std::vector<std::string> disabledPrivs;  // 禁用中的高危特权
    std::string protection;            // PPL 保护级别字符串
    bool pplBroken = false;            // Protection == None 但本来应该有保护

    std::vector<ThreadInfo> threads;
    std::vector<ModuleInfo> modules;
    std::vector<MemRegion> suspiciousMem;
    std::vector<HandleEntry> handles;  // 指向本进程的强权限句柄
};

// ───────────────────────────────────────────────────────────────
//  命令行参数
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

struct Args {
    ULONG_PTR pid = 0;
    bool hasPid = false;
    int maxDepth = 0;
    bool json = false;
    bool security = false;
    SecurityArgs secArgs;
};

} // namespace das