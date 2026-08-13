// NativeApi.h
//
// ntdll 未文档化 API 的动态加载 + 相关结构体定义。
// 所有 Nt* 函数在用户态通过 GetModuleHandle("ntdll") + GetProcAddress 拿到,
// 不依赖 phnt / ntdll.lib,避免链接问题。

#pragma once
#include <Windows.h>
#include <winternl.h>

// ───────────────────────────────────────────────────────────────
//  常量(未文档化的 SystemInformationClass / ProcessInformationClass / ThreadInformationClass)
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

// 全局 ntdll 函数指针(InitNtdll 初始化,后续 Collector 直接用)
inline PFN_NtQuerySystemInformation      g_NtQuerySystemInformation = nullptr;
inline PFN_NtQueryInformationProcess     g_NtQueryInformationProcess = nullptr;
inline PFN_NtQueryInformationThread      g_NtQueryInformationThread = nullptr;
inline PFN_NtQueryObject                 g_NtQueryObject = nullptr;

inline bool InitNtdll()
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

// PROCESS_BASIC_INFORMATION
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
