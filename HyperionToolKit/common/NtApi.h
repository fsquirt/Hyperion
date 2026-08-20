// NtApi.h — ntdll 未文档化 API 统一加载
//
// 合并自原 NativeApi.h (NtQuerySystemInformation / NtQueryInformationProcess /
// NtQueryInformationThread / NtQueryObject + SYSTEM_PROCESS_INFORMATION 结构)
// 与 ObjectScanner.cpp 的 NTAPI 对象管理器函数 (NtOpenDirectoryObject 等)。
//
// 所有 Nt* 函数在用户态通过 GetModuleHandle("ntdll") + GetProcAddress 动态加载,
// 不依赖 phnt / ntdll.lib。InitNtApi 一次加载全部, 各模块按需使用。

#pragma once

#include <Windows.h>
#include <winternl.h>

namespace das {

	// ───────────────────────────────────────────────────────────────
	//  常量 (未文档化的 SystemInformationClass / ProcessInformationClass)
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
	typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
		ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(WINAPI* PFN_NtQueryInformationProcess)(
		HANDLE, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(WINAPI* PFN_NtQueryInformationThread)(
		HANDLE, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(WINAPI* PFN_NtQueryObject)(
		HANDLE, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* PFN_NtOpenDirectoryObject)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	typedef NTSTATUS(NTAPI* PFN_NtQueryDirectoryObject)(
		HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
	typedef NTSTATUS(NTAPI* PFN_NtOpenSymbolicLinkObject)(
		PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	typedef NTSTATUS(NTAPI* PFN_NtQuerySymbolicLinkObject)(
		HANDLE, PUNICODE_STRING, PULONG);
	typedef VOID(NTAPI* PFN_RtlInitUnicodeString)(
		PUNICODE_STRING, PCWSTR);
	typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);

	// 全局函数指针 (InitNtApi 填充)
	extern PFN_NtQuerySystemInformation      g_NtQuerySystemInformation;
	extern PFN_NtQueryInformationProcess     g_NtQueryInformationProcess;
	extern PFN_NtQueryInformationThread      g_NtQueryInformationThread;
	extern PFN_NtQueryObject                 g_NtQueryObject;
	extern PFN_NtOpenDirectoryObject         g_NtOpenDirectoryObject;
	extern PFN_NtQueryDirectoryObject        g_NtQueryDirectoryObject;
	extern PFN_NtOpenSymbolicLinkObject      g_NtOpenSymbolicLinkObject;
	extern PFN_NtQuerySymbolicLinkObject     g_NtQuerySymbolicLinkObject;
	extern PFN_RtlInitUnicodeString          g_RtlInitUnicodeString;
	extern PFN_NtClose                       g_NtClose;

	// 加载全部 ntdll 函数指针; 返回 false 表示关键函数加载失败
	bool InitNtApi();

	// ───────────────────────────────────────────────────────────────
	//  未文档化结构体定义
	// ───────────────────────────────────────────────────────────────

	// SYSTEM_PROCESS_INFORMATION (phnt 完整定义)
	// 关键: HardFaultCount / NumberOfThreadsHighWatermark 是 ULONG(4字节),
	//       不是 LARGE_INTEGER(8字节), 写错会导致后续字段偏移错位崩溃。
	// 注意: 结构末尾紧跟 NumberOfThreads 个 SYSTEM_THREAD_INFORMATION,
	//       这是 NtQuerySystemInformation 原生返回的线程数据, 无需再调
	//       CreateToolhelp32Snapshot。
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
	} SYSTEM_THREAD_INFORMATION_FULL, * PSYSTEM_THREAD_INFORMATION_FULL;

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
	} SYSTEM_PROCESS_INFORMATION_FULL, * PSYSTEM_PROCESS_INFORMATION_FULL;

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
				UCHAR Type : 3;  // 0=None, 1=Protected, 2=ProtectedLight
				UCHAR Audit : 1;
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

} // namespace das