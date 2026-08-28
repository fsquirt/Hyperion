#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include "GameProtect.h"
#include "EtwLogger.h"

// 其他c里面的函数 变量
extern PUCHAR PsGetProcessImageFileName(IN PEPROCESS Process);
extern ULONG g_ProtectionOffset;
extern BOOLEAN VerifyMicrosoftImageByPath(_In_ PUNICODE_STRING DosPath);

// 线程信息类: 隐藏线程不受调试器 (防反调试)
#ifndef ThreadHideFromDebugger
#define ThreadHideFromDebugger 17
#endif

// 线程权限: SET_INFORMATION (用于 ZwOpenThread)
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION      (0x0020)
#endif

// ZwOpenThread 未在 WDK 头文件中导出,手动声明 (用户提供)
NTSYSAPI NTSTATUS NTAPI ZwOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

// 拿到进程的 PEB (Process Environment Block) 指针,用于获取模块列表
NTKERNELAPI PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS NTAPI IoQueryFileDosDeviceName(
	_In_ PFILE_OBJECT FileObject,
	_Out_ POBJECT_NAME_INFORMATION* ObjectNameInformation
);
NTSTATUS NTAPI PsReferenceProcessFilePointer(
	IN PEPROCESS Process,
	OUT PVOID* OutFileObject // 实际上输出的是 PFILE_OBJECT*
);

// PEB 与 LDR 基础结构 (简化版，适配 x64)
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// ============================================================
// ZwQuerySystemInformation (SystemProcessInformation) 相关
// 枚举进程已有线程用,未公开结构体手动声明 (用户提供)
// ============================================================
#define SystemProcessInformation 0x05

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// ============================================================
// ZwQuerySystemInformation (SystemExtendedHandleInformation) 相关
// 未公开结构体与函数,手动声明 (WDK 头文件不含这些定义)
// ============================================================
#define SystemExtendedHandleInformation 0x40

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;               // 句柄指向的内核对象地址
	ULONG_PTR UniqueProcessId;  // 持有该句柄的进程 PID
	ULONG_PTR HandleValue;      // 句柄值
	ULONG GrantedAccess;        // 权限掩码
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

// ============================================================
// 句柄降级权限掩码
// ============================================================
// 需要剔除的进程权限包含：
// PROCESS_TERMINATE(0x0001) | PROCESS_CREATE_THREAD(0x0002) | PROCESS_VM_OPERATION(0x0008) |
// PROCESS_VM_READ(0x0010)   | PROCESS_VM_WRITE(0x0020)      | PROCESS_DUP_HANDLE(0x0040)   |
// PROCESS_SUSPEND_RESUME(0x0800) | MAXIMUM_ALLOWED(0x02000000L) | GENERIC_ALL(0x10000000L) |
// GENERIC_EXECUTE(0x20000000L)   | GENERIC_WRITE(0x40000000L)   | GENERIC_READ(0x80000000L)
#define FULL_STRIPPED_PROCESS_ACCESS \
    (0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0800 | \
     0x02000000L | 0x10000000L | 0x20000000L | 0x40000000L | 0x80000000L)

// 需要剔除的线程权限包含：
// THREAD_TERMINATE(0x0001)   | THREAD_SUSPEND_RESUME(0x0002) | THREAD_GET_CONTEXT(0x0008) | 
// THREAD_SET_CONTEXT(0x0010) | MAXIMUM_ALLOWED(0x02000000L)  | GENERIC_ALL(0x10000000L)   |
// GENERIC_EXECUTE(0x20000000L)| GENERIC_WRITE(0x40000000L)    | GENERIC_READ(0x80000000L)
#define FULL_STRIPPED_THREAD_ACCESS \
    (0x0001 | 0x0002 | 0x0008 | 0x0010 | \
     0x02000000L | 0x10000000L | 0x20000000L | 0x40000000L | 0x80000000L)

// 受保护进程 (持有引用,PsLookupProcessByProcessId 取得)
static PEPROCESS g_ProtectedProcess = NULL;
static KSPIN_LOCK g_GameProtectLock;
static BOOLEAN g_Initialized = FALSE;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static BOOLEAN g_ImageLoadNotifyRegistered = FALSE;

// ImageLoad 监控目标 PID (独立于句柄保护,由 IOCTL_GAMEPROTECT_MONITOR_IMAGELOAD 设置)
static HANDLE g_ImageLoadMonitorPid = NULL;

// 新线程反调试目标 PID (独立于句柄保护,由 IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG 设置)
// AntiDebugThreadNotify 线程创建回调只处理该进程新建的线程
static HANDLE g_ThreadAntiDebugPid = NULL;

// Ob 回调注册句柄 (一次注册同时覆盖 Process + Thread 两个类型)
static PVOID g_ObRegistrationHandle = NULL;

// 定义 PspTerminateThreadByPointer 的函数指针类型
typedef NTSTATUS(NTAPI* PPSP_TERMINATE_THREAD_BY_POINTER)(
	_In_ PETHREAD pEThread,
	_In_ NTSTATUS ExitStatus,
	_In_ BOOLEAN DirectTerminate
	);

// 全局缓存该函数地址，避免每次杀线程都去搜一遍内存
static PPSP_TERMINATE_THREAD_BY_POINTER g_PspTerminateThreadByPointer = NULL;

// 遍历并校验所有模块
BOOLEAN VerifyProcessAndAllModules(_In_ PEPROCESS Process)
{
	PFILE_OBJECT fileObject = NULL;
	POBJECT_NAME_INFORMATION dosNameInfo = NULL;
	BOOLEAN result = FALSE;

	// 取进程映像的文件对象
	NTSTATUS status = PsReferenceProcessFilePointer(Process, &fileObject);
	if (!NT_SUCCESS(status) || fileObject == NULL) {
		return FALSE;
	}

	// 取 DOS 路径 (例如: C:\Windows\System32\lsass.exe)
	status = IoQueryFileDosDeviceName(fileObject, &dosNameInfo);
	if (NT_SUCCESS(status) && dosNameInfo != NULL) {

		// 验证主程序签名
		result = VerifyMicrosoftImageByPath(&dosNameInfo->Name);
		if (!result) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
				"[GameProtect] UNTRUSTED IMAGE FOUND: %wZ\n", &dosNameInfo->Name);
		}

		// 安全释放内存 (仅在分配成功时释放)
		ExFreePool(dosNameInfo);
	}

	// 释放文件对象引用
	ObDereferenceObject(fileObject);

	// 如果主程序都没过验证，直接拒绝，不用再往下看模块了
	if (!result) {
		return FALSE;
	}

	PPEB peb = (PPEB)PsGetProcessPeb(Process);
	if (!peb) return FALSE;

	KAPC_STATE apcState;
	// 挂靠到目标进程空间以安全读取 PEB[cite: 2]
	KeStackAttachProcess(Process, &apcState);

	PPEB_LDR_DATA ldr = *(PPEB_LDR_DATA*)((PUCHAR)peb + 0x18); // x64 PEB->Ldr 偏移
	if (!ldr) {
		KeUnstackDetachProcess(&apcState);
		return FALSE;
	}

	PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
	PLIST_ENTRY entry = listHead->Flink;
	BOOLEAN allTrusted = TRUE;

	while (entry != listHead && entry != NULL) {
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (ldrEntry->FullDllName.Buffer != NULL && ldrEntry->FullDllName.Length > 0) {
			// 注意：这里需要你实现一个 VerifyMicrosoftImageByPath 函数
			// 接收 UNICODE_STRING 路径，调用 ZwCreateFile 和 CiValidateFileObject
			if (!VerifyMicrosoftImageByPath(&ldrEntry->FullDllName)) {
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
					"[GameProtect] UNTRUSTED MODULE FOUND: %wZ\n", &ldrEntry->FullDllName);
				allTrusted = FALSE;
				break;
			}
		}
		entry = entry->Flink;
	}

	KeUnstackDetachProcess(&apcState);
	return allTrusted;
}

// ------------------------------------------------------------
// 前置回调: 进程对象句柄创建/复制
// ------------------------------------------------------------
static OB_PREOP_CALLBACK_STATUS GameProtectProcessPreOp(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// 1. 只处理进程对象
	if (OperationInformation->ObjectType != *PsProcessType) {
		return OB_PREOP_SUCCESS;
	}

	// 2. 快速路径: 未设定保护目标,直接放行
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	PEPROCESS protectedProcess = g_ProtectedProcess;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (protectedProcess == NULL) {
		return OB_PREOP_SUCCESS;
	}

	// 3. 目标必须是受保护进程本身 (指针比较,天然免疫 PID 复用)
	PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
	if (targetProcess != protectedProcess) {
		return OB_PREOP_SUCCESS;
	}

	
	// 4. 放行: 游戏自己 / System (PID 4)
	HANDLE callerPid = PsGetCurrentProcessId();
	HANDLE targetPid = PsGetProcessId(targetProcess);
	if (callerPid == targetPid || callerPid == (HANDLE)4) {
		return OB_PREOP_SUCCESS;
	}

	PEPROCESS callerProcess = PsGetCurrentProcess();
	PUCHAR processName = PsGetProcessImageFileName(callerProcess);

	if (processName != NULL) {
		// 使用 _stricmp 进行不区分大小写的字符串比较
		if (_stricmp((const char*)processName, "lsass.exe") == 0 ||
			_stricmp((const char*)processName, "csrss.exe") == 0 ) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[KernelService] GameProtect: System process %s (PID: %p), Checking...\n", processName, callerPid);
			if (VerifyProcessAndAllModules(callerProcess)){
				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
					"[KernelService] GameProtect: System process %s (PID: %p) successed verification, accessed to protected process PID %p\n",
					processName, callerPid, targetPid);
				return OB_PREOP_SUCCESS;
			}
		}
	}

	// 进程降权
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
			~FULL_STRIPPED_PROCESS_ACCESS;
	}
	else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
			~FULL_STRIPPED_PROCESS_ACCESS;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: downgraded PROCESS handle to %p (caller PID %p)\n",
		targetPid, callerPid);

	return OB_PREOP_SUCCESS;
}

// ------------------------------------------------------------
// 前置回调: 线程对象句柄创建/复制
// ------------------------------------------------------------
static OB_PREOP_CALLBACK_STATUS GameProtectThreadPreOp(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// 1. 只处理线程对象
	if (OperationInformation->ObjectType != *PsThreadType) {
		return OB_PREOP_SUCCESS;
	}

	// 2. 快速路径: 未设定保护目标,直接放行
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	PEPROCESS protectedProcess = g_ProtectedProcess;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (protectedProcess == NULL) {
		return OB_PREOP_SUCCESS;
	}

	// 3. 该线程必须属于受保护进程
	PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
	PEPROCESS targetProcess = PsGetThreadProcess(targetThread);
	if (targetProcess != protectedProcess) {
		return OB_PREOP_SUCCESS;
	}

	// 4. 放行: 游戏自己 / System (PID 4)
	HANDLE callerPid = PsGetCurrentProcessId();
	HANDLE targetPid = PsGetProcessId(targetProcess);
	if (callerPid == targetPid || callerPid == (HANDLE)4) {
		return OB_PREOP_SUCCESS;
	}

	// 进程降权
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
			~FULL_STRIPPED_THREAD_ACCESS;
	}
	else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
			~FULL_STRIPPED_THREAD_ACCESS;
	}


	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: downgraded THREAD handle of PID %p (caller PID %p)\n",
		targetPid, callerPid);

	return OB_PREOP_SUCCESS;
}

// ------------------------------------------------------------
// 进程退出通知: 受保护进程退出时自动解除保护
// CreateInfo == NULL 表示进程退出
// ------------------------------------------------------------
static VOID GameProtectProcessNotify(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);

	// 只在进程退出时清理
	if (CreateInfo != NULL) {
		return;
	}

	PEPROCESS toDeref = NULL;

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	if (g_ProtectedProcess == Process) {
		g_ProtectedProcess = NULL;
		toDeref = Process;
	}
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (toDeref != NULL) {
		ObDereferenceObject(toDeref);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] GameProtect: protected process exited, protection auto-cleared\n");
	}
}

// 指定内存区域的特征码扫描
PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{
	PVOID pAddress = NULL;
	PUCHAR i = NULL;
	ULONG m = 0;

	// 扫描内存
	for (i = (PUCHAR)pStartAddress; i < (PUCHAR)pEndAddress; i++)
	{
		// 判断特征码
		for (m = 0; m < ulMemoryDataSize; m++)
		{
			if (*(PUCHAR)(i + m) != pMemoryData[m])
			{
				break;
			}
		}
		// 判断是否找到符合特征码的地址
		if (m >= ulMemoryDataSize)
		{
			// 找到特征码位置, 获取紧接着特征码的下一地址
			pAddress = (PVOID)(i + ulMemoryDataSize);
			break;
		}
	}

	return pAddress;
}

PVOID ResolvePspTerminateThreadByPointer()
{
	UNICODE_STRING ustrFuncName;
	PVOID pAddress = NULL;
	LONG lOffset = 0;
	PVOID pPsTerminateSystemThread = NULL;
	PVOID pPspTerminateThreadByPointer = NULL;

	// 获取 PsTerminateSystemThread 函数地址
	RtlInitUnicodeString(&ustrFuncName, L"PsTerminateSystemThread");
	pPsTerminateSystemThread = MmGetSystemRoutineAddress(&ustrFuncName);

	DbgPrint("[KernelService] PsTerminateSystemThread = 0x%p \n", pPsTerminateSystemThread);
	if (NULL == pPsTerminateSystemThread)
	{
		return 0;
	}

	/*
	lkd> uf nt!PsTerminateSystemThread
			nt!PsTerminateSystemThread:
			fffff806`060a3340 4883ec28        sub     rsp,28h
			fffff806`060a3344 8bd1            mov     edx,ecx
			fffff806`060a3346 65488b0c2588010000 mov   rcx,qword ptr gs:[188h]
			fffff806`060a334f f7417400040000  test    dword ptr [rcx+74h],400h
			fffff806`060a3356 0f844eaf1600    je      nt!FsRtlRegisterFltMgrCalls+0x38c6a (fffff806`0620e2aa)

			nt!PsTerminateSystemThread+0x1c:
			fffff806`060a335c 41b001          mov     r8b,1
			fffff806`060a335f e87c460600      call    nt!PspTerminateThreadByPointer (fffff806`061079e0)

			nt!PsTerminateSystemThread+0x24:
			fffff806`060a3364 4883c428        add     rsp,28h
			fffff806`060a3368 c3              ret

			nt!FsRtlRegisterFltMgrCalls+0x38c6a:
			fffff806`0620e2aa b80d0000c0      mov     eax,0C000000Dh
			fffff806`0620e2af e9b050e9ff      jmp     nt!PsTerminateSystemThread+0x24 (fffff806`060a3364)

	*/

	// 优化后的特征码: mov r8b,1 (41 b0 01) + call (e8)
	UCHAR pSpecialData[] = { 0x41, 0xB0, 0x01, 0xE8 };
	ULONG ulSpecialDataSize = sizeof(pSpecialData);

	// 搜索地址 PsTerminateSystemThread --> PsTerminateSystemThread + 0xff 查找 e87c460600
	pAddress = SearchMemory(pPsTerminateSystemThread, (PVOID)((PUCHAR)pPsTerminateSystemThread + 0xFF), pSpecialData, ulSpecialDataSize);
	if (NULL == pAddress)
	{
		return 0;
	}

	// 先获取偏移,再计算地址
	lOffset = *(PLONG)pAddress;
	pPspTerminateThreadByPointer = (PVOID)((PUCHAR)pAddress + sizeof(LONG) + lOffset);
	if (NULL == pPspTerminateThreadByPointer)
	{
		return 0;
	}

	return pPspTerminateThreadByPointer;
}

// ------------------------------------------------------------
// 线程创建回调: 隐藏目标进程 (g_ThreadAntiDebugPid) 新线程的调试器能力
// (ThreadHideFromDebugger 让调试器收不到该线程的任何事件)
// 目标 PID 独立于句柄保护,由 IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG 设置,
// 通过 IOCTL_GAMEPROTECT_THREAD_ANTIDEBUG_STOP 卸载回调。
// 事件经 ETW (EventId=3) 回传 creatorPid / ProcessId / ThreadId。
// ------------------------------------------------------------
VOID AntiDebugThreadNotify(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create)
{
	// 只处理线程创建,且目标是 g_ThreadAntiDebugPid
	if (!Create) {
		return;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	HANDLE antiDebugPid = g_ThreadAntiDebugPid;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (antiDebugPid == NULL || ProcessId != antiDebugPid) {
		return;
	}

	HANDLE creatorPid = PsGetCurrentProcessId(); // 真正的幕后黑手！

	// 经 ETW 把 创建者PID / 进程PID / 线程ID 传回用户层
	EtwLogThreadAntiDebugEvent(creatorPid, ProcessId, ThreadId);

	// 如果创建者 PID 不是游戏自己，也不是 System (PID 4)
	if (creatorPid != ProcessId && creatorPid != (HANDLE)4) {

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] RemoteThread Injection Detected! Initiator: %p, Target: %p, Thread: %p\n",
			creatorPid, ProcessId, ThreadId);

		// 使用 PspTerminateThreadByPointer 强杀线程
		if (g_PspTerminateThreadByPointer != NULL) {
			PETHREAD pTargetThread = NULL;

			// 通过 ThreadId 获取底层的 PETHREAD 对象
			if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &pTargetThread))) {

				// 参数3 DirectTerminate 设为 TRUE，无视一切直接抹杀
				g_PspTerminateThreadByPointer(pTargetThread, STATUS_ACCESS_DENIED, TRUE);

				// 必须释放引用
				ObDereferenceObject(pTargetThread);

				DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
					"[KernelService] Malicious thread forcefully terminated via internal API.\n");
			}
		}
		else {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
				"[KernelService] Internal API missing, failed to kill thread!\n");
		}

		// 既然线程已经被杀了，直接 return
		return;
	}

	HANDLE hThread = NULL;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	clientId.UniqueProcess = ProcessId;
	clientId.UniqueThread = ThreadId;

	// 打开刚创建的线程句柄
	if (NT_SUCCESS(ZwOpenThread(&hThread, THREAD_SET_INFORMATION, &objAttr, &clientId))) {
		// 剥夺调试器接收该线程事件的能力
		ZwSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
		ZwClose(hThread);

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] Thread %p hidden from debugger.\n", ThreadId);
	}
}

// ------------------------------------------------------------
// LoadImage 回调: 监控指定进程 (g_ImageLoadMonitorPid) 的用户态 DLL/映像加载
// 事件通过 ETW (EtwLogImageLoadEvent) 传回用户层。
// 注意:
//   - FullImageName 指针仅在回调生命周期内有效,
//     EtwLogImageLoadEvent 内部已深拷贝进 UserData
//   - 回调内不阻塞,不做长耗时操作
// ------------------------------------------------------------
VOID GameImageLoadNotify(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
	// 过滤掉内核模式驱动加载 (我们只关心用户态 DLL 加载)
	if (ImageInfo->SystemModeImage) {
		return;
	}

	// 必须有目标进程上下文
	if (ProcessId == NULL || FullImageName == NULL) {
		return;
	}

	// 安全获取当前 ImageLoad 监控目标 PID
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	HANDLE monitorPid = g_ImageLoadMonitorPid;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (monitorPid == NULL) {
		return; // 当前没有开启 ImageLoad 监控
	}

	// 仅拦截发生在目标进程内的模块映射
	if (ProcessId == monitorPid) {
		// 谁发起的映像加载 (initiatorPid) 也一并记录,方便用户层分析
		HANDLE initiatorPid = PsGetCurrentProcessId();

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] GameProtect: module loaded in Target PID %p (Initiated by PID %p): %wZ (Base: %p, Size: 0x%X)\n",
			ProcessId, initiatorPid, FullImageName, ImageInfo->ImageBase, (ULONG)ImageInfo->ImageSize);

		// 将发起者 PID (initiatorPid) 一并压入 ETW 或传输队列传回用户层
		EtwLogImageLoadEvent(ProcessId, initiatorPid, FullImageName,
			(ULONG_PTR)ImageInfo->ImageBase, (ULONG)ImageInfo->ImageSize);
	}
}

// ============================================================
// Exports
// ============================================================

NTSTATUS GameProtectInit(VOID)
{
	KeInitializeSpinLock(&g_GameProtectLock);
	// 定义一个高度字符串（可以根据你的驱动需求修改具体的数字，通常是一个小数形式的字符串）
	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"114514.1234");

	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	OB_OPERATION_REGISTRATION operationRegistration[2] = { 0 };

	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 2;
	callbackRegistration.Altitude = altitude;
	callbackRegistration.OperationRegistration = operationRegistration;
	callbackRegistration.RegistrationContext = NULL;

	operationRegistration[0].ObjectType = PsProcessType;
	operationRegistration[0].Operations =
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration[0].PreOperation = GameProtectProcessPreOp;

	operationRegistration[1].ObjectType = PsThreadType;
	operationRegistration[1].Operations =
		OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration[1].PreOperation = GameProtectThreadPreOp;

	NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &g_ObRegistrationHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] GameProtectInit: ObRegisterCallbacks failed: 0x%08X\n", status);
		return status;
	}

	// 动态解析未公开的强杀线程 API
	g_PspTerminateThreadByPointer = (PPSP_TERMINATE_THREAD_BY_POINTER)ResolvePspTerminateThreadByPointer();
	if (!g_PspTerminateThreadByPointer) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] Failed to resolve PspTerminateThreadByPointer!\n");
	}
	else {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] PspTerminateThreadByPointer found at %p\n", g_PspTerminateThreadByPointer);
	}

	// 进程退出自动清理 (失败不致命,仅失去自动解除能力)
	status = PsSetCreateProcessNotifyRoutineEx(GameProtectProcessNotify, FALSE);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] GameProtectInit: PsSetCreateProcessNotifyRoutineEx failed: 0x%08X "
			"(auto-clear on exit unavailable)\n", status);
	}
	else {
		g_ProcessNotifyRegistered = TRUE;
	}

	// 注册 LoadImage 回调,监控受保护进程的映像加载 (失败不致命)
	status = PsSetLoadImageNotifyRoutine(GameImageLoadNotify);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] GameProtectInit: PsSetLoadImageNotifyRoutine failed: 0x%08X "
			"(ImageLoad monitor unavailable)\n", status);
	}
	else {
		g_ImageLoadNotifyRegistered = TRUE;
	}

	g_Initialized = TRUE;

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect initialized (process/thread handle downgrade callbacks registered)\n");

	return STATUS_SUCCESS;
}

VOID GameProtectUnload(VOID)
{
	if (!g_Initialized) {
		return;
	}

	// 1. 先注销线程创建通知,避免回调访问正在被清理的资源
	if (g_ThreadNotifyRegistered) {
		PsRemoveCreateThreadNotifyRoutine(AntiDebugThreadNotify);
		g_ThreadNotifyRegistered = FALSE;
	}

	// 2. 注销 LoadImage 通知
	if (g_ImageLoadNotifyRegistered) {
		PsRemoveLoadImageNotifyRoutine(GameImageLoadNotify);
		g_ImageLoadNotifyRegistered = FALSE;
	}

	// 3. 注销进程退出通知,避免回调访问正在被清理的资源
	if (g_ProcessNotifyRegistered) {
		PsSetCreateProcessNotifyRoutineEx(GameProtectProcessNotify, TRUE);
		g_ProcessNotifyRegistered = FALSE;
	}

	// 4. 注销 Ob 回调
	if (g_ObRegistrationHandle != NULL) {
		ObUnRegisterCallbacks(g_ObRegistrationHandle);
		g_ObRegistrationHandle = NULL;
	}

	// 5. 清空保护目标并释放引用
	GameProtectStop();

	g_Initialized = FALSE;

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect unloaded\n");
}

NTSTATUS GameProtectStart(_In_ HANDLE TargetPid)
{
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] GameProtectStart: PsLookupProcessByProcessId(%p) failed: 0x%08X\n",
			TargetPid, status);
		return status;
	}

	// 交换保护目标 (替换旧目标时先释放旧引用)
	PEPROCESS oldProcess = NULL;

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	oldProcess = g_ProtectedProcess;
	g_ProtectedProcess = process;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (oldProcess != NULL) {
		ObDereferenceObject(oldProcess);
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: protecting PID %p\n", TargetPid);

	return STATUS_SUCCESS;
}

NTSTATUS GameProtectStop(VOID)
{
	PEPROCESS oldProcess = NULL;

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	oldProcess = g_ProtectedProcess;
	g_ProtectedProcess = NULL;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	if (oldProcess != NULL) {
		ObDereferenceObject(oldProcess);
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: protection stopped\n");

	return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// 已有句柄丢弃: 扫描全局句柄表,强制关闭其他进程握有的
// 指向目标游戏进程的高危句柄 (VM_READ/VM_WRITE/VM_OPERATION)。
// 通过 ZwQuerySystemInformation(SystemExtendedHandleInformation)
// 拿到句柄指向的内核对象指针,直接与游戏进程 PEPROCESS 比对,
// 避免 ObReferenceObjectByHandle 的开销。
// ------------------------------------------------------------
NTSTATUS GameProtectSetImageLoadMonitor(_In_ HANDLE MonitorPid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	g_ImageLoadMonitorPid = MonitorPid;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: ImageLoad monitor PID set to %p\n", MonitorPid);

	return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// 设置新线程反调试目标 PID,并注册线程创建回调
// (与句柄保护完全独立,不依赖 g_ProtectedProcess)
// ------------------------------------------------------------
NTSTATUS GameProtectSetThreadAntiDebug(_In_ HANDLE TargetPid)
{
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	g_ThreadAntiDebugPid = TargetPid;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	// 注册线程创建回调 (若尚未注册)
	if (!g_ThreadNotifyRegistered) {
		NTSTATUS ns = PsSetCreateThreadNotifyRoutine(AntiDebugThreadNotify);
		if (!NT_SUCCESS(ns)) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
				"[KernelService] GameProtectSetThreadAntiDebug: PsSetCreateThreadNotifyRoutine failed: 0x%08X\n",
				ns);
			return ns;
		}
		g_ThreadNotifyRegistered = TRUE;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: thread anti-debug target PID set to %p\n", TargetPid);

	return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// 停止新线程反调试: 卸载线程创建回调并清空目标
// ------------------------------------------------------------
NTSTATUS GameProtectStopThreadAntiDebug(VOID)
{
	// 卸载线程创建回调
	if (g_ThreadNotifyRegistered) {
		PsRemoveCreateThreadNotifyRoutine(AntiDebugThreadNotify);
		g_ThreadNotifyRegistered = FALSE;
	}

	KIRQL oldIrql;
	KeAcquireSpinLock(&g_GameProtectLock, &oldIrql);
	g_ThreadAntiDebugPid = NULL;
	KeReleaseSpinLock(&g_GameProtectLock, oldIrql);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: thread anti-debug stopped\n");

	return STATUS_SUCCESS;
}

// ------------------------------------------------------------
// 已有线程反调试: 枚举目标进程已有的全部线程,
// 对每个线程执行 ThreadHideFromDebugger (剥夺调试器能力)。
// 通过 ZwQuerySystemInformation(SystemProcessInformation) 遍历。
// ------------------------------------------------------------
NTSTATUS GameProtectHideExistingThreads(_In_ HANDLE TargetPid)
{
	// 1. 获取所需缓冲区大小
	ULONG bufferSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

	// 2. 循环分配内存,直到获取成功 (因为进程/线程数在不断变化)
	PVOID buffer = NULL;
	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != NULL) {
			ExFreePoolWithTag(buffer, 'Proc');
		}

		// 多分配一点空间,防止两次调用之间条目突然增多
		bufferSize += 1024 * sizeof(SYSTEM_THREAD_INFORMATION);
		buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'Proc');
		if (buffer == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != NULL) {
			ExFreePoolWithTag(buffer, 'Proc');
		}
		return status;
	}

	// 防御: 首次查询意外直接成功时,缓冲区尚未分配
	if (buffer == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

	ULONG hiddenCount = 0;

	// 3. 遍历进程列表,找到目标进程
	while (TRUE) {
		if (processInfo->UniqueProcessId == TargetPid) {
			// 4. 遍历该进程已有的全部线程
			for (ULONG i = 0; i < processInfo->NumberOfThreads; i++) {
				PSYSTEM_THREAD_INFORMATION threadInfo = &processInfo->Threads[i];
				if (threadInfo->ClientId.UniqueProcess == TargetPid) {

					HANDLE hThread = NULL;
					OBJECT_ATTRIBUTES objAttr;
					CLIENT_ID clientId;

					InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
					clientId.UniqueProcess = TargetPid;
					clientId.UniqueThread = threadInfo->ClientId.UniqueThread;

					// 打开线程并剥夺调试器能力
					if (NT_SUCCESS(ZwOpenThread(&hThread, THREAD_SET_INFORMATION, &objAttr, &clientId))) {
						ZwSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
						ZwClose(hThread);
						hiddenCount++;
					}
				}
			}
			break;
		}

		if (processInfo->NextEntryOffset == 0) {
			break;
		}
		processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
	}

	ExFreePoolWithTag(buffer, 'Proc');

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: hidden %lu existing thread(s) of PID %p from debugger\n",
		hiddenCount, TargetPid);

	return STATUS_SUCCESS;
}

NTSTATUS GameProtectDropHandles(_In_ HANDLE TargetPid)
{
	PEPROCESS gameProcess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &gameProcess);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] GameProtectDropHandles: PsLookupProcessByProcessId(%p) failed: 0x%08X\n",
			TargetPid, status);
		return status;
	}

	ULONG bufferSize = 0;
	PVOID buffer = NULL;
	PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;

	// 1. 获取所需缓冲区大小
	status = ZwQuerySystemInformation(SystemExtendedHandleInformation, NULL, 0, &bufferSize);

	// 2. 循环分配内存,直到获取成功 (因为句柄数在不断变化)
	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != NULL) {
			ExFreePoolWithTag(buffer, 'Hndl');
		}

		// 多分配一点空间,防止两次调用之间句柄突然增多
		bufferSize += 1024 * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
		buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, 'Hndl');
		if (buffer == NULL) {
			ObDereferenceObject(gameProcess);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(SystemExtendedHandleInformation, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != NULL) {
			ExFreePoolWithTag(buffer, 'Hndl');
		}
		ObDereferenceObject(gameProcess);
		return status;
	}

	// 防御: 首次查询意外直接成功时,缓冲区尚未分配
	if (buffer == NULL) {
		ObDereferenceObject(gameProcess);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)buffer;

	// 3. 遍历全局系统句柄
	for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &handleInfo->Handles[i];

		// 核心过滤 1: 这个句柄指向的对象是我们被保护的游戏进程吗?
		if (entry->Object == gameProcess) {

			// 核心过滤 2: 过滤掉 System 和游戏自身的正常句柄
			HANDLE ownerPid = (HANDLE)entry->UniqueProcessId;
			HANDLE gamePid = PsGetProcessId(gameProcess);

			if (ownerPid == gamePid || ownerPid == (HANDLE)4) {
				continue;
			}

			// 核心过滤 3: 检查危险权限 (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
			if (entry->GrantedAccess & (0x0010 | 0x0020 | 0x0008)) {
				// 提前获取所有者进程，检查是否为系统核心进程
				PEPROCESS ownerProcess = NULL;
				if (NT_SUCCESS(PsLookupProcessByProcessId(ownerPid, &ownerProcess))) {

					PUCHAR processName = PsGetProcessImageFileName(ownerProcess);
					if (processName != NULL) {
						// 忽略关键系统进程，防止 C000021A 蓝屏
						if (_stricmp((const char*)processName, "csrss.exe") == 0 ||
							_stricmp((const char*)processName, "lsass.exe") == 0 ||
							_stricmp((const char*)processName, "smss.exe") == 0 ||
							_stricmp((const char*)processName, "winlogon.exe") == 0 ||
							_stricmp((const char*)processName, "services.exe") == 0 ||
							_stricmp((const char*)processName, "wininit.exe") == 0) {
							if (g_ProtectionOffset != 0) {
								UCHAR pplLevel = *(PUCHAR)((PUCHAR)ownerProcess + g_ProtectionOffset);
								if (pplLevel > 0) {
									// 有 PPL，是真正的系统进程，放行
									DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "[AntiCheat] Real system process have handle, Name: %s, PID: %p, Continued\n", processName, ownerPid);
									ObDereferenceObject(ownerProcess);
									continue;
								}
								else {
									// PPL 为 0，踏马的敢骗老子
									DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "[AntiCheat] FAKE SYSTEM PROCESS DETECTED! Name: %s, PID: %p\n", processName, ownerPid);
								}
							}
						}
					}

					DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
						"[KernelService] GameProtect: dangerous handle found! Owner: %s (PID: %p), Handle: 0x%zX, Access: 0x%08X\n",
						processName ? (const char*)processName : "Unknown", ownerPid, entry->HandleValue, entry->GrantedAccess);

					KAPC_STATE apcState;
					// 挂靠到外挂进程内存空间
					KeStackAttachProcess(ownerProcess, &apcState);

					// 强制关闭句柄: 目标进程本身,来源句柄,传 NULL,选项 DUPLICATE_CLOSE_SOURCE
					ZwDuplicateObject(
						NtCurrentProcess(),
						(HANDLE)entry->HandleValue,
						NULL,
						NULL,
						0,
						0,
						DUPLICATE_CLOSE_SOURCE
					);

					KeUnstackDetachProcess(&apcState);
					ObDereferenceObject(ownerProcess);
				}
			}
		}
	}

	ExFreePoolWithTag(buffer, 'Hndl');
	ObDereferenceObject(gameProcess);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] GameProtect: handle drop scan complete for PID %p\n", TargetPid);

	return STATUS_SUCCESS;
}