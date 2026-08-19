#include <ntifs.h>
#include "GameProtect.h"

// ============================================================
// GameProtect — 游戏进程保护: 句柄降级
//
// 通过 ObRegisterCallbacks 注册进程/线程对象的句柄创建与复制
// 预操作回调,对受保护游戏进程的句柄做"权限剥离" (handle downgrade):
//
//   进程句柄剥离 (外挂最常利用的危险权限):
//     PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
//     PROCESS_VM_READ    | PROCESS_VM_WRITE      | PROCESS_SUSPEND_RESUME
//   线程句柄剥离:
//     THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SET_CONTEXT |
//     THREAD_GET_CONTEXT
//
// 触发时机 (参考 句柄降级.txt):
//   OpenProcess / OpenThread / DuplicateHandle 走到对象管理器时
//   回调都会触发,剥离后系统按降权后的 DesiredAccess 生成句柄。
//
// 放行规则:
//   - 目标不是受保护进程(或其线程) → 直接放行
//   - 发起者是受保护进程自己(游戏内部句柄) → 放行
//   - 发起者是 System (PID 4) → 放行
//   - 其余一律剥离危险权限
//
// 生命周期:
//   GameProtectInit    → 注册 Ob 回调 (无保护目标,惰性)
//   GameProtectStart   → 设定保护目标 PID (由 IOCTL_GAMEPROTECT_START 触发)
//   GameProtectStop    → 清空保护目标
//   GameProtectUnload  → 注销回调 + 清空目标
//
// 并发模型: g_ProtectedProcess 用 KSPIN_LOCK 保护。Ob 预操作回调
// 可能在 PASSIVE/DISPATCH_LEVEL 触发,自旋锁两档都安全;进程退出
// 通知回调在 PASSIVE_LEVEL 触发,同样持锁交换指针,锁外释放引用。
// ============================================================

// 进程句柄剥离权限 (winnt.h 的 PROCESS_* 常量在内核头里未声明,手动定义)
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE          (0x0001)
#define PROCESS_CREATE_THREAD      (0x0002)
#define PROCESS_VM_OPERATION       (0x0008)
#define PROCESS_VM_READ            (0x0010)
#define PROCESS_VM_WRITE           (0x0020)
#define PROCESS_SUSPEND_RESUME     (0x0800)
#define PROCESS_DUP_HANDLE         (0x0040)
#endif

#define STRIPPED_PROCESS_ACCESS \
    (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | \
     PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_DUP_HANDLE)

// 线程句柄剥离权限
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE           (0x0001)
#define THREAD_SUSPEND_RESUME      (0x0002)
#define THREAD_GET_CONTEXT         (0x0008)
#define THREAD_SET_CONTEXT         (0x0010)
#endif

#define STRIPPED_THREAD_ACCESS \
    (THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SET_CONTEXT | \
     THREAD_GET_CONTEXT)

// 补充通用权限宏定义
#ifndef MAXIMUM_ALLOWED
#define MAXIMUM_ALLOWED            (0x02000000L)
#define GENERIC_ALL                (0x10000000L)
#define GENERIC_EXECUTE            (0x20000000L)
#define GENERIC_WRITE              (0x40000000L)
#define GENERIC_READ               (0x80000000L)
#endif

// 需要剔除的所有权限（包含泛型掩码和具体敏感权限）
#define FULL_STRIPPED_PROCESS_ACCESS \
    (STRIPPED_PROCESS_ACCESS | MAXIMUM_ALLOWED | \
     GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE)

#define FULL_STRIPPED_THREAD_ACCESS \
    (STRIPPED_THREAD_ACCESS | MAXIMUM_ALLOWED | \
     GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE)

// 受保护进程 (持有引用,PsLookupProcessByProcessId 取得)
static PEPROCESS g_ProtectedProcess = NULL;
static KSPIN_LOCK g_GameProtectLock;
static BOOLEAN g_Initialized = FALSE;
static BOOLEAN g_ProcessNotifyRegistered = FALSE;

// Ob 回调注册句柄 (一次注册同时覆盖 Process + Thread 两个类型)
static PVOID g_ObRegistrationHandle = NULL;

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

// ============================================================
// Exports
// ============================================================

NTSTATUS GameProtectInit(VOID)
{
	KeInitializeSpinLock(&g_GameProtectLock);
	// 定义一个高度字符串（可以根据你的驱动需求修改具体的数字，通常是一个小数形式的字符串）
	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"114514.1234");

	OB_CALLBACK_REGISTRATION callbackRegistration = {0};
	OB_OPERATION_REGISTRATION operationRegistration[2] = {0};

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

	// 1. 先注销进程退出通知,避免回调访问正在被清理的资源
	if (g_ProcessNotifyRegistered) {
		PsSetCreateProcessNotifyRoutineEx(GameProtectProcessNotify, TRUE);
		g_ProcessNotifyRegistered = FALSE;
	}

	// 2. 注销 Ob 回调
	if (g_ObRegistrationHandle != NULL) {
		ObUnRegisterCallbacks(g_ObRegistrationHandle);
		g_ObRegistrationHandle = NULL;
	}

	// 3. 清空保护目标并释放引用
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