#include <ntifs.h>
#include <ntstrsafe.h>
#include "UserServiceProtect.h"

// ============================================================
// Dynamic EPROCESS Protection offset (opcode parsing)
// ============================================================
// 在 UserServiceProtect.c 顶部声明一个标志
static ULONG g_ProtectionOffset = 0;

// ============================================================
// Locate Protection offset by scanning PsGetProcessProtection
// ============================================================
static ULONG LocateProtectionOffset(VOID)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"PsGetProcessProtection");
	PUCHAR pCode = (PUCHAR)MmGetSystemRoutineAddress(&name);

	if (!pCode) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] PsGetProcessProtection not found\n");
		return 0;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PsGetProcessProtection at %p: %02X %02X %02X %02X %02X %02X %02X\n",
		pCode, pCode[0], pCode[1], pCode[2], pCode[3], pCode[4], pCode[5], pCode[6]);

	for (size_t i = 0; i < 30; i++) {
		if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x81) {
			ULONG offset = *(PULONG)(&pCode[i + 3]);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x41) {
			ULONG offset = (ULONG)pCode[i + 3];
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		if (pCode[i] == 0x8A && pCode[i + 1] == 0x81) {
			ULONG offset = *(PULONG)(&pCode[i + 2]);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		if (pCode[i] == 0x8A && pCode[i + 1] == 0x41) {
			ULONG offset = (ULONG)pCode[i + 2];
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		if (pCode[i] == 0xC3) break;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
		"[KernelService] Failed to locate Protection offset\n");
	return 0;
}

// ============================================================
// Set PPL - ARK mode: only write Protection byte
// ============================================================
static VOID SetProcessPPL(_In_ PEPROCESS Process, _In_ UCHAR SignerType)
{
	UCHAR level = PsProtectedTypeProtectedLight_KS | (SignerType << 4);
	*(PUCHAR)((PUCHAR)Process + g_ProtectionOffset) = level;
}

// ============================================================
// Set PPL on a specific PID (called from IOCTL handler)
// ============================================================
NTSTATUS SetProcessPPLByPid(_In_ HANDLE TargetPid, _In_ UCHAR SignerType)
{
	if (!g_ProtectionOffset)
		return STATUS_UNSUCCESSFUL;

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] PsLookupProcessByProcessId(%p) failed: 0x%08X\n",
			TargetPid, status);
		return status;
	}

	SetProcessPPL(process, SignerType);
	ObDereferenceObject(process);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PPL set on PID %p (signer %d)\n",
		TargetPid, SignerType);

	return STATUS_SUCCESS;
}

// ============================================================
// Terminate a process by PID (kernel-mode, can kill PPL processes)
// ============================================================
// 流程:
//   PsLookupProcessByProcessId → PEPROCESS
//   ObOpenObjectByPointer(PROCESS_TERMINATE, OBJ_KERNEL_HANDLE) → HANDLE
//   ZwTerminateProcess(handle, STATUS_SUCCESS)
//   ZwClose / ObDereferenceObject
//
// 关键点:
//   - 内核态调用不受 PPL 限制, 可以正常结束 PPL 进程
//   - 用 OBJ_KERNEL_HANDLE 避免句柄泄漏到用户态
//   - PROCESS_TERMINATE (0x0001) 是最小权限, 安全
// ============================================================
NTSTATUS TerminateProcessByPid(_In_ HANDLE TargetPid)
{
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] Terminate: PsLookupProcessByProcessId(%p) failed: 0x%08X\n",
			TargetPid, status);
		return status;
	}

	// 不允许结束 System 进程 (PID 4) 或 Idle 进程 (PID 0),防止误杀系统
	if (process == PsInitialSystemProcess) {
		ObDereferenceObject(process);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] Terminate: refusing to kill System process\n");
		return STATUS_ACCESS_DENIED;
	}

	HANDLE hProcess = NULL;
	status = ObOpenObjectByPointer(
		process,
		OBJ_KERNEL_HANDLE,
		NULL,
		0x0001L,                // PROCESS_TERMINATE
		*PsProcessType,
		KernelMode,
		&hProcess);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] Terminate: ObOpenObjectByPointer failed: 0x%08X\n", status);
		ObDereferenceObject(process);
		return status;
	}

	// ZwTerminateProcess 第二参数为退出码, 用 STATUS_SUCCESS (0)
	status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);

	ZwClose(hProcess);
	ObDereferenceObject(process);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] Terminate: ZwTerminateProcess on PID %p -> 0x%08X\n",
		TargetPid, status);

	return status;
}

// ============================================================
// Init
// ============================================================
NTSTATUS UserServiceProtectInit(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] Initializing PPL...\n");

	// 1. Discover EPROCESS.Protection offset via opcode parsing
	g_ProtectionOffset = LocateProtectionOffset();
	if (!g_ProtectionOffset) {
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PPL initialized, callback registered\n");

	return STATUS_SUCCESS;
}

// ============================================================
// Unload
// ============================================================
VOID UserServiceProtectUnload(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PPL unloaded\n");
}
