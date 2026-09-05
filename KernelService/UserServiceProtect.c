#include <ntifs.h>
#include <ntstrsafe.h>
#include "UserServiceProtect.h"

// Dynamic EPROCESS Protection offset (opcode parsing)
// 在 UserServiceProtect.c 顶部声明一个标志
ULONG g_ProtectionOffset = 0;

// Locate Protection offset by scanning PsGetProcessProtection
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

	// 扫描窗口 32 字节,任何读取都不能越过窗口右边界。
	// PsGetProcessProtection 是极小的叶子函数,通常 5~8 字节就以 ret 结束
	for (size_t i = 0; i < 32; i++) {
		// 遇到 ret 立刻停止,绝不往函数体外面读,跨到未映射页即蓝屏
		if (pCode[i] == 0xC3) {
			break;
		}

		// 匹配 movzx + disp32: 0F B6 81 [xx xx xx xx],共 7 字节
		if (i + 7 <= 32 && pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x81) {
			ULONG offset = *(PULONG)(&pCode[i + 3]);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		// 匹配 movzx + disp8: 0F B6 41 [xx],共 4 字节
		if (i + 4 <= 32 && pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x41) {
			ULONG offset = (ULONG)pCode[i + 3];
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		// 匹配 mov + disp32: 8A 81 [xx xx xx xx],共 6 字节
		if (i + 6 <= 32 && pCode[i] == 0x8A && pCode[i + 1] == 0x81) {
			ULONG offset = *(PULONG)(&pCode[i + 2]);
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
		// 匹配 mov + disp8: 8A 41 [xx],共 3 字节
		if (i + 3 <= 32 && pCode[i] == 0x8A && pCode[i + 1] == 0x41) {
			ULONG offset = (ULONG)pCode[i + 2];
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] Protection offset: 0x%03X\n", offset);
			return offset;
		}
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
		"[KernelService] Failed to locate Protection offset\n");
	return 0;
}

static VOID SetProcessPPL(_In_ PEPROCESS Process, _In_ UCHAR SignerType)
{
	UCHAR level = PsProtectedTypeProtectedLight_KS | (SignerType << 4);
	*(PUCHAR)((PUCHAR)Process + g_ProtectionOffset) = level;
}

NTSTATUS SetProcessPPLByPid(_In_ HANDLE TargetPid, _In_ UCHAR SignerType)
{
	if (!g_ProtectionOffset)
		return STATUS_UNSUCCESSFUL;

	// 入参校验: SignerType 与 TargetPid 完全来自用户态 IOCTL, 不可轻信, 严防内核提权原语
	// 1. 绝对禁止修改 Idle 与 System, 对应 PID 0 与 4
	if (TargetPid == (HANDLE)0 || TargetPid == (HANDLE)4) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] SetPPL: refusing to protect Idle/System (pid %p)\n", TargetPid);
		return STATUS_INVALID_PARAMETER;
	}
	// 2. SignerType 必须落在 PS_PROTECTED_SIGNER 合法枚举范围内,
	//    防止写坏 Protection 结构引发不可预期的内核行为
	if (SignerType > PsProtectedSignerMax) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] SetPPL: signer type %d out of range (max %d)\n",
			SignerType, PsProtectedSignerMax);
		return STATUS_INVALID_PARAMETER_2;
	}

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(TargetPid, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] PsLookupProcessByProcessId(%p) failed: 0x%08X\n",
			TargetPid, status);
		return status;
	}

	// 3. 双保险: System 进程对象直接拒绝
	if (process == PsInitialSystemProcess) {
		ObDereferenceObject(process);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] SetPPL: refusing to protect System process\n");
		return STATUS_ACCESS_DENIED;
	}

	SetProcessPPL(process, SignerType);
	ObDereferenceObject(process);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PPL set on PID %p (signer %d)\n",
		TargetPid, SignerType);

	return STATUS_SUCCESS;
}


// Terminate a process by PID (kernel-mode, can kill PPL processes)
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

VOID UserServiceProtectUnload(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] PPL unloaded\n");
}
