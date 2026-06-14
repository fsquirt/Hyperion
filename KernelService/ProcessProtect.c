#include <ntifs.h>
#include <ntstrsafe.h>
#include "ProcessProtect.h"

// ============================================================
// Dynamic EPROCESS Protection offset (opcode parsing)
// ============================================================
// 在 ProcessProtect.c 顶部声明一个标志
static ULONG g_ProtectionOffset = 0;
static BOOLEAN g_CallbackRegistered = FALSE;

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
// Process creation callback: set PPL on notepad.exe
// ============================================================
static VOID CreateProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!CreateInfo || !g_ProtectionOffset) return;

    PUNICODE_STRING imageName = NULL;
    if (!NT_SUCCESS(SeLocateProcessImageName(Process, &imageName)))
        return;
    if (!imageName || !imageName->Buffer) return;

    PWCHAR fileName = wcsrchr(imageName->Buffer, L'\\');
    fileName = fileName ? (fileName + 1) : imageName->Buffer;

    if (_wcsicmp(fileName, L"notepad.exe") == 0) {
        SetProcessPPL(Process, PsProtectedSignerAntimalware_KS);
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[KernelService] PPL_Antimalware set on notepad.exe (PID: %p)\n",
            ProcessId);
    }

    ExFreePool(imageName);
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
// Init
// ============================================================
NTSTATUS ProcessProtectInit(VOID)
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Initializing PPL...\n");

    // 1. Discover EPROCESS.Protection offset via opcode parsing
    g_ProtectionOffset = LocateProtectionOffset();
    if (!g_ProtectionOffset) {
        return STATUS_UNSUCCESSFUL;
    }

    // 2. Register process creation callback
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        return status;
    }

    g_CallbackRegistered = TRUE;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] PPL initialized, callback registered\n");

    return STATUS_SUCCESS;
}

// ============================================================
// Unload
// ============================================================
VOID ProcessProtectUnload(VOID)
{
    if (g_CallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);
        g_CallbackRegistered = FALSE;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] PPL unloaded\n");
}
