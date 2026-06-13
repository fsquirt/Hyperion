#include <ntifs.h>
#include <ntstrsafe.h>
#include "ProcessProtect.h"

// ============================================================
// System process information for ZwQuerySystemInformation
// ============================================================
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
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#define SystemProcessInformation 5

// ============================================================
// Dynamic EPROCESS offsets (resolved at runtime)
// ============================================================
static ULONG g_ProtectionOffset = 0;
static ULONG g_SignatureLevelOffset = 0;
static ULONG g_SectionSignatureLevelOffset = 0;

// ============================================================
// Globals - ObRegisterCallbacks (disabled, kept for reference)
// ============================================================
static PVOID g_RegistrationHandle = NULL;
static OB_CALLBACK_REGISTRATION g_CallbackRegistration;
static OB_OPERATION_REGISTRATION g_OperationRegistration;

// ============================================================
// Locate Protection offset by scanning PsGetProcessProtection
// This function is exported from ntoskrnl (declared in header)
// ============================================================
static ULONG LocateProtectionOffset(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsGetProcessProtection");
    PUCHAR pCode = (PUCHAR)MmGetSystemRoutineAddress(&name);

    if (!pCode) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] PsGetProcessProtection not found via MmGetSystemRoutineAddress\n");
        return 0;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] PsGetProcessProtection at %p, first bytes: %02X %02X %02X %02X %02X %02X %02X\n",
        pCode, pCode[0], pCode[1], pCode[2], pCode[3], pCode[4], pCode[5], pCode[6]);

    // Scan first 30 bytes
    for (size_t i = 0; i < 30; i++) {
        // movzx eax, byte ptr [rcx + imm32] -> 0F B6 81 XX XX XX XX
        if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x81) {
            ULONG offset = *(PULONG)(&pCode[i + 3]);
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] Protection offset: 0x%03X (movzx r,rm32)\n", offset);
            return offset;
        }
        // movzx eax, byte ptr [rcx + imm8] -> 0F B6 41 XX
        if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x41) {
            ULONG offset = (ULONG)pCode[i + 3];
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] Protection offset: 0x%03X (movzx r,rm8)\n", offset);
            return offset;
        }
        // mov al, byte ptr [rcx + imm32] -> 8A 81 XX XX XX XX
        if (pCode[i] == 0x8A && pCode[i + 1] == 0x81) {
            ULONG offset = *(PULONG)(&pCode[i + 2]);
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] Protection offset: 0x%03X (mov al,[rcx+imm32])\n", offset);
            return offset;
        }
        // mov al, byte ptr [rcx + imm8] -> 8A 41 XX
        if (pCode[i] == 0x8A && pCode[i + 1] == 0x41) {
            ULONG offset = (ULONG)pCode[i + 2];
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] Protection offset: 0x%03X (mov al,[rcx+imm8])\n", offset);
            return offset;
        }
        // mov eax, dword ptr [rcx + imm32] -> 8B 81 XX XX XX XX
        if (pCode[i] == 0x8B && pCode[i + 1] == 0x81) {
            ULONG offset = *(PULONG)(&pCode[i + 2]);
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] Protection offset: 0x%03X (mov r,[rcx+imm32])\n", offset);
            return offset;
        }
        // Stop at ret
        if (pCode[i] == 0xC3) break;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
        "[KernelService] Failed to locate Protection offset in PsGetProcessProtection\n");
    return 0;
}

// ============================================================
// Locate SignatureLevel offsets by scanning PsGetProcessSignatureLevel
// ============================================================
static BOOLEAN LocateSignatureLevelsOffsets(PULONG SigLevelOffset, PULONG SecSigLevelOffset)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsGetProcessSignatureLevel");
    PUCHAR pCode = (PUCHAR)MmGetSystemRoutineAddress(&name);

    if (!pCode) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] PsGetProcessSignatureLevel not found via MmGetSystemRoutineAddress\n");
        return FALSE;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] PsGetProcessSignatureLevel at %p, first bytes: %02X %02X %02X %02X %02X %02X %02X\n",
        pCode, pCode[0], pCode[1], pCode[2], pCode[3], pCode[4], pCode[5], pCode[6]);

    ULONG found = 0;

    for (size_t i = 0; i < 80; i++) {
        if (pCode[i] == 0xC3) break; // stop at ret

        // mov al, byte ptr [rcx + imm32] -> 8A 81 XX XX XX XX
        if (pCode[i] == 0x8A && pCode[i + 1] == 0x81) {
            ULONG offset = *(PULONG)(&pCode[i + 2]);
            if (found == 0) {
                *SigLevelOffset = offset;
                found++;
                i += 5;
            }
            else {
                *SecSigLevelOffset = offset;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[KernelService] SignatureLevel=0x%03X, SectionSignatureLevel=0x%03X\n",
                    *SigLevelOffset, *SecSigLevelOffset);
                return TRUE;
            }
        }
        // mov al, byte ptr [rcx + imm8] -> 8A 41 XX
        else if (pCode[i] == 0x8A && pCode[i + 1] == 0x41) {
            ULONG offset = (ULONG)pCode[i + 2];
            if (found == 0) {
                *SigLevelOffset = offset;
                found++;
                i += 2;
            }
            else {
                *SecSigLevelOffset = offset;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[KernelService] SignatureLevel=0x%03X, SectionSignatureLevel=0x%03X\n",
                    *SigLevelOffset, *SecSigLevelOffset);
                return TRUE;
            }
        }
        // movzx eax, byte ptr [rcx + imm32] -> 0F B6 81 XX XX XX XX
        else if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x81) {
            ULONG offset = *(PULONG)(&pCode[i + 3]);
            if (found == 0) {
                *SigLevelOffset = offset;
                found++;
                i += 6;
            }
            else {
                *SecSigLevelOffset = offset;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[KernelService] SignatureLevel=0x%03X, SectionSignatureLevel=0x%03X\n",
                    *SigLevelOffset, *SecSigLevelOffset);
                return TRUE;
            }
        }
        // movzx eax, byte ptr [rcx + imm8] -> 0F B6 41 XX
        else if (pCode[i] == 0x0F && pCode[i + 1] == 0xB6 && pCode[i + 2] == 0x41) {
            ULONG offset = (ULONG)pCode[i + 3];
            if (found == 0) {
                *SigLevelOffset = offset;
                found++;
                i += 3;
            }
            else {
                *SecSigLevelOffset = offset;
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[KernelService] SignatureLevel=0x%03X, SectionSignatureLevel=0x%03X\n",
                    *SigLevelOffset, *SecSigLevelOffset);
                return TRUE;
            }
        }
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
        "[KernelService] Failed to locate SignatureLevel offsets\n");
    return FALSE;
}

// ============================================================
// Set PPL by directly modifying EPROCESS fields
// ============================================================
static VOID SetProcessPPLDirect(
    _In_ PEPROCESS Process,
    _In_ UCHAR ProtectionType,
    _In_ UCHAR SignerType,
    _In_ UCHAR SignatureLevel,
    _In_ UCHAR SectionSignatureLevel
)
{
    UCHAR protectionLevel = ProtectionType | (SignerType << 4);

    *(PUCHAR)((PUCHAR)Process + g_ProtectionOffset) = protectionLevel;
    *(PUCHAR)((PUCHAR)Process + g_SignatureLevelOffset) = SignatureLevel;
    *(PUCHAR)((PUCHAR)Process + g_SectionSignatureLevelOffset) = SectionSignatureLevel;
}

// ============================================================
// Enumerate all existing processes and set PPL on notepad.exe
// ============================================================
static VOID SetAllNotepadPPL(VOID)
{
    if (g_ProtectionOffset == 0 || g_SignatureLevelOffset == 0 || g_SectionSignatureLevelOffset == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] Offsets not resolved, cannot set PPL\n");
        return;
    }

    NTSTATUS status;
    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    ULONG count = 0;

    for (int attempt = 0; attempt < 5; attempt++) {
#pragma warning(suppress: 4996)
        buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'LPPs');
        if (!buffer) return;

        status = ZwQuerySystemInformation(
            SystemProcessInformation, buffer, bufferSize, &bufferSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(buffer, 'LPPs');
            bufferSize *= 2;
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(status) || !buffer) {
        if (buffer) ExFreePoolWithTag(buffer, 'LPPs');
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] ZwQuerySystemInformation failed: 0x%08X\n", status);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (entry->ImageName.Length > 0 && entry->ImageName.Buffer != NULL) {
            PWCHAR fileName = wcsrchr(entry->ImageName.Buffer, L'\\');
            fileName = fileName ? (fileName + 1) : entry->ImageName.Buffer;

            if (_wcsicmp(fileName, PPL_TARGET_PROCESS_NAME) == 0) {
                PEPROCESS process = NULL;
                status = PsLookupProcessByProcessId(entry->UniqueProcessId, &process);
                if (NT_SUCCESS(status) && process) {
                    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                        "[KernelService] Setting PPL_System on existing %ws (PID: %p)\n",
                        PPL_TARGET_PROCESS_NAME, entry->UniqueProcessId);

                    SetProcessPPLDirect(
                        process,
                        PsProtectedTypeProtectedLight_KS,
                        PsProtectedSignerWinSystem_KS,
                        SE_SIGNING_LEVEL_WINDOWS_TCB_KS,
                        SE_SIGNING_LEVEL_WINDOWS_TCB_KS
                    );
                    count++;
                    ObDereferenceObject(process);
                }
            }
        }

        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, 'LPPs');

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] PPL set on %u existing %ws process(es)\n",
        count, PPL_TARGET_PROCESS_NAME);
}

// ============================================================
// Process creation callback: set PPL on new notepad.exe
// ============================================================
static VOID CreateProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo == NULL || g_ProtectionOffset == 0) {
        return;
    }

    PUNICODE_STRING imageName = NULL;
    NTSTATUS status = SeLocateProcessImageName(Process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL) {
        return;
    }

    PWCHAR fileName = wcsrchr(imageName->Buffer, L'\\');
    fileName = fileName ? (fileName + 1) : imageName->Buffer;

    if (_wcsicmp(fileName, PPL_TARGET_PROCESS_NAME) != 0) {
        ExFreePool(imageName);
        return;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Detected %ws launch (PID: %p), setting PPL_System...\n",
        PPL_TARGET_PROCESS_NAME, ProcessId);

    SetProcessPPLDirect(
        Process,
        PsProtectedTypeProtectedLight_KS,
        PsProtectedSignerWinSystem_KS,
        SE_SIGNING_LEVEL_WINDOWS_TCB_KS,
        SE_SIGNING_LEVEL_WINDOWS_TCB_KS
    );

    ExFreePool(imageName);
}

// ============================================================
// ObRegisterCallbacks: Pre-operation callback (disabled, kept for reference)
// ============================================================
static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OpInfo->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;

    PEPROCESS process = (PEPROCESS)OpInfo->Object;
    if (process == NULL || process == PsGetCurrentProcess()) return OB_PREOP_SUCCESS;

    PUNICODE_STRING imageName = NULL;
    NTSTATUS status = SeLocateProcessImageName(process, &imageName);
    if (!NT_SUCCESS(status) || imageName == NULL || imageName->Buffer == NULL) return OB_PREOP_SUCCESS;

    PWCHAR fileName = wcsrchr(imageName->Buffer, L'\\');
    fileName = fileName ? (fileName + 1) : imageName->Buffer;

    if (_wcsicmp(fileName, TARGET_PROCESS_NAME) != 0) {
        ExFreePool(imageName);
        return OB_PREOP_SUCCESS;
    }

    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        OpInfo->Parameters->CreateHandleInformation.DesiredAccess &= ALLOWED_ACCESS_MASK;
    else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ALLOWED_ACCESS_MASK;

    ExFreePool(imageName);
    return OB_PREOP_SUCCESS;
}

static VOID PostOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_POST_OPERATION_INFORMATION OpInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OpInfo);
}

// ============================================================
// Init
// ============================================================
NTSTATUS ProcessProtectInit(VOID)
{
    NTSTATUS status;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Initializing process protection...\n");

    // --- 1. Dynamic offset discovery via opcode parsing ---

    g_ProtectionOffset = LocateProtectionOffset();
    if (g_ProtectionOffset == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] CRITICAL: Cannot resolve Protection offset\n");
        return STATUS_UNSUCCESSFUL;
    }

    if (!LocateSignatureLevelsOffsets(&g_SignatureLevelOffset, &g_SectionSignatureLevelOffset)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] CRITICAL: Cannot resolve SignatureLevel offsets\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] EPROCESS offsets: Protection=0x%03X, SigLevel=0x%03X, SecSigLevel=0x%03X\n",
        g_ProtectionOffset, g_SignatureLevelOffset, g_SectionSignatureLevelOffset);

    // --- 2. Set PPL on all existing notepad.exe ---

    SetAllNotepadPPL();

    // --- 3. Register process creation callback ---

    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
    }
    else {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[KernelService] Process notify callback registered (PPL_System for %ws)\n",
            PPL_TARGET_PROCESS_NAME);
    }

    // --- 4. ObRegisterCallbacks (disabled, kept for reference) ---
    //
    // g_OperationRegistration.ObjectType = PsProcessType;
    // g_OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    // g_OperationRegistration.PreOperation = PreOperationCallback;
    // g_OperationRegistration.PostOperation = PostOperationCallback;
    // g_CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    // g_CallbackRegistration.OperationRegistrationCount = 1;
    // g_CallbackRegistration.OperationRegistration = &g_OperationRegistration;
    // g_CallbackRegistration.RegistrationContext = NULL;
    // RtlInitUnicodeString(&g_CallbackRegistration.Altitude, L"321000");
    // status = ObRegisterCallbacks(&g_CallbackRegistration, &g_RegistrationHandle);
    // if (!NT_SUCCESS(status)) g_RegistrationHandle = NULL;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Process protection initialized\n");

    return STATUS_SUCCESS;
}

// ============================================================
// Unload
// ============================================================
VOID ProcessProtectUnload(VOID)
{
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyCallback, TRUE);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Process notify callback unregistered\n");

    // ObRegisterCallbacks (disabled)
    // if (g_RegistrationHandle != NULL) {
    //     ObUnRegisterCallbacks(g_RegistrationHandle);
    //     g_RegistrationHandle = NULL;
    // }
    UNREFERENCED_PARAMETER(g_RegistrationHandle);
}
