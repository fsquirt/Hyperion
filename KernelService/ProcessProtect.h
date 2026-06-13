#pragma once

#include <ntddk.h>

// ============================================================
// ObRegisterCallbacks: Access rights stripping for PvZ (disabled)
// ============================================================
#define TARGET_PROCESS_NAME L"PlantsVsZombies.exe"
#define ALLOWED_ACCESS_MASK (0x0200 | 0x0400 | 0x1000)

// ============================================================
// PPL (Protected Process Light)
// ============================================================

#define PPL_TARGET_PROCESS_NAME L"notepad.exe"

// ProcessProtectionInformation = 61 per WDK 28000 ntddk.h
#ifndef ProcessProtectionInformation
#define ProcessProtectionInformation ((PROCESSINFOCLASS)61)
#endif

// PS_PROTECTION union
#pragma warning(push)
#pragma warning(disable: 4201)
typedef union _PS_PROTECTION_KS {
    UCHAR Level;
    struct {
        UCHAR Type : 3;
        UCHAR Audit : 1;
        UCHAR SignerType : 4;
    };
} PS_PROTECTION_KS;
#pragma warning(pop)

// Protection types
#define PsProtectedTypeNone_KS              0
#define PsProtectedTypeProtectedLight_KS    1
#define PsProtectedTypeProtected_KS         2

// Protection signers
#define PsProtectedSignerNone_KS            0
#define PsProtectedSignerAuthenticode_KS    1
#define PsProtectedSignerCodeGen_KS         2
#define PsProtectedSignerAntimalware_KS     3
#define PsProtectedSignerLsa_KS             4
#define PsProtectedSignerWindows_KS         5
#define PsProtectedSignerWinTcb_KS          6
#define PsProtectedSignerWinSystem_KS       7

// Signing levels
#define SE_SIGNING_LEVEL_NONE_KS                0x00
#define SE_SIGNING_LEVEL_UNSIGNED_KS            0x01
#define SE_SIGNING_LEVEL_ENTERPRISE_KS          0x02
#define SE_SIGNING_LEVEL_AUTHENTICODE_KS        0x04
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN_KS     0x06
#define SE_SIGNING_LEVEL_WINDOWS_KS             0x08
#define SE_SIGNING_LEVEL_ANTIMALWARE_KS         0x0A
#define SE_SIGNING_LEVEL_MICROSOFT_KS           0x0C
#define SE_SIGNING_LEVEL_WINDOWS_TCB_KS         0x0E

// ============================================================
// Kernel API declarations
// ============================================================

// ZwQuerySystemInformation (semi-documented)
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// PsGetProcessProtection - exported from ntoskrnl but not in WDK headers
NTKERNELAPI UCHAR PsGetProcessProtection(_In_ PEPROCESS Process);

// PsGetProcessSignatureLevel - exported from ntoskrnl but not in WDK headers
NTKERNELAPI NTSTATUS PsGetProcessSignatureLevel(
    _In_ PEPROCESS Process,
    _Out_ PULONG SignatureLevel,
    _Out_ PULONG SectionSignatureLevel
);

// ============================================================
// Exports
// ============================================================
NTSTATUS ProcessProtectInit(VOID);
VOID ProcessProtectUnload(VOID);
