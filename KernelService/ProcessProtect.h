#pragma once

#include <ntddk.h>

// ============================================================
// PPL (Protected Process Light)
// ============================================================

typedef union _PS_PROTECTION_KS {
    UCHAR Level;
    struct {
        UCHAR Type : 3;
        UCHAR Audit : 1;
        UCHAR SignerType : 4;
    } Bits;
} PS_PROTECTION_KS;

#define PsProtectedTypeNone_KS              0
#define PsProtectedTypeProtectedLight_KS    1
#define PsProtectedTypeProtected_KS         2

#define PsProtectedSignerNone_KS            0
#define PsProtectedSignerAuthenticode_KS    1
#define PsProtectedSignerCodeGen_KS         2
#define PsProtectedSignerAntimalware_KS     3
#define PsProtectedSignerLsa_KS             4
#define PsProtectedSignerWindows_KS         5
#define PsProtectedSignerWinTcb_KS          6
#define PsProtectedSignerWinSystem_KS       7

// ============================================================
// Exports
// ============================================================

NTSTATUS ProcessProtectInit(VOID);
VOID ProcessProtectUnload(VOID);
NTSTATUS SetProcessPPLByPid(_In_ HANDLE TargetPid, _In_ UCHAR SignerType);
