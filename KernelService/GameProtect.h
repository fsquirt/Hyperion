#pragma once

#include <ntddk.h>

// ============================================================
// Exports
// ============================================================

NTSTATUS GameProtectInit(VOID);
VOID GameProtectUnload(VOID);
NTSTATUS GameProtectStart(_In_ HANDLE TargetPid);
NTSTATUS GameProtectStop(VOID);
NTSTATUS GameProtectDropHandles(_In_ HANDLE TargetPid);