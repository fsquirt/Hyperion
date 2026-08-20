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

// 设置 ImageLoad 监控目标 PID (独立于句柄保护)
NTSTATUS GameProtectSetImageLoadMonitor(_In_ HANDLE MonitorPid);