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

// 设置 ImageLoad 监控目标 PID，独立于句柄保护
NTSTATUS GameProtectSetImageLoadMonitor(_In_ HANDLE MonitorPid);

// 设置新线程反调试目标 PID，独立于句柄保护，并注册线程创建回调
NTSTATUS GameProtectSetThreadAntiDebug(_In_ HANDLE TargetPid);

// 停止新线程反调试: 卸载线程创建回调并清空目标
NTSTATUS GameProtectStopThreadAntiDebug(VOID);

// 对目标进程已有的全部线程执行反调试 (ThreadHideFromDebugger)
NTSTATUS GameProtectHideExistingThreads(_In_ HANDLE TargetPid);