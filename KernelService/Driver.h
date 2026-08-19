#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

// UserServiceProtect exports
NTSTATUS UserServiceProtectInit(VOID);
VOID UserServiceProtectUnload(VOID);
NTSTATUS SetProcessPPLByPid(_In_ HANDLE TargetPid, _In_ UCHAR SignerType);
NTSTATUS TerminateProcessByPid(_In_ HANDLE TargetPid);

// GameProtect exports
NTSTATUS GameProtectInit(VOID);
VOID GameProtectUnload(VOID);
NTSTATUS GameProtectStart(_In_ HANDLE TargetPid);
NTSTATUS GameProtectStop(VOID);
