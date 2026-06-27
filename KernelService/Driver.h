#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;

// ProcessProtect exports
NTSTATUS ProcessProtectInit(VOID);
VOID ProcessProtectUnload(VOID);
NTSTATUS SetProcessPPLByPid(_In_ HANDLE TargetPid, _In_ UCHAR SignerType);
NTSTATUS TerminateProcessByPid(_In_ HANDLE TargetPid);
