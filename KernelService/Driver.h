#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;

// ProcessProtect exports
NTSTATUS ProcessProtectInit(VOID);
VOID ProcessProtectUnload(VOID);
