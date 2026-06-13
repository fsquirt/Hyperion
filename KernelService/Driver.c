#include "Driver.h"
#include "ProcessProtect.h"

// WDF unload callback - called by framework when SCM sends stop request
VOID EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver unloading...\n");

    // Unregister ObRegisterCallbacks
    ProcessProtectUnload();

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver unloaded\n");
}

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loading...\n");

    // No EvtDriverDeviceAdd — pure software driver, no hardware
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

    // Mark as Non-PnP software driver so `sc stop` works
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

    // Register unload via WDF framework
    config.EvtDriverUnload = EvtDriverUnload;

    // Create WDF driver object
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfDriverCreate failed: 0x%08X\n", status);
        return status;
    }

    // Initialize process protection (ObRegisterCallbacks)
    status = ProcessProtectInit();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] ProcessProtectInit failed: 0x%08X\n", status);
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loaded successfully\n");

    return STATUS_SUCCESS;
}
