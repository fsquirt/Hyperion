#include "Driver.h"
#include "ProcessProtect.h"

// ============================================================
// IOCTL definitions
// ============================================================

#define IOCTL_SET_PPL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PPL_REQUEST {
    ULONG_PTR Pid;
    UCHAR SignerType;
} PPL_REQUEST, *PPPL_REQUEST;

// ============================================================
// Device name & symbolic link
// ============================================================

#define DEVICE_NAME     L"\\Device\\KernelService"
#define SYMLINK_NAME    L"\\DosDevices\\KernelService"

// ============================================================
// WDF EvtDriverDeviceAdd — create device + symbolic link
// ============================================================

NTSTATUS EvtDriverDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;
    WDFDEVICE device;
    UNICODE_STRING devName, symLink;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(DeviceInit, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfDeviceInitAssignName failed: 0x%08X\n", status);
        return status;
    }

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfDeviceCreate failed: 0x%08X\n", status);
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfDeviceCreateSymbolicLink failed: 0x%08X\n", status);
        return status;
    }

    // Manual I/O queue for IOCTL dispatch
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfIoQueueCreate failed: 0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Device created: %ws -> %ws\n", DEVICE_NAME, SYMLINK_NAME);

    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL dispatch
// ============================================================

VOID EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (IoControlCode == IOCTL_SET_PPL) {
        if (InputBufferLength < sizeof(PPL_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            PPPL_REQUEST req = NULL;
            size_t reqSize = 0;

            status = WdfRequestRetrieveInputBuffer(Request, sizeof(PPL_REQUEST), &req, &reqSize);
            if (NT_SUCCESS(status) && req) {
                DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                    "[KernelService] IOCTL_SET_PPL: PID=%p, Signer=%d\n",
                    (HANDLE)req->Pid, req->SignerType);

                status = SetProcessPPLByPid((HANDLE)req->Pid, req->SignerType);
            }
        }
    }

    WdfRequestCompleteWithInformation(Request, status, 0);
}

// ============================================================
// WDF unload callback
// ============================================================

VOID EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver unloading...\n");

    ProcessProtectUnload();

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver unloaded\n");
}

// ============================================================
// Driver entry point
// ============================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loading...\n");

    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

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

    // Initialize process protection (PPL + callback)
    status = ProcessProtectInit();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] ProcessProtectInit failed: 0x%08X\n", status);
        // Continue loading — device + IOCTL still usable
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loaded successfully\n");

    return STATUS_SUCCESS;
}
