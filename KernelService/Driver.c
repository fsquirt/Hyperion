#include "Driver.h"
#include "ProcessProtect.h"

#define IOCTL_SET_PPL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SDDL: SYSTEM full access, Admins full access, Users read+execute
// 不能用 SDDL_DEVOBJ_* 宏，链接会找不到符号（需要 wdmsec.lib）
DECLARE_CONST_UNICODE_STRING(g_Sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;WD)");

typedef struct _PPL_REQUEST {
    ULONG_PTR Pid;
    UCHAR SignerType;
} PPL_REQUEST, *PPPL_REQUEST;

#define DEVICE_NAME     L"\\Device\\KernelService"
#define SYMLINK_NAME    L"\\DosDevices\\KernelService"

// 【新增】全局变量保存设备对象，以便在卸载时删除
WDFDEVICE g_Device = NULL;

NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver);

NTSTATUS CreateControlDevice(_In_ WDFDRIVER Driver)
{
    NTSTATUS status;
    WDFDEVICE device;
    UNICODE_STRING devName, symLink;
    PWDFDEVICE_INIT pDeviceInit = NULL;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    // 必须传 SDDL，NULL 会在 KMDF verifier 下触发 WDF_VIOLATION
    pDeviceInit = WdfControlDeviceInitAllocate(Driver, &g_Sddl);
    if (pDeviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(pDeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(pDeviceInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetExclusive(pDeviceInit, TRUE);

    status = WdfDeviceInitAssignName(pDeviceInit, &devName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    // 创建设备
    status = WdfDeviceCreate(&pDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        // 创建失败时，框架不会消费 pDeviceInit，需手动 Free
        WdfDeviceInitFree(pDeviceInit);
        return status;
    }

    // 【极易蓝屏点修复】创建符号链接
    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) {
        // 如果这里失败，设备已经是"半成品"，直接 return 会导致 KMDF 抛出 WDF_VIOLATION！
        // 必须手动销毁刚创建的 device
        WdfObjectDelete(device);
        return status;
    }

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    // 【极易蓝屏点修复】创建 I/O 队列
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        // 同样，如果这里失败，必须手动销毁 device
        WdfObjectDelete(device);
        return status;
    }

    // 控制设备创建完毕，通知框架
    WdfControlFinishInitializing(device);

    // 【新增】保存到全局变量，留给 Unload 使用
    g_Device = device;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Control device created.\n");

    return STATUS_SUCCESS;
}

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

            status = WdfRequestRetrieveInputBuffer(Request, sizeof(PPL_REQUEST), (PVOID*)&req, &reqSize);
            if (NT_SUCCESS(status) && req) {
                status = SetProcessPPLByPid((HANDLE)req->Pid, req->SignerType);
            }
        }
    }

    WdfRequestCompleteWithInformation(Request, status, 0);
}

VOID EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    ProcessProtectUnload();

    // 【核心修复】Non-PnP 驱动必须在 Unload 中手动调用 WdfObjectDelete 销毁控制设备！
    if (g_Device) {
        WdfObjectDelete(g_Device);
        g_Device = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver unloaded.\n");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loading...\n");

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = EvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] WdfDriverCreate failed: 0x%08X\n", status);
        return status;
    }

    status = CreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] CreateControlDevice failed: 0x%08X\n", status);
        return status;
    }

    status = ProcessProtectInit();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] ProcessProtectInit failed: 0x%08X\n", status);
        // 必须清理已创建的控制设备，否则框架检测到孤立设备 → WDF_VIOLATION
        if (g_Device) {
            WdfObjectDelete(g_Device);
            g_Device = NULL;
        }
        return status;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Driver loaded successfully\n");

    return STATUS_SUCCESS;
}
