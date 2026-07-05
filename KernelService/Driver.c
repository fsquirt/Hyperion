// ntifs.h 必须在 ntddk.h/wdm.h 之前 include(否则 PEPROCESS 等类型重定义)
// DriverNameResolver.h 里用到 ZwOpenDirectoryObject,需要 ntifs.h
#include <ntifs.h>
#include "Driver.h"
#include "ProcessProtect.h"
#include "DriverMonitor.h"
#include "DriverScanner.h"
#include "DriverDevices.h"
#include "DriverNameResolver.h"

#define IOCTL_SET_PPL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_TERMINATE_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WAIT_LOADIMAGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CANCEL_LOADIMAGE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SDDL: SYSTEM full access, Admins full access, Users read+execute
// 不能用 SDDL_DEVOBJ_* 宏，链接会找不到符号（需要 wdmsec.lib）
DECLARE_CONST_UNICODE_STRING(g_Sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;WD)");

typedef struct _PPL_REQUEST {
	ULONG_PTR Pid;
	UCHAR SignerType;
} PPL_REQUEST, * PPPL_REQUEST;

typedef struct _TERMINATE_REQUEST {
	ULONG_PTR Pid;
} TERMINATE_REQUEST, * PTERMINATE_REQUEST;

#define DEVICE_NAME     L"\\Device\\KernelService"
#define SYMLINK_NAME    L"\\DosDevices\\KernelService"

// 全局变量保存设备对象，以便在卸载时删除
WDFDEVICE g_Device = NULL;

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
	// 允许同时打开多个句柄。
	// 原因: UserService 主监控线程持有一个长生命周期句柄发 IOCTL_WAIT_LOADIMAGE
	//       (挂起),Cleanup 时需要再用一个短生命周期句柄同步发 IOCTL_CANCEL_LOADIMAGE。
	//       若 Exclusive=TRUE,第二个 CreateFile 返回 ERROR_ACCESS_DENIED;
	//       若用同一句柄发同步 IO,会被前面挂起的 overlapped IRP 阻塞。
	// 安全由 SDDL(仅 SYSTEM/Admins 可访问)+ 后续证书校验保证,不依赖 Exclusive。
	WdfDeviceInitSetExclusive(pDeviceInit, FALSE);

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

	// 创建符号链接
	status = WdfDeviceCreateSymbolicLink(device, &symLink);
	if (!NT_SUCCESS(status)) {
		// 如果这里失败，设备已经是"半成品"，直接 return 会导致 KMDF 抛出 WDF_VIOLATION！
		// 必须手动销毁刚创建的 device
		WdfObjectDelete(device);
		return status;
	}

	WDF_IO_QUEUE_CONFIG queueConfig;
	WDFQUEUE queue;

	// 必须用 Parallel!不能用 Sequential。
	// 原因: IOCTL_WAIT_LOADIMAGE 收到后会挂起入队 (return STATUS_PENDING,不 Complete),
	//       Sequential 队列会阻塞后续所有 IOCTL 直到该请求完成 → IOCTL_CANCEL_LOADIMAGE
	//       永远进不来 EvtIoDeviceControl,导致 UserService 无法通知驱动取消,死锁。
	//       Parallel 队列允许并发 dispatch,挂起的 WAIT_LOADIMAGE 不阻塞 CANCEL_LOADIMAGE。
	// 并发安全: ProcessProtect 的 g_ProtectionOffset 在 Init 后只读;
	//          DriverMonitor 的队列用 KSPIN_LOCK 保护。
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
	queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

	// 创建 I/O 队列
	status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
	if (!NT_SUCCESS(status)) {
		// 同样，如果这里失败，必须手动销毁 device
		WdfObjectDelete(device);
		return status;
	}

	// 控制设备创建完毕，通知框架
	WdfControlFinishInitializing(device);

	// 保存到全局变量，留给 Unload 使用
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
	else if (IoControlCode == IOCTL_TERMINATE_PROCESS) {
		if (InputBufferLength < sizeof(TERMINATE_REQUEST)) {
			status = STATUS_BUFFER_TOO_SMALL;
		}
		else {
			PTERMINATE_REQUEST req = NULL;
			size_t reqSize = 0;

			status = WdfRequestRetrieveInputBuffer(Request, sizeof(TERMINATE_REQUEST), (PVOID*)&req, &reqSize);
			if (NT_SUCCESS(status) && req) {
				status = TerminateProcessByPid((HANDLE)req->Pid);
			}
		}
	}
	else if (IoControlCode == IOCTL_WAIT_LOADIMAGE) {
		// 反向调用: 挂起 WDFREQUEST,等回调触发时完成
		// 输出缓冲区必须能容纳 LOADIMAGE_NOTIFY
		if (OutputBufferLength < sizeof(LOADIMAGE_NOTIFY)) {
			WdfRequestCompleteWithInformation(Request, STATUS_BUFFER_TOO_SMALL, 0);
			return;
		}
		// 入队挂起;成功返回 STATUS_PENDING,失败返回错误码
		status = DriverMonitorQueuePendingRequest(Request);
		if (status == STATUS_PENDING) {
			// 请求已挂起,不要在此完成,等待回调触发完成
			return;
		}
		// 入队失败,完成请求
		WdfRequestCompleteWithInformation(Request, status, 0);
		return;
	}
	else if (IoControlCode == IOCTL_CANCEL_LOADIMAGE) {
		// UserService 主动通知驱动:游戏要退出了,请立即完成所有挂起的
		// IOCTL_WAIT_LOADIMAGE IRP(用 STATUS_CANCELLED 完成)。
		// 这是为了绕过 WDF cancel 机制(CancelIoEx → EvtRequestCancel 路径不可靠):
		//   - 用户态调 CancelIoEx 后,IO Manager 不会立即让 IRP 完成
		//   - CloseHandle 也会因 IRP 未完成而阻塞
		// 由 UserService 在 Cleanup 早期同步调用本 IOCTL,
		// 驱动在此直接把挂起的 WDFREQUEST 完成掉,IRP 立即归零,
		// 用户态 WaitForSingleObject(hEvent) 立即返回,CloseHandle 不阻塞。
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] IOCTL_CANCEL_LOADIMAGE received, completing pending requests\n");
		DriverMonitorCancelAllPendingRequests();
		status = STATUS_SUCCESS;
	}
	else if (IoControlCode == IOCTL_SCAN_LOADED_DRIVERS) {
		// DriverAttachSelector / UserService 调用:扫描已加载内核驱动模块列表
		// 驱动用 ZwQuerySystemInformation(SystemModuleInformation) 扫描,
		// 把模块列表(基址/大小/路径)填到输出缓冲区返回给应用层。
		// 应用层拿到列表后用 WinVerifyTrust 验签,决定哪些驱动要附着。
		//
		// 注意:本 IOCTL 是同步完成,不挂起
		// DriverScannerHandleIoctl 内部已用 WdfRequestSetInformation 设置实际返回字节数
		status = DriverScannerHandleIoctl(Request, InputBufferLength, OutputBufferLength);

		// 用实际返回字节数(由 DriverScannerHandleIoctl 设置)完成请求
		ULONG_PTR info = 0;
		if (NT_SUCCESS(status)) {
			info = WdfRequestGetInformation(Request);
		} else if (status == STATUS_BUFFER_TOO_SMALL) {
			// 缓冲区不够,把所需大小通过 IoStatus.Information 返回给应用层
			info = WdfRequestGetInformation(Request);
		}
		WdfRequestCompleteWithInformation(Request, status, info);
		return; // 已完成,不要再走下面的通用完成路径
	}
	else if (IoControlCode == IOCTL_ENUM_DRIVER_DEVICES) {
		// DriverAttachSelector 调用:把待附着驱动名传进来,内核扫该驱动的设备列表
		// 内核用 ObReferenceObjectByName 找 DRIVER_OBJECT (\Driver 或 \FileSystem),
		// 遍历 DeviceObject->NextDevice 链,返回每个设备的地址/类型/名字/栈深等。
		// 应用层拿到设备列表后,后续可发新的 IOCTL 让驱动 IoAttachDeviceToDeviceStack。
		//
		// 注意:本 IOCTL 同步完成,不挂起
		status = DriverDevicesHandleIoctl(Request, InputBufferLength, OutputBufferLength);

		ULONG_PTR info = 0;
		if (NT_SUCCESS(status)) {
			info = WdfRequestGetInformation(Request);
		} else if (status == STATUS_BUFFER_TOO_SMALL) {
			info = WdfRequestGetInformation(Request);
		}
		// STATUS_OBJECT_NAME_NOT_FOUND 时驱动已填好响应头(EntryCount=0),按成功完成
		if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
			info = WdfRequestGetInformation(Request);
			WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, info);
			return;
		}
		WdfRequestCompleteWithInformation(Request, status, info);
		return;
	}

	WdfRequestCompleteWithInformation(Request, status, 0);
}

VOID EvtDriverUnload(_In_ WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);

	// 最先移除驱动加载监控,防止卸载过程中回调触发访问已释放资源
	DriverMonitorUnload();

	// 卸载驱动扫描器(无状态,目前仅打印日志)
	DriverScannerUnload();

	// 卸载设备列表扫描器(无状态)
	DriverDevicesUnload();

	// 卸载驱动名解析器(无状态)
	DriverNameResolverUnload();

	ProcessProtectUnload();

	// Non-PnP 驱动必须在 Unload 中手动调用 WdfObjectDelete 销毁控制设备！
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

	// 注册驱动加载监控 (放在最后,确保其他模块已就绪)
	status = DriverMonitorInit();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverMonitorInit failed: 0x%08X\n", status);
		ProcessProtectUnload();
		if (g_Device) {
			WdfObjectDelete(g_Device);
			g_Device = NULL;
		}
		return status;
	}

	// 初始化驱动模块扫描器(无状态,目前仅打印日志)
	status = DriverScannerInit();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverScannerInit failed: 0x%08X\n", status);
		DriverMonitorUnload();
		ProcessProtectUnload();
		if (g_Device) {
			WdfObjectDelete(g_Device);
			g_Device = NULL;
		}
		return status;
	}

	// 初始化设备列表扫描器(无状态)
	status = DriverDevicesInit();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverDevicesInit failed: 0x%08X\n", status);
		DriverScannerUnload();
		DriverMonitorUnload();
		ProcessProtectUnload();
		if (g_Device) {
			WdfObjectDelete(g_Device);
			g_Device = NULL;
		}
		return status;
	}

	// 初始化驱动名解析器(无状态)
	status = DriverNameResolverInit();
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverNameResolverInit failed: 0x%08X\n", status);
		DriverDevicesUnload();
		DriverScannerUnload();
		DriverMonitorUnload();
		ProcessProtectUnload();
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
