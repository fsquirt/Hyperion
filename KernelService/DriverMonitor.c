#include "DriverMonitor.h"


// 驱动加载监控 - 反向调用实现，KMDF 版
//
// 数据流:
//   UserService: DeviceIoControl(IOCTL_WAIT_LOADIMAGE, OVERLAPPED) → 挂起
//   驱动 EvtIoDeviceControl: 收到 WDFREQUEST → WdfRequestMarkCancelableEx → 入队 → 返回 STATUS_PENDING
//   内核回调 DriverMonitorLoadImageNotify:
//     过滤 ProcessId==0 && .sys → 从队列取 WDFREQUEST → 填数据 → WdfRequestCompleteWithInformation
//   UserService: WaitForSingleObject 返回 → 读缓冲区 → Shutdown


#define LOADIMAGE_POOL_TAG 'LBKI'

// pending WDFREQUEST 队列节点
typedef struct _PENDING_REQUEST_ENTRY {
	LIST_ENTRY  ListEntry;
	WDFREQUEST  Request;
} PENDING_REQUEST_ENTRY, * PPENDING_REQUEST_ENTRY;

// 全局队列
static KSPIN_LOCK g_QueueLock;
static LIST_ENTRY g_QueueHead;
static BOOLEAN    g_Initialized = FALSE;


// 取消回调，WDFREQUEST 被取消时调用，如 UserService 关闭设备句柄

static VOID EvtRequestCancel(_In_ WDFREQUEST Request)
{
	// 从队列中找到并移除该 Request
	KIRQL oldIrql = PASSIVE_LEVEL;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);

	PLIST_ENTRY pEntry = g_QueueHead.Flink;
	while (pEntry != &g_QueueHead) {
		PPENDING_REQUEST_ENTRY entry = CONTAINING_RECORD(pEntry, PENDING_REQUEST_ENTRY, ListEntry);
		if (entry->Request == Request) {
			RemoveEntryList(pEntry);
			KeReleaseSpinLock(&g_QueueLock, oldIrql);

			ExFreePoolWithTag(entry, LOADIMAGE_POOL_TAG);
			WdfRequestCompleteWithInformation(Request, STATUS_CANCELLED, 0);

			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] DriverMonitor: Request cancelled by framework\n");
			return;
		}
		pEntry = pEntry->Flink;
	}

	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	// 没找到，可能刚被回调取走即将完成，让回调处理
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
		"[KernelService] DriverMonitor: Cancel callback: request not in queue\n");
}


// 初始化 / 卸载


NTSTATUS DriverMonitorInit(VOID)
{
	KeInitializeSpinLock(&g_QueueLock);
	InitializeListHead(&g_QueueHead);
	g_Initialized = TRUE;

	NTSTATUS status = PsSetLoadImageNotifyRoutine(
		(PLOAD_IMAGE_NOTIFY_ROUTINE)DriverMonitorLoadImageNotify);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverMonitorInit: PsSetLoadImageNotifyRoutine failed: 0x%08X\n",
			status);
		g_Initialized = FALSE;
		return status;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: Load-image notify registered (KMDF reverse-call mode)\n");

	return STATUS_SUCCESS;
}

VOID DriverMonitorUnload(VOID)
{
	// 1. 先移除回调,防止新触发
	PsRemoveLoadImageNotifyRoutine(
		(PLOAD_IMAGE_NOTIFY_ROUTINE)DriverMonitorLoadImageNotify);

	// 2. 取消所有 pending WDFREQUEST
	DriverMonitorCancelAllPendingRequests();

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: Unloaded\n");
}


// WDFREQUEST 队列管理


// 挂起 WDFREQUEST 入队，由 EvtIoDeviceControl 调用
NTSTATUS DriverMonitorQueuePendingRequest(_In_ WDFREQUEST Request)
{
	if (!g_Initialized) {
		return STATUS_UNSUCCESSFUL;
	}

	PPENDING_REQUEST_ENTRY entry = (PPENDING_REQUEST_ENTRY)ExAllocatePool2(
		POOL_FLAG_NON_PAGED, sizeof(PENDING_REQUEST_ENTRY), LOADIMAGE_POOL_TAG);
	if (entry == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	entry->Request = Request;

	// 注册取消回调，UserService 关闭句柄时 WDF 会触发，避免泄漏
	// WdfRequestMarkCancelableEx 返回 NTSTATUS，WdfRequestMarkCancelable 返回 VOID 不可用
	NTSTATUS status = WdfRequestMarkCancelableEx(Request, EvtRequestCancel);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(entry, LOADIMAGE_POOL_TAG);
		return status;
	}

	KIRQL oldIrql = PASSIVE_LEVEL;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);
	InsertTailList(&g_QueueHead, &entry->ListEntry);
	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: Request queued (pending)\n");

	return STATUS_PENDING;
}

// 取消所有 pending WDFREQUEST，由 Unload 或 IOCTL_CANCEL_LOADIMAGE 调用
VOID DriverMonitorCancelAllPendingRequests(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: CancelAllPendingRequests ENTERED\n");

	KIRQL oldIrql = PASSIVE_LEVEL;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);

	if (IsListEmpty(&g_QueueHead)) {
		KeReleaseSpinLock(&g_QueueLock, oldIrql);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] DriverMonitor: CancelAll: queue empty, nothing to cancel\n");
		return;
	}

	while (!IsListEmpty(&g_QueueHead)) {
		PLIST_ENTRY pEntry = RemoveHeadList(&g_QueueHead);
		PPENDING_REQUEST_ENTRY entry = CONTAINING_RECORD(pEntry, PENDING_REQUEST_ENTRY, ListEntry);

		WDFREQUEST request = entry->Request;

		// 释放锁后再操作，因为完成/Unmark 可能触发 WDF 回调
		KeReleaseSpinLock(&g_QueueLock, oldIrql);

		ExFreePoolWithTag(entry, LOADIMAGE_POOL_TAG);

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] DriverMonitor: CancelAll: processing Request=%p\n", request);

		// WdfRequestUnmarkCancelable 返回值:
		//   STATUS_SUCCESS    - 已成功 unmark,本线程获得完成权
		//   STATUS_CANCELLED  - 框架已在调用/已调用 EvtRequestCancel,本线程不能完成
		//   其他              - 状态异常,不要完成
		// 不检查返回值直接 Complete 会造成双重完成 → WDF_VIOLATION 蓝屏
		NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(request);
		if (NT_SUCCESS(unmarkStatus)) {
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
				"[KernelService] DriverMonitor: CancelAll: Unmark SUCCESS, completing with STATUS_CANCELLED\n");
			WdfRequestCompleteWithInformation(request, STATUS_CANCELLED, 0);
		}
		else {
			// STATUS_CANCELLED 等: 框架正在/已经通过 EvtRequestCancel 完成此请求
			// 不能再次完成,否则 WDF_VIOLATION
			DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
				"[KernelService] DriverMonitor: CancelAll: Unmark returned 0x%08X, framework owns completion\n",
				unmarkStatus);
		}

		KeAcquireSpinLock(&g_QueueLock, &oldIrql);
	}

	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: CancelAllPendingRequests EXITED\n");
}


// 映像加载回调


// 检查 Unicode 字符串是否以 .sys 结尾，不区分大小写
static BOOLEAN IsSysExtension(_In_ PCUNICODE_STRING Name)
{
	if (Name == NULL || Name->Buffer == NULL || Name->Length < sizeof(WCHAR) * 4) {
		return FALSE;
	}
	USHORT offset = (USHORT)(Name->Length - sizeof(WCHAR) * 4);
	PWCHAR p = (PWCHAR)((PUCHAR)Name->Buffer + offset);
	return (p[0] == L'.' &&
		(p[1] == L's' || p[1] == L'S') &&
		(p[2] == L'y' || p[2] == L'Y') &&
		(p[3] == L's' || p[3] == L'S'));
}

VOID DriverMonitorLoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo)
{
	// DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[KernelService] LoadImage Triggered: %wZ\n", FullImageName);

	UNREFERENCED_PARAMETER(ProcessId);

	// 1. 只监控内核驱动加载
	//    不要用 ProcessId == 0 判断! sc start 动态加载的驱动 ProcessId 是 services.exe/System PID
	//    必须用 IMAGE_INFO.SystemModeImage 标志位,1 = 内核模块
	if (!ImageInfo->SystemModeImage) {
		// DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[KernelService] DriverMonitor: SKIP (SystemModeImage=0, user-mode image): %wZ\n", FullImageName);
		return;
	}

	// DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[KernelService] DriverMonitor: Kernel image detected: %wZ\n", FullImageName);

	// 打进内核的驱动不一定是sys后缀
	// 2. 只过滤 .sys 后缀
	//if (!IsSysExtension(FullImageName)) {
		// DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,"[KernelService] DriverMonitor: SKIP (not .sys): %wZ\n", FullImageName);
	//	return;
	//}

	// 3. 从队列取一个 pending WDFREQUEST
	KIRQL oldIrql = PASSIVE_LEVEL;
	KeAcquireSpinLock(&g_QueueLock, &oldIrql);

	if (IsListEmpty(&g_QueueHead)) {
		KeReleaseSpinLock(&g_QueueLock, oldIrql);
		// 没有等待的 UserService,事件丢失
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] DriverMonitor: EVENT LOST - no pending request in queue! (%wZ)\n",
			FullImageName);
		return;
	}

	PLIST_ENTRY pEntry = RemoveHeadList(&g_QueueHead);
	PPENDING_REQUEST_ENTRY entry = CONTAINING_RECORD(pEntry, PENDING_REQUEST_ENTRY, ListEntry);

	KeReleaseSpinLock(&g_QueueLock, oldIrql);

	WDFREQUEST request = entry->Request;
	ExFreePoolWithTag(entry, LOADIMAGE_POOL_TAG);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: LoadImageNotify: UnmarkCancelable Request=%p\n", request);

	// 4. 取消"可取消"标记，现在由我们完成，不是被框架取消
	// WdfRequestUnmarkCancelable 返回:
	//   STATUS_SUCCESS     - 已成功 unmark,本回调获得完成权
	//   STATUS_CANCELLED   - 框架正在/已调用 EvtRequestCancel，即 UserService 关句柄触发的 cancel,
	//                        本回调不能完成此请求,否则双重完成 → WDF_VIOLATION
	NTSTATUS unmarkStatus = WdfRequestUnmarkCancelable(request);
	if (!NT_SUCCESS(unmarkStatus)) {
		// 请求已被框架取消，UserService 关闭了句柄，不要完成它
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] DriverMonitor: LoadImageNotify: Unmark returned 0x%08X (already cancelled), skipping\n",
			unmarkStatus);
		return;
	}

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverMonitor: LoadImageNotify: Unmark SUCCESS, completing request\n");

	// 5. 填充通知数据
	PLOADIMAGE_NOTIFY notify = NULL;
	size_t outBufLen = 0;
	NTSTATUS status = WdfRequestRetrieveOutputBuffer(
		request, sizeof(LOADIMAGE_NOTIFY), (PVOID*)&notify, &outBufLen);

	if (NT_SUCCESS(status) && notify != NULL) {
		// WdfRequestRetrieveOutputBuffer 第二参数为 sizeof(LOADIMAGE_NOTIFY),
		// 返回 success 即保证 outBufLen >= sizeof(LOADIMAGE_NOTIFY)。
		// 这里显式取 min 让静态分析器看到我们在比较,避免 C6386 误报。
		size_t zeroBytes = outBufLen < sizeof(LOADIMAGE_NOTIFY) ? outBufLen : sizeof(LOADIMAGE_NOTIFY);
		RtlZeroMemory(notify, zeroBytes);
		notify->ImageBase = (ULONG_PTR)ImageInfo->ImageBase;
		notify->ImageSize = (ULONG)ImageInfo->ImageSize;

		ULONG copyBytes = (ULONG)FullImageName->Length;
		ULONG maxBytes = sizeof(notify->ImageName) - sizeof(WCHAR);
		if (copyBytes > maxBytes) copyBytes = maxBytes;
		RtlCopyMemory(notify->ImageName, FullImageName->Buffer, copyBytes);

		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] DriverMonitor: NEW driver load detected: %wZ (completing request)\n",
			FullImageName);

		WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(LOADIMAGE_NOTIFY));
	}
	else {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverMonitor: RetrieveOutputBuffer failed: 0x%08X\n", status);
		WdfRequestCompleteWithInformation(request, STATUS_BUFFER_TOO_SMALL, 0);
	}
}
