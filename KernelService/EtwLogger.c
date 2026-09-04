// EtwLogger.c — ETW 内核 Provider 实现
//
// 核心流程:
//   1. EtwLoggerInit: EtwRegister 注册 Provider
//   2. EtwLogIrpEvent:
//      - 从 IRP 取 IoControlCode / InputBuffer / InputBufferLength
//      - 根据 METHOD_* 决定怎么读 InputBuffer，METHOD_NEITHER 要用 __try
//      - 截断到 ETW_MAX_PAYLOAD_CAPTURE 字节
//      - EtwWrite 发事件，UserData 为固定头 + Payload
//      - ETW 框架自动抓跨态栈
//   3. EtwLoggerUnload: EtwUnregister 注销
//
// 性能:
//   - EtwWrite 无订阅时几乎零开销，只是位掩码判断
//   - 有订阅时 ETW 同步抓栈，走内核高度优化路径
//   - Payload 最多拷 4KB，用栈上缓冲区，不分配池

#include "EtwLogger.h"
#include <ntstrsafe.h>

// ============================================================
// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// 应用层订阅必须用同一个 GUID
// ============================================================

// {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
static const GUID g_IoctlProviderGuid =
{ 0xA7B3C9D2, 0x4E5F, 0x4A1B, { 0x9C, 0x8E, 0x7D, 0x6F, 0x5E, 0x4A, 0x3B, 0x2C } };

static REGHANDLE g_EtwRegHandle = 0;
static BOOLEAN   g_EtwRegistered = FALSE;

// 事件描述符，静态，初始化一次
// EVENT_DESCRIPTOR 字段 (evntprov.h):
//   USHORT Id, UCHAR Version, UCHAR Channel, UCHAR Level,
//   USHORT Task, UCHAR Opcode, ULONGLONG Keyword
static EVENT_DESCRIPTOR g_IoctlEventDesc = { 0 };
static EVENT_DESCRIPTOR g_ImageLoadEventDesc = { 0 };
static EVENT_DESCRIPTOR g_ThreadAntiDebugEventDesc = { 0 };
static BOOLEAN g_EventDescInited = FALSE;

static VOID InitEventDesc(VOID)
{
	if (g_EventDescInited) return;
	g_IoctlEventDesc.Id = ETW_EVENT_IOCTL_INTERCEPT;
	g_IoctlEventDesc.Level = 4;  // TRACE_LEVEL_INFORMATION

	g_ImageLoadEventDesc.Id = ETW_EVENT_IMAGELOAD;
	g_ImageLoadEventDesc.Level = 4;  // TRACE_LEVEL_INFORMATION

	g_ThreadAntiDebugEventDesc.Id = ETW_EVENT_THREAD_ANTIDEBUG;
	g_ThreadAntiDebugEventDesc.Level = 4;  // TRACE_LEVEL_INFORMATION

	g_EventDescInited = TRUE;
}

// ============================================================
// EtwLoggerInit — 注册 Provider
// 在 DriverEntry 中调用
// ============================================================

NTSTATUS EtwLoggerInit(VOID)
{
	if (g_EtwRegistered) {
		return STATUS_SUCCESS;
	}

	NTSTATUS status = EtwRegister(&g_IoctlProviderGuid, NULL, NULL, &g_EtwRegHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] EtwRegister failed: 0x%08X\n", status);
		g_EtwRegHandle = 0;
		return status;
	}

	InitEventDesc();
	g_EtwRegistered = TRUE;
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] ETW Provider registered (GUID=A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C)\n");
	return STATUS_SUCCESS;
}

// ============================================================
// EtwLoggerUnload — 注销 Provider
// 在 EvtDriverUnload 中调用
// ============================================================

VOID EtwLoggerUnload(VOID)
{
	if (g_EtwRegistered && g_EtwRegHandle != 0) {
		EtwUnregister(g_EtwRegHandle);
		g_EtwRegHandle = 0;
		g_EtwRegistered = FALSE;
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] ETW Provider unregistered\n");
	}
}

// ============================================================
// 从 IoControlCode 提取 METHOD，即低 2 位
//   METHOD_BUFFERED    = 0
//   METHOD_IN_DIRECT   = 1
//   METHOD_OUT_DIRECT  = 2
//   METHOD_NEITHER     = 3
// ============================================================

static __forceinline ULONG ExtractMethod(ULONG IoControlCode)
{
	return IoControlCode & 3;
}

// ============================================================
// 安全读取用户态指针 (METHOD_NEITHER)
//
// IRP_MJ_DEVICE_CONTROL 派发时 IRQL = PASSIVE_LEVEL,处于原始进程上下文,
// 可以用 __try / ProbeForRead / RtlCopyMemory 安全读取 Type3InputBuffer。
//
// 返回: 成功拷贝的字节数，可能 < RequestedSize；失败返回 0
// ============================================================

static ULONG SafeCopyUserBuffer(
	_In_opt_ const VOID* UserPtr,
	_In_ ULONG RequestedSize,
	_Out_writes_to_(RequestedSize, return) PUCHAR DestBuffer)
{
	if (UserPtr == NULL || RequestedSize == 0) {
		return 0;
	}

	__try {
		// ProbeForRead 要求 IRQL <= APC_LEVEL,Dispatch 例程满足
		// 对齐要求:1 字节对齐，任意地址都可读
		ProbeForRead((PVOID)UserPtr, RequestedSize, sizeof(UCHAR));
		RtlCopyMemory(DestBuffer, UserPtr, RequestedSize);
		return RequestedSize;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// 用户态传了野指针,直接返回 0,不记录 payload
		return 0;
	}
}

// ============================================================
// EtwLogIrpEvent — 核心:记录一次 IOCTL 拦截事件
//
// 调用上下文:
//   - 由 FilterPassIrp 在 IRP 透传前调用
//   - IRQL = PASSIVE_LEVEL，由用户态发起的同步 IOCTL
//   - 处于原始请求进程上下文，可安全读用户态内存
//
// Payload 抓取策略:
//   - METHOD_BUFFERED / METHOD_IN_DIRECT / METHOD_OUT_DIRECT:
//       InputBuffer 在 SystemBuffer 里，是内核态有效地址，直接拷
//   - METHOD_NEITHER:
//       Type3InputBuffer 是用户态指针,必须 __try + ProbeForRead
//
// 大小处理:
//   - 实际抓取 = min(InputBufferLength, ETW_MAX_PAYLOAD_CAPTURE)
//   - 原始 InputBufferLength 仍然填到 Header 里供分析
// ============================================================

VOID EtwLogIrpEvent(
	_In_ PDEVICE_OBJECT FilterDevice,
	_In_ PDEVICE_OBJECT TargetDevice,
	_In_ ULONG          AttachId,
	_In_ PIRP           Irp,
	_In_ UCHAR          MajorFunction)
{
	UNREFERENCED_PARAMETER(TargetDevice);

	// 未注册直接返回，无开销
	if (!g_EtwRegistered || g_EtwRegHandle == 0) {
		return;
	}

	// 只对 IRP_MJ_DEVICE_CONTROL 抓 payload,其他 MJ (CREATE/CLOSE/READ/WRITE) 只发空事件
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	ULONG ioControlCode = 0;
	ULONG inputBufferLength = 0;
	ULONG method = 0;
	PVOID inputBuffer = NULL;
	BOOLEAN isDeviceControl = (MajorFunction == IRP_MJ_DEVICE_CONTROL);

	if (isDeviceControl) {
		ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
		inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
		method = ExtractMethod(ioControlCode);

		switch (method) {
		case METHOD_BUFFERED:
		case METHOD_IN_DIRECT:
		case METHOD_OUT_DIRECT:
			// SystemBuffer 是内核地址,IoManager 已把用户输入拷进来
			inputBuffer = Irp->AssociatedIrp.SystemBuffer;
			break;
		case METHOD_NEITHER:
			// Type3InputBuffer 是用户态指针,需要 __try 安全读
			inputBuffer = stack->Parameters.DeviceIoControl.Type3InputBuffer;
			break;
		default:
			inputBuffer = NULL;
			break;
		}
	}

	// 实际抓取大小
	ULONG captureSize = 0;
	if (inputBufferLength > 0) {
		captureSize = (inputBufferLength > ETW_MAX_PAYLOAD_CAPTURE)
			? ETW_MAX_PAYLOAD_CAPTURE : inputBufferLength;
	}

	// 栈上 Payload 缓冲区，不分配池，避免高频 IOCTL 时池碎片化
	// 4KB 栈空间在内核 PASSIVE_LEVEL 是安全的，内核栈有 16KB
	UCHAR payloadBuffer[ETW_MAX_PAYLOAD_CAPTURE];
	ULONG actualCaptured = 0;

	if (captureSize > 0) {
		if (method == METHOD_NEITHER) {
			// 用户态指针,安全拷
			actualCaptured = SafeCopyUserBuffer(inputBuffer, captureSize, payloadBuffer);
		}
		else if (inputBuffer != NULL) {
			// 内核态地址,直接拷
			__try {
				RtlCopyMemory(payloadBuffer, inputBuffer, captureSize);
				actualCaptured = captureSize;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				actualCaptured = 0;
			}
		}
	}

	// 构建事件 UserData = Header + Payload
	ETW_IOCTL_EVENT_HEADER header;
	RtlZeroMemory(&header, sizeof(header));
	header.Version = 1;
	header.IoControlCode = ioControlCode;
	header.InputBufferLength = inputBufferLength;
	header.CaptureSize = actualCaptured;
	header.RequestorPid = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
	header.TargetDeviceAddr = (ULONGLONG)TargetDevice;
	header.FilterDeviceAddr = (ULONGLONG)FilterDevice;
	header.AttachId = AttachId;
	header.MajorFunction = MajorFunction;
	header.Method = method;

	// 组装 UserData 描述符
	// 注意:Ptr 字段是 ULONGLONG,EventDataDescCreate 会做指针转 ULONGLONG
	EVENT_DATA_DESCRIPTOR dataDesc[2];
	EventDataDescCreate(&dataDesc[0], &header, sizeof(ETW_IOCTL_EVENT_HEADER));
	EventDataDescCreate(&dataDesc[1], payloadBuffer, actualCaptured);

	// 发事件 — ETW 框架会:
	//   1. 检查是否有 Session 订阅，位掩码判断，极快
	//   2. 若有订阅且开了 STACK_TRACE,同步抓跨态调用栈
	//   3. 把 Header + Payload + 调用栈一起写入 ETW 缓冲区
	NTSTATUS status = EtwWrite(
		g_EtwRegHandle,
		&g_IoctlEventDesc,
		NULL,                // ActivityId
		(actualCaptured > 0) ? 2 : 1,  // UserDataCount
		dataDesc);

	if (!NT_SUCCESS(status)) {
		// EtwWrite 失败不影响 IOCTL 透传,只记录日志
		// 常见失败:无订阅对应 STATUS_INVALID_HANDLE，事件太大对应 STATUS_BUFFER_OVERFLOW
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] EtwWrite failed: 0x%08X (ICC=0x%08X, CaptureSize=%lu)\n",
			status, ioControlCode, actualCaptured);
	}
}

// ============================================================
// EtwLogImageLoadEvent — 记录一次 ImageLoad 事件
//
// 调用上下文:
//   - 由 GameProtect 的 PsSetLoadImageNotifyRoutine 回调调用
//   - 用户态 DLL 加载时回调在 PASSIVE_LEVEL,不能阻塞
//   - FullImageName 指针仅在回调生命周期内有效,这里立即深拷贝进
//     UserData 会被 EtwWrite 再拷贝到 ETW 缓冲区,回调返回后安全
// ============================================================

VOID EtwLogImageLoadEvent(
	_In_ HANDLE          ProcessId,
	_In_ HANDLE          initiatorPid,
	_In_ PUNICODE_STRING FullImageName,
	_In_ ULONG_PTR       ImageBase,
	_In_ ULONG           ImageSize)
{
	// 未注册直接返回，无开销
	if (!g_EtwRegistered || g_EtwRegHandle == 0) {
		return;
	}

	// 深拷贝映像路径到栈上缓冲区，回调内不分配池
	WCHAR nameBuffer[ETW_MAX_IMAGENAME_BYTES / sizeof(WCHAR)];
	ULONG nameBytes = 0;

	if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
		nameBytes = FullImageName->Length;
		if (nameBytes > ETW_MAX_IMAGENAME_BYTES) {
			nameBytes = ETW_MAX_IMAGENAME_BYTES;
		}
		RtlCopyMemory(nameBuffer, FullImageName->Buffer, nameBytes);
	}

	ETW_IMAGELOAD_EVENT_HEADER header;
	RtlZeroMemory(&header, sizeof(header));
	header.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
	header.InitiatorPid = (ULONGLONG)(ULONG_PTR)initiatorPid;
	header.ImageBase = (ULONGLONG)ImageBase;
	header.ImageSize = ImageSize;
	header.ImageNameBytes = nameBytes;

	// 组装 UserData 描述符 = Header + 深拷贝的 ImageName
	EVENT_DATA_DESCRIPTOR dataDesc[2];
	EventDataDescCreate(&dataDesc[0], &header, sizeof(ETW_IMAGELOAD_EVENT_HEADER));
	EventDataDescCreate(&dataDesc[1], nameBuffer, nameBytes);

	NTSTATUS status = EtwWrite(
		g_EtwRegHandle,
		&g_ImageLoadEventDesc,
		NULL,                    // ActivityId
		(nameBytes > 0) ? 2 : 1, // UserDataCount
		dataDesc);

	if (!NT_SUCCESS(status)) {
		// EtwWrite 失败只记录日志,不影响映像加载
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] EtwWrite(ImageLoad) failed: 0x%08X\n", status);
	}
}

// ============================================================
// EtwLogThreadAntiDebugEvent — 记录一次线程反调试事件
//
// 调用上下文:
//   - 由 GameProtect 的 PsSetCreateThreadNotifyRoutine 回调调用
//   - 线程创建回调在 PASSIVE_LEVEL,不能阻塞
//   - 固定 24 字节,无变长数据,直接发
// ============================================================

VOID EtwLogThreadAntiDebugEvent(
	_In_ HANDLE CreatorPid,
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId)
{
	// 未注册直接返回，无开销
	if (!g_EtwRegistered || g_EtwRegHandle == 0) {
		return;
	}

	ETW_THREAD_ANTIDEBUG_EVENT_HEADER header;
	RtlZeroMemory(&header, sizeof(header));
	header.CreatorPid = (ULONGLONG)(ULONG_PTR)CreatorPid;
	header.ProcessId = (ULONGLONG)(ULONG_PTR)ProcessId;
	header.ThreadId = (ULONGLONG)(ULONG_PTR)ThreadId;

	EVENT_DATA_DESCRIPTOR dataDesc[1];
	EventDataDescCreate(&dataDesc[0], &header, sizeof(ETW_THREAD_ANTIDEBUG_EVENT_HEADER));

	NTSTATUS status = EtwWrite(
		g_EtwRegHandle,
		&g_ThreadAntiDebugEventDesc,
		NULL,                    // ActivityId
		1,                       // UserDataCount
		dataDesc);

	if (!NT_SUCCESS(status)) {
		// EtwWrite 失败只记录日志,不影响线程创建
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] EtwWrite(ThreadAntiDebug) failed: 0x%08X\n", status);
	}
}
