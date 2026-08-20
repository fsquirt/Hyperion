#include "DriverDevices.h"
#include <ntstrsafe.h>

// ============================================================
// 驱动设备列表扫描实现
//
// 流程:
//   1. ObReferenceObjectByName(L"\\Driver\\<Name>", *IoDriverObjectType)
//      拿到 PDRIVER_OBJECT;找不到再试 \FileSystem\<Name>
//   2. 遍历 DriverObject->DeviceObject -> NextDevice 链表
//   3. 每个设备用 ObQueryNameString 查设备名,数 AttachedDevice 链表长度
//
// 注意:
//   - ObReferenceObjectByName 是 ntoskrnl 未文档化但导出的 API
//   - IoDriverObjectType 是 ntoskrnl 导出的全局变量 (POBJECT_TYPE*)
//   - 遍历 DeviceObject 链时,设备可能随时被创建/销毁,这里 best-effort,
//     不加锁(锁也只能保证单次 Next 不变,链表整体仍可能变化)
//   - 设备对象指针必须 ObDereferenceObject 释放引用
// ============================================================

#define DEV_POOL_TAG 'DDKD'   // 'DKDD' 倒过来

// ntoskrnl 未文档化但导出
// 注意:必须声明为 POBJECT_TYPE* 并在调用时解引用 (*IoDriverObjectType)。
//   IoDriverObjectType 是 ntoskrnl 导出的全局变量,但其导出符号指向的是
//   一个 POBJECT_TYPE 指针的存储槽(导入表地址),不解引用会拿到无意义的
//   导入表地址,ObReferenceObjectByName 内部对象类型校验会失败,静默返回
//   STATUS_OBJECT_TYPE_MISMATCH,结果就是"驱动找不到"。
extern POBJECT_TYPE* IoDriverObjectType;

// ObReferenceObjectByName 真实签名有 8 个参数(在 AccessState 和 ObjectType 之间
// 还有一个 ACCESS_MASK DesiredAccess)。少声明这个参数会导致 x64 调用约定下
// 所有后续参数错位:ObjectType 拿到 KernelMode(0)、Object 输出指针读到栈上
// 随机残骸(实测是 DbgPrint 字符串 "[KernelService] " 的尾部 "ervice]"),
// 内核往这个野指针写入 → 0xc0000005 蓝屏 (BUGCHECK 3b)
NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectName,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_In_opt_ PVOID ParseContext,
	_Out_ PVOID* Object);

// ObQueryNameString 在某些 WDK 版本 ntddk.h 中未声明,手动 extern
NTKERNELAPI NTSTATUS NTAPI ObQueryNameString(
	_In_ PVOID Object,
	_Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION NameInfo,
	_In_ ULONG Length,
	_Out_ PULONG ReturnLength);

// ------------------------------------------------------------
// 内部:尝试在指定目录 (\Driver 或 \FileSystem) 下找驱动对象
// 成功返回 PDRIVER_OBJECT (已 ObReferenceObject);失败返回 NULL
// ------------------------------------------------------------
static PDRIVER_OBJECT ReferenceDriverByName(
	_In_ PCWSTR DirPrefix,         // 如 L"\\Driver\\"
	_In_ PCWSTR DriverName,        // 如 L"ahflt"
	_Out_writes_z_(cchPathBuf) PWSTR PathBuf,
	_In_ USHORT cchPathBuf)
{
	// 拼出完整对象路径 "\Driver\<Name>" 或 "\FileSystem\<Name>"
	UNICODE_STRING name;
	WCHAR stackBuf[96];

	name.Buffer = stackBuf;
	name.Length = 0;
	name.MaximumLength = sizeof(stackBuf);

	NTSTATUS s = RtlStringCbPrintfW(
		stackBuf, sizeof(stackBuf), L"%ws%ws", DirPrefix, DriverName);
	if (!NT_SUCCESS(s)) return NULL;

	name.Length = (USHORT)(wcsnlen_s(stackBuf, RTL_NUMBER_OF(stackBuf)) * sizeof(WCHAR));

	// 同时回写到调用方的 PathBuf(诊断用)
	if (PathBuf && cchPathBuf > 0) {
		wcsncpy_s(PathBuf, cchPathBuf, stackBuf, _TRUNCATE);
	}

	PVOID obj = NULL;
	s = ObReferenceObjectByName(
		&name, OBJ_CASE_INSENSITIVE,
		NULL, 0,                   // DesiredAccess = 0
		*IoDriverObjectType,       // 必须解引用!IoDriverObjectType 是 POBJECT_TYPE*,
		// 解引用后才是真正的 POBJECT_TYPE
		KernelMode, NULL, &obj);

	if (!NT_SUCCESS(s) || obj == NULL) return NULL;
	return (PDRIVER_OBJECT)obj;
}

// ------------------------------------------------------------
// 内部:数 AttachedDevice 链表长度 (不持锁,best-effort)
// ------------------------------------------------------------
static USHORT CountAttachedDevices(PDEVICE_OBJECT pDev)
{
	USHORT count = 0;
	PDEVICE_OBJECT pAttached = pDev->AttachedDevice;
	while (pAttached) {
		count++;
		// 防御性:链表坏了不死循环
		if (count > 256) break;
		pAttached = pAttached->AttachedDevice;
	}
	return count;
}

// ------------------------------------------------------------
// 内部:取设备名 (ObQueryNameString)
// 设备创建时如果调用 IoCreateDevice 指定了 DeviceName,
// 这里能拿到 "\Device\<Name>";未命名的返回 "(unnamed)"
// ------------------------------------------------------------
static VOID QueryDeviceName(PDEVICE_OBJECT pDev,
	_Out_writes_z_(cchDest) PWSTR pDest,
	_In_ USHORT cchDest)
{
	if (cchDest == 0 || pDest == NULL) return;
	pDest[0] = L'\0';

	// 第一次拿所需大小
	ULONG needed = 0;
	NTSTATUS s = ObQueryNameString(pDev, NULL, 0, &needed);
	if (s != STATUS_INFO_LENGTH_MISMATCH || needed == 0) {
		wcsncpy_s(pDest, cchDest, L"(unnamed)", _TRUNCATE);
		return;
	}

	// 在栈上分配(单设备名一般 < 1KB)
	if (needed > 4096) needed = 4096;
	BYTE stackBuf[4096];
	POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)stackBuf;

	s = ObQueryNameString(pDev, pNameInfo, needed, &needed);
	if (!NT_SUCCESS(s)) {
		wcsncpy_s(pDest, cchDest, L"(unnamed)", _TRUNCATE);
		return;
	}

	if (pNameInfo->Name.Length == 0 || pNameInfo->Name.Buffer == NULL) {
		wcsncpy_s(pDest, cchDest, L"(unnamed)", _TRUNCATE);
		return;
	}

	// 复制到调用方缓冲区(定长)
	ULONG copyChars = pNameInfo->Name.Length / sizeof(WCHAR);
	if (copyChars >= (ULONG)cchDest) copyChars = cchDest - 1;
	RtlCopyMemory(pDest, pNameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
	pDest[copyChars] = L'\0';
}

// ------------------------------------------------------------
// 初始化 / 卸载 (本模块无状态)
// ------------------------------------------------------------
NTSTATUS DriverDevicesInit(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverDevices: initialized\n");
	return STATUS_SUCCESS;
}

VOID DriverDevicesUnload(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverDevices: unloaded\n");
}

// ------------------------------------------------------------
// 主处理函数:处理 IOCTL_ENUM_DRIVER_DEVICES
// ------------------------------------------------------------
NTSTATUS DriverDevicesHandleIoctl(
	_In_ WDFREQUEST Request,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength)
{
	NTSTATUS status;

	// 1. 校验输入
	if (InputBufferLength < sizeof(ENUM_DRIVER_DEVICES_REQUEST)) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	PENUM_DRIVER_DEVICES_REQUEST pReq = NULL;
	status = WdfRequestRetrieveInputBuffer(
		Request, sizeof(ENUM_DRIVER_DEVICES_REQUEST), (PVOID*)&pReq, NULL);
	if (!NT_SUCCESS(status)) return status;

	// 强制以 \0 结尾,防越界
	pReq->DriverName[RTL_NUMBER_OF(pReq->DriverName) - 1] = L'\0';

	// 2. 找驱动对象:先 \Driver,再 \FileSystem
	WCHAR foundPath[96] = { 0 };
	PDRIVER_OBJECT pDrvObj = ReferenceDriverByName(
		L"\\Driver\\", pReq->DriverName, foundPath, RTL_NUMBER_OF(foundPath));

	if (pDrvObj == NULL) {
		pDrvObj = ReferenceDriverByName(
			L"\\FileSystem\\", pReq->DriverName, foundPath, RTL_NUMBER_OF(foundPath));
	}

	if (pDrvObj == NULL) {
		// 找不到驱动 — 输出一个空响应告诉应用层
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
			"[KernelService] DriverDevices: driver '%ws' not found\n", pReq->DriverName);

		// 若输出缓冲区放得下响应头,就填一个 Status=NOT_FOUND
		if (OutputBufferLength >= sizeof(ENUM_DRIVER_DEVICES_RESPONSE)) {
			PENUM_DRIVER_DEVICES_RESPONSE pResp = NULL;
			status = WdfRequestRetrieveOutputBuffer(
				Request, sizeof(ENUM_DRIVER_DEVICES_RESPONSE),
				(PVOID*)&pResp, NULL);
			if (NT_SUCCESS(status) && pResp) {
				pResp->EntryCount = 0;
				pResp->TotalCount = 0;
				pResp->NeededOutputBytes = sizeof(ENUM_DRIVER_DEVICES_RESPONSE);
				pResp->Status = STATUS_OBJECT_NAME_NOT_FOUND;
				wcsncpy_s(pResp->FoundPath, RTL_NUMBER_OF(pResp->FoundPath),
					L"(not found)", _TRUNCATE);
				WdfRequestSetInformation(Request,
					(ULONG_PTR)sizeof(ENUM_DRIVER_DEVICES_RESPONSE));
				return STATUS_SUCCESS;
			}
		}
		WdfRequestSetInformation(Request,
			(ULONG_PTR)sizeof(ENUM_DRIVER_DEVICES_RESPONSE));
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	// 3. 数 DeviceObject 链表上有多少设备
	ULONG totalCount = 0;
	for (PDEVICE_OBJECT p = pDrvObj->DeviceObject; p != NULL; p = p->NextDevice) {
		totalCount++;
		if (totalCount > 4096) break; // 防御性
	}

	// 4. 决定返回多少条
	ULONG maxEntries = pReq->MaxEntries;
	if (maxEntries == 0 || maxEntries > totalCount) {
		maxEntries = totalCount;
	}

	// 5. 计算所需输出大小
	ULONG neededBytes = sizeof(ENUM_DRIVER_DEVICES_RESPONSE) +
		maxEntries * sizeof(DEVICE_ENTRY);

	if (OutputBufferLength < neededBytes) {
		ObDereferenceObject(pDrvObj);
		WdfRequestSetInformation(Request, (ULONG_PTR)neededBytes);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] DriverDevices: out buf too small, need %lu bytes\n",
			neededBytes);
		return STATUS_BUFFER_TOO_SMALL;
	}

	// 6. 取输出缓冲区
	PENUM_DRIVER_DEVICES_RESPONSE pResp = NULL;
	status = WdfRequestRetrieveOutputBuffer(
		Request, neededBytes, (PVOID*)&pResp, NULL);
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(pDrvObj);
		return status;
	}

	// 7. 填充响应头
	pResp->TotalCount = totalCount;
	pResp->NeededOutputBytes = neededBytes;
	pResp->Status = STATUS_SUCCESS;
	pResp->EntryCount = maxEntries;
	wcsncpy_s(pResp->FoundPath, RTL_NUMBER_OF(pResp->FoundPath),
		foundPath, _TRUNCATE);

	// 8. 遍历 DeviceObject 链,逐个填充 DEVICE_ENTRY
	PDEVICE_ENTRY pEntries = (PDEVICE_ENTRY)(pResp + 1);
	PDEVICE_OBJECT pDev = pDrvObj->DeviceObject;
	for (ULONG i = 0; i < maxEntries && pDev != NULL; i++) {
		PDEVICE_ENTRY pOut = &pEntries[i];

		pOut->DeviceObject = (ULONGLONG)pDev;
		pOut->DeviceType = pDev->DeviceType;
		pOut->Characteristics = pDev->Characteristics;
		pOut->Flags = pDev->Flags;
		pOut->AttachedCount = CountAttachedDevices(pDev);
		pOut->StackSize = pDev->StackSize;
		QueryDeviceName(pDev, pOut->DeviceName, RTL_NUMBER_OF(pOut->DeviceName));

		pDev = pDev->NextDevice;
	}

	ObDereferenceObject(pDrvObj);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverDevices: driver '%ws' found at %ws, returned %lu / %lu devices\n",
		pReq->DriverName, foundPath, maxEntries, totalCount);

	WdfRequestSetInformation(Request, (ULONG_PTR)neededBytes);
	return STATUS_SUCCESS;
}
