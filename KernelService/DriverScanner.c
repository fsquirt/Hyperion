// ntifs.h 必须在 ntddk.h/wdm.h 之前 include，否则 PEPROCESS 等类型重定义
// DriverNameResolver.h 里用到 ZwOpenDirectoryObject,需要 ntifs.h
#include <ntifs.h>
#include "DriverScanner.h"
#include "DriverNameResolver.h"

// ============================================================
// 驱动模块扫描实现
//
// 用 ZwQuerySystemInformation(SystemModuleInformation) 查询已加载内核模块
// 内部就是从 PsLoadedModuleList 双向链表复制的
//
// 注意:
//   - SystemModuleInformation = 11，未文档化的信息类别
//   - 不同 WDK 版本中 RTL_PROCESS_MODULE_INFORMATION 字段顺序/可见性可能不同,
//     这里自定义一份结构,不依赖 SDK 头文件
//   - FullPathName 是 ANSI 字符串，例如 "\SystemRoot\System32\drivers\tcpip.sys"
//   - OffsetToFileName 指向 FullPathName 内的文件名起始偏移
// ============================================================

#define SCAN_POOL_TAG 'DSDK'     // 'DKSD' 倒过来
#define SystemModuleInformation 11

// ZwQuerySystemInformation 在 ntddk.h 中未正式声明,需要自己声明
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	_In_ ULONG SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength);

// 自定义模块信息结构，布局与 WDK 的 RTL_PROCESS_MODULE_INFORMATION 一致
typedef struct _SYS_MODULE_ENTRY {
	HANDLE  Section;
	PVOID   MappedBase;
	PVOID   ImageBase;
	ULONG   ImageSize;
	ULONG   Flags;
	USHORT  LoadOrderIndex;
	USHORT  InitOrderIndex;
	USHORT  LoadCount;
	USHORT  OffsetToFileName;
	UCHAR   FullPathName[256];
} SYS_MODULE_ENTRY, * PSYS_MODULE_ENTRY;

// ZwQuerySystemInformation 返回的模块列表，变长数组
typedef struct _SYS_MODULE_LIST {
	ULONG           Count;
	SYS_MODULE_ENTRY Modules[1];
} SYS_MODULE_LIST, * PSYS_MODULE_LIST;

// ------------------------------------------------------------
// 内部:查询系统已加载模块
// 调用者负责 ExFreePoolWithTag 释放返回的缓冲区
// ------------------------------------------------------------
static NTSTATUS QuerySystemModules(
	_Out_ PSYS_MODULE_LIST* ppModules,
	_Out_ PULONG pActualSize)
{
	*ppModules = NULL;
	*pActualSize = 0;

	// 第一次:取所需大小，预期返回 STATUS_INFO_LENGTH_MISMATCH
	ULONG actualSize = 0;
#pragma warning(suppress : 6387) // 故意传 NULL 查询所需缓冲区大小
	NTSTATUS status = ZwQuerySystemInformation(
		SystemModuleInformation, NULL, 0, &actualSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		// 某些情况第一次调用会返回其他错误,直接尝试一个估计大小
		actualSize = 0x10000; // 64KB 起步
	}

	// 重试3次，模块数量在变化时可能返回 STATUS_INFO_LENGTH_MISMATCH
	for (int retry = 0; retry < 3; retry++) {
		ULONG size = actualSize + 0x1000; // 多分配一页防增长
		PVOID buf = ExAllocatePool2(
			POOL_FLAG_NON_PAGED, size, SCAN_POOL_TAG);
		if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(
			SystemModuleInformation, buf, size, &actualSize);

		if (NT_SUCCESS(status)) {
			*ppModules = (PSYS_MODULE_LIST)buf;
			*pActualSize = actualSize;
			return STATUS_SUCCESS;
		}

		ExFreePoolWithTag(buf, SCAN_POOL_TAG);

		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			return status;
		}
		// 否则用新的 actualSize 重试
	}

	return STATUS_INFO_LENGTH_MISMATCH;
}

// ------------------------------------------------------------
// 把 ANSI 路径转成 Unicode 写入定长目标缓冲区
// 不分配内存,失败则目标保持空字符串
// ------------------------------------------------------------
static VOID AnsiPathToUnicode(
	_In_ PCSZ pAnsiStr,
	_In_ ULONG ansiLen,             // 不含 \0
	_Out_writes_z_(cchDest) PWSTR pDest,
	_In_ USHORT cchDest)
{
	if (cchDest == 0 || pDest == NULL) return;
	pDest[0] = L'\0';

	if (pAnsiStr == NULL || ansiLen == 0) return;

	ANSI_STRING ansi;
	ansi.Buffer = (PCHAR)pAnsiStr;
	ansi.Length = (USHORT)ansiLen;
	ansi.MaximumLength = (USHORT)ansiLen;

	UNICODE_STRING uni;
	uni.Buffer = pDest;
	uni.Length = 0;
	uni.MaximumLength = cchDest * sizeof(WCHAR);

	// 不分配新内存，即传 FALSE，直接写到 pDest
	RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
}

// ------------------------------------------------------------
// 初始化 / 卸载，本模块无状态
// ------------------------------------------------------------
NTSTATUS DriverScannerInit(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverScanner: initialized\n");
	return STATUS_SUCCESS;
}

VOID DriverScannerUnload(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverScanner: unloaded\n");
}

// ------------------------------------------------------------
// 主处理函数:处理 IOCTL_SCAN_LOADED_DRIVERS
// ------------------------------------------------------------
NTSTATUS DriverScannerHandleIoctl(
	_In_ WDFREQUEST Request,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength)
{
	NTSTATUS status;

	// 1. 校验并取输入请求
	if (InputBufferLength < sizeof(SCAN_DRIVERS_REQUEST)) {
		return STATUS_BUFFER_TOO_SMALL;
	}

	PSCAN_DRIVERS_REQUEST pReq = NULL;
	status = WdfRequestRetrieveInputBuffer(
		Request, sizeof(SCAN_DRIVERS_REQUEST), (PVOID*)&pReq, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// 2. 查询内核已加载模块
	PSYS_MODULE_LIST pModules = NULL;
	ULONG actualSize = 0;
	status = QuerySystemModules(&pModules, &actualSize);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
			"[KernelService] DriverScanner: QuerySystemModules failed: 0x%08X\n", status);
		return status;
	}

	// 3. 决定返回多少条
	ULONG totalCount = pModules->Count;
	ULONG maxEntries = pReq->MaxEntries;
	if (maxEntries == 0 || maxEntries > totalCount) {
		maxEntries = totalCount;
	}

	// 4. 计算所需输出字节数
	ULONG neededBytes = sizeof(SCAN_DRIVERS_RESPONSE) +
		maxEntries * sizeof(LOADED_DRIVER_ENTRY);

	// 5. 缓冲区不够 → 设置所需大小并返回 STATUS_BUFFER_TOO_SMALL
	//    调用方即 EvtIoDeviceControl，会用此状态完成 IRP
	//    应用层可拿 IoStatus.Information 重发
	if (OutputBufferLength < neededBytes) {
		ExFreePoolWithTag(pModules, SCAN_POOL_TAG);
		WdfRequestSetInformation(Request, (ULONG_PTR)neededBytes);
		DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
			"[KernelService] DriverScanner: out buffer too small, need %lu bytes\n",
			neededBytes);
		return STATUS_BUFFER_TOO_SMALL;
	}

	// 6. 取输出缓冲区
	PSCAN_DRIVERS_RESPONSE pResp = NULL;
	status = WdfRequestRetrieveOutputBuffer(
		Request, neededBytes, (PVOID*)&pResp, NULL);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(pModules, SCAN_POOL_TAG);
		return status;
	}

	// 7. 填充响应头
	pResp->TotalCount = totalCount;
	pResp->NeededOutputBytes = neededBytes;
	pResp->ScanStatus = STATUS_SUCCESS;
	pResp->EntryCount = maxEntries;

	// 8. 填充每个 entry
	PLOADED_DRIVER_ENTRY pEntries = (PLOADED_DRIVER_ENTRY)(pResp + 1);

	for (ULONG i = 0; i < maxEntries; i++) {
		PSYS_MODULE_ENTRY pMod = &pModules->Modules[i];
		PLOADED_DRIVER_ENTRY pOut = &pEntries[i];

		pOut->ImageBase = (ULONGLONG)pMod->ImageBase;
		pOut->ImageSize = pMod->ImageSize;
		pOut->LoadOrderIndex = pMod->LoadOrderIndex;
		pOut->Flags = (USHORT)pMod->Flags;

		// 完整路径 (ANSI → Unicode)
		ULONG fullLen = (ULONG)strnlen_s(
			(PCCHAR)pMod->FullPathName, sizeof(pMod->FullPathName));
		AnsiPathToUnicode(
			(PCSZ)pMod->FullPathName, fullLen,
			pOut->FullPath, RTL_NUMBER_OF(pOut->FullPath));

		// 短名，从 OffsetToFileName 处开始
		if (pMod->OffsetToFileName < fullLen) {
			AnsiPathToUnicode(
				(PCSZ)(pMod->FullPathName + pMod->OffsetToFileName),
				fullLen - pMod->OffsetToFileName,
				pOut->ModuleName, RTL_NUMBER_OF(pOut->ModuleName));
		}

		// 真实驱动对象名:用 ImageBase 反查 \Driver / \FileSystem
		// 这样应用层拿到的就是真实服务名，例如 "OpenArkDrv"，而不是文件名砍后缀
		pOut->DriverObjectName[0] = L'\0';  // 先置空
		NTSTATUS nameStatus = FindDriverObjectNameByImageBase(
			pMod->ImageBase,
			pOut->DriverObjectName,
			RTL_NUMBER_OF(pOut->DriverObjectName));
		if (!NT_SUCCESS(nameStatus)) {
			// 找不到 DriverObject，例如 ntoskrnl.exe / HAL.dll / 自己 KernelService
			// 留空,应用层可据此跳过
			pOut->DriverObjectName[0] = L'\0';
		}
	}

	ExFreePoolWithTag(pModules, SCAN_POOL_TAG);

	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverScanner: returned %lu / %lu modules (out=%lu bytes)\n",
		maxEntries, totalCount, neededBytes);

	// 9. 设置实际返回的字节数,由调用方完成 IRP
	WdfRequestSetInformation(Request, (ULONG_PTR)neededBytes);

	return STATUS_SUCCESS;
}
