// ntifs.h 必须在最前，先于 ntddk.h/wdm.h include
// DriverNameResolver.h 里已 include ntddk.h,这里先 include ntifs.h
#include <ntifs.h>
#include "DriverNameResolver.h"
#include <ntstrsafe.h>

// ============================================================
// 驱动对象名解析器实现
//
// 用 ZwOpenDirectoryObject + ZwQueryDirectoryObject 遍历对象目录,
// 对每个对象用 ObReferenceObjectByName 拿 DRIVER_OBJECT,
// 比对 DriverStart == ImageBase 找到真实驱动对象名
//
// 注意:
//   - ZwQueryDirectoryObject / OBJECT_DIRECTORY_INFORMATION / DIRECTORY_QUERY
//     在 WDK ntifs.h / wdm.h 中部分声明,部分需要手动 extern
//     ZwOpenDirectoryObject 在 ntifs.h 已声明
//     DIRECTORY_QUERY 在 wdm.h 已定义
//     ZwQueryDirectoryObject / OBJECT_DIRECTORY_INFORMATION 在 WDK 头里没有,
//     定义来自 ReactOS / phnt，已与微软 rust 文档核对一致
// ============================================================

// WDK 头文件未声明,手动 extern，签名来自 phnt / ReactOS，与微软 rust 文档一致
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
	_In_ HANDLE DirectoryHandle,
	_Out_writes_bytes_opt_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_ BOOLEAN ReturnSingleEntry,
	_In_ BOOLEAN RestartScan,
	_Inout_ PULONG Context,
	_Out_opt_ PULONG ReturnLength);

// 对象目录查询返回的单条记录，来自 phnt / ReactOS
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

// ntoskrnl 导出但 WDK 未声明
extern POBJECT_TYPE* IoDriverObjectType;

NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectName,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_In_opt_ PVOID ParseContext,
	_Out_ PVOID* Object);

#define RESOLVER_POOL_TAG 'RNDD'   // 'DDNR' 倒过来

// ------------------------------------------------------------
// 在指定目录中按 ImageBase 查找驱动对象名
// ------------------------------------------------------------
NTSTATUS FindDriverNameByImageBase(
	_In_ PCWSTR DirName,
	_In_ PVOID TargetImageBase,
	_Out_writes_z_(OutNameChars) PWSTR OutName,
	_In_ ULONG OutNameChars)
{
	if (OutName == NULL || OutNameChars == 0) {
		return STATUS_INVALID_PARAMETER;
	}
	OutName[0] = L'\0';

	NTSTATUS status;

	// 1. 打开目录 \Driver 或 \FileSystem
	UNICODE_STRING dirName;
	RtlInitUnicodeString(&dirName, DirName);

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &dirName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE hDir = NULL;
	status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// 2. 分配查询缓冲区，4KB 一般够一次返回几十个对象
	ULONG bufSize = 4096;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, bufSize, RESOLVER_POOL_TAG);
	if (buffer == NULL) {
		ZwClose(hDir);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ULONG context = 0;       // 遍历上下文,ZwQueryDirectoryObject 会维护
	BOOLEAN restart = TRUE;  // 第一次从头开始

	// 3. 循环遍历目录
	//    方案A:同一 ImageBase 可能存在多个驱动对象，典型如 OpenArk 手动映射,
	//    会额外建一个随机数字命名的对象,与正常 \Driver\<Name> 共享 DriverStart。
	//    优先返回"有设备"的那个对象，即 \Driver\00000095 无设备,\Driver\OpenArkDrv64
	//    挂 \Device\OpenArkDrv;仅当所有匹配对象都无设备时,回退到第一个匹配。
	WCHAR fallbackName[64] = { 0 };
	BOOLEAN foundFallback = FALSE;

	while (TRUE) {
		ULONG returnLength = 0;
		status = ZwQueryDirectoryObject(
			hDir, buffer, bufSize,
			FALSE,        // ReturnSingleEntry = FALSE,返回多个
			restart,      // RestartScan:第一次 TRUE,之后 FALSE
			&context,
			&returnLength);

		restart = FALSE;

		if (status == STATUS_NO_MORE_ENTRIES) {
			// 遍历完毕
			status = STATUS_NOT_FOUND;
			break;
		}

		if (!NT_SUCCESS(status)) {
			// 其他错误，包括 STATUS_BUFFER_TOO_SMALL 之类
			break;
		}

		// 4. 遍历本批次返回的所有对象
		POBJECT_DIRECTORY_INFORMATION pEntry = (POBJECT_DIRECTORY_INFORMATION)buffer;
		ULONG count = returnLength / sizeof(OBJECT_DIRECTORY_INFORMATION);

		for (ULONG i = 0; i < count; i++) {
			if (pEntry[i].Name.Length == 0 || pEntry[i].Name.Buffer == NULL) {
				break;  // 结束
			}

			// 只关心类型为 "Driver" 的对象，跳过 "Device" / "SymbolicLink" 等
			// 注意:TypeName 比较要大小写不敏感
			if (pEntry[i].TypeName.Length == 0 || pEntry[i].TypeName.Buffer == NULL) {
				continue;
			}
			UNICODE_STRING driverType = RTL_CONSTANT_STRING(L"Driver");
			if (!RtlEqualUnicodeString(&pEntry[i].TypeName, &driverType, TRUE)) {
				continue;
			}

			// 5. 用 ObReferenceObjectByName 拿 PDRIVER_OBJECT
			//    对象名需要拼成完整路径 "\Driver\<Name>"
			UNICODE_STRING fullPath;
			WCHAR pathBuf[96];

			// 拼接 "\Driver\<Name>" 或 "\FileSystem\<Name>"
			// 注意:pEntry[i].Name 是相对名,不含前缀
			fullPath.Buffer = pathBuf;
			fullPath.Length = 0;
			fullPath.MaximumLength = sizeof(pathBuf);

			status = RtlStringCbPrintfW(
				pathBuf, sizeof(pathBuf), L"%ws\\%wZ",
				DirName, &pEntry[i].Name);
			if (!NT_SUCCESS(status)) {
				continue;
			}
			fullPath.Length = (USHORT)(wcsnlen_s(pathBuf, RTL_NUMBER_OF(pathBuf)) * sizeof(WCHAR));

			PVOID obj = NULL;
			status = ObReferenceObjectByName(
				&fullPath,
				OBJ_CASE_INSENSITIVE,
				NULL, 0,
				*IoDriverObjectType,
				KernelMode, NULL, &obj);

			if (!NT_SUCCESS(status) || obj == NULL) {
				continue;
			}

			PDRIVER_OBJECT pDrvObj = (PDRIVER_OBJECT)obj;

			// 6. 核心比对:DriverStart == ImageBase
			if (pDrvObj->DriverStart == TargetImageBase) {
				// 优先返回"有设备"的驱动对象:直接命中,无需再遍历
				if (pDrvObj->DeviceObject != NULL) {
					ULONG copyChars = pEntry[i].Name.Length / sizeof(WCHAR);
					if (copyChars >= OutNameChars) {
						copyChars = OutNameChars - 1;
					}
					RtlCopyMemory(OutName, pEntry[i].Name.Buffer, copyChars * sizeof(WCHAR));
					OutName[copyChars] = L'\0';

					ObDereferenceObject(pDrvObj);
					ExFreePoolWithTag(buffer, RESOLVER_POOL_TAG);
					ZwClose(hDir);
					return STATUS_SUCCESS;
				}

				// 无设备的匹配:暂存为回退，只记第一个，继续找有没有带设备的
				if (!foundFallback) {
					ULONG copyChars = pEntry[i].Name.Length / sizeof(WCHAR);
					if (copyChars >= RTL_NUMBER_OF(fallbackName)) {
						copyChars = RTL_NUMBER_OF(fallbackName) - 1;
					}
					RtlCopyMemory(fallbackName, pEntry[i].Name.Buffer, copyChars * sizeof(WCHAR));
					fallbackName[copyChars] = L'\0';
					foundFallback = TRUE;
				}
			}

			ObDereferenceObject(pDrvObj);
		}
	}

	// 全部遍历完也没找到"有设备"的匹配,回退到第一个匹配，即无设备的那个
	if (foundFallback) {
		wcsncpy_s(OutName, OutNameChars, fallbackName, _TRUNCATE);
		ExFreePoolWithTag(buffer, RESOLVER_POOL_TAG);
		ZwClose(hDir);
		return STATUS_SUCCESS;
	}

	ExFreePoolWithTag(buffer, RESOLVER_POOL_TAG);
	ZwClose(hDir);
	return status;
}

// ------------------------------------------------------------
// 同时扫 \Driver 和 \FileSystem
// ------------------------------------------------------------
NTSTATUS FindDriverObjectNameByImageBase(
	_In_ PVOID TargetImageBase,
	_Out_writes_z_(OutNameChars) PWSTR OutName,
	_In_ ULONG OutNameChars)
{
	// 先扫 \Driver，绝大多数驱动都在此
	NTSTATUS status = FindDriverNameByImageBase(
		L"\\Driver", TargetImageBase, OutName, OutNameChars);

	if (NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}

	// \Driver 找不到,再扫 \FileSystem
	status = FindDriverNameByImageBase(
		L"\\FileSystem", TargetImageBase, OutName, OutNameChars);

	return status;
}

// ------------------------------------------------------------
// 初始化 / 卸载，本模块无状态
// ------------------------------------------------------------
NTSTATUS DriverNameResolverInit(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverNameResolver: initialized\n");
	return STATUS_SUCCESS;
}

VOID DriverNameResolverUnload(VOID)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
		"[KernelService] DriverNameResolver: unloaded\n");
}
