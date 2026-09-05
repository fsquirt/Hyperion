#pragma once

#include <ntddk.h>
#include <wdf.h>

// 驱动模块扫描 (Driver Scanner)
//
// 功能:
//   应用层通过 IOCTL_SCAN_LOADED_DRIVERS 调用,内核扫描已加载内核驱动
//   模块列表,返回每个模块的:基址、大小、模块名、完整路径、加载序号
//
// 实现:
//   ZwQuerySystemInformation(SystemModuleInformation)
//   该 API 内部就是遍历 PsLoadedModuleList 双向链表
//
// 数据流:
//   应用层: DeviceIoControl(IOCTL_SCAN_LOADED_DRIVERS)
//     输入缓冲区: SCAN_DRIVERS_REQUEST
//     输出缓冲区: SCAN_DRIVERS_RESPONSE + LOADED_DRIVER_ENTRY[EntryCount]
//   驱动: 扫描 → 填充输出 → 完成 IRP
//
// 注意:本模块只负责"扫描",不附着、不分类
//       附着决策由应用层做完 WinVerifyTrust 后再发新的 IOCTL

#define IOCTL_SCAN_LOADED_DRIVERS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 输入请求
typedef struct _SCAN_DRIVERS_REQUEST {
	ULONG MaxEntries;   // 0 = 返回所有已加载模块
	// >0 = 最多返回这么多条目，超出部分丢弃，TotalCount 仍反映总数
} SCAN_DRIVERS_REQUEST, * PSCAN_DRIVERS_REQUEST;

// 单条已加载驱动模块信息，定长，数组形式便于应用层解析
typedef struct _LOADED_DRIVER_ENTRY {
	ULONGLONG   ImageBase;          // 映像基址，即内核地址
	ULONG       ImageSize;          // 映像大小，单位字节
	USHORT      LoadOrderIndex;     // 加载序号
	USHORT      Flags;              // 模块标志，来自 RTL_PROCESS_MODULE_INFORMATION.Flags
	WCHAR       ModuleName[64];     // 模块短名，例如 "ntoskrnl.exe"
	WCHAR       FullPath[260];      // 完整路径，例如 "\SystemRoot\System32\drivers\tcpip.sys"
	WCHAR       DriverObjectName[64]; // 真实驱动对象名，来自 \Driver\<Name>，通常等于服务名
	// 由 DriverNameResolver 用 ImageBase 反查
	// 为空表示查不到，可能驱动没有 DriverObject，如 ntoskrnl
} LOADED_DRIVER_ENTRY, * PLOADED_DRIVER_ENTRY;

// 输出响应，变长，后跟 entries 数组
typedef struct _SCAN_DRIVERS_RESPONSE {
	ULONG       EntryCount;         // 实际返回的条目数
	ULONG       TotalCount;         // 内核扫描到的总数，可能 > EntryCount
	ULONG       NeededOutputBytes;  // 完整返回所需的总输出字节数
	NTSTATUS    ScanStatus;         // 扫描内部状态，STATUS_SUCCESS 或警告
	// 紧跟 LOADED_DRIVER_ENTRY entries[EntryCount]
} SCAN_DRIVERS_RESPONSE, * PSCAN_DRIVERS_RESPONSE;

// 初始化 / 卸载，本模块无状态，目前为空
NTSTATUS DriverScannerInit(VOID);
VOID     DriverScannerUnload(VOID);

// 由 Driver.c 的 EvtIoDeviceControl 调用:
// 处理 IOCTL_SCAN_LOADED_DRIVERS
//
// 返回值: STATUS_SUCCESS = 请求已成功,调用方用 WdfRequestCompleteWithInformation 完成
//         其他 = 失败,调用方用错误码完成请求
//         若返回 STATUS_BUFFER_TOO_SMALL,会先用 WdfRequestSetInformation
//         设置所需大小,调用方完成时 IoStatus.Information 会带这个大小
NTSTATUS DriverScannerHandleIoctl(
	_In_ WDFREQUEST Request,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength);
