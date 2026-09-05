#pragma once
#include <ntddk.h>
#include <wdf.h>

// 设备附着模块 (Driver Attach)
//
// 功能:
//   应用层通过 IOCTL 传入设备路径，例如 "\Device\Tcp"。内核:
//     1. 用 IoCreateDriver 创建独立的 Filter DriverObject
//        主 DriverObject 被 KMDF 接管，不能复用
//     2. 用 IoGetDeviceObjectPointer 按名字拿到目标 DEVICE_OBJECT
//     3. 用 IoCreateDevice 创建匿名 FiDO (Filter Device Object)
//        继承目标的 DeviceType / Characteristics
//     4. 用 IoAttachDeviceToDeviceStack 把 FiDO 附着到设备栈顶
//     5. 所有 IRP 通过 FilterPassIrp 透传给下一层
// 卸载顺序:
//   1. 遍历链表 IoDetachDevice + IoDeleteDevice
//   2. IoDeleteDriver 删除 Filter DriverObject
//   须在 WdfObjectDelete(g_Device) 之前完成

//  IOCTL 定义 (function code 0x806-0x808)
#define IOCTL_ATTACH_DEVICE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DETACH_DEVICE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUERY_ATTACHMENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

// dump 被附着设备所属驱动的内存映像
// 输入: AttachId，按附着 ID 找 TargetDevice->DriverObject
// 输出: 先返回 DUMP_DRIVER_MEMORY_RESPONSE 头，内含 ImageBase/ImageSize/FullPath,
//       若 OutputBufferLength > sizeof(RESPONSE), 紧跟 ImageSize 字节的映像数据
#define IOCTL_DUMP_DRIVER_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)


//  设备扩展，即每个 FiDO 的私有上下文
typedef struct _ATTACH_DEVICE_EXTENSION {
	PDEVICE_OBJECT  FilterDevice;       // 自己 (FiDO)
	PDEVICE_OBJECT  LowerDeviceObject;  // IoAttachDeviceToDeviceStack 返回值，即下一层设备
	PDEVICE_OBJECT  TargetDevice;       // 被附着的原始设备，诊断用
	PFILE_OBJECT    TargetFileObject;   // IoGetDeviceObjectPointer 返回的 FileObject，持有引用
	ULONG           AttachId;           // 唯一 ID，供应用层引用
	WCHAR           TargetPath[260];    // 附着的目标路径，例如 L"\Device\Tcp"
	LIST_ENTRY      ListEntry;          // 挂入全局链表
} ATTACH_DEVICE_EXTENSION, * PATTACH_DEVICE_EXTENSION;


//  IOCTL_ATTACH_DEVICE (0x806) — 附着到指定设备
// 输入
typedef struct _ATTACH_DEVICE_REQUEST {
	WCHAR  DevicePath[260];   // 如 L"\\Device\\Tcp"
} ATTACH_DEVICE_REQUEST, * PATTACH_DEVICE_REQUEST;

// 输出
typedef struct _ATTACH_DEVICE_RESPONSE {
	NTSTATUS    Status;             // 0=成功, 其他=失败码
	ULONG       AttachId;           // 附着 ID，后续 unattach 用; 0=失败
	ULONGLONG   FilterDeviceAddr;   // FiDO 内核地址，诊断用
	ULONGLONG   LowerDeviceAddr;    // 下一层设备地址，即 IoAttachDeviceToDeviceStack 返回值
	USHORT      NewStackSize;       // 附着后 FiDO 的 StackSize
	USHORT      TargetStackSize;    // 附着前目标设备的 StackSize
} ATTACH_DEVICE_RESPONSE, * PATTACH_DEVICE_RESPONSE;


//  IOCTL_DETACH_DEVICE (0x807) — 解绑指定附着
// 输入
typedef struct _DETACH_DEVICE_REQUEST {
	ULONG  AttachId;         // >0 时按 ID 匹配
	WCHAR  DevicePath[260];  // AttachId=0 时按路径匹配
} DETACH_DEVICE_REQUEST, * PDETACH_DEVICE_REQUEST;

// 输出
typedef struct _DETACH_DEVICE_RESPONSE {
	NTSTATUS Status;
	ULONG    DetachedId;     // 被解绑的 AttachId
} DETACH_DEVICE_RESPONSE, * PDETACH_DEVICE_RESPONSE;


//  IOCTL_QUERY_ATTACHMENTS (0x808) — 查询当前所有附着
// 单条附着信息。注意: ULONGLONG 放前面保证 8 字节自然对齐
typedef struct _ATTACH_ENTRY {
	ULONGLONG   FilterDeviceAddr;   // 8, offset 0
	ULONGLONG   LowerDeviceAddr;    // 8, offset 8
	WCHAR       TargetPath[260];    // 520, offset 16
	ULONG       AttachId;           // 4, offset 536
	USHORT      StackSize;          // 2, offset 540
	// 2 bytes tail padding → total 544
} ATTACH_ENTRY, * PATTACH_ENTRY;

// 输出响应，变长，后跟 entries 数组
typedef struct _QUERY_ATTACHMENTS_RESPONSE {
	ULONG    Count;               // 实际返回的条目数
	ULONG    NeededOutputBytes;   // 完整返回所需总字节数
	// 紧跟 ATTACH_ENTRY entries[Count]
} QUERY_ATTACHMENTS_RESPONSE, * PQUERY_ATTACHMENTS_RESPONSE;

// 初始化
NTSTATUS DriverAttachInit(VOID);

// 卸载，在 EvtDriverUnload 中调用，必须在 WdfObjectDelete 之前
VOID     DriverAttachUnload(VOID);

// IOCTL 处理，由 Driver.c 的 EvtIoDeviceControl 调用
// 返回值: STATUS_SUCCESS = 成功; 其他 = 失败
// 用 WdfRequestSetInformation 设置实际返回字节数
NTSTATUS DriverAttachHandleIoctl(
	_In_ WDFREQUEST Request,
	_In_ ULONG IoControlCode,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength);


//  IOCTL_DUMP_DRIVER_MEMORY (0x809) — dump 被附着设备所属驱动内存

// 输入
typedef struct _DUMP_DRIVER_MEMORY_REQUEST {
	ULONG  AttachId;         // 附着 ID，按 ID 找 TargetDevice->DriverObject
} DUMP_DRIVER_MEMORY_REQUEST, * PDUMP_DRIVER_MEMORY_REQUEST;

// 输出头，后跟 ImageSize 字节映像数据，若 OutputBuffer 足够大
typedef struct _DUMP_DRIVER_MEMORY_RESPONSE {
	NTSTATUS    Status;             // 0=成功, 其他=失败码
	ULONGLONG   DriverObjectAddr;   // 找到的 DriverObject 内核地址，用于诊断
	ULONGLONG   ImageBase;          // 驱动映像基址 (DriverObject->DriverStart)
	ULONG       ImageSize;          // 驱动映像大小 (DriverObject->DriverSize)
	ULONG       BytesDumped;        // 实际拷贝的字节数，可能 < ImageSize，若用户缓冲不够
	WCHAR       FullPath[260];      // 驱动文件完整路径，例如 "\SystemRoot\System32\drivers\tcpip.sys"
	WCHAR       BaseName[64];       // 驱动短名，例如 "tcpip.sys"
} DUMP_DRIVER_MEMORY_RESPONSE, * PDUMP_DRIVER_MEMORY_RESPONSE;
