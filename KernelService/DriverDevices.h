#pragma once

#include <ntddk.h>
#include <wdf.h>

// ============================================================
// 驱动设备列表扫描 (Driver Devices Scanner)
//
// 功能:
//   应用层通过 IOCTL_ENUM_DRIVER_DEVICES 调用,内核根据驱动名
//   (如 "ahflt" / "tcpip") 找到对应的 DRIVER_OBJECT,遍历其
//   DeviceObject->NextDevice 链表,返回该驱动创建的所有设备信息。
//
// 实现:
//   1. ObReferenceObjectByName(L"\\Driver\\<Name>", *IoDriverObjectType)
//      拿到 PDRIVER_OBJECT;找不到再试 \FileSystem\<Name>
//   2. 从 DriverObject->DeviceObject 开始,沿 NextDevice 走完整条链
//   3. 对每个设备收集:
//        - DeviceObject 内核地址
//        - DeviceType / Characteristics / Flags
//        - StackSize (设备栈深度)
//        - AttachedCount (沿 AttachedDevice 链表数有多少挂在上面)
//        - DeviceName (ObQueryNameString)
//
// 数据流:
//   应用层: DeviceIoControl(IOCTL_ENUM_DRIVER_DEVICES)
//     输入: ENUM_DRIVER_DEVICES_REQUEST (DriverName + MaxEntries)
//     输出: ENUM_DRIVER_DEVICES_RESPONSE + DEVICE_ENTRY[EntryCount]
//   驱动: 找 DriverObject → 遍历 DeviceObject 链 → 填充输出 → 完成 IRP
//
// 注意:本 IOCTL 同步完成,不挂起
// ============================================================

#define IOCTL_ENUM_DRIVER_DEVICES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 输入请求(与应用层 EnumDevicesRequest 一致)
typedef struct _ENUM_DRIVER_DEVICES_REQUEST {
	WCHAR  DriverName[64];   // 驱动短名 (不含路径,如 "ahflt" / "tcpip" / "_null")
	// 内核会依次尝试:
	//   \Driver\<DriverName>
	//   \FileSystem\<DriverName>
	ULONG  MaxEntries;       // 0 = 返回所有设备;>0 = 最多返回这么多
} ENUM_DRIVER_DEVICES_REQUEST, * PENUM_DRIVER_DEVICES_REQUEST;

// 单条设备信息(定长,数组形式便于应用层解析)
typedef struct _DEVICE_ENTRY {
	ULONGLONG DeviceObject;    // 设备对象地址 (内核地址)
	ULONG     DeviceType;      // DeviceObject->DeviceType (FILE_DEVICE_*)
	ULONG     Characteristics; // DeviceObject->Characteristics
	ULONG     Flags;           // DeviceObject->Flags (DO_DIRECT_IO / DO_BUFFERED_IO ...)
	USHORT    AttachedCount;   // AttachedDevice 链表上有多少设备 (栈深)
	USHORT    StackSize;       // DeviceObject->StackSize
	WCHAR     DeviceName[260]; // 设备名 (ObQueryNameString,如 "\Device\Tcp" / "(unnamed)")
} DEVICE_ENTRY, * PDEVICE_ENTRY;

// 输出响应(变长,后跟 entries 数组)
typedef struct _ENUM_DRIVER_DEVICES_RESPONSE {
	ULONG    EntryCount;         // 实际返回的条目数
	ULONG    TotalCount;         // 设备总数(可能 > EntryCount)
	ULONG    NeededOutputBytes;  // 完整返回所需总字节数
	NTSTATUS Status;             // 内部状态(STATUS_SUCCESS / STATUS_OBJECT_NAME_NOT_FOUND ...)
	WCHAR    FoundPath[96];      // 找到驱动的对象路径(诊断用,如 "\Driver\tcpip")
	// 紧跟 DEVICE_ENTRY entries[EntryCount]
} ENUM_DRIVER_DEVICES_RESPONSE, * PENUM_DRIVER_DEVICES_RESPONSE;

// 初始化 / 卸载(本模块无状态,目前为空)
NTSTATUS DriverDevicesInit(VOID);
VOID     DriverDevicesUnload(VOID);

// 由 Driver.c 的 EvtIoDeviceControl 调用:
// 处理 IOCTL_ENUM_DRIVER_DEVICES
//
// 返回值: STATUS_SUCCESS = 请求已成功,调用方用 WdfRequestCompleteWithInformation 完成
//         其他 = 失败,调用方用错误码完成请求
//         STATUS_BUFFER_TOO_SMALL 时会先用 WdfRequestSetInformation 设置所需大小
NTSTATUS DriverDevicesHandleIoctl(
	_In_ WDFREQUEST Request,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength);
