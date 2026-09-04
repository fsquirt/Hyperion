#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <evntprov.h>

// ============================================================
// ETW Logger 模块 (EtwLogger)
//
// 功能:
//   注册一个内核态 ETW Provider,在过滤驱动拦截到 IOCTL 时,
//   把 IoControlCode + InputBuffer payload 塞进 EtwWrite 事件。
//   ETW 框架会自动附加从 Ring3 到 Ring0 的跨态调用栈。
//
//   应用层用 StartTrace + EnableTraceEx2(EVENT_ENABLE_PROPERTY_STACK_TRACE)
//   + OpenTrace(PROCESS_TRACE_MODE_REAL_TIME) 实时订阅。
//
// 事件设计:
//   Event Id = 1: IOCTL 拦截事件
//   UserData = ETW_IOCTL_EVENT_HEADER + Payload[CaptureSize]
//
//   注意:UserData 总大小 ≤ 64KB,这里限制 Payload ≤ 4096 字节
//   BYOVD 攻击的核心数据都在前几百字节
//
// 性能:
//   - 无 Session 订阅时,EtwWrite 内部一次位掩码判断直接返回,几乎零开销
//   - 有订阅时,ETW 框架同步抓栈，走内核态高度优化路径
//   - 埋点可永久留在生产代码里,按需开关 Session
// ============================================================

// ═══════════════════════════════════════════════════════════════
//  Provider GUID — 自行生成,应用层订阅时必须一致
//  {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// ═══════════════════════════════════════════════════════════════

// clang-format off
// 17B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C  ← 改成 A7B3C9D2 开头避免和系统冲突
// 实际 GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// clang-format on

// ETW_IOCTL_PROVIDER_GUID — 应用层订阅用
#define ETW_IOCTL_PROVIDER_GUID_L  0x4E5FA7B3C9D2ULL
#define ETW_IOCTL_PROVIDER_GUID_S1 0x4A1B
#define ETW_IOCTL_PROVIDER_GUID_S2 0x9C8E
#define ETW_IOCTL_PROVIDER_GUID_S3 0x7D6F5E4A3B2CULL

// Event Id
#define ETW_EVENT_IOCTL_INTERCEPT  1
#define ETW_EVENT_IMAGELOAD        2
#define ETW_EVENT_THREAD_ANTIDEBUG 3

// 最大抓取的 Payload 字节数，ETW 单事件上限 64KB，这里保守取 4KB
#define ETW_MAX_PAYLOAD_CAPTURE   4096

// ImageLoad 事件中深拷贝的映像路径最大字节数，Unicode 编码，含结尾符
#define ETW_MAX_IMAGENAME_BYTES   512

// ═══════════════════════════════════════════════════════════════
//  事件 UserData 结构: 固定头 + 变长 Payload
//  注意: 字段对齐必须与应用层一致，即 8 字节自然对齐
// ═══════════════════════════════════════════════════════════════

#pragma pack(push, 8)

typedef struct _ETW_IOCTL_EVENT_HEADER {
	ULONG       Version;            // 结构版本,当前 = 1
	ULONG       IoControlCode;      // IOCTL 控制码，例如 0x222004
	ULONG       InputBufferLength;  // 原始 InputBuffer 长度，可能 > CaptureSize
	ULONG       CaptureSize;        // 实际抓取的字节数 (≤ ETW_MAX_PAYLOAD_CAPTURE)
	ULONGLONG   RequestorPid;       // 发起进程 PID
	ULONGLONG   TargetDeviceAddr;   // 被附着的原设备 DEVICE_OBJECT 地址
	ULONGLONG   FilterDeviceAddr;   // 我们的 FiDO 地址
	ULONGLONG   AttachId;           // 附着 ID，与应用层 --list-attach 一致
	ULONG       MajorFunction;      // IRP_MJ_*，通常为 IRP_MJ_DEVICE_CONTROL=0x0E
	ULONG       Method;             // IOCTL 的 METHOD_* (0/1/2/3)
} ETW_IOCTL_EVENT_HEADER, * PETW_IOCTL_EVENT_HEADER;

// ImageLoad 事件头 (EventId = 2),后跟 WCHAR ImageName[ImageNameBytes/2]
// 深拷贝的映像路径,规避 LoadImage 回调内 FullImageName 仅回调期有效的限制。
typedef struct _ETW_IMAGELOAD_EVENT_HEADER {
	ULONGLONG   ProcessId;          // 发生映像加载的进程 PID
	ULONGLONG   InitiatorPid;       // 发起者 PID
	ULONGLONG   ImageBase;          // 映像基址
	ULONG       ImageSize;          // 映像大小
	ULONG       ImageNameBytes;     // 后随的映像路径字节数 (≤ ETW_MAX_IMAGENAME_BYTES)
} ETW_IMAGELOAD_EVENT_HEADER, * PETW_IMAGELOAD_EVENT_HEADER;

// ThreadAntiDebug 事件头 (EventId = 3),由线程创建回调上报
// 固定 24 字节,无变长数据。
typedef struct _ETW_THREAD_ANTIDEBUG_EVENT_HEADER {
	ULONGLONG   CreatorPid;         // 线程创建者 PID，远程线程注入的幕后黑手
	ULONGLONG   ProcessId;          // 线程所属进程 PID
	ULONGLONG   ThreadId;           // 线程 ID
} ETW_THREAD_ANTIDEBUG_EVENT_HEADER, * PETW_THREAD_ANTIDEBUG_EVENT_HEADER;

#pragma pack(pop)

// ═══════════════════════════════════════════════════════════════
//  公开函数
// ═══════════════════════════════════════════════════════════════

// 初始化，在 DriverEntry 中调用并注册 Provider
NTSTATUS EtwLoggerInit(VOID);

// 卸载，在 EvtDriverUnload 中调用并注销 Provider
VOID     EtwLoggerUnload(VOID);

// 核心:记录一次 IOCTL 拦截事件
// 由 FilterPassIrp 调用,如果 Session 开启了 STACK_TRACE 会自动抓栈
//
// 参数:
//   FilterDevice    — 我们的 FiDO
//   TargetDevice    — 被附着的原设备
//   AttachId        — 附着 ID
//   Irp             — IRP 指针
//   MajorFunction   — IRP 主功能号，通常为 IRP_MJ_DEVICE_CONTROL
VOID EtwLogIrpEvent(
	_In_ PDEVICE_OBJECT FilterDevice,
	_In_ PDEVICE_OBJECT TargetDevice,
	_In_ ULONG          AttachId,
	_In_ PIRP           Irp,
	_In_ UCHAR          MajorFunction);

// 记录一次 ImageLoad 事件，由 GameProtect 的 LoadImage 回调调用
// FullImageName 深拷贝进 UserData,回调返回后可安全使用
VOID EtwLogImageLoadEvent(
	_In_ HANDLE          ProcessId,
	_In_ HANDLE		     initiatorPid,
	_In_ PUNICODE_STRING FullImageName,
	_In_ ULONG_PTR       ImageBase,
	_In_ ULONG           ImageSize);

// 记录一次线程反调试事件，由 GameProtect 的线程创建回调调用
// 上报 创建者PID / 进程PID / 线程ID,用户层可据此识别远程线程注入
VOID EtwLogThreadAntiDebugEvent(
	_In_ HANDLE CreatorPid,
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId);
