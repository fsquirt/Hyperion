#pragma once

#include <ntddk.h>
#include <wdf.h>

// 驱动加载监控
//
// 原理:
//   1. PsSetLoadImageNotifyRoutine 监视新驱动加载
//   2. 回调中过滤 ProcessId==0 且 .sys 后缀
//   3. 不在回调里做事! 只把信息塞进用户态预先挂起的 WDFREQUEST,完成它
//   4. UserService 收到请求完成 → 走 Shutdown 流程，即 kill 游戏 + 停 kmdf
//
// 注意: 本模块只负责"监控+通知",不拦截驱动加载本身
//       真正的"拦截"由 UserService 触发 Shutdown 实现，即杀游戏+停kmdf
//
// 为什么不在回调里直接 kill 游戏:
//   - PsSetLoadImageNotifyRoutine 回调里调用 ZwTerminateProcess 会触发
//     进程映像卸载通知,可能递归回调导致死锁/蓝屏
//   - 回调运行在 PASSIVE_LEVEL 但持有关键锁,不能做阻塞操作
//
// KMDF 注意:
//   - 不能用 IoCompleteRequest/PIRP,必须用 WdfRequestComplete*
//   - 必须 WdfRequestMarkCancelableEx 注册取消回调,否则设备关闭时挂起的请求会泄漏

// 用户态 → 内核: IOCTL_WAIT_LOADIMAGE，无输入，输出为 LOADIMAGE_NOTIFY
// 内核 → 用户态: 回调触发时完成请求,输出映像路径

typedef struct _LOADIMAGE_NOTIFY {
	ULONG_PTR ImageBase;        // 映像基址
	ULONG     ImageSize;        // 映像大小
	WCHAR     ImageName[260];   // 映像路径 (Unicode)
} LOADIMAGE_NOTIFY, * PLOADIMAGE_NOTIFY;

NTSTATUS DriverMonitorInit(VOID);
VOID DriverMonitorUnload(VOID);

// 映像加载回调，由 PsSetLoadImageNotifyRoutine 注册
VOID DriverMonitorLoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo);

// 由 Driver.c 的 EvtIoDeviceControl 调用:
// 收到 IOCTL_WAIT_LOADIMAGE 时挂起 WDFREQUEST 入队
// 返回 STATUS_PENDING 表示请求已挂起,调用方不应再完成它
NTSTATUS DriverMonitorQueuePendingRequest(_In_ WDFREQUEST Request);

// 由 Driver.c 的 EvtDriverUnload / 设备清理调用:
// 取消所有 pending WDFREQUEST
VOID DriverMonitorCancelAllPendingRequests(VOID);
