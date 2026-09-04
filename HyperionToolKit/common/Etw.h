// Etw.h — ETW 实时订阅引擎 + 内核事件契约
//
// 原 EtwConsumer (das --etw) 与 CommsMonitor (dumper) 各自搭了一套几乎相同的
// ETW 管道: 权限→StartTrace→EnableTraceEx2→OpenTrace→ProcessTrace→轮询→清理,
// 这里收拢成 RunEtwSession: 使用者只提供事件回调, 引擎负责管道与 Ctrl+C/超时。
//
// 同时统一原来被重复定义的事件契约:
//   EtwIoctlEventHeader — 内核端 ETW 事件头,56 字节, 与内核 EtwLogger.h 对齐
//   ModuleRange         — 目标进程模块表项,栈符号化用
//   ETW_IOCTL_PROVIDER_GUID_STR / 栈追踪 ExtType 常量

#pragma once

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>

#include <string>
#include <functional>

namespace das {

	// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C},与内核 EtwLogger.h 一致
	extern const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR;

	// ETW 栈追踪 ExtType, evntcons.h 在新 SDK 才有定义
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE32
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE32 5
#endif
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE64
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE64 6
#endif

// 内核端定义的 ETW_IOCTL_EVENT_HEADER,必须与内核 EtwLogger.h 字节对齐一致
#pragma pack(push, 8)
	struct EtwIoctlEventHeader {
		unsigned long       Version;
		unsigned long       IoControlCode;
		unsigned long       InputBufferLength;
		unsigned long       CaptureSize;
		unsigned long long  RequestorPid;
		unsigned long long  TargetDeviceAddr;
		unsigned long long  FilterDeviceAddr;
		unsigned long long  AttachId;
		unsigned long       MajorFunction;
		unsigned long       Method;
	};
#pragma pack(pop)
	static_assert(sizeof(EtwIoctlEventHeader) == 56, "EtwIoctlEventHeader size mismatch");

	// 目标进程模块表项,栈地址符号化用
	struct ModuleRange {
		unsigned long long base;
		unsigned long size;
		wchar_t path[MAX_PATH];
	};

	// 事件回调: 由使用者提供, 只负责解析 UserData / ExtendedData
	typedef std::function<void(const EVENT_RECORD*)> EtwEventCallback;

	struct EtwSessionConfig {
		std::wstring  sessionName;    // 唯一会话名,如 "KernelServiceIoctlTrace"
		std::wstring  etlPath;        // 可选: 非空时同时落盘 .etl
		unsigned int  durationSec = 0;   // 0 = 永久直到 Ctrl+C
		bool          enableStack = true; // EVENT_ENABLE_PROPERTY_STACK_TRACE 抓跨态栈
	};

	// 运行一个 ETW 实时会话,阻塞直到 Ctrl+C / 超时 / 停止, 返回 0 成功
	int RunEtwSession(const EtwSessionConfig& cfg, EtwEventCallback onEvent);

} // namespace das