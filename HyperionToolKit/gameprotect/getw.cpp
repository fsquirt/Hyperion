// getw.cpp — gameprotect --etw 实现
//
// ETW 管道生命周期复用 common/Etw::RunEtwSession (StartTrace→EnableTraceEx2→
// OpenTrace→ProcessTrace→Ctrl+C/超时清理 全部在那里),本文件只负责:
//   - 过滤需要的 ETW 事件 ID:
//       EventId=2 = ImageLoad (游戏进程 DLL 加载)
//       EventId=3 = ThreadAntiDebug (新线程反调试)
//   - 解析 UserData (深拷贝,安全)
//   - 打印

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "getw.h"
#include "../common/Etw.h"
#include "../common/Out.h"

#include <windows.h>
#include <evntcons.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace das {

	// 与内核 EtwLogger.h 保持一致:
	//   ETW_EVENT_IMAGELOAD        = 2
	//   ETW_EVENT_THREAD_ANTIDEBUG = 3
	//   ETW_MAX_IMAGENAME_BYTES    = 512
#define ETW_EVENT_IMAGELOAD        2
#define ETW_EVENT_THREAD_ANTIDEBUG 3
#define ETW_MAX_IMAGENAME_BYTES    512

// 内核端 ETW_IMAGELOAD_EVENT_HEADER (与 EtwLogger.h 字节对齐一致)
#pragma pack(push, 8)
	struct EtwImageLoadEventHeader {
		unsigned long long  ProcessId;         // 8
		unsigned long long  InitiatorPid;      // 8
		unsigned long long  ImageBase;         // 8
		unsigned long       ImageSize;         // 4
		unsigned long       ImageNameBytes;    // 4
	};                                        // = 32
#pragma pack(pop)
	static_assert(sizeof(EtwImageLoadEventHeader) == 32,
		"EtwImageLoadEventHeader size mismatch");

	// 内核端 ETW_THREAD_ANTIDEBUG_EVENT_HEADER (与 EtwLogger.h 字节对齐一致)
#pragma pack(push, 8)
	struct EtwThreadAntiDebugEventHeader {
		unsigned long long  CreatorPid;        // 8
		unsigned long long  ProcessId;         // 8
		unsigned long long  ThreadId;          // 8
	};                                        // = 24
#pragma pack(pop)
	static_assert(sizeof(EtwThreadAntiDebugEventHeader) == 24,
		"EtwThreadAntiDebugEventHeader size mismatch");

	// 事件回调 — 处理 EventId=2 (ImageLoad) 和 EventId=3 (ThreadAntiDebug)
	static void OnGameProtectEvent(const EVENT_RECORD* record)
	{
		SYSTEMTIME st;
		FILETIME ft;
		ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
		ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
		FileTimeToSystemTime(&ft, &st);

		std::wostringstream ss;
		ss << L"["
			<< std::dec << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
			<< std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
			<< std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
			<< std::setw(3) << std::setfill(L'0') << st.wMilliseconds
			<< L"] ";

		if (record->EventHeader.EventDescriptor.Id == ETW_EVENT_IMAGELOAD) {
			if (record->UserDataLength < (LONG)sizeof(EtwImageLoadEventHeader)) {
				return;
			}

			const EtwImageLoadEventHeader* hdr =
				(const EtwImageLoadEventHeader*)record->UserData;

			// 读取深拷贝的映像路径 (ImageNameBytes 字节, 后跟 WCHAR 数组)
			const unsigned char* data =
				(const unsigned char*)record->UserData + sizeof(EtwImageLoadEventHeader);
			unsigned long nameBytes = hdr->ImageNameBytes;
			long available = record->UserDataLength - (LONG)sizeof(EtwImageLoadEventHeader);
			if ((long)nameBytes > available) {
				nameBytes = (unsigned long)available;
			}

			std::wstring imageName;
			if (nameBytes >= sizeof(wchar_t)) {
				unsigned long chars = nameBytes / sizeof(wchar_t);
				imageName.assign((const wchar_t*)data, chars);
			}

			ss << L"ImageLoad PID=" << std::dec << (unsigned long long)hdr->ProcessId
				<< L" InitiatorPid=" << std::dec << (unsigned long long)hdr->InitiatorPid
				<< L" Base=0x" << std::hex << (unsigned long long)hdr->ImageBase
				<< L" Size=0x" << std::hex << (unsigned long long)hdr->ImageSize
				<< L" Path=" << imageName << L"\n";
		}
		else if (record->EventHeader.EventDescriptor.Id == ETW_EVENT_THREAD_ANTIDEBUG) {
			if (record->UserDataLength < (LONG)sizeof(EtwThreadAntiDebugEventHeader)) {
				return;
			}

			const EtwThreadAntiDebugEventHeader* hdr =
				(const EtwThreadAntiDebugEventHeader*)record->UserData;

			ss << L"ThreadAntiDebug CreatorPid=" << std::dec << (unsigned long long)hdr->CreatorPid
				<< L" ProcessId=" << std::dec << (unsigned long long)hdr->ProcessId
				<< L" ThreadId=" << std::dec << (unsigned long long)hdr->ThreadId << L"\n";
		}
		else {
			return;
		}

		Out(ss.str());
	}

	int RunGameProtectEtw()
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  GameProtect ETW — 订阅 KernelService ETW\n");
		Out(L"    EventId=2 ImageLoad / EventId=3 ThreadAntiDebug\n");
		Out(L"═══════════════════════════════════════════════════════\n");
		OutLine(L"  Ctrl+C 退出\n");

		EtwSessionConfig cfg;
		cfg.sessionName = L"KernelServiceGameProtectTrace";
		cfg.durationSec = 0;        // 0 = 永久直到 Ctrl+C
		cfg.enableStack = false;    // 不需要调用栈,加速订阅

		return RunEtwSession(cfg, OnGameProtectEvent);
	}

} // namespace das