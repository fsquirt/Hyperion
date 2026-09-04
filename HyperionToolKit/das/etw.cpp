// etw.cpp — ETW 实时订阅实现,对应 das --etw,原 EtwConsumer.cpp
//
// 原文件包含完整的 ETW 管道: 权限→StartTrace→EnableTraceEx2→OpenTrace→
// ProcessTrace→轮询→清理, 现改由 common/Etw::RunEtwSession 承担;
// 本文件保留事件回调与 IOCTL 事件格式化输出。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "etw.h"
#include "../common/Etw.h"
#include "../common/Out.h"
#include "../common/StackResolver.h"
#include "../common/Str.h"

#include <windows.h>
#include <psapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace das {

#define ETW_MAX_PAYLOAD_CAPTURE 4096

	// Session 名称,与应用层命令行一致
	static const wchar_t* SESSION_NAME = L"KernelServiceIoctlTrace";

	// 工具:格式化 IOCTL 控制码的 METHOD
	static const wchar_t* MethodName(unsigned long ioctl)
	{
		switch (ioctl & 3) {
		case 0: return L"BUFFERED";
		case 1: return L"IN_DIRECT";
		case 2: return L"OUT_DIRECT";
		case 3: return L"NEITHER";
		default: return L"?";
		}
	}

	// 打印调用栈,最多 64 帧, 跨进程符号化复用 common/StackResolver
	static void PrintStackTrace(const EVENT_RECORD* record, unsigned long long requestorPid)
	{
		if (record->ExtendedDataCount == 0) {
			OutLine(L"  调用栈: <无 ExtendedData — 栈未被捕获,检查 SeSystemProfilePrivilege>");
			return;
		}

		std::vector<ModuleRange> modules = BuildModuleTable(requestorPid);

		bool foundStack = false;

		for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
			const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record->ExtendedData[i];

			if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32 &&
				item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
				continue;
			}

			// 真实结构: ULONG64 MatchId 占 8 字节 + Address[];帧数 = (DataSize - 8) / 8
			if (item.DataSize < sizeof(unsigned long long)) {
				continue;
			}

			bool is64 = (item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64);
			const unsigned long long* pMatchId = (const unsigned long long*)item.DataPtr;
			(void)pMatchId;
			const unsigned char* addrStart = (const unsigned char*)item.DataPtr + sizeof(unsigned long long);

			unsigned long frameCount = 0;
			const unsigned long long* frames64 = nullptr;
			const unsigned long* frames32 = nullptr;

			if (is64) {
				frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long long);
				frames64 = (const unsigned long long*)addrStart;
			}
			else {
				frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long);
				frames32 = (const unsigned long*)addrStart;
			}

			if (frameCount == 0) {
				OutLine(L"  调用栈: <栈帧数为 0>");
				continue;
			}

			foundStack = true;
			std::wostringstream ss;
			ss << L"  调用栈 共 " << frameCount << L" 帧, " << (is64 ? L"64位" : L"32位") << L":\n";

			unsigned long maxPrint = std::min(frameCount, (unsigned long)64);
			for (unsigned long f = 0; f < maxPrint; f++) {
				unsigned long long addr = is64 ? frames64[f] : frames32[f];

				ss << L"    [" << std::setw(2) << f << L"] " << std::hex
					<< std::setw(16) << std::setfill(L'0') << addr;

				// 用户态地址 (< 0x800000000000 on x64) 查目标进程模块
				if (addr < 0x800000000000ULL) {
					std::wstring resolved = ResolveStackAddress(addr, modules);
					if (!resolved.empty()) {
						ss << L"  " << resolved;
					}
					else {
						ss << L"  <用户态:未解析>";
					}
				}
				else {
					ss << L"  <内核态>";
				}
				ss << L"\n";
			}

			if (frameCount > maxPrint) {
				ss << L"    ... 还有 " << (frameCount - maxPrint) << L" 帧未显示\n";
			}

			Out(ss.str());
			break; // 只处理第一个栈条目
		}

		if (!foundStack) {
			std::wostringstream dbg;
			dbg << L"  调用栈: <ExtendedData 里没有 STACK_TRACE32/64 条目>\n";
			dbg << L"  [诊断] ExtendedDataCount=" << record->ExtendedDataCount << L"\n";
			for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
				dbg << L"    [" << i << L"] ExtType=" << record->ExtendedData[i].ExtType
					<< L" DataSize=" << record->ExtendedData[i].DataSize << L"\n";
			}
			Out(dbg.str());
		}
	}

	// 事件回调 — 解析 UserData
	static void OnIoctlEvent(const EVENT_RECORD* record)
	{
		// 只处理我们 Provider 的事件 (EventId == 1)
		if (record->EventHeader.EventDescriptor.Id != 1) {
			return;
		}

		// UserData = EtwIoctlEventHeader + Payload[CaptureSize]
		if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) {
			OutLine(L"[ETW] 事件 UserData 太短,跳过");
			return;
		}

		const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;
		const unsigned char* payload = (const unsigned char*)record->UserData + sizeof(EtwIoctlEventHeader);
		unsigned long payloadLen = hdr->CaptureSize;

		if (sizeof(EtwIoctlEventHeader) + payloadLen > (unsigned long)record->UserDataLength) {
			payloadLen = (unsigned long)record->UserDataLength - sizeof(EtwIoctlEventHeader);
		}

		std::wostringstream ss;
		ss << L"\n═══════════════════════════════════════════════════════\n";
		ss << L"  IOCTL 拦截事件  (AttachId=" << hdr->AttachId << L")\n";
		ss << L"───────────────────────────────────────────────────────\n";
		ss << L"  IoControlCode:    0x" << std::hex << std::setw(8) << std::setfill(L'0') << hdr->IoControlCode
			<< L"  (METHOD_" << MethodName(hdr->IoControlCode) << L")\n";
		ss << L"  MajorFunction:    0x" << std::hex << std::setw(2) << std::setfill(L'0') << hdr->MajorFunction;
		if (hdr->MajorFunction == 0x0E) ss << L" (DEVICE_CONTROL)";
		else if (hdr->MajorFunction == 0x00) ss << L" (CREATE)";
		else if (hdr->MajorFunction == 0x02) ss << L" (CLOSE)";
		else if (hdr->MajorFunction == 0x03) ss << L" (READ)";
		else if (hdr->MajorFunction == 0x04) ss << L" (WRITE)";
		ss << L"\n";
		ss << L"  发起进程 PID:     " << std::dec << hdr->RequestorPid << L"\n";
		ss << L"  InputBuffer 长度: " << hdr->InputBufferLength << L" 字节\n";
		ss << L"  实际抓取:         " << hdr->CaptureSize << L" 字节,上限 " << ETW_MAX_PAYLOAD_CAPTURE << L"\n";
		ss << L"  FilterDevice:     0x" << std::hex << hdr->FilterDeviceAddr << L"\n";
		ss << L"  TargetDevice:     0x" << hdr->TargetDeviceAddr << L"\n";

		// 时间戳
		SYSTEMTIME st;
		FILETIME ft;
		ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
		ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
		FileTimeToSystemTime(&ft, &st);
		ss << L"  时间:             " << std::dec
			<< std::setw(2) << std::setfill(L'0') << st.wHour << L":"
			<< std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
			<< std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
			<< std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L"\n";

		Out(ss.str());

		if (payloadLen > 0) {
			std::wostringstream ph;
			ph << L"  Payload (Hex Dump):\n";
			ph << HexDump(payload, payloadLen);
			Out(ph.str());
		}
		else {
			OutLine(L"  Payload: <空>");
		}

		// 打印调用栈,传入发起进程 PID 用于跨进程符号化
		PrintStackTrace(record, hdr->RequestorPid);
	}

	int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath)
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  ETW 实时订阅 — IOCTL 拦截事件 + 跨态调用栈\n");
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  Provider GUID: " + std::wstring(ETW_IOCTL_PROVIDER_GUID_STR) + L"\n");
		if (durationSec > 0) {
			Out(L"  持续时间: " + std::to_wstring(durationSec) + L" 秒\n");
		}
		else {
			Out(L"  持续时间: 永久,Ctrl+C 退出\n");
		}
		if (!etlPath.empty()) {
			Out(L"  落盘文件: " + etlPath + L"\n");
		}
		Out(L"\n");

		EtwSessionConfig cfg;
		cfg.sessionName = SESSION_NAME;
		cfg.etlPath = etlPath;
		cfg.durationSec = durationSec;
		cfg.enableStack = true;

		return RunEtwSession(cfg, OnIoctlEvent);
	}

} // namespace das