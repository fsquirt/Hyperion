// monitor.cpp — dumper ETW 事件回调协调器 (原 CommsMonitor.cpp)
//
// 原文件自带完整 ETW 管道, 现改用 common/Etw::RunEtwSession;
// 原 EnablePrivilege 改用 common/Priv::das::EnablePrivilege。
// 事件回调只处理 AttachId != 0 的事件, 协调 pathlog/moddump/drvdump/jsonlog。

#include "monitor.h"
#include "MonitorTypes.h"
#include "pathlog.h"
#include "moddump.h"
#include "drvdump.h"
#include "jsonlog.h"
#include "../common/Etw.h"
#include "../common/Priv.h"
#include "../common/KernelComms.h"
#include "../common/Out.h"

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

namespace das {

	// 独立 Session 名,避免与 das --etw 同时运行时冲突
	const wchar_t* SESSION_NAME = L"HeuristicDumperIoctlTrace";

	// 全局停止信号 (ETW 回调线程与主线程共享)
	std::atomic<bool> g_Stop{ false };

	// JSON 日志开关 (由 RunCommsMonitor 根据 options.enableJson 设置,
	// EventRecordCallback 是回调访问不到 options, 所以用文件内 static 控制)
	static bool g_jsonEnabled = false;

	// ═══════════════════════════════════════════════════════════════════════
	//  事件回调 — 解析事件, 定位通信文件, 协调各拆分模块
	// ═══════════════════════════════════════════════════════════════════════

	static void OnIoctlEvent(const EVENT_RECORD* record)
	{
		if (g_Stop.load()) return;
		if (record->EventHeader.EventDescriptor.Id != 1) return;

		if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) return;

		const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;

		// 只处理被附着的设备 (AttachId != 0 表示 KernelService FiDO 拦截到的事件)
		if (hdr->AttachId == 0) return;

		// 时间戳
		SYSTEMTIME st;
		FILETIME ft;
		ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
		ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
		FileTimeToSystemTime(&ft, &st);

		// 事件头
		std::wostringstream head;
		head << L"\n───────────────────────────────────────────────────────\n";
		head << L"[" << std::setfill(L'0')
			<< std::setw(2) << st.wHour << L":"
			<< std::setw(2) << st.wMinute << L":"
			<< std::setw(2) << st.wSecond << L"."
			<< std::setw(3) << st.wMilliseconds << L"] ";
		head << L"AttachId=" << hdr->AttachId
			<< L"  PID=" << hdr->RequestorPid
			<< L"  IOCTL=0x" << std::hex << std::setw(8) << std::setfill(L'0') << hdr->IoControlCode;
		if (hdr->MajorFunction == 0x0E) head << L" (DEVICE_CONTROL)";
		else if (hdr->MajorFunction == 0x00) head << L" (CREATE)";
		else if (hdr->MajorFunction == 0x02) head << L" (CLOSE)";
		head << L"\n";
		Out(head.str());

		// 打开进程 (需要 QUERY_INFORMATION 取 exe 路径 + VM_READ 建模块表/dump)
		HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, (DWORD)hdr->RequestorPid);

		// 取发起进程主 exe 路径
		std::wstring exePath;
		if (hProc) {
			wchar_t buf[MAX_PATH];
			DWORD len = MAX_PATH;
			if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
				exePath.assign(buf, len);
			}
		}

		// 建模块表 + 从调用栈收集业务模块
		auto modules = BuildModuleTable(hdr->RequestorPid);
		auto stackModules = CollectStackModules(record, modules);

		// 查 exe 模块的基址/大小 (供 Raw 模式 dump 用, Mifudump 模式忽略)
		unsigned long long exeBase = 0;
		unsigned long exeSize = 0;
		for (const auto& mr : modules) {
			if (mr.path == exePath) {
				exeBase = mr.base;
				exeSize = mr.size;
				break;
			}
		}

		Out(L"  通信文件:\n");

		// 每事件都打印 (不去重, 显示哪个进程哪个模块)
		PrintFileLine(exePath, L"进程 exe");
		if (stackModules.empty()) {
			OutLine(L"    调用栈业务模块: <无> (调用栈只有系统模块或未捕获)");
		}
		else {
			for (size_t i = 0; i < stackModules.size(); i++) {
				std::wostringstream tag;
				tag << L"栈模块[" << (i + 1) << L"]";
				PrintFileLine(stackModules[i].path, tag.str());
			}
		}

		// 登记 + dump (路径去重登记; dump 方式由 ModuleDumper 开关决定)
		RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
			exePath, L"进程 exe", exeBase, exeSize);
		for (size_t i = 0; i < stackModules.size(); i++) {
			std::wostringstream tag;
			tag << L"栈模块[" << (i + 1) << L"]";
			RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
				stackModules[i].path, tag.str(),
				stackModules[i].base, stackModules[i].size);
		}

		// 对端驱动 dump (按 AttachId 去重: 磁盘有拷 FileDump, 没有从内存 dump 到 dumpfile)
		DumpTargetDriver((unsigned long)hdr->AttachId);

		// (可选) 写 JSON 通信日志 — 由 --json 开关控制
		if (g_jsonEnabled) {
			// ETW UserData 布局: EtwIoctlEventHeader(56B) + CaptureSize 字节 InputBuffer
			const unsigned char* inputBuf = (const unsigned char*)record->UserData
				+ sizeof(EtwIoctlEventHeader);
			unsigned long inputSize = hdr->CaptureSize;
			// 防止越界 (UserData 可能被截断)
			if (sizeof(EtwIoctlEventHeader) + inputSize > (unsigned long)record->UserDataLength) {
				inputSize = (unsigned long)record->UserDataLength - sizeof(EtwIoctlEventHeader);
			}
			WriteJsonEvent(st, hdr, exePath, stackModules, inputBuf, inputSize);
		}

		if (hProc) CloseHandle(hProc);
		Out(L"───────────────────────────────────────────────────────\n");
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  主入口 — 初始化 + 运行 ETW 会话
	// ═══════════════════════════════════════════════════════════════════════

	int RunCommsMonitor(const MonitorOptions& options)
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  通信文件监控 — ETW 订阅 + 调用栈定位 + RHS 属性告警\n");
		Out(std::wstring(L"  引用 DriverAttachSelector 的 ETW 逻辑 (Provider ")
			+ ETW_IOCTL_PROVIDER_GUID_STR + L")\n");
		Out(L"  只处理被附着设备 (AttachId != 0) 的通信事件\n");
		if (options.durationSec > 0) {
			Out(L"  持续时间: " + std::to_wstring(options.durationSec) + L" 秒\n");
		}
		else {
			Out(L"  持续时间: 永久 (Ctrl+C 退出)\n");
		}
		if (options.enableJson) {
			Out(L"  JSON 通信日志: 已启用 (--json)\n");
		}
		else {
			Out(L"  JSON 通信日志: 未启用 (默认关闭, 加 --json 开启)\n");
		}
		if (options.enableMifudump) {
			Out(L"  Dump 模式: Full Minidump (--mifudump, 体积大, 含句柄表/线程上下文)\n");
		}
		else if (options.enableMinidump) {
			Out(L"  Dump 模式: Minidump (--minidump, 体积中, 基本线程/模块/堆栈)\n");
		}
		else {
			Out(L"  Dump 模式: Raw 内存镜像 (默认, 加 --minidump 或 --mifudump 切换)\n");
		}
		Out(L"═══════════════════════════════════════════════════════\n\n");

		// 设置 dump 模式开关 (ModuleDumper 内部按此走 Raw / Mini / Mifudump 分支)
		DumpMode mode = DumpMode::Raw;
		if (options.enableMifudump)      mode = DumpMode::Mifudump;
		else if (options.enableMinidump) mode = DumpMode::Mini;
		SetDumpMode(mode);

		// 1. 启用权限 (抓栈靠 SeSystemProfilePrivilege)
		if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME)) {
			OutLine(L"[警告] 启用 SeSystemProfilePrivilege 失败,可能无法抓栈");
		}
		if (!EnablePrivilege(SE_DEBUG_NAME)) {
			OutLine(L"[警告] 启用 SeDebugPrivilege 失败 (跨进程读模块需要)");
		}

		// 1b. 初始化 dump 目录 (内存映像) + FileDump 目录 (磁盘文件副本)
		if (InitDumpDir()) {
			Out(L"[OK] dump 目录: " + GetDumpDir() + L"\n");
		}
		else {
			OutLine(L"[警告] dump 目录初始化失败,将跳过内存 dump");
		}
		if (InitFileDumpDir()) {
			Out(L"[OK] FileDump 目录: " + GetFileDumpDir() + L"\n");
		}
		else {
			OutLine(L"[警告] FileDump 目录初始化失败,将跳过磁盘文件拷贝");
		}

		// 1c. 打开 KernelService 句柄 (供 dump 对端驱动内存用)
		HANDLE hKs = CreateFileW(L"\\\\.\\KernelService", GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, 0, NULL);
		if (hKs != INVALID_HANDLE_VALUE) {
			// 把 KernelService 句柄 + dumpfile/FileDump 路径传给 DriverDumper
			InitDriverDumper((void*)hKs, GetDumpDir(), GetFileDumpDir());
			OutLine(L"[OK] 已连接 KernelService (驱动内存 dump 可用)");
		}
		else {
			Out(L"[警告] 打开 KernelService 失败 err="
				+ std::to_wstring(GetLastError())
				+ L" (将跳过对端驱动 dump)\n");
		}

		// 1d. 初始化 JSON 通信日志 (仅在 --json 启用时)
		if (options.enableJson) {
			g_jsonEnabled = true;
			if (InitJsonLog()) {
				Out(L"[OK] JSON 通信日志: " + GetJsonPath() + L"\n");
			}
			else {
				Out(L"[警告] JSON 日志初始化失败 err="
					+ std::to_wstring(GetLastError()) + L"\n");
			}
		}
		else {
			g_jsonEnabled = false;
		}

		// 2. 运行 ETW 会话 (Ctrl+C / 超时 由 common/Etw 引擎统一处理)
		EtwSessionConfig cfg;
		cfg.sessionName = SESSION_NAME;
		cfg.durationSec = options.durationSec;
		cfg.enableStack = true;
		int ret = RunEtwSession(cfg, OnIoctlEvent);

		// 3. 清理
		CloseHandle(hKs);

		// 关闭 JSON 通信日志 (仅在启用时写入数组结尾并关闭句柄)
		if (g_jsonEnabled) {
			CloseJsonLog();
			if (!GetJsonPath().empty()) {
				Out(L"[OK] JSON 通信日志已保存: " + GetJsonPath() + L"\n");
			}
		}

		// 输出去重汇总表
		PrintPathTable();
		return ret;
	}

} // namespace das