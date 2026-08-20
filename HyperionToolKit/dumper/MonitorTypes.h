// MonitorTypes.h — dumper 通信监控共享类型
//
// 拆分自 CommsMonitor.cpp。ETW 事件头 / ModuleRange / StackModuleInfo 已
// 下沉到 common/Etw.h 与 common/StackResolver.h, 本头只保留 dumper 特有类型:
//   - PathEntry: 路径去重表条目
//   - MonitorOptions: 命令行解析后的监控选项
//   - SESSION_NAME / g_Stop: dumper 的 ETW 会话与停止信号

#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <atomic>
#include "../common/Etw.h"
#include "../common/StackResolver.h"

namespace das {

	// 路径表条目 (Ctrl+C 汇总用)
	struct PathEntry {
		std::wstring  path;            // 文件完整路径
		std::wstring  tag;             // 来源标记: "进程 exe" / "栈模块"
		unsigned long pid = 0;         // 首次命中时的进程 PID (诊断用)
		bool          abnormal = false; // 不存在 或 含 RHS
		std::wstring  note;            // 异常说明 (如 "[RHS: R H]" / "[磁盘上不存在!]")
		unsigned long hitCount = 1;    // 该路径被通信命中的次数
		bool          dumped = false;  // 是否已 dump 成功 (内存映像)
		std::wstring  dumpFile;        // dump 文件名 (相对 dumpfile/ 目录)
		bool          fileCopied = false;  // 是否已拷贝磁盘文件到 FileDump
		std::wstring  fileCopyName;   // FileDump 里的副本文件名
	};

	// 监控选项 (由命令行解析后传入 RunCommsMonitor)
	struct MonitorOptions {
		unsigned int durationSec = 0;     // 0 = 永久直到 Ctrl+C
		bool         enableJson = false;   // 是否启用 JSON 通信日志 (默认关闭, --json 开启)
		bool         enableMinidump = false;  // --minidump: MiniDumpNormal (体积中)
		bool         enableMifudump = false;  // --mifudump: Full Minidump (体积大)
	};

	// 独立 Session 名,避免与 das --etw 同时运行时冲突 (定义在 monitor.cpp)
	extern const wchar_t* SESSION_NAME;

	// 全局停止信号 (ETW 回调线程与主线程共享, 定义在 monitor.cpp)
	extern std::atomic<bool> g_Stop;

} // namespace das