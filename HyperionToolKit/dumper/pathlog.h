#pragma once

#include <string>
#include <windows.h>
#include "MonitorTypes.h"

namespace das {

	// 每事件都打印进程/模块,不去重
	void PrintFileLine(const std::wstring& path, const std::wstring& tag);

	// 登记 + dump: 路径去重, 首次出现时调用 DumpModule / CopyFileFromDisk
	// base/size 仅 Raw 模式用, Mifudump 模式按 PID 去重,moddump 内部处理
	void RegisterForDump(HANDLE hProcess, unsigned long pid,
		const std::wstring& path, const std::wstring& tag,
		unsigned long long base, unsigned long size);

	// Ctrl+C 后打印完整去重路径表
	void PrintPathTable();

} // namespace das