// StackResolver.h — 调用栈符号化 (shared)
// 模块表枚举 + 地址解析:
//   - BuildModuleTable      建立目标进程模块表 (EnumProcessModules)
//   - CollectStackModules   从 ETW 事件 ExtendedData 收集命中的业务模块,排除系统目录
//   - ResolveStackAddress   单个地址 → "模块短名+0x偏移", 供 das --etw 打印使用

#pragma once

#include <vector>
#include <string>
#include <windows.h>
#include <evntcons.h>
#include "Etw.h"

namespace das {

	// 调用栈命中的业务模块
	struct StackModuleInfo {
		std::wstring path;
		unsigned long long base = 0;
		unsigned long size = 0;
	};

	// 建立目标进程模块表 (EnumProcessModules + GetModuleInformation)
	std::vector<ModuleRange> BuildModuleTable(unsigned long long pid);

	// 从 ETW 事件 ExtendedData 收集调用栈命中的业务模块,排除系统目录, 按栈深排序
	std::vector<StackModuleInfo> CollectStackModules(
		const EVENT_RECORD* record,
		const std::vector<ModuleRange>& modules);

	// 解析单个调用栈地址: 命中返回 "模块短名+0x偏移", 未命中返回空串
	// 用户态未命中 / 内核态地址由调用方自行标注
	std::wstring ResolveStackAddress(unsigned long long addr,
		const std::vector<ModuleRange>& modules);

} // namespace das