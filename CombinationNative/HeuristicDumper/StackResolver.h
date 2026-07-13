// StackResolver.h — 调用栈符号化
//
// 建立目标进程模块表, 从 ETW 事件 ExtendedData 收集调用栈命中的业务模块。
// 实现在 StackResolver.cpp。

#pragma once

#include <vector>
#include <windows.h>
#include <evntcons.h>
#include "MonitorTypes.h"

namespace das {

// 构建目标进程模块表 (EnumProcessModules + GetModuleInformation)
std::vector<ModuleRange> BuildModuleTable(unsigned long long pid);

// 从 ETW 事件 ExtendedData 收集调用栈命中的业务模块 (排除系统目录)
std::vector<StackModuleInfo> CollectStackModules(
    const EVENT_RECORD* record,
    const std::vector<ModuleRange>& modules);

} // namespace das
