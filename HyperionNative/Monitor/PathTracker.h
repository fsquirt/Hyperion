// PathTracker.h — 路径去重表
//
// 按路径去重登记; 首次出现时调用 DumpModule/CopyFileFromDisk。
// 实现在 PathTracker.cpp。

#pragma once

#include <string>
#include <windows.h>
#include "MonitorTypes.h"

namespace das {

// 登记 + dump: 路径去重, 首次出现时调用 DumpModule / CopyFileFromDisk
// base/size 仅 Raw 模式用, Mifudump 模式按 PID 去重 (ModuleDumper 内部处理)
void RegisterForDump(HANDLE hProcess, unsigned long pid,
                     const std::wstring& path, const std::wstring& tag,
                     unsigned long long base, unsigned long size);

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 获取已收集的路径表副本 (不打印)
// 返回路径表的拷贝; 若尚未运行过监控则为空
std::vector<PathEntry> GetCollectedPaths();

// 重置路径表 (在开始新的一轮监控前调用)
void ResetCollectedPaths();

} // namespace das
