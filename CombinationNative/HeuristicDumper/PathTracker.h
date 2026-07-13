// PathTracker.h — 路径去重表
//
// 每事件打印进程/模块, 并按路径去重登记; 首次出现时调用 DumpModule/CopyFileFromDisk。
// Ctrl+C 后打印完整去重路径表汇总。
// 实现在 PathTracker.cpp。

#pragma once

#include <string>
#include <windows.h>
#include "MonitorTypes.h"

namespace das {

// 每事件都打印进程/模块 (不去重)
void PrintFileLine(const std::wstring& path, const std::wstring& tag);

// 登记 + dump: 路径去重, 首次出现时调用 DumpModule / CopyFileFromDisk
// base/size 仅 Raw 模式用, Mifudump 模式按 PID 去重 (ModuleDumper 内部处理)
void RegisterForDump(HANDLE hProcess, unsigned long pid,
                     const std::wstring& path, const std::wstring& tag,
                     unsigned long long base, unsigned long size);

// Ctrl+C 后打印完整去重路径表
void PrintPathTable();

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 获取已收集的路径表副本 (不打印)
// 返回路径表的拷贝; 若尚未运行过监控则为空
std::vector<PathEntry> GetCollectedPaths();

// 重置路径表 (在开始新的一轮监控前调用)
void ResetCollectedPaths();

} // namespace das
