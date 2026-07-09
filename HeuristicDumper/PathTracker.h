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

// 登记 + dump: 路径去重, 首次出现时调用 DumpModule/CopyFileFromDisk
void RegisterForDump(HANDLE hProcess, unsigned long pid,
                     const std::wstring& path, const std::wstring& tag,
                     unsigned long long base, unsigned long size);

// Ctrl+C 后打印完整去重路径表
void PrintPathTable();

} // namespace das
