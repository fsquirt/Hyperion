// DriverDumper.h — 内核驱动内存 dump
//
// 按 AttachId 通过 KernelService 从内核 dump 被附着设备所属驱动的内存映像。
// KernelService 设备句柄由 RunCommsMonitor 打开后通过 InitDriverDumper 传入。
// 实现在 DriverDumper.cpp。

#pragma once

#include <string>
#include <windows.h>

namespace das {

// 初始化 DriverDumper: 传入 KernelService 设备句柄 + dumpfile/FileDump 路径
// (RunCommsMonitor 启动时打开 KernelService 后调用)
void InitDriverDumper(void* hKs, const std::wstring& dumpDir,
                     const std::wstring& fileDumpDir);

// dump 被附着设备所属驱动的内存 (按 AttachId 去重)
// 磁盘有 sys → 拷贝到 FileDump; 磁盘缺失 → 内核 dump 到 dumpfile
void DumpTargetDriver(unsigned long attachId);

} // namespace das
