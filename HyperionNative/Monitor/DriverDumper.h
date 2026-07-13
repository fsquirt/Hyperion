// DriverDumper.h — 内核驱动内存 dump
//
// 按 AttachId 通过 KernelService 从内核 dump 被附着设备所属驱动的内存映像。
// KernelService 设备句柄由 RunCommsMonitor 打开后通过 InitDriverDumper 传入。
// 实现在 DriverDumper.cpp。

#pragma once

#include <string>
#include <windows.h>
#include <vector>

namespace das {

// 驱动 dump 元数据 (供 FFI 数据导出使用)
struct DriverDumpEntry {
    int32_t          status = 0;
    uint32_t         attachId = 0;
    uint64_t         driverObjectAddr = 0;
    uint64_t         imageBase = 0;
    uint32_t         imageSize = 0;
    uint32_t         bytesDumped = 0;
    std::wstring     fullPath;
    std::wstring     baseName;
    std::wstring     dumpFile;     // dump 文件名 (相对 dumpfile/ 目录)
};

// 初始化 DriverDumper: 传入 KernelService 设备句柄 + dumpfile/FileDump 路径
// (RunCommsMonitor 启动时打开 KernelService 后调用)
void InitDriverDumper(void* hKs, const std::wstring& dumpDir,
                     const std::wstring& fileDumpDir);

// dump 被附着设备所属驱动的内存 (按 AttachId 去重)
// 磁盘有 sys → 拷贝到 FileDump; 磁盘缺失 → 内核 dump 到 dumpfile
void DumpTargetDriver(unsigned long attachId);

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 获取已收集的驱动 dump 元数据列表
std::vector<DriverDumpEntry> GetCollectedDriverDumps();

// 重置已收集的驱动 dump 元数据
void ResetCollectedDriverDumps();

} // namespace das
