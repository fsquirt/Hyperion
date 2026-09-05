#pragma once

#include <string>
#include <windows.h>

namespace das {
	// 初始化 drvdump: 传入 KernelService 设备句柄 + dumpfile/FileDump 路径
	void InitDriverDumper(void* hKs, const std::wstring& dumpDir,
		const std::wstring& fileDumpDir);

	// dump 被附着设备所属驱动的内存,按 AttachId 去重
	// 磁盘有 sys → 拷贝到 FileDump; 磁盘缺失 → 内核 dump 到 dumpfile
	void DumpTargetDriver(unsigned long attachId);

} // namespace das