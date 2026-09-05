#pragma once
#include <windows.h>
#include <string>

namespace das {

	// 扫描全系统句柄, 输出持有 targetPid 的 VM_READ 及更高危句柄的所有进程
	// 执行一次后返回, 不循环
	// 返回 0 表示成功, 非 0 表示错误码
	int ScanHandlesForPid(unsigned long targetPid);

} // namespace das