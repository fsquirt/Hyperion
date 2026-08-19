// handle.h — dumper 一次性全系统句柄扫描 (原 HandleScanner)
//
// 复用 procs/collect 的全系统句柄扫描能力 (CollectHandles),
// 找出持有目标 PID 的 VM_READ (及更高危) 句柄的所有进程, 单次执行后退出。

#pragma once
#include <windows.h>
#include <string>

namespace das {

// 扫描全系统句柄, 输出持有 targetPid 的 VM_READ (及更高危) 句柄的所有进程
// 执行一次后返回, 不循环
// 返回 0 表示成功, 非 0 表示错误码
int ScanHandlesForPid(unsigned long targetPid);

} // namespace das