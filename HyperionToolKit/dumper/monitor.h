// monitor.h — dumper ETW 通信监控入口,原 CommsMonitor
//
// 管道层已下沉到 common/Etw::RunEtwSession; 本模块负责事件回调协调:
// 定位通信文件, 来源为进程 exe 与栈中业务模块 → 检查 RHS → 去重登记 dump → 对端驱动 dump → JSON 日志。

#pragma once
#include "MonitorTypes.h"

namespace das {

	// 启动通信监控,阻塞直到 Ctrl+C / 超时 / 停止
	int RunCommsMonitor(const MonitorOptions& options);

} // namespace das