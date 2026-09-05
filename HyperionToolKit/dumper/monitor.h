#pragma once
#include "MonitorTypes.h"

namespace das {

	// 启动通信监控,阻塞直到 Ctrl+C / 超时 / 停止
	int RunCommsMonitor(const MonitorOptions& options);

} // namespace das