// CommsMonitor.h — 通信文件监控
//
// 引用 DriverAttachSelector 的 ETW 订阅逻辑 (Provider GUID / EtwIoctlEventHeader / 管道搭建),
// 定制回调: 从调用栈定位"与被附着驱动通信的磁盘文件",并检查 RHS 属性。
//
// 用法:
//   HeuristicDumper.exe                  永久订阅 (Ctrl+C 退出)
//   HeuristicDumper.exe --duration 60    订阅 60 秒
//   HeuristicDumper.exe --json           启用 JSON 通信日志 (默认关闭以节省性能)

#pragma once

#include "MonitorTypes.h"

namespace das {

// 启动 ETW 监控 (options 控制持续时间/JSON 开关等)
int RunCommsMonitor(const MonitorOptions& options);

} // namespace das
