// CommsMonitor.h — 通信文件监控
//
// 引用 DriverAttachSelector 的 ETW 订阅逻辑 (Provider GUID / EtwIoctlEventHeader / 管道搭建),
// 定制回调: 从调用栈定位"与被附着驱动通信的磁盘文件",并检查 RHS 属性。
//
// 用法:
//   HeuristicDumper.exe                  永久订阅 (Ctrl+C 退出)
//   HeuristicDumper.exe --duration 60    订阅 60 秒

#pragma once

namespace das {

// 启动 ETW 订阅,监控与被附着驱动的通信,输出通信文件并检查 RHS 属性
//   durationSec: 0 = 永久直到 Ctrl+C
int RunCommsMonitor(unsigned int durationSec);

} // namespace das
