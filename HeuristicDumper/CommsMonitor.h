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

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 设置静默模式 (true = 不打印进度, 仅收集路径)
void SetCommsSilentMode(bool enable);

// 运行监控并返回收集到的路径 (静默模式)
// 等价于 RunCommsMonitor 但不打印, 完成后返回路径表
int RunCommsMonitorCollect(const MonitorOptions& options);

// 外部请求停止通信监控 (设置内部停止标志, 供 CombinationNative 导出函数调用)
// 非阻塞: 仅设置标志位, RunCommsMonitor 的轮询循环会在 200ms 内检测到并退出
void RequestStopCommsMonitor();

} // namespace das
