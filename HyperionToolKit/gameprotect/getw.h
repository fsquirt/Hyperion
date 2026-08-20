// getw.h — gameprotect --MonitorImageLoad <PID> 入口
//
// 订阅 KernelService ETW Provider,过滤 EventId=2 的 ImageLoad 事件,
// 打印被保护进程的用户态 DLL/映像加载情况。

#pragma once

namespace das {

// 启动 ImageLoad ETW 监控 (阻塞直到 Ctrl+C / 超时)
// pid: 0 = 不按 PID 过滤;>0 = 只显示该进程的 ImageLoad 事件
int RunImageLoadMonitor(unsigned long pid);

} // namespace das