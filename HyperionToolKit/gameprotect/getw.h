// getw.h — gameprotect --etw 入口
//
// 订阅 KernelService ETW Provider,解析 EventId=2 (ImageLoad)
// 和 EventId=3 (ThreadAntiDebug) 两类事件。

#pragma once

namespace das {

// 启动 GameProtect ETW 订阅 (阻塞直到 Ctrl+C / 超时)
// 覆盖 ImageLoad (EventId=2) 与 ThreadAntiDebug (EventId=3)
int RunGameProtectEtw();

} // namespace das