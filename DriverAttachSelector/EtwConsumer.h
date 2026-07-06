// EtwConsumer.h — 实时订阅 KernelService ETW Provider 的 IOCTL 拦截事件
//
// 功能:
//   1. StartTrace 开辟 Real-Time Session
//   2. EnableTraceEx2 启用 Provider,带 EVENT_ENABLE_PROPERTY_STACK_TRACE
//      → ETW 框架会自动抓取跨态调用栈 (Ring3 业务代码 → ntdll → ntoskrnl → 驱动)
//   3. OpenTrace + ProcessTrace 实时消费事件
//   4. EventRecordCallback 解析 UserData:
//        [ETW_IOCTL_EVENT_HEADER] + [Payload 字节流]
//      并打印调用栈 (从 ExtendedData 里取 STACK_TRACE)
//
// 用法:
//   DriverAttachSelector.exe --etw                 默认订阅 30 秒
//   DriverAttachSelector.exe --etw --duration 60   订阅 60 秒
//   DriverAttachSelector.exe --etw --out C:\x.etl  同时落盘到 etl 文件
//
// 注意:
//   - 需要管理员权限 (SeSystemProfilePrivilege + SeTraceLoggingPrivilege)
//   - Provider GUID 必须与内核 EtwLogger.c 一致:
//     {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}

#pragma once

#include <string>

namespace das {

// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// 与内核 EtwLogger.h 一致
extern const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR;

// 启动 ETW 实时订阅
//   durationSec: 订阅持续秒数 (0 = 永久直到 Ctrl+C)
//   etlPath:     若非空,事件同时落盘到该 .etl 文件
// 返回 0 = 成功,非 0 = 失败码
int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath);

} // namespace das
