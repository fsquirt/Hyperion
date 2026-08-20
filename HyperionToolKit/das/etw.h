// etw.h — ETW 实时订阅 (das --etw, 原 EtwConsumer)
//
// 管道层已下沉到 common/Etw (RunEtwSession), 本模块只负责:
//   - 事件回调: 解析 UserData = EtwIoctlEventHeader + Payload, 打印 + 调用栈符号化
//   - 调用栈符号化用 common/StackResolver (BuildModuleTable + ResolveStackAddress)

#pragma once
#include <string>

namespace das {

	// 启动 ETW 实时订阅
	//   durationSec: 订阅持续秒数 (0 = 永久直到 Ctrl+C)
	//   etlPath:     若非空,事件同时落盘到该 .etl 文件
	// 返回 0 = 成功,非 0 = 失败码
	int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath);

} // namespace das