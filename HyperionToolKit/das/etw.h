#pragma once
#include <string>

namespace das {

	// 启动 ETW 实时订阅
	//   durationSec: 订阅持续秒数, 传 0 表示永久, 直到 Ctrl+C
	//   etlPath:     若非空,事件同时落盘到该 .etl 文件
	// 返回 0 = 成功,非 0 = 失败码
	int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath);

} // namespace das