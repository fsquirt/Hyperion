// security.h — procs 安全采集模式,原 JsonWriter
//
// JSON 输出 + 主流程编排。输出统一走 das::Out。

#pragma once
#include "DataTypes.h"

namespace das {

	// 安全采集模式入口
	int RunSecurityMode(const SecurityArgs& args);

} // namespace das