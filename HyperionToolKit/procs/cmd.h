#pragma once

namespace das {
	// 主入口: 解析参数并分发到树形 / 安全采集模式
	int RunProcs(int argc, wchar_t** argv);

} // namespace das