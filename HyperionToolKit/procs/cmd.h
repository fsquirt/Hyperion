// cmd.h — procs 子命令入口
//
// 进程树快照 / 安全采集,原 ProcessTreeSnapshot.cpp, 命令行解析后分发到
// tree / security 两个模式。

#pragma once

namespace das {

	// 主入口: 解析参数并分发到树形 / 安全采集模式
	int RunProcs(int argc, wchar_t** argv);

} // namespace das