// cmd.h — gameprotect 子命令入口
//
// 通过 KernelService 驱动对指定游戏进程启用/停用句柄降级保护
// 即 GameProtect: 对进程/线程句柄在创建与复制时做危险权限剥离。

#pragma once

namespace das {

	// 主入口: gameprotect --StartHandleProtect <PID> / --StopHandleProtect / ... / --help
	int RunGameProtect(int argc, wchar_t** argv);

} // namespace das