#pragma once

namespace das {

	// 主入口: gameprotect --StartHandleProtect <PID> / --StopHandleProtect / ... / --help
	int RunGameProtect(int argc, wchar_t** argv);

} // namespace das