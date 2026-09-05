#pragma once

namespace das {

	// 启动 GameProtect ETW 订阅,阻塞直到 Ctrl+C / 超时
	// 覆盖 ImageLoad (EventId=2) 与 ThreadAntiDebug (EventId=3)
	int RunGameProtectEtw();

} // namespace das