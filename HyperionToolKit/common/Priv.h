// Priv.h — 进程 Token 特权启用,单一实现
//
// 原 EtwConsumer / CommsMonitor / HandleScanner 各有一份 EnablePrivilege,
// 这里收拢成一套。实现在 Priv.cpp。

#pragma once

#include <windows.h>

namespace das {

	// 启用当前进程的指定特权,如 SE_DEBUG_NAME / SE_SYSTEM_PROFILE_NAME
	// 返回 true 表示成功
	bool EnablePrivilege(LPCWSTR privilegeName);

} // namespace das