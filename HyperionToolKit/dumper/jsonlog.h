// jsonlog.h — dumper JSON 通信日志,原 JsonLogger
//
// 默认关闭, 通过命令行 --json 开关启用,由 monitor 控制 InitJsonLog 调用。
// 每次通信事件直接追加写文件, 不在内存缓存。
// 底层写文件改用 common/Json::JsonArrayFile。

#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "MonitorTypes.h"

namespace das {

	// 初始化 JSON 日志文件 (comms_log.json), 写入数组开头 "[\n"
	bool InitJsonLog();

	// 追加一个通信事件,直接写文件, 不缓存
	void WriteJsonEvent(
		const SYSTEMTIME& st,
		const EtwIoctlEventHeader* hdr,
		const std::wstring& exePath,
		const std::vector<StackModuleInfo>& stackModules,
		const unsigned char* inputBuffer,
		unsigned long inputBufferSize);

	// 关闭 JSON 日志, 写入 "]\n"
	void CloseJsonLog();

	// JSON 日志文件路径访问器,供 monitor 打印提示用
	const std::wstring& GetJsonPath();

} // namespace das