// jsonlog.cpp — dumper JSON 通信日志,原 JsonLogger.cpp
//
// 拆分自 CommsMonitor.cpp:
//   - InitJsonLog / WriteJsonEvent / CloseJsonLog: JSON 数组文件写入
//
// JsonEscape / BytesToHex 已下沉到 common/Str.h; 文件写入下沉到 common/Json
// 的 JsonArrayFile。输出层改用 common/Out (Out / OutLine)。
// 默认关闭, 由 monitor 根据 MonitorOptions.enableJson 决定是否调用 InitJsonLog。
// 每次通信事件直接追加写文件, 不在内存缓存。
// ETW 回调是单线程串行, 跑在 ProcessTrace 专用线程上, 无需加锁。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "jsonlog.h"
#include "MonitorTypes.h"
#include "../common/Json.h"
#include "../common/Str.h"
#include "../common/Out.h"

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace das {

	// JSON 日志文件路径 + 写器
	static std::wstring g_jsonPath;
	static JsonArrayFile g_jsonFile;

	// 初始化 JSON 日志文件: 创建 comms_log.json, 写入数组开头 "[\n"
	bool InitJsonLog()
	{
		wchar_t exePath[MAX_PATH];
		DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
		if (len == 0) return false;

		std::wstring dir(exePath);
		size_t slash = dir.find_last_of(L"\\/");
		if (slash != std::wstring::npos) dir = dir.substr(0, slash);

		g_jsonPath = dir + L"\\comms_log.json";

		// 如果文件已存在则覆盖, 因为 JsonArrayFile::Open 内部以 CREATE_ALWAYS 打开
		if (!g_jsonFile.Open(g_jsonPath)) return false;
		return true;
	}

	// 追加一个通信事件到 JSON 文件,直接写, 不缓存
	void WriteJsonEvent(
		const SYSTEMTIME& st,
		const EtwIoctlEventHeader* hdr,
		const std::wstring& exePath,
		const std::vector<StackModuleInfo>& stackModules,
		const unsigned char* inputBuffer,  // ETW UserData 紧跟 header 之后的 payload
		unsigned long inputBufferSize)     // 实际 payload 字节数
	{
		if (!g_jsonFile.IsOpen()) return;

		// 用 JsonBuilder 构建单条对象 (UTF-8)
		JsonBuilder o;

		// 时间戳 ISO 格式
		{
			std::ostringstream ts;
			ts << std::setfill('0')
				<< std::setw(4) << st.wYear << "-"
				<< std::setw(2) << st.wMonth << "-"
				<< std::setw(2) << st.wDay << "T"
				<< std::setw(2) << st.wHour << ":"
				<< std::setw(2) << st.wMinute << ":"
				<< std::setw(2) << st.wSecond << "."
				<< std::setw(3) << st.wMilliseconds;
			o.FieldStr("timestamp", ts.str());
		}

		o.Field("attach_id", (unsigned long)hdr->AttachId);
		o.Field("pid", (unsigned long long)hdr->RequestorPid);
		{
			std::ostringstream ioctlHex;
			ioctlHex << "0x" << std::hex << std::setw(8) << std::setfill('0')
				<< hdr->IoControlCode;
			o.FieldStr("ioctl_code", ioctlHex.str());
		}
		o.Field("major_function", (int)hdr->MajorFunction);
		o.Field("method", (int)hdr->Method);
		o.FieldW("process_exe", exePath);

		// InputBuffer (hex)
		o.FieldStr("input_buffer_hex", BytesToHex(inputBuffer, inputBufferSize));
		o.Field("input_buffer_size", (unsigned long)inputBufferSize);

		// 栈模块数组
		{
			std::string arr = "[";
			for (size_t i = 0; i < stackModules.size(); i++) {
				JsonBuilder m;
				m.FieldW("path", stackModules[i].path);
				m.Field("base", (unsigned long long)stackModules[i].base);
				m.Field("size", (unsigned long)stackModules[i].size);
				if (i > 0) arr += ",";
				arr += m.ToString();
			}
			arr += "]";
			o.Field("stack_modules", arr);
		}

		// 直接写文件
		g_jsonFile.Write(o.ToString());
	}

	// 关闭 JSON 日志: 写入数组结尾 "]\n" 并关闭文件
	void CloseJsonLog()
	{
		if (g_jsonFile.IsOpen()) g_jsonFile.Close();
	}

	// JSON 日志文件路径访问器,供 monitor 打印提示用
	const std::wstring& GetJsonPath() { return g_jsonPath; }

} // namespace das