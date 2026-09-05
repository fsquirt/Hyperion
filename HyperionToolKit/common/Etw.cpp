//   1. 启用 SeSystemProfilePrivilege + SeDebugPrivilege
//   2. 准备 EVENT_TRACE_PROPERTIES,含会话名 + 可选 .etl 落盘
//   3. 停掉残留同名 Session → StartTraceW
//   4. EnableTraceEx2 带 EVENT_ENABLE_PROPERTY_STACK_TRACE 启用 Provider
//   5. OpenTraceW (REAL_TIME | EVENT_RECORD) → ProcessTrace 独立线程
//   6. 主线程 200ms 轮询: Ctrl+C 或定时器到期后主动 Stop 踢醒卡死的 ProcessTrace
//   7. 统一清理

#include "Etw.h"
#include "Priv.h"
#include "Out.h"

#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>

#include <string>
#include <vector>
#include <atomic>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace das {

	const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR = L"{A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}";

	namespace {

		std::atomic<bool> g_StopRequested{ false };
		EtwEventCallback g_callback;

		//  事件回调 — 转发给使用者
		void WINAPI EventRecordCallback(EVENT_RECORD* record)
		{
			if (g_StopRequested.load()) return;
			if (g_callback) g_callback(record);
		}

		// BufferCallback — 检测停止信号, 返回 FALSE 让 ProcessTrace 退出
		ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* logfile)
		{
			UNREFERENCED_PARAMETER(logfile);
			return g_StopRequested.load() ? FALSE : TRUE;
		}

	} // namespace

	
	//  RunEtwSession — 主入口
	int RunEtwSession(const EtwSessionConfig& cfg, EtwEventCallback onEvent)
	{
		g_callback = std::move(onEvent);

		// 1. 启用权限,抓栈靠 SeSystemProfilePrivilege
		if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME))
			OutLine(L"[警告] 启用 SeSystemProfilePrivilege 失败, 可能无法抓栈");
		if (!EnablePrivilege(SE_DEBUG_NAME))
			OutLine(L"[警告] 启用 SeDebugPrivilege 失败,非致命");

		// 2. Ctrl+C 处理
		g_StopRequested.store(false);
		auto handler = [](DWORD ctrl) -> BOOL {
			if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT)
			{
				g_StopRequested.store(true);
				OutLine(L"\n[收到 Ctrl+C, 正在停止订阅...]");
				return TRUE;
			}
			return FALSE;
			};
		SetConsoleCtrlHandler(handler, TRUE);

		// 3. 准备 EVENT_TRACE_PROPERTIES = 固定头 + SessionName + LogFileName
		const size_t sessionNameLen = wcslen(cfg.sessionName.c_str()) + 1;
		size_t logFileNameLen = cfg.etlPath.empty() ? 0 : cfg.etlPath.length() + 1;

		size_t propSize = sizeof(EVENT_TRACE_PROPERTIES)
			+ sessionNameLen * sizeof(wchar_t)
			+ logFileNameLen * sizeof(wchar_t);

		std::vector<unsigned char> propBuf(propSize, 0);
		EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)propBuf.data();
		props->Wnode.BufferSize = (ULONG)propSize;
		props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		props->Wnode.ClientContext = 1;  // QPC
		props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		if (!cfg.etlPath.empty())
		{
			props->LogFileMode |= EVENT_TRACE_FILE_MODE_SEQUENTIAL;
			props->LogFileNameOffset = (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) + sessionNameLen * sizeof(wchar_t));
			wcscpy_s((LPWSTR)((unsigned char*)props + props->LogFileNameOffset),
				logFileNameLen, cfg.etlPath.c_str());
		}
		else
		{
			props->LogFileNameOffset = 0;
		}
		props->LoggerNameOffset = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
		wcscpy_s((LPWSTR)((unsigned char*)props + props->LoggerNameOffset),
			sessionNameLen, cfg.sessionName.c_str());
		props->BufferSize = 64;          // 64KB 缓冲区
		props->MinimumBuffers = 4;
		props->MaximumBuffers = 32;
		props->MaximumFileSize = 100;    // 100 MB
		props->FlushTimer = 1;           // 1 秒强制 flush

		// 4. 停掉残留同名 Session, 再启动
		ControlTraceW((TRACEHANDLE)0, cfg.sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);

		TRACEHANDLE sessionHandle = 0;
		ULONG status = StartTraceW(&sessionHandle, cfg.sessionName.c_str(), props);
		if (status != ERROR_SUCCESS)
		{
			OutLine(L"[错误] StartTraceW 失败: " + std::to_wstring(status));
			SetConsoleCtrlHandler(handler, FALSE);
			return 1;
		}
		OutLine(L"[OK] ETW Session 已启动: " + cfg.sessionName);

		// 5. EnableTraceEx2 启用 Provider,带跨态栈捕获
		GUID providerGuid;
		CLSIDFromString(ETW_IOCTL_PROVIDER_GUID_STR, &providerGuid);

		ENABLE_TRACE_PARAMETERS params{};
		params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
		params.EnableProperty = cfg.enableStack ? EVENT_ENABLE_PROPERTY_STACK_TRACE : 0;
		params.SourceId = providerGuid;

		status = EnableTraceEx2(sessionHandle, &providerGuid,
			EVENT_CONTROL_CODE_ENABLE_PROVIDER,
			TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
		if (status != ERROR_SUCCESS)
		{
			OutLine(L"[错误] EnableTraceEx2 失败: " + std::to_wstring(status));
			ControlTraceW(sessionHandle, cfg.sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
			SetConsoleCtrlHandler(handler, FALSE);
			return 1;
		}
		OutLine(L"[OK] Provider 已启用" + std::wstring(cfg.enableStack
			? L", 带 EVENT_ENABLE_PROPERTY_STACK_TRACE" : L""));

		// 6. OpenTrace,实时模式必须叠加 PROCESS_TRACE_MODE_EVENT_RECORD
		EVENT_TRACE_LOGFILE logFile{};
		logFile.LoggerName = (LPWSTR)cfg.sessionName.c_str();
		logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
		logFile.EventRecordCallback = EventRecordCallback;
		logFile.BufferCallback = BufferCallback;
		logFile.IsKernelTrace = FALSE;

		TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
		if (consumerHandle == INVALID_PROCESSTRACE_HANDLE)
		{
			OutLine(L"[错误] OpenTraceW 失败: " + std::to_wstring(GetLastError()));
			ControlTraceW(sessionHandle, cfg.sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
			SetConsoleCtrlHandler(handler, FALSE);
			return 1;
		}

		// 7. 超时计时器
		HANDLE hTimer = NULL;
		if (cfg.durationSec > 0)
		{
			hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
			if (hTimer)
			{
				LARGE_INTEGER due;
				due.QuadPart = -((LONGLONG)cfg.durationSec * 10000000LL);  // 负值 = 相对时间
				SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
			}
		}

		// 8. ProcessTrace 在独立线程跑, 主线程 200ms 轮询等超时 / Ctrl+C
		HANDLE hTraceThread = CreateThread(
			NULL, 0,
			[](LPVOID param) -> DWORD {
				TRACEHANDLE* ph = (TRACEHANDLE*)param;
				ProcessTrace(ph, 1, NULL, NULL);
				return 0;
			},
			&consumerHandle, 0, NULL);

		HANDLE waits[2] = { hTraceThread, hTimer };
		DWORD waitCount = (hTimer != NULL) ? 2 : 1;

		while (true)
		{
			DWORD waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, 200);
			if (waitResult != WAIT_TIMEOUT) break;  // 线程退出或定时器到期
			if (g_StopRequested.load()) break;      // Ctrl+C
		}

		// 9. 统一清理: 主动 Stop 踢醒卡死的 ProcessTrace, 等线程安全退出
		g_StopRequested.store(true);
		ControlTraceW(sessionHandle, cfg.sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
		if (hTraceThread)
		{
			WaitForSingleObject(hTraceThread, 5000);
			CloseHandle(hTraceThread);
		}
		if (hTimer) CloseHandle(hTimer);
		CloseTrace(consumerHandle);
		ControlTraceW(sessionHandle, cfg.sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);

		SetConsoleCtrlHandler(handler, FALSE);
		g_callback = nullptr;

		OutLine(L"\n[OK] ETW 订阅已停止");
		return 0;
	}

} // namespace das