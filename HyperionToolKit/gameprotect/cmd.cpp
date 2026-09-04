// cmd.cpp — gameprotect 子命令实现
//
// 告诉 KernelService 驱动执行游戏进程保护相关操作:
//
//   HyperionToolKit.exe gameprotect --StartHandleProtect <PID>  启用句柄降级保护
//   HyperionToolKit.exe gameprotect --StopHandleProtect          停止句柄降级保护
//   HyperionToolKit.exe gameprotect --drophandle <PID>           丢弃已有高危句柄
//   HyperionToolKit.exe gameprotect --MonitorImageLoad <PID>     开启 ImageLoad 监控
//   HyperionToolKit.exe gameprotect --StopMonitorImageLoad       关闭 ImageLoad 监控
//   HyperionToolKit.exe gameprotect --NewThreadAntiDebug <PID>   新线程反调试,注册回调
//   HyperionToolKit.exe gameprotect --NewThreadAntiDebug STOP    停止新线程反调试
//   HyperionToolKit.exe gameprotect --AlreadyThreadAntiDebug <PID> 已有线程反调试
//   HyperionToolKit.exe gameprotect --etw                        订阅 ETW (ImageLoad+ThreadAntiDebug)
//
// 驱动收到后 (GameProtect.c) 通过 ObRegisterCallbacks 对该进程的
// 进程/线程句柄创建与复制做权限剥离:
//   进程句柄: PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
//             PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
//   线程句柄: THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SET_CONTEXT |
//             THREAD_GET_CONTEXT
//
// 输出统一走 das::Out (UTF-8)。

#include <windows.h>
#include <string>
#include <cstdlib>

#include "../common/Common.h"
#include "../common/KernelComms.h"
#include "../common/Out.h"
#include "getw.h"

namespace das {

	static void PrintHelp()
	{
		Out(L"用法:\n");
		Out(L"  HyperionToolKit.exe gameprotect --StartHandleProtect <PID>   启用句柄降级保护\n");
		Out(L"  HyperionToolKit.exe gameprotect --StopHandleProtect           停止句柄降级保护\n");
		Out(L"  HyperionToolKit.exe gameprotect --drophandle <PID>            丢弃其他进程握有的高危句柄\n");
		Out(L"  HyperionToolKit.exe gameprotect --MonitorImageLoad <PID>      开启 ImageLoad 监控\n");
		Out(L"  HyperionToolKit.exe gameprotect --StopMonitorImageLoad        关闭 ImageLoad 监控\n");
		Out(L"  HyperionToolKit.exe gameprotect --NewThreadAntiDebug <PID>    新线程反调试,注册回调\n");
		Out(L"  HyperionToolKit.exe gameprotect --NewThreadAntiDebug STOP     停止新线程反调试\n");
		Out(L"  HyperionToolKit.exe gameprotect --AlreadyThreadAntiDebug <PID> 对已有线程执行反调试\n");
		Out(L"  HyperionToolKit.exe gameprotect --etw                         订阅 ETW (ImageLoad+ThreadAntiDebug)\n");
		Out(L"  HyperionToolKit.exe gameprotect --help                        显示此帮助\n");
		Out(L"\n");
		Out(L"说明:\n");
		Out(L"  驱动对指定 PID 的进程/线程句柄创建与复制做权限剥离\n");
		Out(L"    - 进程句柄: TERMINATE | CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | SUSPEND_RESUME\n");
		Out(L"    - 线程句柄: SUSPEND_RESUME | TERMINATE | SET_CONTEXT | GET_CONTEXT\n");
		Out(L"  --drophandle 扫描全局句柄表,强制关闭其他进程持有的\n");
		Out(L"    PROCESS_VM_READ | VM_WRITE | VM_OPERATION 句柄\n");
		Out(L"  --MonitorImageLoad 通知驱动开始监控指定 PID 的 DLL 加载;\n");
		Out(L"    用 --etw 订阅 ETW 查看监控结果,用 --StopMonitorImageLoad 关闭监控\n");
		Out(L"  --NewThreadAntiDebug 通知驱动对指定 PID 新建线程做反调试\n");
		Out(L"    (ThreadHideFromDebugger),并注册线程创建回调;\n");
		Out(L"  --AlreadyThreadAntiDebug 通知驱动对指定 PID 已有全部线程做反调试\n");
		Out(L"  --etw 订阅驱动 ETW,接收 ImageLoad 与 ThreadAntiDebug 两类事件\n");
		Out(L"  游戏自己与 System (PID 4) 的句柄不受影响。\n");
	}

	// 解析无 PID 的请求 (<PID> 参数)
	static unsigned long ParsePidArg(int argc, wchar_t** argv, int idx)
	{
		if (argc < idx + 1) {
			return 0;
		}
		return (unsigned long)wcstoul(argv[idx], nullptr, 10);
	}

	int RunGameProtect(int argc, wchar_t** argv)
	{
		SetConsoleOutputCP(CP_UTF8);

		if (argc < 2) {
			PrintHelp();
			return 1;
		}

		std::wstring op = argv[1];

		if (op == L"--help" || op == L"-h") {
			PrintHelp();
			return 0;
		}

		void* hDevice = OpenKernelService();
		if (hDevice == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			Out(L"[ERROR] 打开 KernelService 设备失败, 错误码=" + std::to_wstring(err) + L"\n");
			if (err == ERROR_ACCESS_DENIED) {
				OutLine(L"[HINT] 需要管理员权限运行");
			}
			else if (err == ERROR_FILE_NOT_FOUND) {
				OutLine(L"[HINT] KernelService 驱动未加载 (sc start KernelService)");
			}
			return 1;
		}

		int result = 0;

		if (op == L"--etw") {
			// 纯 ETW 订阅,接收 ImageLoad + ThreadAntiDebug 两类事件
			int etwRet = RunGameProtectEtw();
			CloseKernelService(hDevice);
			return etwRet;
		}

		if (op == L"--MonitorImageLoad") {
			unsigned long pid = ParsePidArg(argc, argv, 2);
			if (pid == 0) {
				OutLine(L"[ERROR] 用法: gameprotect --MonitorImageLoad <PID>");
				CloseKernelService(hDevice);
				return 1;
			}

			Out(L"[INFO] 通知驱动开启 ImageLoad 监控, PID " + std::to_wstring(pid) + L"...\n");
			if (!GameProtectSetImageLoadMonitor(hDevice, pid)) {
				DWORD err = GetLastError();
				Out(L"[ERROR] GameProtectSetImageLoadMonitor 失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
			else {
				OutLine(L"[OK] 已开启, 用 --etw 订阅查看监控结果");
			}
		}
		else if (op == L"--StopMonitorImageLoad") {
			Out(L"[INFO] 通知驱动关闭 ImageLoad 监控...\n");
			if (!GameProtectSetImageLoadMonitor(hDevice, 0)) {
				DWORD err = GetLastError();
				Out(L"[ERROR] 关闭 ImageLoad 监控失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
			else {
				OutLine(L"[OK] 已关闭");
			}
		}
		else if (op == L"--NewThreadAntiDebug") {
			if (argc < 3) {
				OutLine(L"[ERROR] 用法: gameprotect --NewThreadAntiDebug <PID> 或 --NewThreadAntiDebug STOP");
				CloseKernelService(hDevice);
				return 1;
			}

			if (wcscmp(argv[2], L"STOP") == 0) {
				Out(L"[INFO] 停止新线程反调试...\n");
				if (GameProtectStopThreadAntiDebug(hDevice)) {
					OutLine(L"[OK] 已停止新线程反调试");
				}
				else {
					DWORD err = GetLastError();
					Out(L"[ERROR] GameProtectStopThreadAntiDebug 失败, 错误码=" + std::to_wstring(err) + L"\n");
					result = 1;
				}
			}
			else {
				unsigned long pid = ParsePidArg(argc, argv, 2);
				if (pid == 0) {
					OutLine(L"[ERROR] PID 无效");
					CloseKernelService(hDevice);
					return 1;
				}

				Out(L"[INFO] 对 PID " + std::to_wstring(pid) + L" 开启新线程反调试...\n");
				if (GameProtectSetThreadAntiDebug(hDevice, pid)) {
					OutLine(L"[OK] 已开启: 该进程新建线程将自动执行 ThreadHideFromDebugger");
				}
				else {
					DWORD err = GetLastError();
					Out(L"[ERROR] GameProtectSetThreadAntiDebug 失败, 错误码=" + std::to_wstring(err) + L"\n");
					result = 1;
				}
			}
		}
		else if (op == L"--AlreadyThreadAntiDebug") {
			unsigned long pid = ParsePidArg(argc, argv, 2);
			if (pid == 0) {
				OutLine(L"[ERROR] 用法: gameprotect --AlreadyThreadAntiDebug <PID>");
				CloseKernelService(hDevice);
				return 1;
			}

			Out(L"[INFO] 对 PID " + std::to_wstring(pid) + L" 已有线程执行反调试...\n");
			if (GameProtectHideExistingThreads(hDevice, pid)) {
				OutLine(L"[OK] 已完成: 该进程已有全部线程已执行 ThreadHideFromDebugger");
			}
			else {
				DWORD err = GetLastError();
				Out(L"[ERROR] GameProtectHideExistingThreads 失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
		}
		else if (op == L"--StartHandleProtect") {
			unsigned long pid = ParsePidArg(argc, argv, 2);
			if (pid == 0) {
				OutLine(L"[ERROR] 用法: gameprotect --StartHandleProtect <PID>");
				CloseKernelService(hDevice);
				return 1;
			}

			Out(L"[INFO] 对 PID " + std::to_wstring(pid) + L" 启用句柄降级保护...\n");
			if (GameProtectStart(hDevice, pid)) {
				OutLine(L"[OK] 已启用: 该进程的进程/线程句柄危险权限将自动剥离");
			}
			else {
				DWORD err = GetLastError();
				Out(L"[ERROR] GameProtectStart 失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
		}
		else if (op == L"--StopHandleProtect") {
			Out(L"[INFO] 停止句柄降级保护...\n");
			if (GameProtectStop(hDevice)) {
				OutLine(L"[OK] 已停止保护");
			}
			else {
				DWORD err = GetLastError();
				Out(L"[ERROR] GameProtectStop 失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
		}
		else if (op == L"--drophandle") {
			unsigned long pid = ParsePidArg(argc, argv, 2);
			if (pid == 0) {
				OutLine(L"[ERROR] 用法: gameprotect --drophandle <PID>");
				CloseKernelService(hDevice);
				return 1;
			}

			Out(L"[INFO] 丢弃 PID " + std::to_wstring(pid) + L" 的已有高危句柄...\n");
			if (GameProtectDropHandles(hDevice, pid)) {
				OutLine(L"[OK] 扫描完成, 高危句柄已强制关闭");
			}
			else {
				DWORD err = GetLastError();
				Out(L"[ERROR] GameProtectDropHandles 失败, 错误码=" + std::to_wstring(err) + L"\n");
				result = 1;
			}
		}
		else {
			Out(L"[ERROR] 未知操作: " + op + L"\n");
			PrintHelp();
			result = 1;
		}

		CloseKernelService(hDevice);
		return result;
	}

} // namespace das