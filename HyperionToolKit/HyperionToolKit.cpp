#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>
#include <string>

#include "das/cmd.h"
#include "dumper/cmd.h"
#include "ioctl/cmd.h"
#include "procs/cmd.h"
#include "gameprotect/cmd.h"
#include "common/Out.h"

static void PrintTopHelp()
{
	das::OutLine(L"HyperionToolKit — 内核工具集,合并 DriverAttachSelector / HeuristicDumper / IOCTLSender / ProcessTreeSnapshot");
	das::OutLine(L"");
	das::OutLine(L"用法:");
	das::OutLine(L"  HyperionToolKit.exe <子命令> [参数...]");
	das::OutLine(L"");
	das::OutLine(L"子命令:");
	das::OutLine(L"  das       DriverAttachSelector  驱动附着选择器,含驱动扫描/验签/附着/ETW 订阅/对象扫描");
	das::OutLine(L"  dumper    HeuristicDumper       启发式通信 dump,含 ETW 通信监控 + 文件/驱动 dump");
	das::OutLine(L"  ioctl     IOCTLSender           向 \\\\?\\GLOBALROOT 设备发随机 IOCTL 测试包");
	das::OutLine(L"  procs     ProcessTreeSnapshot   进程树快照 / 安全采集,JSON 输出");
	das::OutLine(L"  gameprotect  GameProtect          游戏进程句柄降级保护/反调试,见 gameprotect --help");
	das::OutLine(L"");
	das::OutLine(L"示例:");
	das::OutLine(L"  HyperionToolKit.exe das --help          查看 DriverAttachSelector 的全部参数");
	das::OutLine(L"  HyperionToolKit.exe dumper --duration 60");
	das::OutLine(L"  HyperionToolKit.exe ioctl");
	das::OutLine(L"  HyperionToolKit.exe procs --security");
	das::OutLine(L"  HyperionToolKit.exe gameprotect --StartHandleProtect <PID>");
	das::OutLine(L"  HyperionToolKit.exe gameprotect --StopHandleProtect");
	das::OutLine(L"");
	das::OutLine(L"在子命令后加 --help 可查看该工具的完整用法。");
}

int wmain(int argc, wchar_t** argv)
{
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2)
	{
		PrintTopHelp();
		return 0;
	}

	std::wstring sub = argv[1];

	if (sub == L"--help" || sub == L"-h" || sub == L"help")
	{
		PrintTopHelp();
		return 0;
	}

	if (sub == L"das" || sub == L"attach" || sub == L"attach-selector")
	{
		// 透传:去掉第一个子命令,子工具里 argv[1] 仍是它的第一个参数
		return das::RunDriverAttachSelector(argc - 1, argv + 1);
	}

	if (sub == L"dumper" || sub == L"heuristic")
	{
		return das::RunHeuristicDumper(argc - 1, argv + 1);
	}

	if (sub == L"ioctl" || sub == L"sender")
	{
		return das::RunIoctlSender();
	}

	if (sub == L"procs" || sub == L"ps" || sub == L"snapshot")
	{
		return das::RunProcs(argc - 1, argv + 1);
	}

	if (sub == L"gameprotect" || sub == L"gp")
	{
		return das::RunGameProtect(argc - 1, argv + 1);
	}

	das::OutError(L"[错误] 未知子命令: " + sub + L"\n\n");
	PrintTopHelp();
	return 2;
}