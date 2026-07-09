// HeuristicDumper.cpp — 主入口
//
// 用法:
//   HeuristicDumper.exe                  永久订阅 (Ctrl+C 退出)
//   HeuristicDumper.exe --duration 60    订阅 60 秒
//   HeuristicDumper.exe --help           显示帮助
//
// 功能:
//   引用 DriverAttachSelector 的 ETW 订阅逻辑,监控与被附着驱动的通信,
//   从调用栈定位通信文件,检查 RHS 属性,异常红色输出。
//   (dumper 功能暂未实现)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

#include <windows.h>
#include <string>
#include "Common.h"
#include "CommsMonitor.h"

using namespace das;

static void PrintHelp()
{
    WriteOut(L"用法:\n");
    WriteOut(L"  HeuristicDumper.exe                  永久订阅 ETW (Ctrl+C 退出)\n");
    WriteOut(L"  HeuristicDumper.exe --duration N     订阅 N 秒后自动退出\n");
    WriteOut(L"  HeuristicDumper.exe --help           显示此帮助\n");
    WriteOut(L"\n");
    WriteOut(L"功能:\n");
    WriteOut(L"  引用 DriverAttachSelector 的 ETW 逻辑,监控被附着设备的通信事件。\n");
    WriteOut(L"  从调用栈定位与驱动通信的磁盘文件 (进程 exe + 栈中业务模块),\n");
    WriteOut(L"  若文件不存在或含 RHS (只读/隐藏/系统) 属性,用红色输出。\n");
    WriteOut(L"  栈模块/exe 首次出现时:\n");
    WriteOut(L"    - 从内存 dump 到 dumpfile\\ 目录 (内存映像,同名只 dump 一次)\n");
    WriteOut(L"    - 若磁盘上有文件,拷贝到 FileDump\\ 目录 (磁盘副本,同名只拷贝一次)\n");
    WriteOut(L"  异常文件名加前缀: MISSING_ (磁盘不存在) / RHS_ (含 RHS 属性)。\n");
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    unsigned int duration = 0;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") {
            PrintHelp();
            return 0;
        }
        if (a == L"--duration" && i + 1 < argc) {
            duration = (unsigned int)_wtoi(argv[++i]);
        }
    }

    return RunCommsMonitor(duration);
}
