// HeuristicDumper.cpp — 主入口
//
// 用法:
//   HeuristicDumper.exe                  永久订阅 (Ctrl+C 退出)
//   HeuristicDumper.exe --duration 60    订阅 60 秒
//   HeuristicDumper.exe --json           启用 JSON 通信日志 (默认关闭以节省性能)
//   HeuristicDumper.exe --handle <pid>  扫描持有目标 PID 的 VM_READ 句柄的进程
//   HeuristicDumper.exe --help           显示帮助
//
// 功能:
//   引用 DriverAttachSelector 的 ETW 订阅逻辑,监控与被附着驱动的通信,
//   从调用栈定位通信文件,检查 RHS 属性,异常红色输出。

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
#include "MonitorTypes.h"
#include "HandleScanner.h"

using namespace das;

static void PrintHelp()
{
    WriteOut(L"用法:\n");
    WriteOut(L"  HeuristicDumper.exe                  永久订阅 ETW (Ctrl+C 退出)\n");
    WriteOut(L"  HeuristicDumper.exe --duration N     订阅 N 秒后自动退出\n");
    WriteOut(L"  HeuristicDumper.exe --json           启用 JSON 通信日志 (默认关闭以节省性能)\n");
    WriteOut(L"  HeuristicDumper.exe --handle <pid>  扫描持有目标 PID 的 VM_READ 句柄的进程 (单次执行后退出)\n");
    WriteOut(L"  HeuristicDumper.exe --help           显示此帮助\n");
    WriteOut(L"\n");
    WriteOut(L"功能:\n");
    WriteOut(L"  引用 DriverAttachSelector 的 ETW 逻辑,监控被附着设备的通信事件。\n");
    WriteOut(L"  从调用栈定位与驱动通信的磁盘文件 (进程 exe + 栈中业务模块),\n");
    WriteOut(L"  若文件不存在或含 RHS (只读/隐藏/系统) 属性,用红色输出。\n");
    WriteOut(L"  栈模块/exe 首次出现时:\n");
    WriteOut(L"    - 从内存 dump 到 dumpfile\\ 目录 (内存映像,同名只 dump 一次)\n");
    WriteOut(L"    - 若磁盘上有文件,拷贝到 FileDump\\ 目录 (磁盘副本,同名只拷贝一次)\n");
    WriteOut(L"  对端驱动 sys (按 AttachId 去重):\n");
    WriteOut(L"    - 磁盘有文件 → 拷贝到 FileDump\\ (内核 IOCTL_DUMP_DRIVER_MEMORY)\n");
    WriteOut(L"    - 磁盘缺失 → 按 PE 区段从内存 dump 到 dumpfile\\ (跳过 DISCARDABLE)\n");
    WriteOut(L"  JSON 通信日志 (可选, 加 --json 开启, 默认关闭以节省性能):\n");
    WriteOut(L"    - 实时导出到 comms_log.json (直接写文件不缓存)\n");
    WriteOut(L"    - 时间戳/AttachId/PID/IOCTL码/InputBuffer(hex)/调用栈模块\n");
    WriteOut(L"  异常文件名加前缀: MISSING_ (磁盘不存在) / RHS_ (含 RHS 属性)。\n");
    WriteOut(L"  --handle <pid> 模式: 单次全系统句柄扫描, 输出持有目标 PID 的\n");
    WriteOut(L"    VM_READ (及更高危) 句柄的所有进程, 执行一次后退出 (不走 ETW)。\n");
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    MonitorOptions options;
    bool handleMode = false;
    unsigned long handlePid = 0;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") {
            PrintHelp();
            return 0;
        }
        if (a == L"--handle") {
            // --handle <pid>: 支持十进制或 0x 十六进制 PID
            if (i + 1 >= argc) {
                WriteOut(L"[错误] --handle 需要一个 PID 参数\n");
                return 1;
            }
            handleMode = true;
            handlePid = wcstoul(argv[++i], nullptr, 0);
            continue;
        }
        if (a == L"--duration" && i + 1 < argc) {
            options.durationSec = (unsigned int)_wtoi(argv[++i]);
        }
        if (a == L"--json") {
            options.enableJson = true;
        }
    }

    // --handle 模式: 单次句柄扫描后退出, 不走 ETW 监控
    if (handleMode) {
        return ScanHandlesForPid(handlePid);
    }

    return RunCommsMonitor(options);
}
