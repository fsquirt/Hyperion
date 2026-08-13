// HyperionToolKit.cpp — 统一入口分发器
//
// 把原先四个独立的 C++ 控制台工具合并到同一个可执行文件里,按第一个
// 参数(子命令)分发到对应工具的入口函数:
//
//   HyperionToolKit.exe das     [参数...]  → DriverAttachSelector (驱动附着选择器)
//   HyperionToolKit.exe dumper  [参数...]  → HeuristicDumper     (启发式通信 dump)
//   HyperionToolKit.exe ioctl             → IOCTLSender         (发随机 IOCTL 测试包)
//   HyperionToolKit.exe procs   [参数...]  → ProcessTreeSnapshot (进程树快照 / 安全采集)
//
// 每个子工具的入口函数就是从原项目 wmain/main 改名的:
//   - Main.cpp              → int RunDriverAttachSelector(int, wchar_t**)
//   - HeuristicDumper.cpp   → int RunHeuristicDumper(int, wchar_t**)
//   - IOCTLSender.cpp       → int RunIoctlSender()
//   - ProcessTreeSnapshot.cpp → int RunProcessTreeSnapshot(int, wchar_t*[])
//
// 子工具各自保留原命令行参数语义(子命令之后的 argv 原样透传)。

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>
#include <string>

// 四个工具入口 (定义在各自原入口文件里)
int RunDriverAttachSelector(int argc, wchar_t** argv);
int RunHeuristicDumper(int argc, wchar_t** argv);
int RunIoctlSender();
int RunProcessTreeSnapshot(int argc, wchar_t* argv[]);

static void PrintTopHelp()
{
    wprintf(L"HyperionToolKit — 内核工具集 (合并 DriverAttachSelector / HeuristicDumper / IOCTLSender / ProcessTreeSnapshot)\n");
    wprintf(L"\n");
    wprintf(L"用法:\n");
    wprintf(L"  HyperionToolKit.exe <子命令> [参数...]\n");
    wprintf(L"\n");
    wprintf(L"子命令:\n");
    wprintf(L"  das       DriverAttachSelector  驱动附着选择器 (驱动扫描/验签/附着/ETW 订阅/对象扫描)\n");
    wprintf(L"  dumper    HeuristicDumper       启发式通信 dump (ETW 通信监控 + 文件/驱动 dump)\n");
    wprintf(L"  ioctl     IOCTLSender           向 \\\\?\\GLOBALROOT 设备发随机 IOCTL 测试包\n");
    wprintf(L"  procs     ProcessTreeSnapshot   进程树快照 / 安全采集 (JSON 输出)\n");
    wprintf(L"\n");
    wprintf(L"示例:\n");
    wprintf(L"  HyperionToolKit.exe das --help          查看 DriverAttachSelector 的全部参数\n");
    wprintf(L"  HyperionToolKit.exe dumper --duration 60\n");
    wprintf(L"  HyperionToolKit.exe ioctl\n");
    wprintf(L"  HyperionToolKit.exe procs --security\n");
    wprintf(L"\n");
    wprintf(L"在子命令后加 --help 可查看该工具的完整用法。\n");
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
        return RunDriverAttachSelector(argc - 1, argv + 1);
    }

    if (sub == L"dumper" || sub == L"heuristic")
    {
        return RunHeuristicDumper(argc - 1, argv + 1);
    }

    if (sub == L"ioctl" || sub == L"sender")
    {
        return RunIoctlSender();
    }

    if (sub == L"procs" || sub == L"ps" || sub == L"snapshot")
    {
        return RunProcessTreeSnapshot(argc - 1, argv + 1);
    }

    wprintf(L"[错误] 未知子命令: %ls\n\n", sub.c_str());
    PrintTopHelp();
    return 2;
}
