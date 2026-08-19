// cmd.cpp — procs 子命令入口 (原 ProcessTreeSnapshot.cpp)
//
// 命令行解析 + 分发到 tree / security 两个模式。

#include "tree.h"
#include "security.h"
#include "DataTypes.h"
#include "../common/Out.h"
#include "../common/NtApi.h"
#include <cstdlib>

namespace das {

static void PrintUsage()
{
    OutLine(L"procs — 进程树快照 / 安全采集");
    OutLine(L"");
    OutLine(L"用法:");
    OutLine(L"  HyperionToolKit procs [options]");
    OutLine(L"");
    OutLine(L"选项:");
    OutLine(L"  --pid <n>        只输出指定 PID 的子树");
    OutLine(L"  --depth <n>      限制最大深度");
    OutLine(L"  --json           输出 JSON 格式 (树形模式)");
    OutLine(L"  --security       安全采集模式 (线程/模块/内存/句柄 + 特权/PPL)");
    OutLine(L"  --no-handles     安全模式: 跳过句柄扫描");
    OutLine(L"  --no-mem         安全模式: 跳过可疑内存扫描");
    OutLine(L"  --no-threads     安全模式: 跳过线程采集");
    OutLine(L"  --no-modules     安全模式: 跳过模块采集");
    OutLine(L"  --no-token       安全模式: 跳过 Token 特权采集");
    OutLine(L"  --handles-target <n>  安全模式: 只扫指向该 PID 的句柄");
    OutLine(L"  -h, --help       显示帮助");
}

int RunProcs(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    if (!InitNtApi())
    {
        OutError(L"[错误] InitNtApi 失败, 无法加载 ntdll 函数指针\n");
        return 1;
    }

    Args args;
    for (int i = 1; i < argc; ++i)
    {
        std::wstring a = argv[i];
        if (a == L"-h" || a == L"--help")
        {
            PrintUsage();
            return 0;
        }
        else if (a == L"--pid" || a == L"-p")
        {
            if (i + 1 < argc) args.pid = wcstoul(argv[++i], nullptr, 10);
            args.hasPid = true;
        }
        else if (a == L"--depth" || a == L"-d")
        {
            if (i + 1 < argc) args.maxDepth = (int)wcstol(argv[++i], nullptr, 10);
        }
        else if (a == L"--json" || a == L"-j")
        {
            args.json = true;
        }
        else if (a == L"--security")
        {
            args.security = true;
        }
        else if (a == L"--no-handles")
        {
            args.secArgs.noHandles = true;
        }
        else if (a == L"--no-mem")
        {
            args.secArgs.noMem = true;
        }
        else if (a == L"--no-threads")
        {
            args.secArgs.noThreads = true;
        }
        else if (a == L"--no-modules")
        {
            args.secArgs.noModules = true;
        }
        else if (a == L"--no-token")
        {
            args.secArgs.noToken = true;
        }
        else if (a == L"--handles-target")
        {
            if (i + 1 < argc) args.secArgs.handlesTarget = wcstoul(argv[++i], nullptr, 10);
        }
        else
        {
            OutError(L"[错误] 未知参数: " + a + L"\n");
            PrintUsage();
            return 1;
        }
    }
    args.secArgs.pid = args.pid;
    args.secArgs.hasPid = args.hasPid;

    if (args.security)
    {
        return RunSecurityMode(args.secArgs);
    }
    return RunTreeMode(args.pid, args.maxDepth, args.json);
}

} // namespace das