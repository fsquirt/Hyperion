// ProcessTreeSnapshot.cpp
//
// 进程树快照 + 安全采集工具入口。
// 解耦后的模块分布:
//   NativeApi.h      — ntdll 动态加载 + 未文档化结构体
//   StringUtils.h    — 字符串/时间/JSON 转义(header-only)
//   DataTypes.h      — 所有数据结构
//   Collector.h/.cpp — 5 大维度采集(进程/线程/模块/内存/句柄)
//   TreePrinter.h/.cpp — 默认树形打印模式
//   JsonWriter.h/.cpp — 安全采集模式(JSON 输出 + 主流程编排)
//   ProcessTreeSnapshot.cpp — 只剩 wmain + 参数解析

#include <Windows.h>
#include <cstdio>
#include <string>
#include "NativeApi.h"
#include "StringUtils.h"
#include "DataTypes.h"
#include "TreePrinter.h"
#include "JsonWriter.h"

// ───────────────────────────────────────────────────────────────
//  参数解析
// ───────────────────────────────────────────────────────────────
static Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        std::wstring s = argv[i];
        if ((s == L"--pid" || s == L"-p") && i + 1 < argc)
        {
            try {
                a.pid = std::stoull(argv[++i], nullptr, 10);
                a.hasPid = true;
                a.secArgs.pid = a.pid;
                a.secArgs.hasPid = true;
            }
            catch (...) { std::fprintf(stderr, "[警告] 无效的 PID: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if ((s == L"--depth" || s == L"-d") && i + 1 < argc)
        {
            try { a.maxDepth = std::stoi(argv[++i]); if (a.maxDepth < 0) a.maxDepth = 0; }
            catch (...) { std::fprintf(stderr, "[警告] 无效的深度: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if (s == L"--json" || s == L"-j")
        {
            a.json = true;
        }
        else if (s == L"--security")
        {
            a.security = true;
        }
        else if (s == L"--no-handles") { a.secArgs.noHandles = true; }
        else if (s == L"--no-mem")     { a.secArgs.noMem = true; }
        else if (s == L"--no-threads") { a.secArgs.noThreads = true; }
        else if (s == L"--no-modules") { a.secArgs.noModules = true; }
        else if (s == L"--no-token")   { a.secArgs.noToken = true; }
        else if (s == L"--handles-target" && i + 1 < argc)
        {
            try { a.secArgs.handlesTarget = std::stoull(argv[++i], nullptr, 10); }
            catch (...) {}
        }
        else if (s == L"--help" || s == L"-h")
        {
            std::printf("用法: ProcessTreeSnapshot [选项]\n\n");
            std::printf("树形打印模式(默认):\n");
            std::printf("  --pid <N>     只打印指定进程及其子树\n");
            std::printf("  --depth <N>   限制树深度(0=不限制)\n");
            std::printf("  --json        输出扁平 JSON(基础信息)\n\n");
            std::printf("安全采集模式:\n");
            std::printf("  --security              完整安全采集,输出 JSON\n");
            std::printf("  --pid <N>               只采集指定进程(默认全系统)\n");
            std::printf("  --no-handles            跳过句柄表扫描\n");
            std::printf("  --no-mem                跳过可疑内存扫描\n");
            std::printf("  --no-threads            跳过线程采集\n");
            std::printf("  --no-modules            跳过模块采集\n");
            std::printf("  --no-token              跳过 Token/Protection 采集\n");
            std::printf("  --handles-target <PID>  句柄扫描只看指向 PID 的句柄\n\n");
            std::printf("  --help                   显示帮助\n");
            exit(0);
        }
    }
    return a;
}

#ifndef COMBINATION_NATIVE_BUILD
int wmain(int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    if (!InitNtdll())
    {
        std::fprintf(stderr, "[错误] 无法加载 ntdll API\n");
        return 1;
    }

    Args args = ParseArgs(argc, argv);

    if (args.security)
    {
        return RunSecurityMode(args.secArgs);
    }
    return RunTreeMode(args.pid, args.maxDepth, args.json);
}
#endif // COMBINATION_NATIVE_BUILD
