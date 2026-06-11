// ════════════════════════════════════════════════════════════════
//  SEWindows.Attack — DLL 注入测试工具
//  自动查找 chrome.exe PID，支持 14 种注入方式
// ════════════════════════════════════════════════════════════════
#include "methods.h"
#include <iostream>
#include <filesystem>
#include <io.h>
#include <fcntl.h>

// ── 控制台 Unicode 输出 ────────────────────────────────────────
static HANDLE g_hConsole = nullptr;

void Print(const wchar_t* fmt, ...)
{
    wchar_t buf[2048]{};
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _countof(buf) - 1, _TRUNCATE, fmt, args);
    va_end(args);

    DWORD written = 0;
    WriteConsoleW(g_hConsole, buf, (DWORD)wcslen(buf), &written, nullptr);
}

struct InjectMethod
{
    const wchar_t* name;
    const wchar_t* desc;
    InjectFn*      fn;
};

static const InjectMethod METHODS[] =
{
    { L"CreateRemoteThread",   L"最经典，LoadLibrary 远程线程",          Inject_CreateRemoteThread   },
    { L"RtlCreateUserThread",  L"底层 API，绕过部分检测",               Inject_RtlCreateUserThread  },
    { L"APC 注入",             L"异步过程调用，不创建新线程",            Inject_APC                  },
    { L"线程上下文劫持",        L"挂起线程改 RIP/EIP，注入 shellcode",   Inject_ThreadContext        },
    { L"反射式注入",            L"手动映射 PE，DLL 不落地",              Inject_Reflective           },
    { L"全局钩子注入",          L"SetWindowsHookEx，消息机制",           Inject_GlobalHook           },
    { L"输入法注入",            L"IME 模块加载，切换输入法时触发",        Inject_IME                  },
    { L"DLL 劫持",             L"利用 DLL 搜索顺序，替换合法 DLL",       Inject_DllHijack            },
    { L"注册表注入",            L"AppInit_DLLs，所有加载 user32 的进程",  Inject_Registry             },
    { L"挂起线程注入",          L"SuspendThread 改 EIP 后 Resume",       Inject_SuspendedThread      },
    { L"挂起进程注入",          L"CREATE_SUSPENDED 创建后注入",          Inject_SuspendedProcess     },
    { L"进程替换",             L"Process Hollowing，替换进程内存",       Inject_ProcessHollow        },
    { L"调试器注入",            L"DEBUG_EVENT 写入 shellcode + CC 断点",  Inject_Debugger             },
    { L"导入表注入",            L"静态修改 PE 导入表（文件操作）",        Inject_ImportTable          },
};

static constexpr int METHOD_COUNT = sizeof(METHODS) / sizeof(METHODS[0]);

// ── 查找 payload.dll ──────────────────────────────────────────
static std::wstring FindPayloadDll()
{
    wchar_t exeDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    auto dir = std::filesystem::path(exeDir).parent_path();

    auto dllPath = dir / L"payload.dll";
    if (std::filesystem::exists(dllPath))
        return dllPath.wstring();

    auto parentDll = dir.parent_path() / L"payload.dll";
    if (std::filesystem::exists(parentDll))
        return parentDll.wstring();

    return L"payload.dll";
}

static void PrintBanner()
{
    Print(L"\n ╔══════════════════════════════════════════════════╗\n");
    Print(L" ║       SEWindows.Attack — DLL 注入测试工具        ║\n");
    Print(L" ╚══════════════════════════════════════════════════╝\n\n");
}

static void PrintMenu()
{
    Print(L"\n  可用注入方法:\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
    for (int i = 0; i < METHOD_COUNT; i++)
        Print(L"  [%2d] %-22s  %s\n", i + 1, METHODS[i].name, METHODS[i].desc);
    Print(L"  [ 0] 退出\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
}

// ── 读取一行输入（宽字符）──────────────────────────────────────
static std::wstring ReadLine()
{
    std::wstring line;
    std::getline(std::wcin, line);
    return line;
}

int wmain(int argc, wchar_t* argv[])
{
    // 设置控制台为 UTF-8 并获取输出句柄
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleMode(g_hConsole, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

    PrintBanner();

    // ── 自动查找 chrome.exe ──
    DWORD pid = FindChromePid();
    if (pid == 0)
    {
        Print(L"  [!] 未找到 chrome.exe 进程，请先启动 Chrome\n");
        Print(L"  [!] 或手动指定 PID: inject.exe <pid>\n");
        Print(L"\n  输入目标 PID (0=退出): ");
        auto input = ReadLine();
        pid = _wtoi(input.c_str());
        if (pid == 0) return 1;
    }
    else
    {
        Print(L"  [+] 已找到 chrome.exe  PID=%lu\n", pid);
    }

    // 命令行参数直接指定方法
    if (argc >= 3)
    {
        pid = _wtoi(argv[1]);
        int methodIdx = _wtoi(argv[2]) - 1;
        if (methodIdx >= 0 && methodIdx < METHOD_COUNT)
        {
            auto dllPath = FindPayloadDll();
            Print(L"\n  [*] 注入方法: %s\n", METHODS[methodIdx].name);
            Print(L"  [*] 目标 PID: %lu\n", pid);
            Print(L"  [*] DLL 路径: %s\n\n", dllPath.c_str());
            METHODS[methodIdx].fn(pid, dllPath.c_str());
            return 0;
        }
    }

    // ── 交互菜单 ──
    auto dllPath = FindPayloadDll();
    Print(L"  [*] payload.dll: %s\n", dllPath.c_str());

    while (true)
    {
        PrintMenu();
        Print(L"\n  选择注入方法 [1-%d]: ", METHOD_COUNT);

        auto input = ReadLine();
        int choice = _wtoi(input.c_str());

        if (choice == 0) break;
        if (choice < 1 || choice > METHOD_COUNT)
        {
            Print(L"  [!] 无效选择\n");
            continue;
        }

        int idx = choice - 1;
        Print(L"\n  ┌─ 方法: %s\n", METHODS[idx].name);
        Print(L"  │  目标 PID: %lu\n", pid);
        Print(L"  │  DLL: %s\n", dllPath.c_str());
        Print(L"  └────────────────────────────────────\n\n");

        bool ok = METHODS[idx].fn(pid, dllPath.c_str());

        Print(L"\n  ─────────────────────────────────────\n");
        Print(L"  结果: %s\n", ok ? L"✓ 成功" : L"✗ 失败");
        Print(L"  ─────────────────────────────────────\n");

        Print(L"\n  按 Enter 继续...");
        ReadLine();
    }

    return 0;
}
