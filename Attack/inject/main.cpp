// ════════════════════════════════════════════════════════════════
//  SEWindows.Attack — DLL 注入测试工具
//  自动启动 PlantsVsZombies.exe，支持 14 种注入方式 + 清理
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

// ── 注入方法表 ────────────────────────────────────────────────
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

// ── 查找已运行的目标进程 ──────────────────────────────────────
static const wchar_t* TARGET_NAME = L"osu!.exe";

static DWORD FindTargetProcess()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD foundPid = 0;

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, TARGET_NAME) == 0)
            {
                foundPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return foundPid;
}

// 检查进程是否还活着
static bool IsProcessAlive(DWORD pid)
{
    if (pid == 0) return false;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    DWORD exitCode = 0;
    GetExitCodeProcess(hProc, &exitCode);
    CloseHandle(hProc);
    return exitCode == STILL_ACTIVE;
}

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

// ═══════════════════════════════════════════════════════════════
//  清理功能
// ═══════════════════════════════════════════════════════════════

static void Cleanup_Registry()
{
    Print(L"  [*] 清理 AppInit_DLLs 注册表...\n");

    HKEY hKey = nullptr;
    LSTATUS ok = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0, KEY_SET_VALUE, &hKey);

    if (ok != ERROR_SUCCESS)
    {
        Print(L"  [!] 打开注册表失败: %lu (需要管理员权限)\n", ok);
        return;
    }

    RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ, (BYTE*)L"", 2);
    DWORD loadFlag = 0;
    RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&loadFlag, sizeof(loadFlag));
    RegCloseKey(hKey);
    Print(L"  [✓] AppInit_DLLs 已清空\n");
}

static void Cleanup_IME()
{
    Print(L"  [*] 清理输入法注册表...\n");

    LSTATUS ok = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\0002F001");

    if (ok == ERROR_SUCCESS)
        Print(L"  [✓] 输入法注册表已删除\n");
    else
        Print(L"  [*] 输入法注册表不存在或已删除\n");

    wchar_t sysDir[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t imePath[MAX_PATH]{};
    swprintf_s(imePath, L"%s\\sewinject.ime", sysDir);

    if (DeleteFileW(imePath))
        Print(L"  [✓] 已删除 %s\n", imePath);
    else
        Print(L"  [*] %s 不存在或已删除\n", imePath);
}

static void Cleanup_GlobalHook()
{
    Print(L"  [*] 全局钩子随注入器退出自动卸载\n");
    Print(L"  [*] 如 payload.dll 仍在目标进程中，需重启目标进程\n");
}

static void Cleanup_DllHijack()
{
    Print(L"  [*] 清理劫持的 DLL 文件...\n");

    const wchar_t* hijackNames[] = {
        L"sewinject_hijack.dll",
        L"version.dll", L"winmm.dll", L"wer.dll",
        L"cryptsp.dll", L"dpx.dll", L"IPHLPAPI.dll",
    };

    wchar_t exeDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    auto dir = std::filesystem::path(exeDir).parent_path();

    int deleted = 0;
    for (auto& entry : std::filesystem::directory_iterator(dir))
    {
        auto fname = entry.path().filename().wstring();
        for (auto* name : hijackNames)
        {
            if (_wcsicmp(fname.c_str(), name) == 0)
            {
                if (DeleteFileW(entry.path().c_str()))
                {
                    Print(L"  [✓] 已删除 %s\n", entry.path().c_str());
                    deleted++;
                }
                break;
            }
        }
    }

    // 删除 .bak 备份
    for (auto& entry : std::filesystem::directory_iterator(dir))
    {
        if (entry.path().extension() == L".bak")
        {
            Print(L"  [✓] 删除备份 %s\n", entry.path().c_str());
            std::filesystem::remove(entry.path());
        }
    }

    Print(deleted > 0 ? L"  [✓] 清理完成\n" : L"  [*] 未发现需要清理的文件\n");
}

static void Cleanup_ImportTable()
{
    Print(L"  [*] 恢复导入表修改...\n");

    wchar_t exeDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    auto dir = std::filesystem::path(exeDir).parent_path();

    int restored = 0;
    for (auto& entry : std::filesystem::directory_iterator(dir))
    {
        if (entry.path().extension() == L".bak")
        {
            auto original = entry.path();
            original.replace_extension(L"");
            if (CopyFileW(entry.path().c_str(), original.c_str(), FALSE))
            {
                Print(L"  [✓] 已恢复 %s\n", original.c_str());
                std::filesystem::remove(entry.path());
                restored++;
            }
            else
            {
                Print(L"  [!] 恢复失败 %s (文件可能被占用)\n", original.c_str());
            }
        }
    }

    Print(restored > 0 ? L"  [✓] 恢复完成\n" : L"  [*] 未发现需要恢复的备份\n");
}

static void Cleanup_All()
{
    Print(L"\n  ═══ 执行全部清理 ═══\n\n");
    Cleanup_Registry();
    Cleanup_IME();
    Cleanup_GlobalHook();
    Cleanup_DllHijack();
    Cleanup_ImportTable();
    Print(L"\n  [✓] 全部清理完成\n");
}

// ═══════════════════════════════════════════════════════════════
//  菜单
// ═══════════════════════════════════════════════════════════════

static void PrintBanner()
{
    Print(L"\n ╔══════════════════════════════════════════════════╗\n");
    Print(L" ║       SEWindows.Attack — DLL 注入测试工具        ║\n");
    Print(L" ╚══════════════════════════════════════════════════╝\n\n");
}

static void PrintMainMenu()
{
    Print(L"\n  主菜单:\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
    Print(L"  [1] 注入 (选择方法)\n");
    Print(L"  [2] 清理 (清理注册表/钩子/文件)\n");
    Print(L"  [0] 退出\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
}

static void PrintInjectMenu()
{
    Print(L"\n  可用注入方法:\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
    for (int i = 0; i < METHOD_COUNT; i++)
        Print(L"  [%2d] %-22s  %s\n", i + 1, METHODS[i].name, METHODS[i].desc);
    Print(L"  [ 0] 返回\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
}

static void PrintCleanMenu()
{
    Print(L"\n  清理选项:\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
    Print(L"  [1] 清理注册表 (AppInit_DLLs)\n");
    Print(L"  [2] 清理输入法 (IME 注册表 + 文件)\n");
    Print(L"  [3] 清理全局钩子\n");
    Print(L"  [4] 清理 DLL 劫持文件\n");
    Print(L"  [5] 恢复导入表 (.bak → 原文件)\n");
    Print(L"  [6] 全部清理\n");
    Print(L"  [0] 返回主菜单\n");
    Print(L"  ────────────────────────────────────────────────────────────\n");
}

static std::wstring ReadLine()
{
    std::wstring line;
    std::getline(std::wcin, line);
    return line;
}

// ═══════════════════════════════════════════════════════════════
//  主程序
// ═══════════════════════════════════════════════════════════════

int wmain(int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleMode(g_hConsole, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

    PrintBanner();

    // ── 查找已运行的目标进程 ──
    DWORD pid = FindTargetProcess();
    if (pid == 0)
    {
        Print(L"  [!] 未找到 %s，请先启动游戏\n", TARGET_NAME);
        return 1;
    }
    Print(L"  [+] 已找到 %s  PID=%lu\n", TARGET_NAME, pid);

    // 命令行参数直接指定方法: inject.exe <方法编号>
    if (argc >= 2)
    {
        int methodIdx = _wtoi(argv[1]) - 1;
        if (methodIdx >= 0 && methodIdx < METHOD_COUNT)
        {
            auto dllPath = FindPayloadDll();
            Print(L"\n  [*] 注入方法: %s\n", METHODS[methodIdx].name);
            Print(L"  [*] 目标 PID: %lu\n", pid);
            Print(L"  [*] DLL 路径: %s\n\n", dllPath.c_str());
            METHODS[methodIdx].fn(pid, dllPath.c_str());

            Print(L"\n  按 Enter 退出...");
            ReadLine();
            return 0;
        }
    }

    auto dllPath = FindPayloadDll();
    Print(L"  [*] payload.dll: %s\n", dllPath.c_str());

    // ── 主循环 ──
    while (true)
    {
        PrintMainMenu();
        Print(L"\n  选择: ");

        auto input = ReadLine();
        int choice = _wtoi(input.c_str());

        if (choice == 0) break;

        // ── 注入 ──
        if (choice == 1)
        {
            while (true)
            {
                PrintInjectMenu();
                Print(L"\n  选择注入方法 [1-%d]: ", METHOD_COUNT);

                auto injInput = ReadLine();
                int injChoice = _wtoi(injInput.c_str());

                if (injChoice == 0) break;
                if (injChoice < 1 || injChoice > METHOD_COUNT)
                {
                    Print(L"  [!] 无效选择\n");
                    continue;
                }

                int idx = injChoice - 1;
                Print(L"\n  ┌─ 方法: %s\n", METHODS[idx].name);
                Print(L"  │  目标 PID: %lu\n", pid);
                Print(L"  │  DLL: %s\n", dllPath.c_str());
                Print(L"  └────────────────────────────────────\n\n");

                bool ok = METHODS[idx].fn(pid, dllPath.c_str());

                Print(L"\n  ─────────────────────────────────────\n");
                Print(L"  结果: %s\n", ok ? L"✓ 成功" : L"✗ 失败");
                Print(L"  ─────────────────────────────────────\n");

                // 注入后检查目标是否还活着
                Print(L"\n  按 Enter 继续...");
                ReadLine();

                if (!IsProcessAlive(pid))
                {
                    Print(L"  [!] 目标进程已退出，重新查找...\n");
                    pid = FindTargetProcess();
                    if (pid == 0)
                    {
                        Print(L"  [!] 未找到 %s，请先启动游戏\n", TARGET_NAME);
                        break;
                    }
                    Print(L"  [+] 已重新找到 %s  PID=%lu\n", TARGET_NAME, pid);
                }
            }
        }

        // ── 清理 ──
        if (choice == 2)
        {
            while (true)
            {
                PrintCleanMenu();
                Print(L"\n  选择: ");

                auto clInput = ReadLine();
                int clChoice = _wtoi(clInput.c_str());

                if (clChoice == 0) break;

                switch (clChoice)
                {
                case 1: Cleanup_Registry(); break;
                case 2: Cleanup_IME(); break;
                case 3: Cleanup_GlobalHook(); break;
                case 4: Cleanup_DllHijack(); break;
                case 5: Cleanup_ImportTable(); break;
                case 6: Cleanup_All(); break;
                default: Print(L"  [!] 无效选择\n"); break;
                }

                Print(L"\n  按 Enter 继续...");
                ReadLine();
            }
        }
    }

    Print(L"\n  退出。\n");
    return 0;
}
