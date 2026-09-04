#include <iostream>
#include <string>
#include <windows.h>

// 全局钩子句柄
HHOOK g_hMouseHook = NULL;
HHOOK g_hKeyboardHook = NULL;

// 控制是否拦截模拟输入的开关：true 时拦截吞掉事件；false 时仅打印检测日志，放行事件
constexpr bool BLOCK_INJECTED_INPUT = true;

// 1. 低级鼠标钩子回调，监听移动 + 点击
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        MSLLHOOKSTRUCT* pMouse = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);

        if (pMouse != nullptr) {
            // 检查鼠标注入标志：0x01 即 LLMHF_INJECTED，或 0x02 即 LLMHF_LOWER_IL_INJECTED
            bool isInjected = (pMouse->flags & LLMHF_INJECTED) ||
                (pMouse->flags & 0x00000002);

            // A. 处理鼠标移动
            if (wParam == WM_MOUSEMOVE) {
                if (isInjected) {
                    std::cout << "[模拟鼠标-移动] 坐标: (" << pMouse->pt.x << ", " << pMouse->pt.y << ")";
                    if (BLOCK_INJECTED_INPUT) {
                        std::cout << " -> [已拦截]";
                    }
                    std::cout << std::endl;

                    if (BLOCK_INJECTED_INPUT) return 1; // 拦截模拟移动
                }
            }
            // B. 处理鼠标点击，涵盖按下与抬起
            else if (wParam == WM_LBUTTONDOWN || wParam == WM_LBUTTONUP ||
                wParam == WM_RBUTTONDOWN || wParam == WM_RBUTTONUP ||
                wParam == WM_MBUTTONDOWN || wParam == WM_MBUTTONUP) {

                if (isInjected) {
                    std::string action;
                    switch (wParam) {
                    case WM_LBUTTONDOWN: action = "左键按下"; break;
                    case WM_LBUTTONUP:   action = "左键抬起"; break;
                    case WM_RBUTTONDOWN: action = "右键按下"; break;
                    case WM_RBUTTONUP:   action = "右键抬起"; break;
                    case WM_MBUTTONDOWN: action = "中键按下"; break;
                    case WM_MBUTTONUP:   action = "中键抬起"; break;
                    }

                    std::cout << "[模拟鼠标-点击] " << action
                        << " | 坐标: (" << pMouse->pt.x << ", " << pMouse->pt.y << ")";
                    if (BLOCK_INJECTED_INPUT) {
                        std::cout << " -> [已拦截]";
                    }
                    std::cout << std::endl;

                    if (BLOCK_INJECTED_INPUT) return 1; // 拦截模拟点击
                }
            }
        }
    }
    // 放行物理真实操作或未被拦截的消息
    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

// 2. 低级键盘钩子回调，监听按键
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN ||
            wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {

            KBDLLHOOKSTRUCT* pKey = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

            if (pKey != nullptr) {
                // 检查键盘注入标志：0x10 即 LLKHF_INJECTED，或 0x02 即 LLKHF_LOWER_IL_INJECTED
                bool isInjected = (pKey->flags & LLKHF_INJECTED) ||
                    (pKey->flags & LLKHF_LOWER_IL_INJECTED);

                if (isInjected) {
                    std::string action = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) ? "按下" : "抬起";

                    std::cout << "[模拟键盘-按键] " << action
                        << " | VK码: 0x" << std::hex << pKey->vkCode << std::dec
                        << " | ScanCode: " << pKey->scanCode;
                    if (BLOCK_INJECTED_INPUT) {
                        std::cout << " -> [已拦截]";
                    }
                    std::cout << std::endl;

                    if (BLOCK_INJECTED_INPUT) return 1; // 拦截模拟按键
                }
            }
        }
    }
    // 放行物理真实按键或未被拦截的消息
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

int main() {
    std::cout << "=== 全局模拟键鼠监控 & 拦截器启动 ===" << std::endl;
    std::cout << "当前拦截模式: " << (BLOCK_INJECTED_INPUT ? "【开启】模拟事件将被丢弃" : "【关闭】仅监控打印") << std::endl;
    std::cout << "按 Ctrl + C 退出程序。\n" << std::endl;

    // 安装底层鼠标钩子
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, GetModuleHandle(NULL), 0);
    if (!g_hMouseHook) {
        std::cerr << "错误：安装鼠标钩子失败，错误码: " << GetLastError() << std::endl;
        return 1;
    }

    // 安装底层键盘钩子
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (!g_hKeyboardHook) {
        std::cerr << "错误：安装键盘钩子失败，错误码: " << GetLastError() << std::endl;
        UnhookWindowsHookEx(g_hMouseHook);
        return 1;
    }

    // 消息循环保持钩子存活
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 退出前卸载
    UnhookWindowsHookEx(g_hMouseHook);
    UnhookWindowsHookEx(g_hKeyboardHook);
    return 0;
}
