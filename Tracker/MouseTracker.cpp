#include <iostream>
#include <windows.h>

// 钩子句柄
HHOOK g_hMouseHook = NULL;

HHOOK hMouseHook = NULL;

// 鼠标钩子回调函数
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // 我们只关心鼠标移动事件
        if (wParam == WM_MOUSEMOVE) {
            // 将 lParam 转换为低级鼠标结构体指针
            MSLLHOOKSTRUCT* pMouseStruct = (MSLLHOOKSTRUCT*)lParam;

            if (pMouseStruct != NULL) {
                // 检查 flags 是否包含注入标志
                // LLMHF_INJECTED = 0x01, LLMHF_LOWER_IL_INJECTED = 0x02
                bool isInjected = (pMouseStruct->flags & LLMHF_INJECTED) ||
                    (pMouseStruct->flags & LLMHF_LOWER_IL_INJECTED);

                if (isInjected) {
                    std::cout << "[模拟移动] 坐标: (" << pMouseStruct->pt.x << ", " << pMouseStruct->pt.y
                        << ") | Flags: 0x" << std::hex << pMouseStruct->flags << std::dec << std::endl;
                    std::cout << "已拦截" << std::endl;
					return 1; // 返回非零值以拦截事件
                }
                else {
                    // std::cout << "[物理移动] 坐标: (" << pMouseStruct->pt.x << ", " << pMouseStruct->pt.y << ")" << std::endl;
                }
            }
        }
    }
    // 将事件传递给链中的下一个钩子
    return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

// 鼠标钩子回调函数
LRESULT CALLBACK LowLevelMouseProc2(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // 【修改1】只筛选鼠标点击事件（左键按下、右键按下、中键按下等）
        if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {

            MSLLHOOKSTRUCT* pMouseStruct = (MSLLHOOKSTRUCT*)lParam;

            // 获取点击发生时的坐标
            int x = pMouseStruct->pt.x;
            int y = pMouseStruct->pt.y;

            // 【修改2】检测是否为“模拟”或注入的鼠标事件
            // LLMHF_INJECTED (0x01) 捕获标准注入
            // 0x02 捕获低完整性级别注入
            bool isInjected = (pMouseStruct->flags & LLMHF_INJECTED) ||
                (pMouseStruct->flags & 0x00000002);

            // 区分事件类型用于打印
            std::string buttonType = "未知点击";
            if (wParam == WM_LBUTTONDOWN) buttonType = "左键按下";
            if (wParam == WM_RBUTTONDOWN) buttonType = "右键按下";
            if (wParam == WM_MBUTTONDOWN) buttonType = "中键按下";

            // 【核心逻辑】只有当它是模拟点击时，才进行拦截或记录
            if (isInjected) {
                std::cout << "[模拟点击] 检测到由 SendInput 注入的 " << buttonType
                    << " -> X: " << x << ", Y: " << y << std::endl;

                // 如果你想【拦截】这个模拟点击，让它不生效，可以直接返回非零值：
                // return 1; 
            }
            else {
                // 如果是真人物理鼠标点击，这里可以选择忽略，或者只做不带提示的记录
                std::cout << "[物理点击] 真实的 " << buttonType << " -> X: " << x << ", Y: " << y << std::endl;
            }
        }
    }

    // 将消息传递给钩子链中的下一个应用程序（如果是真实的物理点击，必须放行）
    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

int main2() {
    std::cout << "--- 全局模拟鼠标点击监控程序启动 ---" << std::endl;
    std::cout << "正在监控模拟点击事件（将忽略常规物理鼠标移动与点击）..." << std::endl;
    std::cout << "按 Ctrl + C 可以退出程序。\n" << std::endl;

    // 设置全局低级鼠标钩子
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc2, GetModuleHandle(NULL), 0);

    if (g_hMouseHook == NULL) {
        std::cerr << "错误：设置鼠标钩子失败！错误码: " << GetLastError() << std::endl;
        return 1;
    }

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 卸载钩子
    UnhookWindowsHookEx(g_hMouseHook);
    return 0;
}

int main() {
    std::cout << "=== 鼠标移动监听程序已启动 ===" << std::endl;
    std::cout << "请试着移动鼠标，或运行模拟鼠标脚本..." << std::endl;
    std::cout << "按下 Ctrl + C 可以退出程序。\n" << std::endl;

    // 设置全局低级鼠标钩子
    hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, GetModuleHandle(NULL), 0);

    if (hMouseHook == NULL) {
        std::cerr << "错误：无法设置鼠标钩子！" << std::endl;
        return 1;
    }

    // 钩子必须依赖 Windows 消息循环来保持存活并接收事件
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 程序退出前注销钩子
    UnhookWindowsHookEx(hMouseHook);
    return 0;
}