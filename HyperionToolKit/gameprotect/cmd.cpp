// cmd.cpp — gameprotect 子命令实现
//
// 告诉 KernelService 驱动启动/停止对指定游戏进程的句柄降级保护,
// 或丢弃其他进程已握有的指向该进程的高危句柄:
//
//   HyperionToolKit.exe gameprotect --start <PID>    启用保护
//   HyperionToolKit.exe gameprotect --stop            停止保护
//   HyperionToolKit.exe gameprotect --drophandle <PID> 丢弃已有高危句柄
//
// 驱动收到后 (GameProtect.c) 通过 ObRegisterCallbacks 对该进程的
// 进程/线程句柄创建与复制做权限剥离:
//   进程句柄: PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
//             PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
//   线程句柄: THREAD_SUSPEND_RESUME | THREAD_TERMINATE | THREAD_SET_CONTEXT |
//             THREAD_GET_CONTEXT
//
// 输出统一走 das::Out (UTF-8)。

#include <windows.h>
#include <string>
#include <cstdlib>

#include "../common/Common.h"
#include "../common/KernelComms.h"
#include "../common/Out.h"

namespace das {

static void PrintHelp()
{
    Out(L"用法:\n");
    Out(L"  HyperionToolKit.exe gameprotect --start <PID>       启用句柄降级保护\n");
    Out(L"  HyperionToolKit.exe gameprotect --stop               停止句柄降级保护\n");
    Out(L"  HyperionToolKit.exe gameprotect --drophandle <PID>   丢弃其他进程握有的高危句柄\n");
    Out(L"  HyperionToolKit.exe gameprotect --help               显示此帮助\n");
    Out(L"\n");
    Out(L"说明:\n");
    Out(L"  驱动对指定 PID 的进程/线程句柄创建与复制做权限剥离\n");
    Out(L"    - 进程句柄: TERMINATE | CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | SUSPEND_RESUME\n");
    Out(L"    - 线程句柄: SUSPEND_RESUME | TERMINATE | SET_CONTEXT | GET_CONTEXT\n");
    Out(L"  --drophandle 扫描全局句柄表,强制关闭其他进程持有的\n");
    Out(L"    PROCESS_VM_READ | VM_WRITE | VM_OPERATION 句柄\n");
    Out(L"  游戏自己与 System (PID 4) 的句柄不受影响。\n");
}

int RunGameProtect(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) {
        PrintHelp();
        return 1;
    }

    std::wstring op = argv[1];

    if (op == L"--help" || op == L"-h") {
        PrintHelp();
        return 0;
    }

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Out(L"[ERROR] 打开 KernelService 设备失败, 错误码=" + std::to_wstring(err) + L"\n");
        if (err == ERROR_ACCESS_DENIED) {
            OutLine(L"[HINT] 需要管理员权限运行");
        } else if (err == ERROR_FILE_NOT_FOUND) {
            OutLine(L"[HINT] KernelService 驱动未加载 (sc start KernelService)");
        }
        return 1;
    }

    int result = 0;

    if (op == L"--start") {
        if (argc < 3) {
            OutLine(L"[ERROR] 用法: gameprotect --start <PID>");
            CloseKernelService(hDevice);
            return 1;
        }
        unsigned long pid = (unsigned long)wcstoul(argv[2], nullptr, 10);
        if (pid == 0) {
            OutLine(L"[ERROR] PID 无效");
            CloseKernelService(hDevice);
            return 1;
        }

        Out(L"[INFO] 对 PID " + std::to_wstring(pid) + L" 启用句柄降级保护...\n");
        if (GameProtectStart(hDevice, pid)) {
            OutLine(L"[OK] 已启用: 该进程的进程/线程句柄危险权限将自动剥离");
        } else {
            DWORD err = GetLastError();
            Out(L"[ERROR] GameProtectStart 失败, 错误码=" + std::to_wstring(err) + L"\n");
            result = 1;
        }
    }
    else if (op == L"--stop") {
        Out(L"[INFO] 停止句柄降级保护...\n");
        if (GameProtectStop(hDevice)) {
            OutLine(L"[OK] 已停止保护");
        } else {
            DWORD err = GetLastError();
            Out(L"[ERROR] GameProtectStop 失败, 错误码=" + std::to_wstring(err) + L"\n");
            result = 1;
        }
    }
else if (op == L"--drophandle") {
        if (argc < 3) {
            OutLine(L"[ERROR] 用法: gameprotect --drophandle <PID>");
            CloseKernelService(hDevice);
            return 1;
        }
        unsigned long pid = (unsigned long)wcstoul(argv[2], nullptr, 10);
        if (pid == 0) {
            OutLine(L"[ERROR] PID 无效");
            CloseKernelService(hDevice);
            return 1;
        }

        Out(L"[INFO] 丢弃 PID " + std::to_wstring(pid) + L" 的已有高危句柄...\n");
        if (GameProtectDropHandles(hDevice, pid)) {
            OutLine(L"[OK] 扫描完成, 高危句柄已强制关闭");
        } else {
            DWORD err = GetLastError();
            Out(L"[ERROR] GameProtectDropHandles 失败, 错误码=" + std::to_wstring(err) + L"\n");
            result = 1;
        }
    }
    else {
        Out(L"[ERROR] 未知操作: " + op + L"\n");
        PrintHelp();
        result = 1;
    }

    CloseKernelService(hDevice);
    return result;
}

} // namespace das