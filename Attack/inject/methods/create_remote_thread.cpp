// ════════════════════════════════════════════════════════════════
//  方法 1: CreateRemoteThread — 最经典的 DLL 注入
//
//  原理：
//    1. OpenProcess 打开目标进程
//    2. VirtualAllocEx 在目标进程分配内存，写入 DLL 路径
//    3. CreateRemoteThread 以 LoadLibraryW 为入口，DLL 路径为参数
//    4. 目标进程的线程调用 LoadLibraryW 加载 DLL
//
//  检测特征：
//    - Sysmon Event 10: OpenProcess(VM_WRITE + CREATE_THREAD)
//    - Sysmon Event 8:  CreateRemoteThread，StartAddress=LoadLibraryW
//    - Sysmon Event 7:  ImageLoad 新增 DLL
//    - Security 4656:   句柄请求含 PROCESS_VM_WRITE | PROCESS_CREATE_THREAD
// ════════════════════════════════════════════════════════════════
#include "../methods.h"

bool Inject_CreateRemoteThread(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] CreateRemoteThread → PID=%lu\n", pid);

    // 1. 打开目标进程
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    // 2. 写入 DLL 路径
    LPVOID remotePath = WriteStringToProcess(hProc, dllPath);
    if (!remotePath)
    {
        Print(L"  [!] VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] DLL 路径已写入 @ %p\n", remotePath);

    // 3. CreateRemoteThread → LoadLibraryW
    LPVOID pLoadLib = GetLoadLibraryAddr();
    Print(L"  [+] LoadLibraryW @ %p\n", pLoadLib);

    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(
        hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pLoadLib,
        remotePath, 0, &tid);

    if (!hThread)
    {
        Print(L"  [!] CreateRemoteThread 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    Print(L"  [+] 远程线程已创建 TID=%lu\n", tid);

    // 等待线程完成
    WaitForSingleObject(hThread, 5000);

    // 清理
    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    Print(L"  [✓] 注入完成\n");
    return true;
}
