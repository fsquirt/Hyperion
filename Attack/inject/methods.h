#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

// 控制台 Unicode 输出（main.cpp 中实现）
void Print(const wchar_t* fmt, ...);

// ── 每种注入方法统一接口 ──────────────────────────────────────
//  返回 true = 注入成功
using InjectFn = bool(DWORD pid, const wchar_t* dllPath);

// ── 14 种注入方法 ─────────────────────────────────────────────
bool Inject_CreateRemoteThread(DWORD pid, const wchar_t* dllPath);
bool Inject_RtlCreateUserThread(DWORD pid, const wchar_t* dllPath);
bool Inject_APC(DWORD pid, const wchar_t* dllPath);
bool Inject_ThreadContext(DWORD pid, const wchar_t* dllPath);
bool Inject_Reflective(DWORD pid, const wchar_t* dllPath);
bool Inject_GlobalHook(DWORD pid, const wchar_t* dllPath);
bool Inject_IME(DWORD pid, const wchar_t* dllPath);
bool Inject_DllHijack(DWORD pid, const wchar_t* dllPath);
bool Inject_Registry(DWORD pid, const wchar_t* dllPath);
bool Inject_SuspendedThread(DWORD pid, const wchar_t* dllPath);
bool Inject_SuspendedProcess(DWORD pid, const wchar_t* dllPath);
bool Inject_ProcessHollow(DWORD pid, const wchar_t* dllPath);
bool Inject_Debugger(DWORD pid, const wchar_t* dllPath);
bool Inject_ImportTable(DWORD pid, const wchar_t* dllPath);

// ── 工具函数 ──────────────────────────────────────────────────

// 查找 chrome.exe PID（取第一个匹配）
inline DWORD FindChromePid()
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{ .dwSize = sizeof(pe) };
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, L"chrome.exe") == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// 获取目标进程中 kernel32 模块的 LoadLibraryW 地址
// 同一 Session 内 kernel32 基址相同，所以可以用本进程地址
inline LPVOID GetLoadLibraryAddr()
{
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    return (LPVOID)GetProcAddress(hK32, "LoadLibraryW");
}

// 获取目标进程中 ntdll 的 RtlExitUserThread 地址
inline LPVOID GetExitThreadAddr()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    return (LPVOID)GetProcAddress(hNtdll, "RtlExitUserThread");
}

// 在目标进程分配内存并写入字符串（宽字符，含 null）
inline LPVOID WriteStringToProcess(HANDLE hProc, const wchar_t* str)
{
    size_t bytes = (wcslen(str) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return nullptr;
    WriteProcessMemory(hProc, remote, str, bytes, nullptr);
    return remote;
}
