#include <windows.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

static HMODULE g_hModule = nullptr;

// ── 导出函数（反射式注入等方法需要调用）────────────────────────
extern "C" __declspec(dllexport) void PayloadInit()
{
    // 被注入后由 shellcode 或反射式装载器调用
}

// ── 写日志 ────────────────────────────────────────────────────
static void WriteLog(const char* msg)
{
    wchar_t path[MAX_PATH]{};
    if (g_hModule)
        GetModuleFileNameW(g_hModule, path, MAX_PATH);
    else
        GetSystemDirectoryW(path, MAX_PATH);

    // 日志写到 DLL 同目录或 system32
    wchar_t* lastSlash = wcsrchr(path, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';
    wcscat_s(path, L"payload_inject.log");

    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);

    std::ofstream f(path, std::ios::app);
    f << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
      << "PID=" << GetCurrentProcessId()
      << " TID=" << GetCurrentThreadId()
      << " | " << msg << "\n";
}

// ── 钩子回调（全局钩子注入使用）──────────────────────────────
// 被 Windows 消息子系统调用，运行在目标进程（如 notepad.exe）中
extern "C" __declspec(dllexport) LRESULT CALLBACK HookProc(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0)
    {
        // DLL 被加载到目标进程 = 注入成功，钩子回调本身不需要做额外的事
        char buf[128]{};
        sprintf_s(buf, "HookProc called | nCode=%d wParam=%llu", nCode, (unsigned long long)wParam);
        WriteLog(buf);
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// ── DllMain ───────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);

        char buf[256]{};
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        std::string host(buf);

        std::ostringstream oss;
        oss << "DLL_PROCESS_ATTACH | Host=" << host;
        WriteLog(oss.str().c_str());

        // 弹窗确认（仅调试用，正式测试可去掉）
        char msg[512]{};
        sprintf_s(msg, "payload.dll loaded!\n\nHost: %s\nPID: %lu",
                  host.c_str(), GetCurrentProcessId());
        MessageBoxA(nullptr, msg, "SEWindows.Attack", MB_OK | MB_ICONINFORMATION);
        break;
    }
    case DLL_PROCESS_DETACH:
        WriteLog("DLL_PROCESS_DETACH");
        break;
    }
    return TRUE;
}
