// Common.cpp — 公共输出函数实现

#include "Common.h"
#include <atomic>

namespace das {

// ═══════════════════════════════════════════════════════════════════════
//  输出 (UTF-8 输出,控制台和重定向都兼容)
// ═══════════════════════════════════════════════════════════════════════

static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int cb = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                 nullptr, 0, nullptr, nullptr);
    std::string s(cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        s.data(), cb, nullptr, nullptr);
    return s;
}

static std::atomic<bool> g_SilentMode{ false };

void SetSilentMode(bool enable) {
    g_SilentMode.store(enable);
}

bool IsSilentMode() {
    return g_SilentMode.load();
}

void WriteOut(const std::wstring& s) {
    if (g_SilentMode.load()) return;  // 静默模式下不输出
    std::string u8 = ToUtf8(s);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, u8.data(), (DWORD)u8.size(), &written, nullptr);
}

} // namespace das
