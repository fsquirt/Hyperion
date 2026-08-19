// Out.cpp — 统一控制台输出层实现

#include "Out.h"
#include "Str.h"

#include <cstdio>
#include <cstdarg>

namespace das {

void Out(const std::wstring& s)
{
    std::string u8 = WToU8(s);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, u8.data(), (DWORD)u8.size(), &written, nullptr);
}

void OutLine(const std::wstring& s)
{
    Out(s + L"\n");
}

void OutError(const std::wstring& s)
{
    std::string u8 = WToU8(s);
    fputs(u8.c_str(), stderr);
}

void OutColored(const std::wstring& s, WORD attr)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD oldAttr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    SetConsoleTextAttribute(hOut, attr);
    Out(s);
    SetConsoleTextAttribute(hOut, oldAttr);
}

void Out(const std::string& utf8)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
}

void OutFmt(const char* fmt, ...)
{
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        size_t n = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
        Out(std::string(buf, n));
    }
}

void OutErrorFmt(const char* fmt, ...)
{
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        size_t n = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
        fwrite(buf, 1, n, stderr);
    }
}

void Pause()
{
    OutLine(L"[INFO] 按任意键退出...");
    getchar();
}

} // namespace das