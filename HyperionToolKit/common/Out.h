// Out.h — 统一控制台输出层
//
// 四个原工具各自用 WriteFile / printf / wprintf / fprintf 输出,这里收拢成一套:
//   Out        — 原样输出 (UTF-8 字节, 控制台与重定向都兼容)
//   OutLine    — 追加换行
//   OutError   — 输出到 stderr
//   OutColored — 带控制台前景色输出 (重定向时颜色属性被忽略, 不会污染文件)
//   OutFmt     — printf 风格窄字节输出 (procs 的 JSON/树形表格原地迁移)
//   Pause      — "按任意键退出" (原 IOCTLSender 的 getchar)
//
// 实现在 Out.cpp。

#pragma once

#include <windows.h>
#include <string>
#include <cstdarg>

namespace das {

// 输出 UTF-8 字节到 stdout (不追加换行)
void Out(const std::wstring& s);

// 输出一行
void OutLine(const std::wstring& s);

// 输出到 stderr
void OutError(const std::wstring& s);

// 带颜色输出到 stdout (attr 为控制台前景色/亮度属性)
void OutColored(const std::wstring& s, WORD attr);

// 原样输出 UTF-8 窄字节 (不转换, 直接 WriteFile)
void Out(const std::string& utf8);

// printf 风格窄字节输出 → stdout
void OutFmt(const char* fmt, ...);

// printf 风格窄字节输出 → stderr
void OutErrorFmt(const char* fmt, ...);

// 打印 "按任意键退出..." 并阻塞等待一次按键
void Pause();

} // namespace das