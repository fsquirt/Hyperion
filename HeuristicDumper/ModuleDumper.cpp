// ModuleDumper.cpp — 用户态模块内存 dump + 磁盘文件拷贝
//
// 拆分自 CommsMonitor.cpp:
//   - InitDumpDir / InitFileDumpDir: 初始化输出目录
//   - DumpModule: 从目标进程读模块内存映像写到 dumpfile\
//   - CopyFileFromDisk: 磁盘文件拷贝到 FileDump\

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ModuleDumper.h"
#include "Common.h"

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>

namespace das {

// dump 目录 (程序同目录下 dumpfile\) + 已 dump 路径去重表
static std::wstring g_dumpDir;
static std::unordered_set<std::wstring> g_dumped;

// FileDump 目录 (磁盘文件副本, 只针对磁盘上存在的文件) + 已拷贝去重表
static std::wstring g_fileDumpDir;
static std::unordered_set<std::wstring> g_fileCopied;

// ═══════════════════════════════════════════════════════════════════════
//  Dumper: 初始化 dumpfile 目录
// ═══════════════════════════════════════════════════════════════════════

bool InitDumpDir()
{
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (len == 0) return false;

    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);
    dir += L"\\dumpfile";

    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(dir.c_str(), NULL)) {
            WriteOut(L"[警告] 创建 dumpfile 目录失败: " + dir + L"\n");
            return false;
        }
    } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WriteOut(L"[警告] dumpfile 路径被文件占用: " + dir + L"\n");
        return false;
    }

    g_dumpDir = dir;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  FileDump: 初始化 FileDump 目录 (磁盘文件副本)
// ═══════════════════════════════════════════════════════════════════════

bool InitFileDumpDir()
{
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (len == 0) return false;

    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);
    dir += L"\\FileDump";

    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(dir.c_str(), NULL)) {
            WriteOut(L"[警告] 创建 FileDump 目录失败: " + dir + L"\n");
            return false;
        }
    } else if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WriteOut(L"[警告] FileDump 路径被文件占用: " + dir + L"\n");
        return false;
    }

    g_fileDumpDir = dir;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  Dumper: 从内存 dump 模块, 返回 dump 文件名 (相对 dumpfile/)
//  已 dump 过的路径直接跳过
// ═══════════════════════════════════════════════════════════════════════

bool DumpModule(HANDLE hProcess,
                unsigned long pid,
                const std::wstring& modulePath,
                unsigned long long base,
                unsigned long size,
                bool abnormal,
                const std::wstring& note,
                std::wstring& outDumpFile)
{
    // 同一路径只 dump 一次
    if (g_dumped.count(modulePath) > 0) return false;
    g_dumped.insert(modulePath);

    if (g_dumpDir.empty()) {
        WriteOut(L"  [dump] 目录未初始化,跳过 dump\n");
        return false;
    }

    // 构造 dump 文件名: 原始文件名 (+ 异常标注)
    std::wstring baseName;
    size_t slash = modulePath.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        baseName = modulePath.substr(slash + 1);
    } else {
        baseName = modulePath.empty() ? L"unknown" : modulePath;
    }

    // 异常文件名标注: 不存在 → 加前缀 "MISSING_", RHS → 加前缀 "RHS_"
    std::wstring dumpName = baseName;
    if (abnormal) {
        std::wstring prefix;
        if (note.find(L"不存在") != std::wstring::npos) prefix = L"MISSING_";
        else if (note.find(L"RHS") != std::wstring::npos) prefix = L"RHS_";
        else prefix = L"ABNORMAL_";
        dumpName = prefix + baseName;
    }

    std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

    // 从内存读取模块映像
    if (size == 0 || base == 0) {
        WriteOut(L"  [dump] 模块基址/大小无效,跳过: " + modulePath + L"\n");
        return false;
    }

    std::vector<unsigned char> buf(size, 0);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)base, buf.data(), size, &bytesRead)
        || bytesRead == 0) {
        WriteOut(L"  [dump] ReadProcessMemory 失败: " + modulePath + L"\n");
        return false;
    }

    // 写入 dump 文件
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WriteOut(L"  [dump] CreateFile 失败: " + dumpPath + L"\n");
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, buf.data(), (DWORD)bytesRead, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != bytesRead) {
        WriteOut(L"  [dump] WriteFile 失败: " + dumpPath + L"\n");
        return false;
    }

    outDumpFile = dumpName;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  FileDump: 若磁盘上存在文件, 拷贝到 FileDump\ 目录 (同一文件只拷贝一次)
//  返回 true = 已拷贝 / 已拷贝过 / 不需要拷贝(磁盘不存在)
//  不影响 RegisterForDump 的命中计数
// ═══════════════════════════════════════════════════════════════════════

void CopyFileFromDisk(const std::wstring& modulePath, bool abnormal,
                     std::wstring& outCopyName, bool& outCopied)
{
    outCopied = false;
    outCopyName.clear();

    // 磁盘不存在 → 跳过 (没有文件可拷)
    if (modulePath.empty()) return;
    DWORD attr = GetFileAttributesW(modulePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return;

    // 同一路径只拷贝一次
    if (g_fileCopied.count(modulePath) > 0) return;
    g_fileCopied.insert(modulePath);

    if (g_fileDumpDir.empty()) return;

    // 构造副本文件名: 原始文件名 (RHS 文件加前缀, 与 dumpfile 一致)
    std::wstring baseName;
    size_t slash = modulePath.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        baseName = modulePath.substr(slash + 1);
    } else {
        baseName = modulePath;
    }

    std::wstring copyName = baseName;
    if (abnormal && (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
        copyName = L"RHS_" + baseName;
    }

    std::wstring copyPath = g_fileDumpDir + L"\\" + copyName;

    // CopyFileEx: FALSE = 不取消拷贝
    BOOL cancel = FALSE;
    if (CopyFileExW(modulePath.c_str(), copyPath.c_str(), NULL, NULL, &cancel, 0)) {
        outCopied = true;
        outCopyName = copyName;
        WriteOut(L"    [file] 已拷贝: FileDump\\" + copyName + L"\n");
    } else {
        DWORD err = GetLastError();
        WriteOut(L"    [file] 拷贝失败: " + copyName + L" (err=" + std::to_wstring(err) + L")\n");
    }
}

// dump 目录访问器 (供 DriverDumper / PathTracker 等模块取路径用)
const std::wstring& GetDumpDir()     { return g_dumpDir; }
const std::wstring& GetFileDumpDir() { return g_fileDumpDir; }

} // namespace das
