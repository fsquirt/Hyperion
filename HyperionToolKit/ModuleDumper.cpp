// ModuleDumper.cpp — 用户态 dump + 磁盘文件拷贝
//
// 两种 dump 模式, 由全局开关 g_dumpMode 控制:
//   - Raw (默认): 原始内存镜像 ReadProcessMemory, 按模块路径去重
//   - Mifudump:   Full Minidump MiniDumpWriteDump, 按 PID 去重

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "ModuleDumper.h"
#include "Common.h"

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <unordered_set>

#pragma comment(lib, "dbghelp.lib")

namespace das {

// dump 目录 (程序同目录下 dumpfile\)
static std::wstring g_dumpDir;

// FileDump 目录 (磁盘文件副本)
static std::wstring g_fileDumpDir;

// dump 模式开关 (默认 Raw, --mifudump 时改为 Mifudump)
static DumpMode g_dumpMode = DumpMode::Raw;

// Raw 模式去重表: 已 dump 的模块路径
static std::unordered_set<std::wstring> g_dumpedPaths;

// Mifudump 模式去重表: 已 dump 的 PID
static std::unordered_set<unsigned long> g_dumpedPids;

// FileDump 去重表
static std::unordered_set<std::wstring> g_fileCopied;

// ═══════════════════════════════════════════════════════════════════════
//  设置 dump 模式
// ═══════════════════════════════════════════════════════════════════════

void SetDumpMode(DumpMode mode) { g_dumpMode = mode; }

// ═══════════════════════════════════════════════════════════════════════
//  初始化 dumpfile 目录
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
//  初始化 FileDump 目录 (磁盘文件副本)
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
//  提取 basename (不含路径)
// ═══════════════════════════════════════════════════════════════════════

static std::wstring ExtractBaseName(const std::wstring& path)
{
    if (path.empty()) return L"unknown";
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) return path.substr(slash + 1);
    return path;
}

// ═══════════════════════════════════════════════════════════════════════
//  Raw 模式: 从内存读模块映像, 按路径去重
// ═══════════════════════════════════════════════════════════════════════

static bool DumpModuleRaw(HANDLE hProcess,
                          unsigned long pid,
                          const std::wstring& modulePath,
                          unsigned long long base, unsigned long size,
                          bool abnormal, const std::wstring& note,
                          std::wstring& outDumpFile)
{
    // 同一路径只 dump 一次
    if (g_dumpedPaths.count(modulePath) > 0) return false;
    g_dumpedPaths.insert(modulePath);

    if (g_dumpDir.empty()) {
        WriteOut(L"  [dump] 目录未初始化,跳过 dump\n");
        return false;
    }

    // 构造 dump 文件名: 原始文件名 (+ 异常标注前缀)
    std::wstring baseName = ExtractBaseName(modulePath);
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
//  Mini 模式: MiniDumpNormal, 按 PID 去重
//  只含基本线程/模块/堆栈信息, 不含完整进程内存 (体积中等)
// ═══════════════════════════════════════════════════════════════════════

static bool DumpModuleMini(HANDLE hProcess,
                            unsigned long pid,
                            const std::wstring& modulePath,
                            std::wstring& outDumpFile)
{
    // 同一 PID 只 dump 一次
    if (g_dumpedPids.count(pid) > 0) return false;
    g_dumpedPids.insert(pid);

    if (g_dumpDir.empty()) {
        WriteOut(L"  [dump] 目录未初始化,跳过 dump\n");
        return false;
    }

    // 构造 dump 文件名: 进程名_pid_mini.dmp
    std::wstring baseName = ExtractBaseName(modulePath);
    std::wstring dumpName = baseName + L"_" + std::to_wstring(pid) + L"_mini.dmp";
    std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WriteOut(L"  [dump] CreateFile 失败: " + dumpPath + L"\n");
        return false;
    }

    // MiniDumpNormal: 仅线程/模块/堆栈基本信息, 不含完整内存
    MINIDUMP_TYPE dumpType = MiniDumpNormal;

    BOOL ok = MiniDumpWriteDump(
        hProcess, pid, hFile, dumpType,
        NULL, NULL, NULL);

    CloseHandle(hFile);

    if (!ok) {
        DWORD err = GetLastError();
        WriteOut(L"  [dump] MiniDumpWriteDump (Mini) 失败: err=" + std::to_wstring(err) + L"\n");
        DeleteFileW(dumpPath.c_str());
        return false;
    }

    outDumpFile = dumpName;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  Mifudump 模式: Full Minidump, 按 PID 去重
//  MiniDumpWithFullMemory | MiniDumpWithHandleData | MiniDumpWithThreadInfo
// ═══════════════════════════════════════════════════════════════════════

static bool DumpModuleMifudump(HANDLE hProcess,
                                unsigned long pid,
                                const std::wstring& modulePath,
                                std::wstring& outDumpFile)
{
    // 同一 PID 只 dump 一次
    if (g_dumpedPids.count(pid) > 0) return false;
    g_dumpedPids.insert(pid);

    if (g_dumpDir.empty()) {
        WriteOut(L"  [dump] 目录未初始化,跳过 dump\n");
        return false;
    }

    // 构造 dump 文件名: 进程名_pid.dmp
    std::wstring baseName = ExtractBaseName(modulePath);
    std::wstring dumpName = baseName + L"_" + std::to_wstring(pid) + L".dmp";
    std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

    // 创建 dump 文件
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WriteOut(L"  [dump] CreateFile 失败: " + dumpPath + L"\n");
        return false;
    }

    // 调用 MiniDumpWriteDump 生成 Full Minidump
    //   MiniDumpWithFullMemory: 完整进程地址空间 (静态分析 + 内存取证)
    //   MiniDumpWithHandleData: 句柄表 (追踪跨进程句柄操作)
    //   MiniDumpWithThreadInfo: 线程信息 (调用栈/寄存器状态)
    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithThreadInfo);

    BOOL ok = MiniDumpWriteDump(
        hProcess,
        pid,
        hFile,
        dumpType,
        NULL,   // ExceptionParam (非异常崩溃场景, 不需要)
        NULL,   // UserStreamParam
        NULL);  // CallbackParam

    CloseHandle(hFile);

    if (!ok) {
        DWORD err = GetLastError();
        WriteOut(L"  [dump] MiniDumpWriteDump 失败: err=" + std::to_wstring(err) + L"\n");
        // 删除空文件
        DeleteFileW(dumpPath.c_str());
        return false;
    }

    outDumpFile = dumpName;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  入口: 按全局开关分发到 Raw 或 Mifudump
// ═══════════════════════════════════════════════════════════════════════

bool DumpModule(HANDLE hProcess,
                unsigned long pid,
                const std::wstring& modulePath,
                unsigned long long base, unsigned long size,
                bool abnormal, const std::wstring& note,
                std::wstring& outDumpFile)
{
    if (g_dumpMode == DumpMode::Mifudump) {
        return DumpModuleMifudump(hProcess, pid, modulePath, outDumpFile);
    }
    if (g_dumpMode == DumpMode::Mini) {
        return DumpModuleMini(hProcess, pid, modulePath, outDumpFile);
    }
    return DumpModuleRaw(hProcess, pid, modulePath, base, size,
                         abnormal, note, outDumpFile);
}

// ═══════════════════════════════════════════════════════════════════════
//  FileDump: 若磁盘上存在文件, 拷贝到 FileDump\ 目录 (同一文件只拷贝一次)
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

    // 构造副本文件名: 原始文件名 (RHS 文件加前缀)
    std::wstring baseName = ExtractBaseName(modulePath);
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

// dump 目录访问器
const std::wstring& GetDumpDir()     { return g_dumpDir; }
const std::wstring& GetFileDumpDir() { return g_fileDumpDir; }

} // namespace das
