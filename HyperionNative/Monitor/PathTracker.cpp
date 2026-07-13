// PathTracker.cpp — 路径去重表
//
// 拆分自 CommsMonitor.cpp:
//   - RegisterForDump: 路径去重, 首次出现时调用 DumpModule/CopyFileFromDisk
//
// ETW 回调是单线程串行调用 (ProcessTrace 专用线程),无需加锁。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "PathTracker.h"
#include "ModuleDumper.h"
#include "Common.h"

#include <windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <algorithm>

namespace das {

// 全局去重路径表
static std::vector<PathEntry>      g_pathTable;     // 按发现顺序保存
static std::unordered_map<std::wstring, size_t> g_pathIndex;  // path → g_pathTable 索引

// ═══════════════════════════════════════════════════════════════════════
//  工具: 检查单个文件的 RHS 属性 / 存在性, 返回 PathEntry (不打印)
// ═══════════════════════════════════════════════════════════════════════

static PathEntry CheckFile(const std::wstring& path, const std::wstring& tag, unsigned long pid)
{
    PathEntry e;
    e.path = path;
    e.tag = tag;
    e.pid = pid;
    e.hitCount = 1;

    if (path.empty()) {
        e.abnormal = true;
        e.note = L"<路径为空>";
        return e;
    }

    DWORD attr = GetFileAttributesW(path.c_str());

    if (attr == INVALID_FILE_ATTRIBUTES) {
        e.abnormal = true;
        e.note = L"[磁盘上不存在!]";
        return e;
    }

    bool r = (attr & FILE_ATTRIBUTE_READONLY) != 0;
    bool h = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
    bool s = (attr & FILE_ATTRIBUTE_SYSTEM) != 0;

    if (r || h || s) {
        e.abnormal = true;
        std::wostringstream flags;
        flags << L"[RHS:";
        if (r) flags << L" R";
        if (h) flags << L" H";
        if (s) flags << L" S";
        flags << L"]";
        e.note = flags.str();
    }
    return e;
}

// ═══════════════════════════════════════════════════════════════════════
//  登记 + dump: 路径去重, 首次出现时 dump, 已登记只累加命中次数
//  dump 方式由 ModuleDumper 全局开关决定 (Raw / Mifudump)
// ═══════════════════════════════════════════════════════════════════════

void RegisterForDump(HANDLE hProcess, unsigned long pid,
                     const std::wstring& path, const std::wstring& tag,
                     unsigned long long base, unsigned long size)
{
    auto it = g_pathIndex.find(path);
    if (it != g_pathIndex.end()) {
        // 已登记, 只累加命中次数
        g_pathTable[it->second].hitCount++;
        return;
    }

    // 新路径: 登记
    PathEntry e = CheckFile(path, tag, pid);
    g_pathTable.push_back(e);
    g_pathIndex[path] = g_pathTable.size() - 1;

    // 首次出现 → dump
    //   Raw 模式: 需 base/size, 按路径去重
    //   Mifudump 模式: 按 PID 去重, base/size 忽略
    if (hProcess != NULL) {
        std::wstring dumpName;
        if (DumpModule(hProcess, pid, path, base, size,
                       e.abnormal, e.note, dumpName)) {
            g_pathTable.back().dumped = true;
            g_pathTable.back().dumpFile = dumpName;
            WriteOut(L"    [dump] 已保存: dumpfile\\" + dumpName + L"\n");
        }
    }

    // 首次出现 → 若磁盘有文件, 拷贝到 FileDump 目录
    std::wstring copyName;
    bool copied = false;
    CopyFileFromDisk(path, e.abnormal, copyName, copied);
    if (copied) {
        g_pathTable.back().fileCopied = true;
        g_pathTable.back().fileCopyName = copyName;
    }
}

// ── 无输出工具函数 ──

std::vector<PathEntry> GetCollectedPaths() {
    return g_pathTable;  // 拷贝
}

void ResetCollectedPaths() {
    g_pathTable.clear();
    g_pathIndex.clear();
}

} // namespace das
