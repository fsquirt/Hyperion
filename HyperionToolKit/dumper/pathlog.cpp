#include "pathlog.h"
#include "MonitorTypes.h"
#include "moddump.h"
#include "../common/Out.h"

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <unordered_map>

namespace das {

// 全局去重路径表,Ctrl+C 时输出汇总
static std::vector<PathEntry>                g_pathTable;   // 按发现顺序保存
static std::unordered_map<std::wstring, size_t> g_pathIndex; // path → g_pathTable 索引

//  工具: 检查单个文件的 RHS 属性 / 存在性, 返回 PathEntry,不打印
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


//  打印: 每事件都打印进程/模块,不去重, 每次都显示
void PrintFileLine(const std::wstring& path, const std::wstring& tag)
{
    PathEntry e = CheckFile(path, tag, 0);
    std::wostringstream ss;
    ss << L"    " << tag << L": " << (path.empty() ? L"<空>" : path);
    if (e.abnormal) ss << L"  " << e.note;
    ss << L"\n";
    if (e.abnormal) {
        OutColored(ss.str(), FOREGROUND_RED | FOREGROUND_INTENSITY);
    } else {
        Out(ss.str());
    }
}


//  登记 + dump: 路径去重, 首次出现时 dump, 已登记只累加命中次数
//  dump 方式由 moddump 全局开关决定 (Raw / Mini / Mifudump)
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
    //   Mini/Mifudump 模式: 按 PID 去重, base/size 忽略
    if (hProcess != NULL) {
        std::wstring dumpName;
        if (DumpModule(hProcess, pid, path, base, size,
                       e.abnormal, e.note, dumpName)) {
            g_pathTable.back().dumped = true;
            g_pathTable.back().dumpFile = dumpName;
            Out(L"    [dump] 已保存: dumpfile\\" + dumpName + L"\n");
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


//  汇总输出: Ctrl+C 后打印完整去重路径表
void PrintPathTable()
{
    Out(L"\n");
    Out(L"  通信文件去重汇总,共 " + std::to_wstring(g_pathTable.size()) + L" 个\n");
    Out(L"\n");

    if (g_pathTable.empty()) {
        Out(L"  未捕获到任何通信事件\n");
        Out(L"\n");
        return;
    }

    // 先打印异常项, 再打印正常项,异常项更值得关注
    int abnormalCount = 0;
    unsigned long totalHits = 0;

    Out(L"\n 异常文件,不存在 或 含 RHS 属性 \n");
    for (const auto& e : g_pathTable) {
        if (!e.abnormal) continue;
        abnormalCount++;
        totalHits += e.hitCount;

        std::wostringstream ss;
        ss << L"  [" << std::setw(4) << e.hitCount << L" 次] "
           << std::left << std::setw(12) << e.tag
           << L" PID=" << std::setw(6) << e.pid << L"  "
           << (e.path.empty() ? L"<空>" : e.path)
           << L"  " << e.note;
        if (e.dumped)     ss << L"  → dumpfile\\" << e.dumpFile;
        if (e.fileCopied) ss << L"  → FileDump\\" << e.fileCopyName;
        ss << L"\n";
        OutColored(ss.str(), FOREGROUND_RED | FOREGROUND_INTENSITY);
    }

    Out(L"\n 正常文件 \n");
    for (const auto& e : g_pathTable) {
        if (e.abnormal) continue;
        totalHits += e.hitCount;

        std::wostringstream ss;
        ss << L"  [" << std::setw(4) << e.hitCount << L" 次] "
           << std::left << std::setw(12) << e.tag
           << L" PID=" << std::setw(6) << e.pid << L"  "
           << e.path;
        if (e.dumped)     ss << L"  → dumpfile\\" << e.dumpFile;
        if (e.fileCopied) ss << L"  → FileDump\\" << e.fileCopyName;
        ss << L"\n";
        Out(ss.str());
    }

    int dumpedCount = 0, copiedCount = 0;
    for (const auto& e : g_pathTable) {
        if (e.dumped)     dumpedCount++;
        if (e.fileCopied) copiedCount++;
    }

    std::wostringstream sum;
    sum << L"\n";
    sum << L"  总路径数:   " << g_pathTable.size() << L"\n";
    sum << L"  异常路径:   " << abnormalCount << L"\n";
    sum << L"  已 dump:    " << dumpedCount << L"  (→ dumpfile)\n";
    sum << L"  已拷贝:     " << copiedCount << L"  磁盘文件 → FileDump\n";
    sum << L"  通信总次数: " << totalHits << L"\n";
    sum << L"  dump 目录:  " << GetDumpDir() << L"\n";
    sum << L"  FileDump:   " << GetFileDumpDir() << L"\n";
    sum << L"\n";
    Out(sum.str());
}

} // namespace das