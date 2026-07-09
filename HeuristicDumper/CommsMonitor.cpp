// CommsMonitor.cpp — ETW 订阅 + 通信文件检测 + RHS 属性告警
//
// 引用 DriverAttachSelector 的 ETW 订阅逻辑:
//   - Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C} (来自 EtwConsumer.h)
//   - 事件结构 EtwIoctlEventHeader (与 EtwConsumer.cpp 一致)
//   - 管道搭建: EnablePrivilege / StartTrace / EnableTraceEx2 / OpenTrace / ProcessTrace
//     (参考 EtwConsumer.cpp 的 RunEtwConsumer)
//
// 定制回调:
//   1. 只处理 AttachId != 0 的事件 (被 KernelService 附着的设备上的通信)
//   2. QueryFullProcessImageName 取发起进程主 exe 路径
//   3. 从调用栈 ExtendedData 符号化用户态模块,排除系统目录,收集业务模块
//   4. 对每个文件 (exe + 业务模块) 检查:
//        - 磁盘上是否存在 (GetFileAttributes != INVALID_FILE_ATTRIBUTES)
//        - 是否含 RHS 属性 (FILE_ATTRIBUTE_READONLY / HIDDEN / SYSTEM)
//   5. 文件不存在或含 RHS 属性 → 红色输出

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "CommsMonitor.h"
#include "Common.h"

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <psapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE32
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE32 5
#endif
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE64
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE64 6
#endif

namespace das {

// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// (来自 DriverAttachSelector/EtwConsumer.h, 与内核 EtwLogger.c 一致)
static const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR = L"{A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}";

// 独立 Session 名,避免与 DriverAttachSelector 同时运行时冲突
static const wchar_t* SESSION_NAME = L"HeuristicDumperIoctlTrace";

// ═══════════════════════════════════════════════════════════════════════
//  全局去重路径表 (Ctrl+C 时输出汇总)
//  ETW 回调是单线程串行调用 (ProcessTrace 专用线程),无需加锁
// ═══════════════════════════════════════════════════════════════════════

struct PathEntry {
    std::wstring  path;        // 文件完整路径
    std::wstring  tag;         // 来源标记: "进程 exe" / "栈模块"
    unsigned long pid = 0;      // 首次命中时的进程 PID (诊断用)
    bool          abnormal = false;  // 不存在 或 含 RHS
    std::wstring  note;        // 异常说明 (如 "[RHS: R H]" / "[磁盘上不存在!]")
    unsigned long hitCount = 1;// 该路径被通信命中的次数
    bool          dumped = false;     // 是否已 dump 成功 (内存映像)
    std::wstring  dumpFile;    // dump 文件名 (相对 dumpfile/ 目录)
    bool          fileCopied = false;  // 是否已拷贝磁盘文件到 FileDump
    std::wstring  fileCopyName;       // FileDump 里的副本文件名
};

static std::vector<PathEntry>      g_pathTable;     // 按发现顺序保存
static std::unordered_map<std::wstring, size_t> g_pathIndex;  // path → g_pathTable 索引

// dump 目录 (程序同目录下 dumpfile\) + 已 dump 路径去重表
static std::wstring g_dumpDir;
static std::unordered_set<std::wstring> g_dumped;

// FileDump 目录 (磁盘文件副本, 只针对磁盘上存在的文件) + 已拷贝去重表
static std::wstring g_fileDumpDir;
static std::unordered_set<std::wstring> g_fileCopied;

// 内核通信: IOCTL_DUMP_DRIVER_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 与 KernelService\DriverAttach.h 一致, 这里内联避免拖入 KernelComms.cpp 链接
//   = (0x22 << 16) | (0 << 14) | (0x809 << 2) | 0
//   = 0x220000 | 0x2024
//   = 0x222024
// (之前硬编码 0x22900C 是错的, 实际对应 function=0x2403 access=FILE_WRITE_DATA, 驱动认不出来)
#define HD_IOCTL_DUMP_DRIVER_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
struct HdDumpDriverMemReq {
    unsigned long AttachId;
};
struct HdDumpDriverMemResp {
    long                Status;
    unsigned long long  DriverObjectAddr;
    unsigned long long  ImageBase;
    unsigned long       ImageSize;
    unsigned long       BytesDumped;
    wchar_t             FullPath[260];
    wchar_t             BaseName[64];
};
#pragma pack(pop)

// 已 dump 的驱动 sys (按 AttachId 去重, 因为同一 AttachId 的对端驱动不变)
static std::unordered_set<unsigned long> g_driverDumped;

// KernelService 设备句柄 (启动时打开, 供 dump 驱动内存用)
static void* g_hKernelService = nullptr;

// 内核端 ETW_IOCTL_EVENT_HEADER 结构 (必须与 EtwConsumer.cpp / EtwLogger.h 字节对齐一致)
#pragma pack(push, 8)
struct EtwIoctlEventHeader {
    unsigned long       Version;
    unsigned long       IoControlCode;
    unsigned long       InputBufferLength;
    unsigned long       CaptureSize;
    unsigned long long  RequestorPid;
    unsigned long long  TargetDeviceAddr;
    unsigned long long  FilterDeviceAddr;
    unsigned long long  AttachId;
    unsigned long       MajorFunction;
    unsigned long       Method;
};
#pragma pack(pop)
static_assert(sizeof(EtwIoctlEventHeader) == 56, "EtwIoctlEventHeader size mismatch");

static std::atomic<bool> g_Stop{ false };

// 目标进程模块表 (用于调用栈用户态地址符号化 + 内存 dump)
struct ModuleRange {
    unsigned long long base;
    unsigned long size;
    wchar_t path[MAX_PATH];
};

// 调用栈命中的业务模块 (路径 + 基址 + 大小, 供 dump 用)
struct StackModuleInfo {
    std::wstring path;
    unsigned long long base = 0;
    unsigned long size = 0;
};

// ═══════════════════════════════════════════════════════════════════════
//  工具: 启用权限
// ═══════════════════════════════════════════════════════════════════════

static bool EnablePrivilege(LPCWSTR priv)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    return ok && err == ERROR_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════
//  工具: 彩色输出
//  WriteOut 用 WriteFile 写 UTF-8, 控制台句柄上 SetConsoleTextAttribute 生效;
//  重定向到文件时颜色属性被忽略 (不会污染文件内容)
// ═══════════════════════════════════════════════════════════════════════

static void WriteColored(const std::wstring& s, WORD attr)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD oldAttr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    SetConsoleTextAttribute(hOut, attr);
    WriteOut(s);
    SetConsoleTextAttribute(hOut, oldAttr);
}

// ═══════════════════════════════════════════════════════════════════════
//  工具: 判断路径是否为系统目录 (用于排除系统 DLL)
// ═══════════════════════════════════════════════════════════════════════

static bool IsSystemPath(const std::wstring& path)
{
    // 不区分大小写查找 \Windows\System32 / \Windows\SysWOW64 / \Windows\WinSxS
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    return lower.find(L"\\windows\\system32\\") != std::wstring::npos
        || lower.find(L"\\windows\\syswow64\\") != std::wstring::npos
        || lower.find(L"\\windows\\winsxs\\")  != std::wstring::npos
        || lower.find(L"\\windows\\system32")  == lower.size() - 17  // 末尾精确
        || lower.find(L"\\windows\\syswow64")  == lower.size() - 17;
}

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
//  打印: 每事件都打印进程/模块 (不去重, 每次都显示)
// ═══════════════════════════════════════════════════════════════════════

static void PrintFileLine(const std::wstring& path, const std::wstring& tag)
{
    PathEntry e = CheckFile(path, tag, 0);
    std::wostringstream ss;
    ss << L"    " << tag << L": " << (path.empty() ? L"<空>" : path);
    if (e.abnormal) ss << L"  " << e.note;
    ss << L"\n";
    if (e.abnormal) {
        WriteColored(ss.str(), FOREGROUND_RED | FOREGROUND_INTENSITY);
    } else {
        WriteOut(ss.str());
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  登记 + dump: 路径去重, 首次出现时 dump 内存, 已登记只累加命中次数
// ═══════════════════════════════════════════════════════════════════════

// 前置声明 (DumpModule / CopyFileFromDisk 实现在后面)
static bool DumpModule(HANDLE hProcess, unsigned long pid,
                       const std::wstring& modulePath,
                       unsigned long long base, unsigned long size,
                       bool abnormal, const std::wstring& note,
                       std::wstring& outDumpFile);
static void CopyFileFromDisk(const std::wstring& modulePath, bool abnormal,
                             std::wstring& outCopyName, bool& outCopied);

static void RegisterForDump(HANDLE hProcess, unsigned long pid,
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

    // 首次出现 → dump 内存 (从目标进程读映像)
    if (base != 0 && size != 0 && hProcess != NULL) {
        std::wstring dumpName;
        if (DumpModule(hProcess, pid, path, base, size, e.abnormal, e.note, dumpName)) {
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

// ═══════════════════════════════════════════════════════════════════════
//  汇总输出: Ctrl+C 后打印完整去重路径表
// ═══════════════════════════════════════════════════════════════════════

static void PrintPathTable()
{
    WriteOut(L"\n═══════════════════════════════════════════════════════\n");
    WriteOut(L"  通信文件去重汇总 (共 " + std::to_wstring(g_pathTable.size()) + L" 个)\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");

    if (g_pathTable.empty()) {
        WriteOut(L"  (未捕获到任何通信事件)\n");
        WriteOut(L"═══════════════════════════════════════════════════════\n");
        return;
    }

    // 先打印异常项, 再打印正常项 (异常项更值得关注)
    int abnormalCount = 0;
    unsigned long totalHits = 0;

    WriteOut(L"\n── 异常文件 (不存在 或 含 RHS 属性) ──\n");
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
        WriteColored(ss.str(), FOREGROUND_RED | FOREGROUND_INTENSITY);
    }

    WriteOut(L"\n── 正常文件 ──\n");
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
        WriteOut(ss.str());
    }

    int dumpedCount = 0, copiedCount = 0;
    for (const auto& e : g_pathTable) {
        if (e.dumped)     dumpedCount++;
        if (e.fileCopied) copiedCount++;
    }

    std::wostringstream sum;
    sum << L"\n───────────────────────────────────────────────────────\n";
    sum << L"  总路径数:   " << g_pathTable.size() << L"\n";
    sum << L"  异常路径:   " << abnormalCount << L"\n";
    sum << L"  已 dump:    " << dumpedCount << L"  (内存映像 → dumpfile)\n";
    sum << L"  已拷贝:     " << copiedCount << L"  (磁盘文件 → FileDump)\n";
    sum << L"  通信总次数: " << totalHits << L"\n";
    sum << L"  dump 目录:  " << g_dumpDir << L"\n";
    sum << L"  FileDump:   " << g_fileDumpDir << L"\n";
    sum << L"═══════════════════════════════════════════════════════\n";
    WriteOut(sum.str());
}

// ═══════════════════════════════════════════════════════════════════════
//  Dumper: 初始化 dumpfile 目录
// ═══════════════════════════════════════════════════════════════════════

static bool InitDumpDir()
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

static bool InitFileDumpDir()
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

static bool DumpModule(HANDLE hProcess,
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

static void CopyFileFromDisk(const std::wstring& modulePath, bool abnormal,
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

// ═══════════════════════════════════════════════════════════════════════
//  对端驱动 dump: 按 AttachId 通过 KernelService 从内核 dump 驱动内存映像
//  - 同一 AttachId 只 dump 一次 (对端驱动不变)
//  - 内核返回 sys 路径 (FullPath/BaseName):
//      磁盘上有文件 → 拷贝到 FileDump\
//      磁盘上没有   → 内存 dump 到 dumpfile\ (文件名 MISSING_<BaseName>)
// ═══════════════════════════════════════════════════════════════════════

static void DumpTargetDriver(unsigned long attachId)
{
    if (attachId == 0) return;
    if (!g_hKernelService) return;

    // 同一 AttachId 只处理一次
    if (g_driverDumped.count(attachId) > 0) return;
    g_driverDumped.insert(attachId);

    // 第一次: 探测响应头拿 ImageSize + 路径
    HdDumpDriverMemReq req{ attachId };
    std::vector<unsigned char> outBuf(sizeof(HdDumpDriverMemResp), 0);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl((HANDLE)g_hKernelService,
                              HD_IOCTL_DUMP_DRIVER_MEMORY,
                              &req, sizeof(req),
                              outBuf.data(), (DWORD)outBuf.size(),
                              &bytesReturned, nullptr);
    if (!ok || bytesReturned < sizeof(HdDumpDriverMemResp)) {
        WriteOut(L"  [驱动] dump 失败: DeviceIoControl 探测失败 err="
                 + std::to_wstring(GetLastError()) + L"\n");
        return;
    }

    HdDumpDriverMemResp resp{};
    memcpy(&resp, outBuf.data(), sizeof(resp));

    if (resp.Status != 0) {
        WriteOut(L"  [驱动] dump 失败: 内核返回 Status=0x"
                 + std::to_wstring(resp.Status) + L"\n");
        return;
    }

    std::wstring fullPath(resp.FullPath);
    std::wstring baseName(resp.BaseName);
    if (baseName.empty()) baseName = L"driver_" + std::to_wstring(attachId) + L".sys";

    // 内核返回的路径是 \SystemRoot\... 格式, 转成物理路径
    std::wstring physPath = fullPath;
    if (physPath.find(L"\\SystemRoot\\") == 0) {
        wchar_t sysRoot[MAX_PATH] = {0};
        GetWindowsDirectoryW(sysRoot, MAX_PATH);
        physPath = std::wstring(sysRoot) + L"\\" + physPath.substr(11);
    } else if (physPath.find(L"\\??\\") == 0) {
        physPath = physPath.substr(4);
    }

    WriteOut(L"  [驱动] 对端 sys: " + (physPath.empty() ? baseName : physPath)
             + L"  (ImageBase=0x" + std::to_wstring(resp.ImageBase)
             + L" Size=" + std::to_wstring(resp.ImageSize) + L")\n");

    // 检查磁盘是否有文件
    DWORD attr = GetFileAttributesW(physPath.c_str());
    bool diskHas = (attr != INVALID_FILE_ATTRIBUTES);

    if (diskHas) {
        // 磁盘有 → 拷贝到 FileDump
        std::wstring copyName = baseName;
        if (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            copyName = L"RHS_" + baseName;
        }
        std::wstring copyPath = g_fileDumpDir + L"\\" + copyName;
        BOOL cancel = FALSE;
        if (CopyFileExW(physPath.c_str(), copyPath.c_str(), NULL, NULL, &cancel, 0)) {
            WriteOut(L"  [file] 已拷贝驱动: FileDump\\" + copyName + L"\n");
        } else {
            WriteOut(L"  [file] 驱动拷贝失败: " + copyName
                     + L" err=" + std::to_wstring(GetLastError()) + L"\n");
        }
    }

    // 无论磁盘有没有, 都从内存 dump 一份到 dumpfile (内存态可能被 patch)
    if (resp.ImageSize > 0) {
        // 第二次: 拿完整映像
        outBuf.assign(sizeof(HdDumpDriverMemResp) + resp.ImageSize, 0);
        ok = DeviceIoControl((HANDLE)g_hKernelService,
                              HD_IOCTL_DUMP_DRIVER_MEMORY,
                              &req, sizeof(req),
                              outBuf.data(), (DWORD)outBuf.size(),
                              &bytesReturned, nullptr);
        if (!ok || bytesReturned < sizeof(HdDumpDriverMemResp)) {
            WriteOut(L"  [dump] 驱动内存 dump 失败: err="
                     + std::to_wstring(GetLastError()) + L"\n");
            return;
        }
        memcpy(&resp, outBuf.data(), sizeof(resp));
        if (resp.BytesDumped == 0) {
            WriteOut(L"  [dump] 驱动内存 dump: BytesDumped=0\n");
            return;
        }

        // 文件名: 磁盘有 → baseName, 磁盘没有 → MISSING_baseName
        std::wstring dumpName = baseName;
        if (!diskHas) dumpName = L"MISSING_" + baseName;
        std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

        HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            WriteOut(L"  [dump] 驱动 CreateFile 失败: " + dumpPath + L"\n");
            return;
        }
        DWORD written = 0;
        const unsigned char* imgStart = outBuf.data() + sizeof(HdDumpDriverMemResp);
        ok = WriteFile(hFile, imgStart, resp.BytesDumped, &written, NULL);
        CloseHandle(hFile);
        if (ok && written == resp.BytesDumped) {
            WriteOut(L"  [dump] 驱动内存已保存: dumpfile\\" + dumpName
                     + L" (" + std::to_wstring(resp.BytesDumped) + L" 字节)\n");
        } else {
            WriteOut(L"  [dump] 驱动 WriteFile 失败\n");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  工具: 建立目标进程模块表 (用于调用栈地址符号化)
// ═══════════════════════════════════════════════════════════════════════

static std::vector<ModuleRange> BuildModuleTable(unsigned long long pid)
{
    std::vector<ModuleRange> modules;
    if (pid == 0) return modules;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                   FALSE, (DWORD)pid);
    if (!hProcess) return modules;

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        DWORD modCount = cbNeeded / sizeof(HMODULE);
        if (modCount > 1024) modCount = 1024;
        for (DWORD m = 0; m < modCount; m++) {
            MODULEINFO mi = {};
            if (GetModuleInformation(hProcess, hMods[m], &mi, sizeof(mi))) {
                ModuleRange mr = {};
                mr.base = (unsigned long long)mi.lpBaseOfDll;
                mr.size = mi.SizeOfImage;
                GetModuleFileNameExW(hProcess, hMods[m], mr.path, MAX_PATH);
                modules.push_back(mr);
            }
        }
    }
    CloseHandle(hProcess);
    return modules;
}

// ═══════════════════════════════════════════════════════════════════════
//  工具: 从调用栈 ExtendedData 收集用户态业务模块 (路径+基址+大小, 去重)
//  返回: 业务模块列表 (已排除系统目录), 按栈深排序 (越深越接近发起者)
// ═══════════════════════════════════════════════════════════════════════

static std::vector<StackModuleInfo> CollectStackModules(
    const EVENT_RECORD* record,
    const std::vector<ModuleRange>& modules)
{
    std::vector<StackModuleInfo> result;
    std::unordered_set<std::wstring> seen;

    for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record->ExtendedData[i];
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32 &&
            item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            continue;
        }
        if (item.DataSize < sizeof(unsigned long long)) continue;

        bool is64 = (item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64);
        const unsigned char* addrStart = (const unsigned char*)item.DataPtr
                                       + sizeof(unsigned long long);

        unsigned long frameCount = 0;
        const unsigned long long* frames64 = nullptr;
        const unsigned long* frames32 = nullptr;
        if (is64) {
            frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long long);
            frames64 = (const unsigned long long*)addrStart;
        } else {
            frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long);
            frames32 = (const unsigned long*)addrStart;
        }

        // 调用栈从深到浅遍历, 先遇到的业务模块更接近发起者
        unsigned long maxScan = std::min(frameCount, (unsigned long)64);
        for (unsigned long f = 0; f < maxScan; f++) {
            unsigned long long addr = is64 ? frames64[f] : frames32[f];
            // 只看用户态地址
            if (addr >= 0x800000000000ULL) continue;

            for (const auto& mr : modules) {
                if (addr >= mr.base && addr < mr.base + mr.size) {
                    std::wstring p = mr.path;
                    if (!IsSystemPath(p) && seen.insert(p).second) {
                        result.push_back({ p, mr.base, mr.size });
                    }
                    break;
                }
            }
        }
        break; // 只处理第一个栈条目
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  事件回调 — 解析事件, 定位通信文件, 检查 RHS
// ═══════════════════════════════════════════════════════════════════════

static void WINAPI EventRecordCallback(EVENT_RECORD* record)
{
    if (g_Stop.load()) return;
    if (record->EventHeader.EventDescriptor.Id != 1) return;

    if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) return;

    const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;

    // 只处理被附着的设备 (AttachId != 0 表示 KernelService FiDO 拦截到的事件)
    if (hdr->AttachId == 0) return;

    // 时间戳
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);

    // 事件头
    std::wostringstream head;
    head << L"\n───────────────────────────────────────────────────────\n";
    head << L"[" << std::setfill(L'0')
         << std::setw(2) << st.wHour << L":"
         << std::setw(2) << st.wMinute << L":"
         << std::setw(2) << st.wSecond << L"."
         << std::setw(3) << st.wMilliseconds << L"] ";
    head << L"AttachId=" << hdr->AttachId
        << L"  PID=" << hdr->RequestorPid
        << L"  IOCTL=0x" << std::hex << std::setw(8) << std::setfill(L'0') << hdr->IoControlCode;
    if (hdr->MajorFunction == 0x0E) head << L" (DEVICE_CONTROL)";
    else if (hdr->MajorFunction == 0x00) head << L" (CREATE)";
    else if (hdr->MajorFunction == 0x02) head << L" (CLOSE)";
    head << L"\n";
    WriteOut(head.str());

    // 打开进程 (需要 QUERY_INFORMATION 取 exe 路径 + VM_READ 建模块表/dump)
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, (DWORD)hdr->RequestorPid);

    // 取发起进程主 exe 路径
    std::wstring exePath;
    if (hProc) {
        wchar_t buf[MAX_PATH];
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
            exePath.assign(buf, len);
        }
    }

    // 建模块表 + 从调用栈收集业务模块
    auto modules = BuildModuleTable(hdr->RequestorPid);
    auto stackModules = CollectStackModules(record, modules);

    // 查 exe 模块的基址/大小 (供 dump 用)
    unsigned long long exeBase = 0;
    unsigned long exeSize = 0;
    for (const auto& mr : modules) {
        if (mr.path == exePath) {
            exeBase = mr.base;
            exeSize = mr.size;
            break;
        }
    }

    WriteOut(L"  通信文件:\n");

    // 每事件都打印 (不去重, 显示哪个进程哪个模块)
    PrintFileLine(exePath, L"进程 exe");
    if (stackModules.empty()) {
        WriteOut(L"    调用栈业务模块: <无> (调用栈只有系统模块或未捕获)\n");
    } else {
        for (size_t i = 0; i < stackModules.size(); i++) {
            std::wostringstream tag;
            tag << L"栈模块[" << (i + 1) << L"]";
            PrintFileLine(stackModules[i].path, tag.str());
        }
    }

    // 登记 + dump (去重: 同一路径只 dump 一次)
    RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
                    exePath, L"进程 exe", exeBase, exeSize);
    for (size_t i = 0; i < stackModules.size(); i++) {
        std::wostringstream tag;
        tag << L"栈模块[" << (i + 1) << L"]";
        RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
                        stackModules[i].path, tag.str(),
                        stackModules[i].base, stackModules[i].size);
    }

    // 对端驱动 dump (按 AttachId 去重: 磁盘有拷 FileDump, 没有从内存 dump 到 dumpfile)
    DumpTargetDriver((unsigned long)hdr->AttachId);

    if (hProc) CloseHandle(hProc);
    WriteOut(L"───────────────────────────────────────────────────────\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  BufferCallback — 检测停止信号
// ═══════════════════════════════════════════════════════════════════════

static ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* logfile)
{
    UNREFERENCED_PARAMETER(logfile);
    return g_Stop.load() ? FALSE : TRUE;
}

// ═══════════════════════════════════════════════════════════════════════
//  主入口 — ETW 管道搭建 (参考 EtwConsumer.cpp 的 RunEtwConsumer)
// ═══════════════════════════════════════════════════════════════════════

int RunCommsMonitor(unsigned int durationSec)
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  通信文件监控 — ETW 订阅 + 调用栈定位 + RHS 属性告警\n");
    WriteOut(L"  引用 DriverAttachSelector 的 ETW 逻辑 (Provider ");
    WriteOut(ETW_IOCTL_PROVIDER_GUID_STR);
    WriteOut(L")\n");
    WriteOut(L"  只处理被附着设备 (AttachId != 0) 的通信事件\n");
    if (durationSec > 0) {
        WriteOut(L"  持续时间: " + std::to_wstring(durationSec) + L" 秒\n");
    } else {
        WriteOut(L"  持续时间: 永久 (Ctrl+C 退出)\n");
    }
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // 1. 启用权限 (抓栈靠 SeSystemProfilePrivilege)
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME)) {
        WriteOut(L"[警告] 启用 SeSystemProfilePrivilege 失败,可能无法抓栈\n");
    }
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        WriteOut(L"[警告] 启用 SeDebugPrivilege 失败 (跨进程读模块需要)\n");
    }

    // 1b. 初始化 dump 目录 (内存映像) + FileDump 目录 (磁盘文件副本)
    if (InitDumpDir()) {
        WriteOut(L"[OK] dump 目录: " + g_dumpDir + L"\n");
    } else {
        WriteOut(L"[警告] dump 目录初始化失败,将跳过内存 dump\n");
    }
    if (InitFileDumpDir()) {
        WriteOut(L"[OK] FileDump 目录: " + g_fileDumpDir + L"\n");
    } else {
        WriteOut(L"[警告] FileDump 目录初始化失败,将跳过磁盘文件拷贝\n");
    }

    // 1c. 打开 KernelService 句柄 (供 dump 对端驱动内存用)
    HANDLE hKs = CreateFileW(L"\\\\.\\KernelService", GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (hKs != INVALID_HANDLE_VALUE) {
        g_hKernelService = hKs;
        WriteOut(L"[OK] 已连接 KernelService (驱动内存 dump 可用)\n");
    } else {
        WriteOut(L"[警告] 打开 KernelService 失败 err="
                 + std::to_wstring(GetLastError())
                 + L" (将跳过对端驱动 dump)\n");
    }

    // 2. Ctrl+C 处理
    g_Stop.store(false);
    auto handler = [](DWORD ctrl) -> BOOL {
        if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT) {
            g_Stop.store(true);
            WriteOut(L"\n[收到 Ctrl+C,正在停止订阅...]\n");
            return TRUE;
        }
        return FALSE;
    };
    SetConsoleCtrlHandler(handler, TRUE);

    // 3. 准备 EVENT_TRACE_PROPERTIES
    const size_t sessionNameLen = wcslen(SESSION_NAME) + 1;
    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameLen * sizeof(wchar_t);
    std::vector<unsigned char> propBuf(propSize, 0);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)propBuf.data();
    props->Wnode.BufferSize = (ULONG)propSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LogFileNameOffset = 0;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((LPWSTR)((unsigned char*)props + props->LoggerNameOffset),
             sessionNameLen, SESSION_NAME);
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 32;
    props->MaximumFileSize = 100;
    props->FlushTimer = 1;

    // 4. 停掉残留同名 Session
    ControlTraceW((TRACEHANDLE)0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    // 5. StartTrace
    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] StartTraceW 失败: " + std::to_wstring(status) + L"\n");
        return 1;
    }
    WriteOut(L"[OK] ETW Session 已启动: " + std::wstring(SESSION_NAME) + L"\n");

    // 6. EnableTraceEx2 带 STACK_TRACE
    GUID providerGuid;
    CLSIDFromString(ETW_IOCTL_PROVIDER_GUID_STR, &providerGuid);
    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
    params.SourceId = providerGuid;
    status = EnableTraceEx2(sessionHandle, &providerGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] EnableTraceEx2 失败: " + std::to_wstring(status) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    WriteOut(L"[OK] Provider 已启用,带 EVENT_ENABLE_PROPERTY_STACK_TRACE\n");
    WriteOut(L"\n等待被附着设备的通信事件...\n\n");

    // 7. OpenTrace (实时模式, 必须叠加 PROCESS_TRACE_MODE_EVENT_RECORD)
    EVENT_TRACE_LOGFILE logFile{};
    logFile.LoggerName = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;
    logFile.IsKernelTrace = FALSE;

    TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG err = GetLastError();
        WriteOut(L"[错误] OpenTraceW 失败: " + std::to_wstring(err) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    // 8. 超时计时器
    HANDLE hTimer = NULL;
    if (durationSec > 0) {
        hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
        if (hTimer) {
            LARGE_INTEGER due;
            due.QuadPart = -((LONGLONG)durationSec * 10000000LL);
            SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
        }
    }

    // 9. ProcessTrace 在独立线程跑, 主线程等超时/Ctrl+C
    HANDLE hTraceThread = CreateThread(
        NULL, 0,
        [](LPVOID param) -> DWORD {
            TRACEHANDLE* ph = (TRACEHANDLE*)param;
            ProcessTrace(ph, 1, NULL, NULL);
            return 0;
        },
        &consumerHandle, 0, NULL);

    HANDLE waits[2] = { hTraceThread, hTimer };
    DWORD waitCount = (hTimer != NULL) ? 2 : 1;

    // 短轮询 (Ctrl+C 后主动 Stop 踢醒卡死的 ProcessTrace)
    while (true) {
        DWORD waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, 200);
        if (waitResult != WAIT_TIMEOUT) break;
        if (g_Stop.load()) break;
    }

    // 10. 清理
    g_Stop.store(true);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    if (hTraceThread) {
        WaitForSingleObject(hTraceThread, 5000);
        CloseHandle(hTraceThread);
    }
    if (hTimer) CloseHandle(hTimer);
    CloseTrace(consumerHandle);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    SetConsoleCtrlHandler(handler, FALSE);

    WriteOut(L"\n[OK] ETW 订阅已停止\n");

    // 关闭 KernelService 句柄
    if (g_hKernelService) {
        CloseHandle((HANDLE)g_hKernelService);
        g_hKernelService = nullptr;
    }

    // 输出去重汇总表
    PrintPathTable();
    return 0;
}

} // namespace das
