// ProcessTreeSnapshot.cpp : 通过 NtQuerySystemInformation 枚举进程并构建进程树
//
// 用法:
//   ProcessTreeSnapshot.exe                打印整棵进程树(从 PID 0 开始)
//   ProcessTreeSnapshot.exe --pid 1234     只打印指定进程及其子树
//   ProcessTreeSnapshot.exe --depth 3      限制树深度
//   ProcessTreeSnapshot.exe --pid 1234 --depth 2
//   ProcessTreeSnapshot.exe --json         输出 JSON(便于 Server 端解析)
//
// 参考: https://www.cnblogs.com/priarieNew/p/9756157.html
//
// 实现要点:
//   1. NtQuerySystemInformation 来自 ntdll.dll,未文档化,动态加载
//   2. SystemProcessInformation (class=5) 返回 SYSTEM_PROCESS_INFORMATION 链表,
//      通过 NextEntryOffset 串联,最后一条 NextEntryOffset=0
//   3. 每条记录含 UniqueProcessId (PID) 和 InheritedFromUniqueProcessId (父 PID),
//      据此构建进程树
//   4. 缓冲区不够时返回 STATUS_INFO_LENGTH_MISMATCH,翻倍重试
//
// 注意: 博客里的代码用 *(DWORD*)((PCHAR)p + 0x3c) 取 ImageName.Buffer,
//       这是 x86 硬编码偏移,x64 下偏移不同。这里用结构体字段直接访问,
//       跨架构都正确。

#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// STATUS_INFO_LENGTH_MISMATCH
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// ───────────────────────────────────────────────────────────────
//  SYSTEM_PROCESS_INFORMATION 完整定义 (来自 phnt)
//  winternl.h 里的 _SYSTEM_PROCESS_INFORMATION 字段不全(SpareLi1/2/3 占位),
//  Win10/11 实际返回结构含 WorkingSetPrivateSize / HardFaultCount /
//  NumberOfThreadsHighWatermark / CycleTime 等字段,偏移会错位。
//  这里用 phnt 的完整定义,确保 x64/x86 都正确。
//
//  关键陷阱(也是之前崩溃的根因):
//    HardFaultCount 和 NumberOfThreadsHighWatermark 是 ULONG (4字节),
//    不是 LARGE_INTEGER (8字节)。如果类型写错,后面所有字段偏移全错位,
//    ImageName.Buffer 读到垃圾值 → 访问违例崩溃。
// ───────────────────────────────────────────────────────────────
typedef struct _SYSTEM_PROCESS_INFORMATION_FULL {
    ULONG NextEntryOffset;                      // 偏移 0x00
    ULONG NumberOfThreads;                      // 偏移 0x04
    ULONGLONG WorkingSetPrivateSize;            // 偏移 0x08 (since VISTA)
    ULONG HardFaultCount;                       // 偏移 0x10 (since WIN7) ← ULONG,不是 LARGE_INTEGER
    ULONG NumberOfThreadsHighWatermark;         // 偏移 0x14              ← ULONG,不是 LARGE_INTEGER
    ULONGLONG CycleTime;                        // 偏移 0x18
    LARGE_INTEGER CreateTime;                   // 偏移 0x20
    LARGE_INTEGER UserTime;                     // 偏移 0x28
    LARGE_INTEGER KernelTime;                   // 偏移 0x30
    UNICODE_STRING ImageName;                   // 偏移 0x38 (x64: Length/Half/Buffer = 2+2+4pad+8)
    KPRIORITY BasePriority;                     // 偏移 0x48 (KPRIORITY = LONG)
    HANDLE UniqueProcessId;                     // 偏移 0x50 (x64: 8字节对齐)
    HANDLE InheritedFromUniqueProcessId;        // 偏移 0x58
    ULONG HandleCount;                          // 偏移 0x60
    ULONG SessionId;                            // 偏移 0x64
    ULONG_PTR UniqueProcessKey;                 // 偏移 0x68 (since VISTA, SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                     // 偏移 0x70 (x64)
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    // SYSTEM_THREAD_INFORMATION Threads[1];    // 末尾变长数组,本工具不枚举线程,省略
} SYSTEM_PROCESS_INFORMATION_FULL, *PSYSTEM_PROCESS_INFORMATION_FULL;

typedef NTSTATUS (WINAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// ───────────────────────────────────────────────────────────────
//  宽字符 → UTF-8 转换(用于控制台输出)
//  之所以不直接用 wprintf + _O_U8TEXT,是因为 MSVC 的 wprintf 在 U8TEXT 模式下
//  遇到 %zu / 某些宽字符序列会静默失败,且一次失败后后续所有 wprintf 都被跳过。
//  改成窄字符串 + printf 输出 UTF-8 字节,稳定可靠。
// ───────────────────────────────────────────────────────────────
static std::string WToU8(const wchar_t* w)
{
    if (!w || !*w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}
static std::string WToU8(const std::wstring& w) { return WToU8(w.c_str()); }

// ───────────────────────────────────────────────────────────────
//  时间转换(FILETIME → 本地时间字符串,UTF-8)
// ───────────────────────────────────────────────────────────────
static std::string FormatCreateTime(const LARGE_INTEGER& ft)
{
    if (ft.QuadPart == 0) return "-";
    // FILETIME 和 LARGE_INTEGER 同布局
    FILETIME localFt;
    if (!FileTimeToLocalFileTime((const FILETIME*)&ft, &localFt)) return "-";
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&localFt, &st)) return "-";
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// ───────────────────────────────────────────────────────────────
//  进程信息条目
// ───────────────────────────────────────────────────────────────
struct ProcInfo {
    ULONG_PTR pid = 0;
    ULONG_PTR ppid = 0;
    std::string name;          // UTF-8
    ULONG threads = 0;
    LARGE_INTEGER createTime{};
    ULONG session = 0;
    SIZE_T workingSet = 0;
    SIZE_T privatePages = 0;
    ULONG handles = 0;
    LONG basePriority = 0;
};

// NtQuerySystemInformation 枚举所有进程
static bool EnumProcesses(std::vector<ProcInfo>& out)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto pNtQuery = (PFN_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQuery) return false;

    // 缓冲区初始 256KB,不够翻倍,最多到 32MB
    ULONG bufSize = 0x40000;
    std::vector<BYTE> buf(bufSize);
    ULONG retLen = 0;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    for (int retry = 0; retry < 10; ++retry)
    {
        status = pNtQuery(SystemProcessInformation, buf.data(), bufSize, &retLen);
        if (status == 0) break;                    // STATUS_SUCCESS
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            bufSize *= 2;
            if (bufSize > 0x2000000) return false; // 超过 32MB 还不够就放弃
            buf.resize(bufSize);
            continue;
        }
        return false;
    }
    if (status != 0) return false;

    out.clear();
    auto p = (PSYSTEM_PROCESS_INFORMATION_FULL)buf.data();
    while (true)
    {
        ProcInfo info;
        info.pid = (ULONG_PTR)p->UniqueProcessId;
        info.ppid = (ULONG_PTR)p->InheritedFromUniqueProcessId;
        info.threads = p->NumberOfThreads;
        info.createTime = p->CreateTime;
        info.session = p->SessionId;
        info.workingSet = p->WorkingSetSize;
        info.privatePages = p->PrivatePageCount;
        info.handles = p->HandleCount;
        info.basePriority = p->BasePriority;

        if (p->ImageName.Buffer && p->ImageName.Length > 0)
        {
            // ImageName.Length 是字节数,转字符数
            std::wstring wname(p->ImageName.Buffer, p->ImageName.Length / sizeof(WCHAR));
            info.name = WToU8(wname);
        }
        else
        {
            // PID 0 (Idle) 没有 ImageName
            info.name = (info.pid == 0) ? "(Idle)" : "(Unknown)";
        }
        out.push_back(std::move(info));

        if (p->NextEntryOffset == 0) break;
        p = (PSYSTEM_PROCESS_INFORMATION_FULL)((BYTE*)p + p->NextEntryOffset);
    }
    return true;
}

// ───────────────────────────────────────────────────────────────
//  树形打印
// ───────────────────────────────────────────────────────────────
struct TreeCtx {
    const std::unordered_map<ULONG_PTR, std::vector<ULONG_PTR>>& children;
    const std::unordered_map<ULONG_PTR, ProcInfo>& byPid;
    int maxDepth;          // 0 = 不限制
};

static void PrintNode(const TreeCtx& ctx, ULONG_PTR pid,
                      const std::string& indent, bool isLast,
                      bool isRoot, int depth)
{
    auto itP = ctx.byPid.find(pid);
    if (itP == ctx.byPid.end()) return;
    const auto& info = itP->second;

    // 当前节点的分支线
    const char* branch = isRoot ? "" : (isLast ? "└── " : "├── ");

    // 附加信息(根节点也显示,便于看 smss.exe/csrss.exe 等的来源)
    std::printf("%s%s%lu %s  [ppid=%lu, t=%u, h=%u, ws=%llu KB, priv=%llu KB, prio=%ld, %s]\n",
        indent.c_str(), branch,
        (unsigned long)info.pid, info.name.c_str(),
        (unsigned long)info.ppid,
        info.threads,
        info.handles,
        (unsigned long long)info.workingSet / 1024,
        (unsigned long long)info.privatePages / 1024,
        info.basePriority,
        FormatCreateTime(info.createTime).c_str());

    // 到达深度上限就不展开子节点
    if (ctx.maxDepth > 0 && depth >= ctx.maxDepth)
    {
        auto itC = ctx.children.find(pid);
        if (itC != ctx.children.end() && !itC->second.empty())
        {
            // 用省略号提示有子进程被折叠
            std::string ellipsisIndent = indent + (isLast ? "    " : "│   ");
            std::printf("%s└── ... (%zu 个子进程)\n",
                ellipsisIndent.c_str(), itC->second.size());
        }
        return;
    }

    auto itC = ctx.children.find(pid);
    if (itC == ctx.children.end()) return;
    const auto& kids = itC->second;

    // 子节点的缩进:如果当前是根,子节点缩进为空;否则在父缩进基础上加
    std::string childIndent = isRoot ? "" : indent + (isLast ? "    " : "│   ");

    for (size_t i = 0; i < kids.size(); ++i)
    {
        bool last = (i + 1 == kids.size());
        PrintNode(ctx, kids[i], childIndent, last, false, depth + 1);
    }
}

// ───────────────────────────────────────────────────────────────
//  JSON 输出(扁平数组,便于 Server 端 C# 解析后自己构建树)
// ───────────────────────────────────────────────────────────────
static void PrintJson(const std::vector<ProcInfo>& procs)
{
    LARGE_INTEGER nowFt;
    GetSystemTimeAsFileTime((FILETIME*)&nowFt);
    std::printf("{\n");
    std::printf("  \"count\": %zu,\n", procs.size());
    std::printf("  \"fetched_at\": \"%s\",\n", FormatCreateTime(nowFt).c_str());
    std::printf("  \"processes\": [\n");
    for (size_t i = 0; i < procs.size(); ++i)
    {
        const auto& p = procs[i];
        // 转义 JSON 字符串里的特殊字符
        std::string escaped;
        escaped.reserve(p.name.size() + 8);
        for (char c : p.name)
        {
            switch (c)
            {
            case '"':  escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n";  break;
            case '\r': escaped += "\\r";  break;
            case '\t': escaped += "\\t";  break;
            default:    escaped += c;     break;
            }
        }
        std::printf("    {\"pid\": %lu, \"ppid\": %lu, \"name\": \"%s\", \"threads\": %u, \"handles\": %u, \"session\": %u, \"working_set_kb\": %llu, \"private_kb\": %llu, \"create_time\": \"%s\"}%s\n",
            (unsigned long)p.pid,
            (unsigned long)p.ppid,
            escaped.c_str(),
            p.threads,
            p.handles,
            p.session,
            (unsigned long long)p.workingSet / 1024,
            (unsigned long long)p.privatePages / 1024,
            FormatCreateTime(p.createTime).c_str(),
            (i + 1 < procs.size()) ? "," : "");
    }
    std::printf("  ]\n");
    std::printf("}\n");
}

// ───────────────────────────────────────────────────────────────
//  命令行参数解析
// ───────────────────────────────────────────────────────────────
struct Args {
    ULONG_PTR pid = 0;          // 0 = 显示整棵树
    bool hasPid = false;
    int maxDepth = 0;           // 0 = 不限制
    bool json = false;
};

static Args ParseArgs(int argc, wchar_t* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        std::wstring s = argv[i];
        if ((s == L"--pid" || s == L"-p") && i + 1 < argc)
        {
            try { a.pid = std::stoull(argv[++i], nullptr, 10); a.hasPid = true; }
            catch (...) { std::fprintf(stderr, "[警告] 无效的 PID: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if ((s == L"--depth" || s == L"-d") && i + 1 < argc)
        {
            try { a.maxDepth = std::stoi(argv[++i]); if (a.maxDepth < 0) a.maxDepth = 0; }
            catch (...) { std::fprintf(stderr, "[警告] 无效的深度: %s\n", WToU8(argv[i]).c_str()); }
        }
        else if (s == L"--json" || s == L"-j")
        {
            a.json = true;
        }
        else if (s == L"--help" || s == L"-h")
        {
            std::printf("用法: ProcessTreeSnapshot [选项]\n");
            std::printf("  --pid <N>     只打印指定进程及其子树\n");
            std::printf("  --depth <N>   限制树深度(0=不限制)\n");
            std::printf("  --json        输出 JSON\n");
            std::printf("  --help        显示帮助\n");
            exit(0);
        }
    }
    return a;
}

// ───────────────────────────────────────────────────────────────
//  入口
// ───────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    // 控制台 UTF-8 输出:
    //   SetConsoleOutputCP(CP_UTF8) 让控制台用 UTF-8 解码字节
    //   源文件用 /utf-8 编译,字符串字面值就是 UTF-8 字节
    //   printf 直接输出这些字节,控制台正确显示
    //   管道/重定向也能正常工作(就是 UTF-8 字节流)
    SetConsoleOutputCP(CP_UTF8);

    Args args = ParseArgs(argc, argv);

    // 1. 枚举进程
    std::vector<ProcInfo> procs;
    if (!EnumProcesses(procs))
    {
        std::fprintf(stderr, "[错误] NtQuerySystemInformation 调用失败\n");
        return 1;
    }

    // JSON 模式直接输出扁平数组
    if (args.json)
    {
        PrintJson(procs);
        return 0;
    }

    // 2. 构建 byPid 和 children 索引
    std::unordered_map<ULONG_PTR, ProcInfo> byPid;
    std::unordered_map<ULONG_PTR, std::vector<ULONG_PTR>> children;
    byPid.reserve(procs.size());
    children.reserve(procs.size());

    for (const auto& p : procs)
    {
        byPid[p.pid] = p;
        // 过滤自引用:PID 0 (Idle) 的 ppid 也是 0,
        // 不过滤的话 children[0] 会包含 0 自己,PrintNode(0) 无限递归 → 栈溢出
        if (p.ppid != p.pid)
            children[p.ppid].push_back(p.pid);
    }

    // 每个 children 列表按 PID 排序(输出稳定)
    for (auto& kv : children)
    {
        std::sort(kv.second.begin(), kv.second.end());
    }

    // 3. 打印统计
    ULONG totalThreads = 0;
    SIZE_T totalWs = 0;
    for (const auto& p : procs)
    {
        totalThreads += p.threads;
        totalWs += p.workingSet;
    }
    std::printf("进程树快照: 共 %zu 个进程, %lu 个线程, 总工作集 %llu KB\n",
        procs.size(), totalThreads, (unsigned long long)totalWs / 1024);
    std::printf("────────────────────────────────────────────────────────────────\n\n");

    // 4. 确定根节点
    TreeCtx ctx{ children, byPid, args.maxDepth };

    if (args.hasPid)
    {
        // 只打印指定 PID 的子树
        if (byPid.find(args.pid) == byPid.end())
        {
            std::fprintf(stderr, "[错误] PID %lu 不存在\n", (unsigned long)args.pid);
            return 1;
        }
        PrintNode(ctx, args.pid, "", true, true, 1);
    }
    else
    {
        // 打印整棵树:从 PID 0 (Idle) 开始递归,能覆盖所有进程
        // 同时找出"孤儿进程"(父 PID 不在列表里)单独作为根打印
        std::vector<ULONG_PTR> roots;
        for (const auto& p : procs)
        {
            if (p.pid == 0)
            {
                roots.insert(roots.begin(), 0); // Idle 放最前
            }
            else if (p.pid != 0 && byPid.find(p.ppid) == byPid.end())
            {
                // 父进程不在列表里(已退出或 PID 重用),作为孤儿根
                roots.push_back(p.pid);
            }
        }
        // 去重(PID 0 可能被加两次)
        std::sort(roots.begin(), roots.end());
        roots.erase(std::unique(roots.begin(), roots.end()), roots.end());

        for (size_t i = 0; i < roots.size(); ++i)
        {
            PrintNode(ctx, roots[i], "", true, true, 1);
            if (i + 1 < roots.size())
                std::printf("\n"); // 多个根之间空一行
        }
    }

    return 0;
}
