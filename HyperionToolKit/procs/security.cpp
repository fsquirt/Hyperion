// security.cpp — procs 安全采集模式实现 (原 JsonWriter.cpp)
//
//   1. 枚举所有进程
//   2. 逐个采集详情(线程/模块/内存/句柄)
//   3. JSON 输出供 Server 端分析
// 字符串转义复用 common/Str, 输出复用 common/Out。

#include "security.h"
#include "collect.h"
#include "../common/NtApi.h"
#include "../common/Str.h"
#include "../common/Out.h"
#include <unordered_map>
#include <vector>

namespace das {

// ───────────────────────────────────────────────────────────────
//  JSON 输出:打印所有进程详情 + 高危句柄列表
// ───────────────────────────────────────────────────────────────
static void PrintSecurityJson(const std::vector<ProcDetail>& details,
                              const std::vector<HandleEntry>& handles,
                              const SecurityArgs& args)
{
    LARGE_INTEGER now;
    GetSystemTimeAsFileTime((FILETIME*)&now);
    OutFmt("{\n");
    OutFmt("  \"mode\": \"security\",\n");
    OutFmt("  \"fetched_at\": \"%s\",\n", FormatTime(now).c_str());
    OutFmt("  \"process_count\": %zu,\n", details.size());
    OutFmt("  \"handle_count\": %zu,\n", handles.size());
    OutFmt("  \"processes\": [\n");

    for (size_t i = 0; i < details.size(); ++i)
    {
        const auto& d = details[i];
        const auto& b = d.brief;
        OutFmt("    {\n");
        OutFmt("      \"pid\": %lu,\n", (unsigned long)b.pid);
        OutFmt("      \"ppid\": %lu,\n", (unsigned long)b.ppid);
        OutFmt("      \"name\": \"%s\",\n", JsonEscape(b.name).c_str());
        OutFmt("      \"image_path\": \"%s\",\n", JsonEscape(d.imagePath).c_str());
        OutFmt("      \"command_line\": \"%s\",\n", JsonEscape(d.commandLine).c_str());
        OutFmt("      \"threads_count\": %u,\n", b.threads);
        OutFmt("      \"handles_count\": %u,\n", b.handles);
        OutFmt("      \"session\": %u,\n", b.session);
        OutFmt("      \"working_set_kb\": %llu,\n", (unsigned long long)b.workingSet / 1024);
        OutFmt("      \"private_kb\": %llu,\n", (unsigned long long)b.privatePages / 1024);
        OutFmt("      \"base_priority\": %ld,\n", b.basePriority);
        OutFmt("      \"create_time\": \"%s\",\n", FormatTime(b.createTime).c_str());
        OutFmt("      \"protection\": \"%s\",\n", JsonEscape(d.protection).c_str());

        // Token 特权
        OutFmt("      \"enabled_high_risk_privileges\": [");
        for (size_t j = 0; j < d.enabledPrivs.size(); ++j)
        {
            OutFmt("\"%s\"%s", d.enabledPrivs[j].c_str(),
                (j + 1 < d.enabledPrivs.size()) ? ", " : "");
        }
        OutFmt("],\n");

        OutFmt("      \"disabled_high_risk_privileges\": [");
        for (size_t j = 0; j < d.disabledPrivs.size(); ++j)
        {
            OutFmt("\"%s\"%s", d.disabledPrivs[j].c_str(),
                (j + 1 < d.disabledPrivs.size()) ? ", " : "");
        }
        OutFmt("],\n");

        // 线程
        if (!args.noThreads && !d.threads.empty())
        {
            OutFmt("      \"threads\": [\n");
            for (size_t j = 0; j < d.threads.size(); ++j)
            {
                const auto& t = d.threads[j];
                OutFmt("        {\"tid\": %lu, \"start_addr\": \"%s\", \"win32_start\": \"%s\", \"start_module\": \"%s\"}%s\n",
                    (unsigned long)t.tid,
                    HexAddr(t.startAddress).c_str(),
                    HexAddr(t.win32StartAddress).c_str(),
                    JsonEscape(t.startModule).c_str(),
                    (j + 1 < d.threads.size()) ? "," : "");
            }
            OutFmt("      ],\n");
        }
        else
        {
            OutFmt("      \"threads\": [],\n");
        }

        // 模块
        if (!args.noModules && !d.modules.empty())
        {
            OutFmt("      \"modules\": [\n");
            for (size_t j = 0; j < d.modules.size(); ++j)
            {
                const auto& m = d.modules[j];
                OutFmt("        {\"base\": \"%s\", \"size\": %lu, \"name\": \"%s\", \"path\": \"%s\"}%s\n",
                    HexAddr(m.base).c_str(),
                    (unsigned long)m.size,
                    JsonEscape(m.name).c_str(),
                    JsonEscape(m.path).c_str(),
                    (j + 1 < d.modules.size()) ? "," : "");
            }
            OutFmt("      ],\n");
        }
        else
        {
            OutFmt("      \"modules\": [],\n");
        }

        // 可疑内存
        if (!args.noMem && !d.suspiciousMem.empty())
        {
            OutFmt("      \"suspicious_memory\": [\n");
            for (size_t j = 0; j < d.suspiciousMem.size(); ++j)
            {
                const auto& r = d.suspiciousMem[j];
                OutFmt("        {\"base\": \"%s\", \"size\": %llu, \"protect\": \"%s\", \"type\": \"%s\", \"reason\": \"%s\"}%s\n",
                    HexAddr(r.base).c_str(),
                    (unsigned long long)r.size,
                    r.protectStr.c_str(),
                    r.typeStr.c_str(),
                    r.reason.c_str(),
                    (j + 1 < d.suspiciousMem.size()) ? "," : "");
            }
            OutFmt("      ],\n");
        }
        else
        {
            OutFmt("      \"suspicious_memory\": [],\n");
        }

        // 指向本进程的句柄
        OutFmt("      \"external_handles\": [");
        bool first = true;
        for (const auto& h : handles)
        {
            if (h.targetPid != b.pid) continue;
            if (!first) OutFmt(", ");
            first = false;
            OutFmt("{\"owner_pid\": %lu, \"owner_name\": \"%s\", \"handle\": %llu, \"access\": \"%s\", \"high_risk\": %s}",
                (unsigned long)h.ownerPid,
                JsonEscape(h.ownerName).c_str(),
                (unsigned long long)h.handleValue,
                h.accessStr.c_str(),
                h.highRisk ? "true" : "false");
        }
        OutFmt("]\n");

        OutFmt("    }%s\n", (i + 1 < details.size()) ? "," : "");
    }
    OutFmt("  ],\n");

    // 全局高危句柄列表(便于 Server 快速检索)
    OutFmt("  \"high_risk_handles\": [\n");
    bool first = true;
    for (const auto& h : handles)
    {
        if (!h.highRisk) continue;
        if (!first) OutFmt(",\n");
        first = false;
        OutFmt("    {\"owner_pid\": %lu, \"owner_name\": \"%s\", \"handle\": %llu, \"target_pid\": %lu, \"access\": \"%s\"}",
            (unsigned long)h.ownerPid,
            JsonEscape(h.ownerName).c_str(),
            (unsigned long long)h.handleValue,
            (unsigned long)h.targetPid,
            h.accessStr.c_str());
    }
    OutFmt("\n  ]\n");

    OutFmt("}\n");
}

// ───────────────────────────────────────────────────────────────
//  安全采集主流程
// ───────────────────────────────────────────────────────────────
int RunSecurityMode(const SecurityArgs& args)
{
    SetConsoleOutputCP(CP_UTF8);

    // 1. 枚举所有进程的基础信息
    std::vector<ProcBrief> briefs;
    if (!EnumProcessesBrief(briefs))
    {
        OutErrorFmt("[错误] 进程枚举失败\n");
        return 1;
    }

    // 2. 构建 PID → ProcBrief 映射(O(1) 查找,替代原来的循环)
    std::unordered_map<ULONG_PTR, ProcBrief*> briefByPid;
    for (auto& b : briefs)
    {
        briefByPid[b.pid] = &b;
    }

    // 3. 确定要采集的进程列表
    std::vector<ULONG_PTR> targetPids;
    if (args.hasPid)
    {
        if (briefByPid.find(args.pid) == briefByPid.end())
        {
            OutErrorFmt("[错误] PID %lu 不存在\n", (unsigned long)args.pid);
            return 1;
        }
        targetPids.push_back(args.pid);
    }
    else
    {
        for (const auto& b : briefs)
        {
            // 跳过 Idle (PID 0),它无法 OpenProcess
            if (b.pid == 0) continue;
            targetPids.push_back(b.pid);
        }
    }

    // 4. 逐个采集详情
    std::vector<ProcDetail> details;
    details.reserve(targetPids.size());
    for (ULONG_PTR pid : targetPids)
    {
        ProcDetail d;
        auto itBrief = briefByPid.find(pid);
        if (itBrief != briefByPid.end())
        {
            d.brief = *itBrief->second;
        }

        // 打开进程(用最大权限尝试,失败降级)
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, (DWORD)pid);
        if (!hProc)
        {
            // 降级:PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
        }
        if (!hProc)
        {
            // 打不开就只记录基础信息,详情留空
            details.push_back(std::move(d));
            continue;
        }

        CollectProcessDetails(hProc, d);

        if (!args.noModules)
            CollectModules(hProc, d);

        if (!args.noThreads)
            CollectThreads(d.brief, hProc, d.modules, d);

        if (!args.noMem)
            CollectSuspiciousMemory(hProc, d.modules, d);

        CloseHandle(hProc);
        details.push_back(std::move(d));
    }

    // 5. 句柄表扫描
    std::vector<HandleEntry> handles;
    if (!args.noHandles)
    {
        ULONG_PTR handleTarget = args.handlesTarget;
        if (handleTarget == 0 && args.hasPid) handleTarget = args.pid;
        // 构建 PID → 名称映射(句柄扫描时用)
        std::unordered_map<ULONG_PTR, std::wstring> pidToName;
        pidToName.reserve(briefs.size());
        for (const auto& b : briefs)
        {
            pidToName[b.pid] = U8ToW(b.name);
        }
        CollectHandles(handleTarget, pidToName, handles);
    }

    // 6. 输出 JSON
    PrintSecurityJson(details, handles, args);
    return 0;
}

} // namespace das