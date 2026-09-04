// tree.cpp — procs 树形打印模式实现

#include "tree.h"
#include "collect.h"
#include "../common/Str.h"
#include "../common/Out.h"
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace das {

	// ───────────────────────────────────────────────────────────────
	//  树形打印上下文
	// ───────────────────────────────────────────────────────────────
	struct TreeCtx {
		const std::unordered_map<ULONG_PTR, std::vector<ULONG_PTR>>& children;
		const std::unordered_map<ULONG_PTR, ProcBrief>& byPid;
		int maxDepth;
	};

	static void PrintNode(const TreeCtx& ctx, ULONG_PTR pid,
		const std::string& indent, bool isLast,
		bool isRoot, int depth)
	{
		auto itP = ctx.byPid.find(pid);
		if (itP == ctx.byPid.end()) return;
		const auto& info = itP->second;

		const char* branch = isRoot ? "" : (isLast ? "└── " : "├── ");

		OutFmt("%s%s%lu %s  [ppid=%lu, t=%u, h=%u, ws=%llu KB, priv=%llu KB, prio=%ld, %s]\n",
			indent.c_str(), branch,
			(unsigned long)info.pid, info.name.c_str(),
			(unsigned long)info.ppid,
			info.threads,
			info.handles,
			(unsigned long long)info.workingSet / 1024,
			(unsigned long long)info.privatePages / 1024,
			info.basePriority,
			FormatTime(info.createTime).c_str());

		if (ctx.maxDepth > 0 && depth >= ctx.maxDepth)
		{
			auto itC = ctx.children.find(pid);
			if (itC != ctx.children.end() && !itC->second.empty())
			{
				std::string ellipsisIndent = indent + (isLast ? "    " : "│   ");
				OutFmt("%s└── ..., 共 %zu 个子进程\n",
					ellipsisIndent.c_str(), itC->second.size());
			}
			return;
		}

		auto itC = ctx.children.find(pid);
		if (itC == ctx.children.end()) return;
		const auto& kids = itC->second;

		std::string childIndent = isRoot ? "" : indent + (isLast ? "    " : "│   ");

		for (size_t i = 0; i < kids.size(); ++i)
		{
			bool last = (i + 1 == kids.size());
			PrintNode(ctx, kids[i], childIndent, last, false, depth + 1);
		}
	}

	int RunTreeMode(ULONG_PTR pidFilter, int maxDepth, bool jsonOut)
	{
		std::vector<ProcBrief> procs;
		if (!EnumProcessesBrief(procs))
		{
			OutErrorFmt("[错误] NtQuerySystemInformation 调用失败\n");
			return 1;
		}

		if (jsonOut)
		{
			OutFmt("{\n");
			OutFmt("  \"count\": %zu,\n", procs.size());
			LARGE_INTEGER now;
			GetSystemTimeAsFileTime((FILETIME*)&now);
			OutFmt("  \"fetched_at\": \"%s\",\n", FormatTime(now).c_str());
			OutFmt("  \"processes\": [\n");
			for (size_t i = 0; i < procs.size(); ++i)
			{
				const auto& p = procs[i];
				OutFmt("    {\"pid\": %lu, \"ppid\": %lu, \"name\": \"%s\", \"threads\": %u, \"handles\": %u, \"session\": %u, \"working_set_kb\": %llu, \"private_kb\": %llu, \"create_time\": \"%s\"}%s\n",
					(unsigned long)p.pid, (unsigned long)p.ppid,
					JsonEscape(p.name).c_str(),
					p.threads, p.handles, p.session,
					(unsigned long long)p.workingSet / 1024,
					(unsigned long long)p.privatePages / 1024,
					FormatTime(p.createTime).c_str(),
					(i + 1 < procs.size()) ? "," : "");
			}
			OutFmt("  ]\n}\n");
			return 0;
		}

		std::unordered_map<ULONG_PTR, ProcBrief> byPid;
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
		for (auto& kv : children)
			std::sort(kv.second.begin(), kv.second.end());

		ULONG totalThreads = 0;
		SIZE_T totalWs = 0;
		for (const auto& p : procs) { totalThreads += p.threads; totalWs += p.workingSet; }
		OutFmt("进程树快照: 共 %zu 个进程, %lu 个线程, 总工作集 %llu KB\n",
			procs.size(), totalThreads, (unsigned long long)totalWs / 1024);
		OutFmt("────────────────────────────────────────────────────────────────\n\n");

		TreeCtx ctx{ children, byPid, maxDepth };

		if (pidFilter != 0)
		{
			if (byPid.find(pidFilter) == byPid.end())
			{
				OutErrorFmt("[错误] PID %lu 不存在\n", (unsigned long)pidFilter);
				return 1;
			}
			PrintNode(ctx, pidFilter, "", true, true, 1);
		}
		else
		{
			std::vector<ULONG_PTR> roots;
			for (const auto& p : procs)
			{
				if (p.pid == 0) roots.insert(roots.begin(), 0);
				else if (p.pid != 0 && byPid.find(p.ppid) == byPid.end())
					roots.push_back(p.pid);
			}
			std::sort(roots.begin(), roots.end());
			roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
			for (size_t i = 0; i < roots.size(); ++i)
			{
				PrintNode(ctx, roots[i], "", true, true, 1);
				if (i + 1 < roots.size()) OutFmt("\n");
			}
		}
		return 0;
	}

} // namespace das