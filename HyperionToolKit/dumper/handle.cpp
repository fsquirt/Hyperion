// handle.cpp — dumper 一次性全系统句柄扫描 (原 HandleScanner.cpp)
//
// 实现 das::ScanHandlesForPid:
//   扫描全系统句柄表, 找出持有目标 PID 的 VM_READ (及更高危) 句柄的所有进程,
//   输出后立即返回, 不循环。
//   复用 procs/collect 的 CollectHandles / EnumProcessesBrief (namespace das),
//   原生 API 走 common/NtApi, 特权启用走 common/Priv, 输出走 common/Out。

#include "handle.h"
#include "../procs/collect.h"
#include "../common/NtApi.h"
#include "../common/Priv.h"
#include "../common/Out.h"
#include "../common/Str.h"

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdio>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

namespace das {

	// 扫描全系统句柄, 输出持有 targetPid 的 VM_READ (及更高危) 句柄的所有进程。
	// 执行一次后返回, 不循环。返回 0 表示成功, 非 0 表示错误码。
	int ScanHandlesForPid(unsigned long targetPid)
	{
		// 1. 初始化 ntdll 函数指针 (CollectHandles 依赖 g_NtQuerySystemInformation)
		if (!InitNtApi()) {
			OutLine(L"[错误] InitNtApi 失败, 无法加载 ntdll 函数指针");
			return 1;
		}

		// 2. 启用 SeDebugPrivilege (跨进程 DuplicateHandle 复制句柄需要)
		if (!EnablePrivilege(SE_DEBUG_NAME)) {
			OutLine(L"[警告] 启用 SeDebugPrivilege 失败, 可能无法扫描受保护进程的句柄");
		}

		// 3. 枚举全系统进程, 构建 pidToName 映射 (CollectHandles 用它填充 ownerName)
		std::vector<ProcBrief> procs;
		if (!EnumProcessesBrief(procs)) {
			OutLine(L"[错误] EnumProcessesBrief 失败");
			return 2;
		}
		std::unordered_map<ULONG_PTR, std::wstring> pidToName;
		pidToName.reserve(procs.size());
		for (const auto& p : procs) {
			pidToName.emplace(p.pid, U8ToW(p.name));
		}

		// 4. 全系统句柄扫描, 过滤指向 targetPid 的 Process 句柄
		std::vector<HandleEntry> out;
		CollectHandles((ULONG_PTR)targetPid, pidToName, out);

		// 5. 输出结果 (只输出 highRisk=true 的条目, 覆盖 VM_READ 及更高危权限)
		std::wostringstream title;
		title << L"句柄扫描: 持有 PID=" << targetPid << L" 的 VM_READ 句柄的进程\n";
		Out(title.str());

		Out(L"  句柄值        权限                              持有者PID  持有者进程名\n");

		int count = 0;
		for (const auto& h : out) {
			if (!h.highRisk) continue;
			std::wostringstream line;
			line << L"  0x" << std::hex << std::setw(8) << std::setfill(L'0')
				<< (unsigned long long)h.handleValue;
			line << std::dec << std::setfill(L' ') << L"  ";
			line << std::left << std::setw(30) << U8ToW(h.accessStr) << L"  ";
			line << std::right << std::setw(8) << (unsigned long long)h.ownerPid << L"  ";
			line << U8ToW(h.ownerName) << L"\n";
			Out(line.str());
			++count;
		}

		if (count == 0) {
			Out(L"  (没有进程持有目标的高危句柄)\n");
		}
		else {
			Out(L" 共 " + std::to_wstring(count) + L" 个进程持有目标的高危句柄\n");
		}

		return 0;
	}

} // namespace das