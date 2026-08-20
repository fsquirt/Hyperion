// collect.h — procs 数据采集层
//
// 进程枚举 + 详情/线程/模块/内存/句柄 5 大维度采集。
// 原 Collector.h/.cpp, 统一 das 命名空间并改用 common/NtApi + common/Str。

#pragma once
#include "DataTypes.h"
#include <unordered_map>

namespace das {

	// ───────────────────────────────────────────────────────────────
	//  进程枚举(NtQuerySystemInformation 一次拿全系统进程 + 线程)
	//  前置: 必须先调用 InitNtApi()
	// ───────────────────────────────────────────────────────────────
	bool EnumProcessesBrief(std::vector<ProcBrief>& out);

	// ───────────────────────────────────────────────────────────────
	//  单进程详情采集:image_path / cmdline / Token特权 / PPL保护级别
	//  注意:需要 hProc 已经以 PROCESS_QUERY_INFORMATION | PROCESS_VM_READ 打开
	// ───────────────────────────────────────────────────────────────
	void CollectProcessDetails(HANDLE hProc, ProcDetail& d);

	// ───────────────────────────────────────────────────────────────
	//  线程采集:复用 brief 里已有的线程列表,补 Win32 StartAddress + 模块匹配
	// ───────────────────────────────────────────────────────────────
	void CollectThreads(const ProcBrief& brief, HANDLE hProc,
		const std::vector<ModuleInfo>& modules,
		ProcDetail& d);

	// ───────────────────────────────────────────────────────────────
	//  模块采集:EnumProcessModulesEx 走 PEB Ldr 链
	// ───────────────────────────────────────────────────────────────
	void CollectModules(HANDLE hProc, ProcDetail& d);

	// ───────────────────────────────────────────────────────────────
	//  可疑内存扫描:VirtualQueryEx 全地址空间找 RWX / RX-unbacked
	// ───────────────────────────────────────────────────────────────
	void CollectSuspiciousMemory(HANDLE hProc,
		const std::vector<ModuleInfo>& modules,
		ProcDetail& d);

	// ───────────────────────────────────────────────────────────────
	//  全系统句柄扫描,过滤指向 targetPid 的强权限句柄
	//  targetPid == 0 表示扫所有进程的所有句柄(数据量大,慎用)
	//  优化:用 ObjectTypeIndex 本地过滤 99% 非 Process 句柄
	// ───────────────────────────────────────────────────────────────
	void CollectHandles(ULONG_PTR targetPid,
		const std::unordered_map<ULONG_PTR, std::wstring>& pidToName,
		std::vector<HandleEntry>& out);

} // namespace das