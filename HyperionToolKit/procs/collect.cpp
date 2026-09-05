// collect.cpp — procs 数据采集层实现

#include "collect.h"
#include "../common/NtApi.h"
#include "../common/Str.h"
#include <Psapi.h>
#include <vector>
#include <unordered_map>

#pragma comment(lib, "Psapi.lib")

namespace das {
	//  句柄访问掩码字符串化,只关注高危权限
	static std::string HandleAccessToStr(ULONG access, bool& highRisk)
	{
		std::string s;
		if (access & 0x0010) { s += "VM_READ|"; highRisk = true; }     // PROCESS_VM_READ
		if (access & 0x0020) { s += "VM_WRITE|"; highRisk = true; }    // PROCESS_VM_WRITE
		if (access & 0x0002) { s += "CREATE_THREAD|"; highRisk = true; } // PROCESS_CREATE_THREAD
		if (access & 0x0040) { s += "DUP_HANDLE|"; highRisk = true; }  // PROCESS_DUP_HANDLE
		if (access & 0x0008) { s += "VM_OP|"; highRisk = true; }       // PROCESS_VM_OPERATION
		if (access & 0x0400) { s += "QUERY_INFO|"; }
		if (access & 0x0800) { s += "SET_INFO|"; }
		if (access & 0x0100) { s += "TERMINATE|"; }
		if (access & 0x0001) { s += "ALL_ACCESS|"; highRisk = true; }
		if (s.empty())
		{
			char buf[32];
			snprintf(buf, sizeof(buf), "0x%08x", access);
			return buf;
		}
		if (s.back() == '|') s.pop_back();
		return s;
	}

	
	//  进程枚举,NtQuerySystemInformation
	//  顺便读出每个进程末尾紧跟的 SYSTEM_THREAD_INFORMATION_FULL 数组,
	//  避免后续每进程调一次 CreateToolhelp32Snapshot,后者每次全系统扫。
	bool EnumProcessesBrief(std::vector<ProcBrief>& out)
	{
		if (!g_NtQuerySystemInformation) return false;
		ULONG bufSize = 0x40000;
		std::vector<BYTE> buf(bufSize);
		ULONG retLen = 0;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
		for (int retry = 0; retry < 10; ++retry)
		{
			status = g_NtQuerySystemInformation(SystemProcessInformation, buf.data(), bufSize, &retLen);
			if (status == 0) break;
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				bufSize *= 2;
				if (bufSize > 0x2000000) return false;
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
			ProcBrief b;
			b.pid = (ULONG_PTR)p->UniqueProcessId;
			b.ppid = (ULONG_PTR)p->InheritedFromUniqueProcessId;
			b.threads = p->NumberOfThreads;
			b.createTime = p->CreateTime;
			b.session = p->SessionId;
			b.workingSet = p->WorkingSetSize;
			b.privatePages = p->PrivatePageCount;
			b.handles = p->HandleCount;
			b.basePriority = p->BasePriority;
			if (p->ImageName.Buffer && p->ImageName.Length > 0)
			{
				std::wstring w(p->ImageName.Buffer, p->ImageName.Length / sizeof(WCHAR));
				b.name = WToU8(w);
			}
			else
			{
				b.name = (b.pid == 0) ? "(Idle)" : "(Unknown)";
			}

			// 紧跟在 SYSTEM_PROCESS_INFORMATION_FULL 后面的是 NumberOfThreads 个
			// SYSTEM_THREAD_INFORMATION_FULL,直接读出来,免去每进程调一次
			// CreateToolhelp32Snapshot,那玩意每次全系统扫,200 进程循环 200 次 = 慢爆
			if (p->NumberOfThreads > 0)
			{
				auto pThreads = (SYSTEM_THREAD_INFORMATION_FULL*)((BYTE*)p + sizeof(SYSTEM_PROCESS_INFORMATION_FULL));
				b.threadList.reserve(p->NumberOfThreads);
				for (ULONG i = 0; i < p->NumberOfThreads; ++i)
				{
					ProcBrief::BriefThread bt;
					bt.tid = (ULONG_PTR)pThreads[i].ClientId.UniqueThread;
					bt.startAddress = (ULONG_PTR)pThreads[i].StartAddress;
					b.threadList.push_back(bt);
				}
			}

			out.push_back(std::move(b));
			if (p->NextEntryOffset == 0) break;
			p = (PSYSTEM_PROCESS_INFORMATION_FULL)((BYTE*)p + p->NextEntryOffset);
		}
		return true;
	}

	
	//  单进程详情采集:image_path / cmdline / Token特权 / PPL保护级别
	void CollectProcessDetails(HANDLE hProc, ProcDetail& d)
	{
		WCHAR pathBuf[MAX_PATH] = { 0 };
		DWORD pathLen = MAX_PATH;
		if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathLen))
		{
			d.imagePath = WToU8(pathBuf);
		}

		//  命令行,读 PEB → ProcessParameters → CommandLine 
		// x64 偏移:PEB+0x20 = ProcessParameters,Params+0x70 = CommandLine(UNICODE_STRING)
		// x86 偏移:PEB+0x10 = ProcessParameters,Params+0x40 = CommandLine
		if (g_NtQueryInformationProcess)
		{
			MY_PROCESS_BASIC_INFORMATION pbi = {};
			ULONG retLen = 0;
			if (g_NtQueryInformationProcess(hProc, ProcessBasicInformation,
				&pbi, sizeof(pbi), &retLen) == 0 && pbi.PebBaseAddress)
			{
#ifdef _WIN64
				const ULONG_PTR offParams = 0x20;
				const ULONG_PTR offCmdLine = 0x70;
#else
				const ULONG_PTR offParams = 0x10;
				const ULONG_PTR offCmdLine = 0x40;
#endif
				ULONG_PTR paramsAddr = 0;
				if (ReadProcessMemory(hProc, (LPCVOID)((ULONG_PTR)pbi.PebBaseAddress + offParams),
					&paramsAddr, sizeof(paramsAddr), nullptr) && paramsAddr)
				{
					UNICODE_STRING cmdLine = {};
					if (ReadProcessMemory(hProc, (LPCVOID)(paramsAddr + offCmdLine),
						&cmdLine, sizeof(cmdLine), nullptr) && cmdLine.Buffer && cmdLine.Length > 0)
					{
						std::wstring wcmd(cmdLine.Length / sizeof(WCHAR), L'\0');
						if (ReadProcessMemory(hProc, cmdLine.Buffer, wcmd.data(), cmdLine.Length, nullptr))
						{
							d.commandLine = WToU8(wcmd);
						}
					}
				}
			}
		}

		//  Token Privileges 
		HANDLE hToken = nullptr;
		if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
		{
			DWORD retLen = 0;
			GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &retLen);
			if (retLen > 0)
			{
				std::vector<BYTE> tokBuf(retLen);
				if (GetTokenInformation(hToken, TokenPrivileges, tokBuf.data(), retLen, &retLen))
				{
					auto privs = (TOKEN_PRIVILEGES*)tokBuf.data();
					for (DWORD i = 0; i < privs->PrivilegeCount; ++i)
					{
						LUID luid = privs->Privileges[i].Luid;
						DWORD attr = privs->Privileges[i].Attributes;
						bool enabled = (attr & SE_PRIVILEGE_ENABLED) != 0;
						WCHAR nameBuf[256] = { 0 };
						DWORD nameLen = 256;
						if (LookupPrivilegeNameW(nullptr, &luid, nameBuf, &nameLen))
						{
							std::string name = WToU8(nameBuf);
							// 只记录高危特权:SeDebug / SeLoadDriver / SeAssignPrimaryToken / SeTcb / SeCreateToken
							if (name.find("SeDebug") != std::string::npos ||
								name.find("SeLoadDriver") != std::string::npos ||
								name.find("SeAssignPrimaryToken") != std::string::npos ||
								name.find("SeTcb") != std::string::npos ||
								name.find("SeCreateToken") != std::string::npos ||
								name.find("SeBackup") != std::string::npos ||
								name.find("SeRestore") != std::string::npos)
							{
								if (enabled) d.enabledPrivs.push_back(name);
								else d.disabledPrivs.push_back(name);
							}
						}
					}
				}
			}
			CloseHandle(hToken);
		}

		//  PPL Protection Level 
		if (g_NtQueryInformationProcess)
		{
			PS_PROTECTION prot = {};
			ULONG retLen = 0;
			if (g_NtQueryInformationProcess(hProc, ProcessProtectionInformation,
				&prot, sizeof(prot), &retLen) == 0)
			{
				d.protection = ProtectionLevelToStr(prot.Level, prot.Type, prot.Signer);
			}
			else
			{
				d.protection = "QueryFailed";
			}
		}
	}

	
	//  线程采集
	void CollectThreads(const ProcBrief& brief, HANDLE hProc,
		const std::vector<ModuleInfo>& modules,
		ProcDetail& d)
	{
		d.threads.reserve(brief.threadList.size());
		for (const auto& bt : brief.threadList)
		{
			ThreadInfo t;
			t.tid = bt.tid;
			t.startAddress = bt.startAddress;  // 内核态记录的 StartAddress

			// 打开线程拿 Win32 StartAddress,抓 manual map shellcode 的字段
			// ThreadQuerySetWin32StartAddress 需要 THREAD_QUERY_INFORMATION (0x40),
			// LIMITED 不够,先试两个权限组合再降级
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
				FALSE, (DWORD)bt.tid);
			if (!hThread)
			{
				hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)bt.tid);
			}
			if (hThread && g_NtQueryInformationThread)
			{
				ULONG_PTR win32Start = 0;
				ULONG retLen = 0;
				if (g_NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress,
					&win32Start, sizeof(win32Start), &retLen) == 0)
				{
					t.win32StartAddress = win32Start;
				}
				CloseHandle(hThread);
			}

			// 判断 StartAddress 所属模块,基于已采集的模块表
			// 优先用 Win32 StartAddress,应用层入口,没有就用内核 StartAddress
			ULONG_PTR checkAddr = t.win32StartAddress ? t.win32StartAddress : t.startAddress;
			if (checkAddr && !modules.empty())
			{
				for (const auto& m : modules)
				{
					if (checkAddr >= m.base && checkAddr < m.base + m.size)
					{
						t.startModule = m.name;
						break;
					}
				}
				// 没匹配到任何模块 → 匿名内存中的 shellcode,Server 端告警
			}

			d.threads.push_back(std::move(t));
		}
	}

	
	//  模块采集:EnumProcessModulesEx, PEB Ldr 链
	void CollectModules(HANDLE hProc, ProcDetail& d)
	{
		HMODULE hMods[1024];
		DWORD cbNeeded = 0;
		if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
		{
			DWORD count = cbNeeded / sizeof(HMODULE);
			for (DWORD i = 0; i < count; ++i)
			{
				ModuleInfo m;
				MODULEINFO mi = {};
				if (GetModuleInformation(hProc, hMods[i], &mi, sizeof(mi)))
				{
					m.base = (ULONG_PTR)mi.lpBaseOfDll;
					m.size = mi.SizeOfImage;
				}
				WCHAR nameBuf[MAX_PATH] = { 0 };
				if (GetModuleBaseNameW(hProc, hMods[i], nameBuf, MAX_PATH))
				{
					m.name = WToU8(nameBuf);
				}
				WCHAR pathBuf[MAX_PATH] = { 0 };
				if (GetModuleFileNameExW(hProc, hMods[i], pathBuf, MAX_PATH))
				{
					m.path = WToU8(pathBuf);
				}
				d.modules.push_back(std::move(m));
			}
		}
	}

	
	//  可疑内存扫描:VirtualQueryEx 全地址空间找 RWX / RX-unbacked
	//  跳过 MEM_IMAGE,合法 EXE/DLL 映射,有数字签名
	void CollectSuspiciousMemory(HANDLE hProc,
		const std::vector<ModuleInfo>& modules,
		ProcDetail& d)
	{
		MEMORY_BASIC_INFORMATION mbi;
		ULONG_PTR addr = 0x10000;
		const ULONG_PTR maxAddr = 0x7FFFFFFFFFFFULL;

		while (addr < maxAddr)
		{
			if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0) break;
			addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

			if (mbi.State != MEM_COMMIT) continue;
			if (mbi.RegionSize < 0x1000) continue;

			DWORD prot = mbi.Protect;
			DWORD type = mbi.Type;
			bool isRWX = (prot & PAGE_EXECUTE_READWRITE) != 0;
			bool isExecUnbacked = ((prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ)) != 0) && (type & MEM_IMAGE) == 0;

			if (!isRWX && !isExecUnbacked) continue;

			MemRegion r;
			r.base = (ULONG_PTR)mbi.BaseAddress;
			r.size = mbi.RegionSize;
			r.protect = prot;
			r.type = type;
			r.protectStr = ProtectToStr(prot);
			r.typeStr = MemTypeToStr(type);
			r.reason = isRWX ? "RWX" : "RX-unbacked";

			// 对 RX-unbacked 检查是否落在已知模块内,有些合法 JIT 也会分配 RX
			if (isExecUnbacked && !modules.empty())
			{
				bool inModule = false;
				for (const auto& m : modules)
				{
					if (r.base >= m.base && r.base < m.base + m.size)
					{
						inModule = true;
						break;
					}
				}
				if (inModule) continue;
			}

			d.suspiciousMem.push_back(std::move(r));

			// 限制每个进程最多记录 256 个可疑区域,防止恶意进程撑爆 JSON
			if (d.suspiciousMem.size() >= 256) break;
		}
	}

	
	//  全系统句柄扫描 用 ObjectTypeIndex 过滤非 Process 句柄
	void CollectHandles(ULONG_PTR targetPid,
		const std::unordered_map<ULONG_PTR, std::wstring>& pidToName,
		std::vector<HandleEntry>& out)
	{
		if (!g_NtQuerySystemInformation) return;

		ULONG bufSize = 0x100000;  // 1MB 起步
		std::vector<BYTE> buf(bufSize);
		ULONG retLen = 0;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
		for (int retry = 0; retry < 8; ++retry)
		{
			status = g_NtQuerySystemInformation(SystemExtendedHandleInformation,
				buf.data(), bufSize, &retLen);
			if (status == 0) break;
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				bufSize *= 2;
				if (bufSize > 0x20000000) return;  // 512MB 上限
				buf.resize(bufSize);
				continue;
			}
			return;
		}
		if (status != 0) return;

		auto info = (SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
		ULONG_PTR count = info->NumberOfHandles;

		// 动态获取 "Process" 对象的 ObjectTypeIndex
		// 每次开机 ObjectTypeIndex 是固定的,运行时查一次即可。
		// 打开自己进程拿一个 Process 句柄,在句柄表里找到它,读它的 ObjectTypeIndex。
		USHORT procTypeIdx = 0;
		HANDLE hSelf = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
		if (hSelf)
		{
			ULONG_PTR selfPid = GetCurrentProcessId();
			ULONG_PTR selfHandleVal = (ULONG_PTR)hSelf;
			for (ULONG_PTR i = 0; i < count; ++i)
			{
				const auto& h = info->Handles[i];
				if (h.UniqueProcessId == selfPid && h.HandleValue == selfHandleVal)
				{
					procTypeIdx = h.ObjectTypeIndex;
					break;
				}
			}
			CloseHandle(hSelf);
		}

		for (ULONG_PTR i = 0; i < count; ++i)
		{
			const auto& h = info->Handles[i];

			// 不是 Process 类型的句柄,直接抛弃
			if (procTypeIdx != 0 && h.ObjectTypeIndex != procTypeIdx) continue;

			ULONG_PTR ownerPid = h.UniqueProcessId;

			if (targetPid != 0 && ownerPid == targetPid) continue;

			HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)ownerPid);
			if (!hOwner) continue;

			HANDLE hDup = nullptr;
			if (!DuplicateHandle(hOwner, (HANDLE)h.HandleValue,
				GetCurrentProcess(), &hDup,
				0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				CloseHandle(hOwner);
				continue;
			}
			CloseHandle(hOwner);

			DWORD targetPidForHandle = GetProcessId(hDup);
			CloseHandle(hDup);

			if (targetPidForHandle == 0) continue;
			if (targetPid != 0 && (ULONG_PTR)targetPidForHandle != targetPid) continue;

			HandleEntry he;
			he.ownerPid = ownerPid;
			he.handleValue = h.HandleValue;
			he.grantedAccess = h.GrantedAccess;
			he.targetPid = targetPidForHandle;
			he.typeName = "Process";  // 已通过 ObjectTypeIndex 过滤
			he.accessStr = HandleAccessToStr(h.GrantedAccess, he.highRisk);

			auto it = pidToName.find(ownerPid);
			if (it != pidToName.end())
				he.ownerName = WToU8(it->second);

			out.push_back(std::move(he));
		}
	}

} // namespace das