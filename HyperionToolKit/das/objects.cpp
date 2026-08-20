// objects.cpp — 对象管理器命名空间扫描实现 (原 ObjectScanner.cpp)
//
// 原文件自定义了一套 NT_UNICODE_STRING / NT_OBJECT_ATTRIBUTES 结构,
// 迁移后统一改用 common/NtApi.h (winternl.h) 的定义与全局函数指针。

#include "objects.h"
#include "../common/Common.h"
#include "../common/NtApi.h"
#include "../common/Out.h"
#include <windows.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace das {

	// winternl.h 未提供的目录/符号链接访问掩码
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

// STATUS_NO_MORE_ENTRIES / STATUS_BUFFER_TOO_SMALL (winternl 未定义)
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

// 把 NTSTATUS 转成可读 hex(如 0xC0000022)
	static std::wstring NtStatusHex(LONG status)
	{
		std::wostringstream ss;
		ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << (ULONG)status;
		return ss.str();
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  符号链接目标解析
	// ═══════════════════════════════════════════════════════════════════════

	// 调用者保证 linkFullPath 以反斜杠开头(如 "\GLOBAL??\C:")
	static std::wstring QuerySymbolicLinkTarget(const std::wstring& linkFullPath)
	{
		if (!g_NtOpenSymbolicLinkObject || !g_NtQuerySymbolicLinkObject) return L"";

		UNICODE_STRING ustr;
		g_RtlInitUnicodeString(&ustr, linkFullPath.c_str());

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hLink = NULL;
		LONG status = g_NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa);
		if (status < 0) {
			return L"<open failed: " + NtStatusHex(status) + L">";
		}

		std::wstring target;
		target.resize(1024);

		UNICODE_STRING targetUs = {};
		targetUs.Buffer = target.data();
		targetUs.Length = 0;
		targetUs.MaximumLength = (USHORT)(target.size() * sizeof(wchar_t));

		ULONG returnedLen = 0;
		status = g_NtQuerySymbolicLinkObject(hLink, &targetUs, &returnedLen);
		if (status == 0) {
			target.resize(targetUs.Length / sizeof(wchar_t));
			g_NtClose(hLink);
			return target;
		}

		// 缓冲区不够,用 returnedLen 重试(returnedLen 是字节数)
		if (status == STATUS_BUFFER_TOO_SMALL && returnedLen > 0) {
			target.resize(returnedLen / sizeof(wchar_t) + 1);
			targetUs.Buffer = target.data();
			targetUs.Length = 0;
			targetUs.MaximumLength = (USHORT)(target.size() * sizeof(wchar_t));

			status = g_NtQuerySymbolicLinkObject(hLink, &targetUs, &returnedLen);
			if (status == 0) {
				target.resize(targetUs.Length / sizeof(wchar_t));
				g_NtClose(hLink);
				return target;
			}
		}

		g_NtClose(hLink);
		return L"<query failed: " + NtStatusHex(status) + L">";
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  目录遍历
	// ═══════════════════════════════════════════════════════════════════════

	static bool EnumDirectory(const std::wstring& dirPath, std::vector<NtDirEntry>& entries)
	{
		entries.clear();
		if (!g_NtOpenDirectoryObject || !g_NtQueryDirectoryObject) return false;

		UNICODE_STRING ustr;
		g_RtlInitUnicodeString(&ustr, dirPath.c_str());

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hDir = NULL;
		LONG status = g_NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
		if (status < 0) {
			Out(L"[EnumDirectory] NtOpenDirectoryObject(" + dirPath +
				L") 失败: " + NtStatusHex(status) + L"\n");
			return false;
		}

		// OBJECT_DIRECTORY_INFORMATION = { UNICODE_STRING Name; UNICODE_STRING TypeName; }
		std::vector<BYTE> buffer(4096);
		ULONG context = 0;
		bool firstCall = true;

		while (true) {
			ULONG returnLength = 0;
			status = g_NtQueryDirectoryObject(
				hDir, buffer.data(), (ULONG)buffer.size(),
				TRUE /*ReturnSingleEntry*/, firstCall /*RestartScan*/,
				&context, &returnLength);

			if (status == 0) {
				BYTE* p = buffer.data();
				UNICODE_STRING* pName = (UNICODE_STRING*)p;
				UNICODE_STRING* pType = (UNICODE_STRING*)(p + sizeof(UNICODE_STRING));

				if (pName->Length == 0 || pName->Buffer == NULL) break;

				NtDirEntry e;
				e.name.assign(pName->Buffer, pName->Length / sizeof(wchar_t));
				if (pType->Length > 0 && pType->Buffer) {
					e.typeName.assign(pType->Buffer, pType->Length / sizeof(wchar_t));
				}

				if (_wcsicmp(e.typeName.c_str(), L"SymbolicLink") == 0) {
					std::wstring fullPath = dirPath;
					if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
					fullPath += e.name;
					e.linkTarget = QuerySymbolicLinkTarget(fullPath);
				}

				entries.push_back(std::move(e));
				firstCall = false;
				continue;
			}

			if (status == STATUS_NO_MORE_ENTRIES || status == 0x00000105) {
				break;
			}

			if (status == STATUS_BUFFER_TOO_SMALL) {
				buffer.resize(buffer.size() * 2);
				continue;
			}

			Out(L"[EnumDirectory] NtQueryDirectoryObject(" + dirPath +
				L") 失败: " + NtStatusHex(status) + L"\n");
			break;
		}

		g_NtClose(hDir);
		return !entries.empty();
	}

	// 把单条目录项格式化为一行输出
	static std::wstring FormatDirEntry(const NtDirEntry& e, size_t nameWidth, size_t typeWidth)
	{
		std::wostringstream ss;
		ss << L"  " << std::left << std::setw((std::streamsize)nameWidth) << e.name
			<< L" " << std::left << std::setw((std::streamsize)typeWidth) << e.typeName;
		if (!e.linkTarget.empty()) {
			ss << L"  -> " << e.linkTarget;
		}
		ss << L"\n";
		return ss.str();
	}

	// depth 是内部递归参数,对外不暴露
	static size_t ScanAndPrintDirectoryImpl(const std::wstring& dirPath, int maxDepth, int depth)
	{
		std::vector<NtDirEntry> entries;
		if (!EnumDirectory(dirPath, entries)) {
			return 0;
		}

		size_t nameWidth = 4;  // "Name"
		size_t typeWidth = 4;  // "Type"
		for (const auto& e : entries) {
			if (e.name.size() > nameWidth) nameWidth = e.name.size();
			if (e.typeName.size() > typeWidth) typeWidth = e.typeName.size();
		}
		if (nameWidth > 60) nameWidth = 60;
		if (typeWidth > 20) typeWidth = 20;

		std::wostringstream title;
		title << L"\n━━━ " << dirPath << L" ━━━ (共 " << entries.size() << L" 项)\n";
		Out(title.str());

		Out(FormatDirEntry({ L"Name", L"Type", L"" }, nameWidth, typeWidth));
		Out(FormatDirEntry({ std::wstring(nameWidth, L'-'), std::wstring(typeWidth, L'-'), L"" }, nameWidth, typeWidth));

		// 排序:SymbolicLink 优先(用户最关心),再按名字
		std::sort(entries.begin(), entries.end(), [](const NtDirEntry& a, const NtDirEntry& b) {
			bool aSym = _wcsicmp(a.typeName.c_str(), L"SymbolicLink") == 0;
			bool bSym = _wcsicmp(b.typeName.c_str(), L"SymbolicLink") == 0;
			if (aSym != bSym) return aSym;
			return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
			});

		for (const auto& e : entries) {
			Out(FormatDirEntry(e, nameWidth, typeWidth));

			// 递归子目录(限制深度)
			if (depth < maxDepth &&
				_wcsicmp(e.typeName.c_str(), L"Directory") == 0 &&
				_wcsicmp(e.name.c_str(), L".") != 0 &&
				_wcsicmp(e.name.c_str(), L"..") != 0) {
				std::wstring sub = dirPath;
				if (sub.back() != L'\\') sub += L'\\';
				sub += e.name;
				ScanAndPrintDirectoryImpl(sub, maxDepth, depth + 1);
			}
		}

		return entries.size();
	}

	size_t ScanAndPrintDirectory(const std::wstring& dirPath, int maxDepth)
	{
		return ScanAndPrintDirectoryImpl(dirPath, maxDepth, 0);
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  主入口
	// ═══════════════════════════════════════════════════════════════════════

	int ScanObjectNamespaces(const std::vector<std::wstring>& dirs)
	{
		if (!InitNtApi()) {
			OutLine(L"初始化 NTAPI 失败:无法加载 ntdll.dll 中的函数");
			return 1;
		}

		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  对象管理器命名空间扫描(NTAPI 直查,无需驱动)\n");
		Out(L"  用途:识别暴露符号链接的第三方 WHQL 驱动 → 附着候选\n");
		Out(L"═══════════════════════════════════════════════════════\n");

		size_t total = 0;
		for (const auto& dir : dirs) {
			total += ScanAndPrintDirectory(dir);
		}

		Out(L"\n═══════════════════════════════════════════════════════\n");
		Out(L"扫描完成,共 " + std::to_wstring(total) + L" 个对象\n");
		Out(L"═══════════════════════════════════════════════════════\n");
		return 0;
	}

} // namespace das