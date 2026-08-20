// NtApi.cpp — ntdll 未文档化 API 加载实现

#include "NtApi.h"

namespace das {

	PFN_NtQuerySystemInformation      g_NtQuerySystemInformation = nullptr;
	PFN_NtQueryInformationProcess     g_NtQueryInformationProcess = nullptr;
	PFN_NtQueryInformationThread      g_NtQueryInformationThread = nullptr;
	PFN_NtQueryObject                 g_NtQueryObject = nullptr;
	PFN_NtOpenDirectoryObject         g_NtOpenDirectoryObject = nullptr;
	PFN_NtQueryDirectoryObject        g_NtQueryDirectoryObject = nullptr;
	PFN_NtOpenSymbolicLinkObject      g_NtOpenSymbolicLinkObject = nullptr;
	PFN_NtQuerySymbolicLinkObject     g_NtQuerySymbolicLinkObject = nullptr;
	PFN_RtlInitUnicodeString          g_RtlInitUnicodeString = nullptr;
	PFN_NtClose                       g_NtClose = nullptr;

	bool InitNtApi()
	{
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		if (!hNtdll) return false;

		g_NtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
		g_NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		g_NtQueryInformationThread = (PFN_NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
		g_NtQueryObject = (PFN_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
		g_NtOpenDirectoryObject = (PFN_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
		g_NtQueryDirectoryObject = (PFN_NtQueryDirectoryObject)GetProcAddress(hNtdll, "NtQueryDirectoryObject");
		g_NtOpenSymbolicLinkObject = (PFN_NtOpenSymbolicLinkObject)GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
		g_NtQuerySymbolicLinkObject = (PFN_NtQuerySymbolicLinkObject)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
		g_RtlInitUnicodeString = (PFN_RtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		g_NtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");

		return g_NtQuerySystemInformation && g_NtQueryInformationProcess
			&& g_NtQueryInformationThread && g_NtQueryObject
			&& g_NtOpenDirectoryObject && g_NtQueryDirectoryObject
			&& g_NtOpenSymbolicLinkObject && g_NtQuerySymbolicLinkObject
			&& g_RtlInitUnicodeString && g_NtClose;
	}

} // namespace das