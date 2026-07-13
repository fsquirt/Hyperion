// StackResolver.cpp — 调用栈符号化
//
// 拆分自 CommsMonitor.cpp:
//   - BuildModuleTable: 建立目标进程模块表 (EnumProcessModules + GetModuleInformation)
//   - CollectStackModules: 从 ETW 事件 ExtendedData 收集调用栈命中的业务模块 (排除系统目录)

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "StackResolver.h"
#include "Common.h"

#include <windows.h>
#include <psapi.h>
#include <evntcons.h>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_set>

#pragma comment(lib, "psapi.lib")

#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE32
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE32 5
#endif
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE64
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE64 6
#endif

namespace das {

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
//  工具: 建立目标进程模块表 (用于调用栈地址符号化)
// ═══════════════════════════════════════════════════════════════════════

std::vector<ModuleRange> BuildModuleTable(unsigned long long pid)
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

std::vector<StackModuleInfo> CollectStackModules(
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

} // namespace das
