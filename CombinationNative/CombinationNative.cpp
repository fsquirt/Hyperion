// CombinationNative.cpp — DLL 主入口 + 导出包装函数
//
// 整合 DriverAttachSelector / HeuristicDumper / ProcessTreeSnapshot
// 三个子项目的核心功能, 统一暴露为 extern "C" 接口。
//
// 编译为 DLL 后可供 C# (MSAFReverseAgent) 或其他调用方
// LoadLibrary + GetProcAddress 调用。

#define COMBINATION_NATIVE_EXPORTS

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

// DriverAttachSelector 头
#include "Common.h"
#include "DriverClassify.h"
#include "LoadedDrivers.h"
#include "ObjectScanner.h"
#include "KernelComms.h"
#include "IatScanner.h"
#include "EtwConsumer.h"

// HeuristicDumper 头
#include "CommsMonitor.h"
#include "MonitorTypes.h"
#include "HandleScanner.h"

// ProcessTreeSnapshot 头
#include "NativeApi.h"
#include "DataTypes.h"
#include "TreePrinter.h"
#include "JsonWriter.h"

#include "CombinationNative.h"

// ═══════════════════════════════════════════════════════════════════════
//  DllMain
// ═══════════════════════════════════════════════════════════════════════

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ═══════════════════════════════════════════════════════════════════════
//  辅助: 逗号分隔的宽字符串 → vector<wstring>
// ═══════════════════════════════════════════════════════════════════════

static std::vector<std::wstring> SplitWString(const wchar_t* input, wchar_t delim)
{
    std::vector<std::wstring> result;
    if (!input || !*input) return result;
    std::wistringstream stream(input);
    std::wstring token;
    while (std::getline(stream, token, delim)) {
        if (!token.empty()) {
            result.push_back(token);
        }
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  初始化
// ═══════════════════════════════════════════════════════════════════════

COMB_API int CombNative_InitNtdll()
{
    return InitNtdll() ? 0 : 1;
}

// ═══════════════════════════════════════════════════════════════════════
//  DriverAttachSelector 导出包装
// ═══════════════════════════════════════════════════════════════════════

COMB_API int CombNative_RunKernelScan()
{
    // 这些函数定义在 DriverAttachSelector\Main.cpp 中 (static 函数)
    // 通过 DriverAttachSelector 的 Main.cpp 编译进来后可以直接调用
    extern int RunKernelScan();
    return RunKernelScan();
}

COMB_API int CombNative_RunScanAndClassify()
{
    extern int RunScanAndClassify();
    return RunScanAndClassify();
}

COMB_API int CombNative_RunScanAndEnumDevices()
{
    extern int RunScanAndEnumDevices();
    return RunScanAndEnumDevices();
}

COMB_API int CombNative_RunEnumDevices(const wchar_t* driverName)
{
    extern int RunEnumDevices(const std::wstring&);
    return RunEnumDevices(driverName ? driverName : L"");
}

COMB_API int CombNative_RunScanIAT(const wchar_t* filePath)
{
    extern int RunScanIAT(const std::wstring&);
    return RunScanIAT(filePath ? filePath : L"");
}

COMB_API int CombNative_RunAttachDevice(const wchar_t* devicePath)
{
    extern int RunAttachDevice(const std::wstring&);
    return RunAttachDevice(devicePath ? devicePath : L"");
}

COMB_API int CombNative_RunUnattachDevice(const wchar_t* arg)
{
    extern int RunUnattachDevice(const std::wstring&);
    return RunUnattachDevice(arg ? arg : L"");
}

COMB_API int CombNative_RunListAttachments()
{
    extern int RunListAttachments();
    return RunListAttachments();
}

COMB_API int CombNative_RunEnumAndClassify()
{
    extern int RunEnumAndClassify();
    return RunEnumAndClassify();
}

COMB_API int CombNative_ScanObjectNamespaces(const wchar_t* dirs)
{
    auto dirList = SplitWString(dirs, L',');
    return das::ScanObjectNamespaces(dirList);
}

COMB_API int CombNative_RunEtwConsumer(unsigned int durationSec, const wchar_t* etlPath)
{
    return das::RunEtwConsumer(durationSec, etlPath ? etlPath : L"");
}

// ═══════════════════════════════════════════════════════════════════════
//  HeuristicDumper 导出包装
// ═══════════════════════════════════════════════════════════════════════

COMB_API int CombNative_RunCommsMonitor(unsigned int durationSec, int enableJson)
{
    das::MonitorOptions options;
    options.durationSec = durationSec;
    options.enableJson = (enableJson != 0);
    return das::RunCommsMonitor(options);
}

COMB_API int CombNative_ScanHandlesForPid(unsigned long targetPid)
{
    return das::ScanHandlesForPid(targetPid);
}

// ═══════════════════════════════════════════════════════════════════════
//  ProcessTreeSnapshot 导出包装
// ═══════════════════════════════════════════════════════════════════════

COMB_API int CombNative_RunTreeMode(unsigned long long pid, int maxDepth, int jsonOut)
{
    return RunTreeMode(pid, maxDepth, jsonOut != 0);
}

COMB_API int CombNative_RunSecurityMode(unsigned long long pid, unsigned int flags)
{
    SecurityArgs args;
    args.pid = pid;
    args.hasPid = (pid != 0);
    args.noHandles  = (flags & 0x01) != 0;
    args.noMem      = (flags & 0x02) != 0;
    args.noThreads  = (flags & 0x04) != 0;
    args.noModules  = (flags & 0x08) != 0;
    args.noToken    = (flags & 0x10) != 0;
    return RunSecurityMode(args);
}