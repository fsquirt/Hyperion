// CombinationNativeData.cpp — 数据导出函数实现
//
// 调用三个子项目的底层数据采集函数 (无输出版本),
// 将 C++ 数据结构转换为扁平化 C 结构体, 返回 malloc 分配的缓冲区。
//
// 缓冲区布局: [CbnResultHeader] [Entry0] [Entry1] ... [EntryN-1]
// 调用方必须用 CombNative_FreeBuffer 释放。

#define COMBINATION_NATIVE_EXPORTS

// 避免 Windows.h 的 min/max 宏污染 std::min/std::max
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "CombinationNativeData.h"

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <thread>

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
#include "PathTracker.h"

// ProcessTreeSnapshot 头
#include "NativeApi.h"
#include "DataTypes.h"
#include "Collector.h"
#include "StringUtils.h"

// ═══════════════════════════════════════════════════════════════════════
//  辅助函数
// ═══════════════════════════════════════════════════════════════════════

namespace {

// 宽字符串截断拷贝到定长 wchar_t 数组
void WcsCpyTrunc(wchar_t* dst, size_t dstCount, const std::wstring& src) {
    if (dstCount == 0) return;
    size_t n = src.size();
    if (n >= dstCount) n = dstCount - 1;
    std::wmemcpy(dst, src.c_str(), n);
    dst[n] = L'\0';
}

// 窄字符串截断拷贝到定长 char 数组 (UTF-8)
void StrCpyTrunc(char* dst, size_t dstCount, const std::string& src) {
    if (dstCount == 0) return;
    size_t n = src.size();
    if (n >= dstCount) n = dstCount - 1;
    std::memcpy(dst, src.c_str(), n);
    dst[n] = '\0';
}

void StrCpyTrunc(char* dst, size_t dstCount, const std::wstring& src) {
    if (dstCount == 0) return;
    std::string u8;
    int cb = WideCharToMultiByte(CP_UTF8, 0, src.c_str(), (int)src.size(),
                                 nullptr, 0, nullptr, nullptr);
    u8.resize(cb);
    WideCharToMultiByte(CP_UTF8, 0, src.c_str(), (int)src.size(),
                        u8.data(), cb, nullptr, nullptr);
    StrCpyTrunc(dst, dstCount, u8);
}

// 将内核模式路径转换为 Win32 可访问路径
//   \SystemRoot\...        → C:\Windows\...
//   \??\C:\...             → C:\...
//   \Device\HarddiskVolumeN\...  → 尝试用 QueryDosDevice 反查盘符
std::wstring NtPathToWin32(const std::wstring& ntPath) {
    if (ntPath.empty()) return ntPath;

    // \SystemRoot\ → %SystemRoot% 环境变量
    if (ntPath.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t sysRoot[MAX_PATH] = {0};
        DWORD len = GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            return std::wstring(sysRoot) + ntPath.substr(11); // 11 = strlen("\\SystemRoot")
        }
        // 退而求其次用硬编码
        return L"C:\\Windows" + ntPath.substr(11);
    }

    // \??\C:\... → C:\...
    if (ntPath.rfind(L"\\??\\", 0) == 0) {
        return ntPath.substr(4);
    }
    // \\?\C:\... → C:\...
    if (ntPath.rfind(L"\\\\?\\", 0) == 0) {
        return ntPath.substr(4);
    }

    // \Device\HarddiskVolumeN\... → 尝试反查盘符
    if (ntPath.rfind(L"\\Device\\HarddiskVolume", 0) == 0) {
        // 找到下一个 '\' 的位置
        size_t slash = ntPath.find(L'\\', 7); // 7 = strlen("\\Device")
        if (slash != std::wstring::npos) {
            std::wstring volume = ntPath.substr(0, slash);  // \Device\HarddiskVolumeN
            std::wstring rest   = ntPath.substr(slash);      // \rest...

            // 遍历 A-Z 盘符, 查找哪个盘符的 DosDevice 名匹配
            wchar_t drive[] = L"C:\\";
            for (wchar_t c = L'A'; c <= L'Z'; c++) {
                drive[0] = c;
                wchar_t target[MAX_PATH] = {0};
                if (QueryDosDeviceW(drive, target, MAX_PATH) > 0) {
                    if (_wcsicmp(target, volume.c_str()) == 0) {
                        return std::wstring(drive) + rest.substr(1);
                    }
                }
            }
        }
    }

    // 不认识的原样返回
    return ntPath;
}


// 分配缓冲区并填充 header
// 返回缓冲区指针, *outSize 写入总字节数
void* AllocBuffer(uint32_t commandId, uint32_t entryCount, uint32_t entrySize,
                  uint32_t* outSize) {
    uint32_t total = sizeof(CbnResultHeader) + entryCount * entrySize;
    void* buf = std::malloc(total);
    if (!buf) {
        if (outSize) *outSize = 0;
        return nullptr;
    }
    std::memset(buf, 0, total);
    auto* hdr = static_cast<CbnResultHeader*>(buf);
    hdr->errorCode  = 0;
    hdr->commandId  = commandId;
    hdr->entryCount = entryCount;
    hdr->entrySize  = entrySize;
    hdr->totalSize  = total;
    hdr->errorMessage[0] = L'\0';
    if (outSize) *outSize = total;
    return buf;
}

// 分配错误缓冲区
void* AllocErrorBuffer(uint32_t commandId, int32_t errorCode,
                       const std::wstring& message, uint32_t* outSize) {
    void* buf = AllocBuffer(commandId, 0, 0, outSize);
    if (!buf) return nullptr;
    auto* hdr = static_cast<CbnResultHeader*>(buf);
    hdr->errorCode = errorCode;
    WcsCpyTrunc(hdr->errorMessage, CBN_MAX_REASON, message);
    return buf;
}

// 获取 entry 数组的起始地址 (跳过 header)
template<typename T>
T* EntriesAfter(CbnResultHeader* hdr) {
    return reinterpret_cast<T*>(reinterpret_cast<char*>(hdr) + sizeof(CbnResultHeader));
}

// ── 扁平化转换函数 ──

void FillSigner(CbnSignerInfo& out, const das::SignerInfo& in) {
    WcsCpyTrunc(out.subject, CBN_MAX_SUBJECT, in.subject);
    WcsCpyTrunc(out.issuer,  CBN_MAX_SUBJECT, in.issuer);
    out.isMicrosoft = in.isMicrosoft ? 1 : 0;
    out.isWhql      = in.isWhql      ? 1 : 0;
    out.isVendor    = in.isVendor    ? 1 : 0;
}

void FillClassifyEntry(CbnClassifyEntry& out,
                       const std::wstring& fileName,
                       const std::wstring& filePath,
                       const std::wstring& driverObjectName,
                       const das::ClassifyResult& result) {
    WcsCpyTrunc(out.fileName,         CBN_MAX_NAME, fileName);
    WcsCpyTrunc(out.filePath,         CBN_MAX_PATH, filePath);
    WcsCpyTrunc(out.driverObjectName, CBN_MAX_NAME, driverObjectName);
    out.klass = static_cast<int32_t>(result.klass);
    out.signerCount = static_cast<int32_t>(
        std::min(result.signers.size(), static_cast<size_t>(CBN_MAX_SIGNERS)));
    for (int32_t i = 0; i < out.signerCount; ++i) {
        FillSigner(out.signers[i], result.signers[i]);
    }
    WcsCpyTrunc(out.vendorName,  CBN_MAX_STR,    result.vendorName);
    WcsCpyTrunc(out.errorReason, CBN_MAX_REASON, result.errorReason);
    out.hasCatalog  = result.hasCatalog  ? 1 : 0;
    out.hasEmbedded = result.hasEmbedded ? 1 : 0;
}

void FillIatEntry(CbnIatEntry& out, const das::IatEntry& in) {
    StrCpyTrunc(out.dllName, CBN_MAX_NAME, in.dllName);
    out.apiCount = static_cast<int32_t>(
        std::min(in.apis.size(), static_cast<size_t>(CBN_MAX_IAT_APIS)));
    for (int32_t i = 0; i < out.apiCount; ++i) {
        StrCpyTrunc(out.apis[i].name, CBN_MAX_NAME, in.apis[i]);
        out.apis[i].isDangerous = 0;  // 当前 IatScanner 不区分高危
    }
}

void FillProcBrief(CbnProcBrief& out, const ProcBrief& in) {
    out.pid          = in.pid;
    out.ppid         = in.ppid;
    StrCpyTrunc(out.name, CBN_MAX_NAME, in.name);
    out.threads      = in.threads;
    out.createTime   = in.createTime.QuadPart;
    out.session      = in.session;
    out.workingSet   = in.workingSet;
    out.privatePages = in.privatePages;
    out.handles      = in.handles;
    out.basePriority = in.basePriority;
    out.threadCount  = static_cast<int32_t>(
        std::min(in.threadList.size(), static_cast<size_t>(CBN_MAX_THREADS)));
    for (int32_t i = 0; i < out.threadCount; ++i) {
        out.threadList[i].tid          = in.threadList[i].tid;
        out.threadList[i].startAddress = in.threadList[i].startAddress;
    }
}

void FillThreadInfo(CbnThreadInfo& out, const ThreadInfo& in) {
    out.tid                = in.tid;
    out.startAddress       = in.startAddress;
    out.win32StartAddress  = in.win32StartAddress;
    out.suspendCount       = in.suspendCount;
    StrCpyTrunc(out.startModule, CBN_MAX_PATH, in.startModule);
    out.isSuspended        = in.isSuspended ? 1 : 0;
}

void FillModuleInfo(CbnModuleInfo& out, const ModuleInfo& in) {
    out.base = in.base;
    out.size = in.size;
    StrCpyTrunc(out.name, CBN_MAX_NAME, in.name);
    StrCpyTrunc(out.path, CBN_MAX_PATH, in.path);
}

void FillMemRegion(CbnMemRegion& out, const MemRegion& in) {
    out.base   = in.base;
    out.size   = in.size;
    out.protect= in.protect;
    out.type   = in.type;
    StrCpyTrunc(out.protectStr, 32, in.protectStr);
    StrCpyTrunc(out.typeStr,    32, in.typeStr);
    StrCpyTrunc(out.reason,     32, in.reason);
}

void FillHandleEntry(CbnHandleEntry& out, const HandleEntry& in) {
    out.ownerPid      = in.ownerPid;
    WcsCpyTrunc(out.ownerName, CBN_MAX_NAME, U8ToW(in.ownerName));
    out.handleValue   = in.handleValue;
    out.grantedAccess = in.grantedAccess;
    WcsCpyTrunc(out.accessStr, CBN_MAX_STR,  U8ToW(in.accessStr));
    out.targetPid     = in.targetPid;
    WcsCpyTrunc(out.typeName,  CBN_MAX_NAME, U8ToW(in.typeName));
    out.highRisk      = in.highRisk ? 1 : 0;
}

void FillProcDetail(CbnProcDetail& out, const ProcDetail& in) {
    FillProcBrief(out.brief, in.brief);

    StrCpyTrunc(out.imagePath,     CBN_MAX_PATH, in.imagePath);
    StrCpyTrunc(out.commandLine,   512,          in.commandLine);
    StrCpyTrunc(out.protection,    32,           in.protection);
    out.pplBroken = in.pplBroken ? 1 : 0;

    // 特权
    out.enabledPrivCount = static_cast<int32_t>(
        std::min(in.enabledPrivs.size(), static_cast<size_t>(CBN_MAX_PRIVS)));
    for (int32_t i = 0; i < out.enabledPrivCount; ++i)
        StrCpyTrunc(out.enabledPrivs[i], 48, in.enabledPrivs[i]);

    out.disabledPrivCount = static_cast<int32_t>(
        std::min(in.disabledPrivs.size(), static_cast<size_t>(CBN_MAX_PRIVS)));
    for (int32_t i = 0; i < out.disabledPrivCount; ++i)
        StrCpyTrunc(out.disabledPrivs[i], 48, in.disabledPrivs[i]);

    // 线程详情
    out.threadInfoCount = static_cast<int32_t>(
        std::min(in.threads.size(), static_cast<size_t>(CBN_MAX_THREADS)));
    for (int32_t i = 0; i < out.threadInfoCount; ++i)
        FillThreadInfo(out.threadInfos[i], in.threads[i]);

    // 模块
    out.moduleCount = static_cast<int32_t>(
        std::min(in.modules.size(), static_cast<size_t>(CBN_MAX_MODULES)));
    for (int32_t i = 0; i < out.moduleCount; ++i)
        FillModuleInfo(out.modules[i], in.modules[i]);

    // 可疑内存
    out.memRegionCount = static_cast<int32_t>(
        std::min(in.suspiciousMem.size(), static_cast<size_t>(CBN_MAX_MEM_REGIONS)));
    for (int32_t i = 0; i < out.memRegionCount; ++i)
        FillMemRegion(out.memRegions[i], in.suspiciousMem[i]);

    // 句柄
    out.handleCount = static_cast<int32_t>(
        std::min(in.handles.size(), static_cast<size_t>(CBN_MAX_HANDLES)));
    for (int32_t i = 0; i < out.handleCount; ++i)
        FillHandleEntry(out.handles[i], in.handles[i]);
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  公共: 释放缓冲区
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void CombNative_FreeBuffer(void* buffer) {
    std::free(buffer);
}

// ═══════════════════════════════════════════════════════════════════════
//  2. kernel-scan → LoadedDriverEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetKernelScanData(uint32_t* outSize) {
    void* hDevice = das::OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return AllocErrorBuffer(2, 1, L"无法打开 KernelService 设备", outSize);
    }

    std::vector<das::LoadedDriverEntry> drivers;
    bool ok = das::ScanLoadedDriversViaKernel(hDevice, CBN_MAX_DRIVERS, drivers);
    das::CloseKernelService(hDevice);

    if (!ok) {
        return AllocErrorBuffer(2, 2, L"ScanLoadedDriversViaKernel 失败", outSize);
    }

    uint32_t count = static_cast<uint32_t>(
        std::min(drivers.size(), static_cast<size_t>(CBN_MAX_DRIVERS)));
    void* buf = AllocBuffer(2, count, sizeof(das::LoadedDriverEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<das::LoadedDriverEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        entries[i] = drivers[i];  // LoadedDriverEntry 已是 POD, 直接拷贝
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  3. scan-classify → CbnClassifyEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetScanAndClassifyData(uint32_t* outSize) {
    // 1. 内核模式扫描已加载驱动
    void* hDevice = das::OpenKernelService();
    std::vector<das::LoadedDriverEntry> kernelDrivers;
    bool useKernel = false;
    if (hDevice != INVALID_HANDLE_VALUE) {
        if (das::ScanLoadedDriversViaKernel(hDevice, CBN_MAX_DRIVERS, kernelDrivers)) {
            useKernel = true;
        }
        das::CloseKernelService(hDevice);
    }

    // 2. 如果内核模式失败, 退回 PSAPI 模式
    std::vector<das::LoadedDriver> psapiDrivers;
    if (!useKernel) {
        if (!das::EnumLoadedDrivers(psapiDrivers)) {
            return AllocErrorBuffer(3, 1, L"EnumLoadedDrivers 失败", outSize);
        }
    }

    uint32_t total = useKernel
        ? static_cast<uint32_t>(std::min(kernelDrivers.size(), static_cast<size_t>(CBN_MAX_DRIVERS)))
        : static_cast<uint32_t>(std::min(psapiDrivers.size(),  static_cast<size_t>(CBN_MAX_DRIVERS)));

    void* buf = AllocBuffer(3, total, sizeof(CbnClassifyEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnClassifyEntry>(static_cast<CbnResultHeader*>(buf));

    for (uint32_t i = 0; i < total; ++i) {
        std::wstring fileName, filePath;
        if (useKernel) {
            fileName = kernelDrivers[i].ModuleName;
            filePath = NtPathToWin32(kernelDrivers[i].FullPath);
        } else {
            fileName = psapiDrivers[i].name;
            filePath = psapiDrivers[i].path;
        }

        if (filePath.empty() ||
            GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // 无路径/文件不存在
            std::wstring name = fileName;
            das::ClassifyResult result;
            result.klass = das::DriverClass::UNTRUSTED;
            result.errorReason = L"无路径或文件不存在";
            FillClassifyEntry(entries[i], name, filePath, L"", result);
            continue;
        }

        das::ClassifyResult result = das::ClassifyDriver(filePath);
        FillClassifyEntry(entries[i], fileName, filePath, L"", result);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  4. scan-enum-devices → CbnClassifyEntry[] (THIRD_PARTY_WHQL 驱动 + 设备列表)
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetScanAndEnumDevicesData(uint32_t* outSize) {
    // 复用 scan-classify 的逻辑, 但只保留 THIRD_PARTY_WHQL 和 UNTRUSTED 的条目
    void* classifyBuf = CombNative_GetScanAndClassifyData(outSize);
    if (!classifyBuf) return nullptr;

    auto* hdr = static_cast<CbnResultHeader*>(classifyBuf);
    if (hdr->errorCode != 0) {
        return classifyBuf;  // 返回错误缓冲区
    }

    auto* srcEntries = EntriesAfter<CbnClassifyEntry>(hdr);
    uint32_t srcCount = hdr->entryCount;

    // 筛选 THIRD_PARTY_WHQL (klass == 2) 和 UNTRUSTED (klass == 3)
    std::vector<CbnClassifyEntry> filtered;
    for (uint32_t i = 0; i < srcCount; ++i) {
        if (srcEntries[i].klass == 2 || srcEntries[i].klass == 3) {
            filtered.push_back(srcEntries[i]);
        }
    }

    std::free(classifyBuf);

    uint32_t count = static_cast<uint32_t>(
        std::min(filtered.size(), static_cast<size_t>(CBN_MAX_DRIVERS)));
    void* buf = AllocBuffer(4, count, sizeof(CbnClassifyEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnClassifyEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        entries[i] = filtered[i];
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  5. enum-devices → DeviceEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetEnumDevicesData(const wchar_t* driverName, uint32_t* outSize) {
    std::wstring name = driverName ? driverName : L"";

    void* hDevice = das::OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return AllocErrorBuffer(5, 1, L"无法打开 KernelService 设备", outSize);
    }

    std::vector<das::DeviceEntry> devices;
    std::wstring foundPath;
    bool ok = das::EnumDriverDevices(hDevice, name, CBN_MAX_DEVICES, devices, &foundPath);
    das::CloseKernelService(hDevice);

    if (!ok) {
        return AllocErrorBuffer(5, 2, L"EnumDriverDevices 失败", outSize);
    }

    uint32_t count = static_cast<uint32_t>(
        std::min(devices.size(), static_cast<size_t>(CBN_MAX_DEVICES)));
    void* buf = AllocBuffer(5, count, sizeof(das::DeviceEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<das::DeviceEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        entries[i] = devices[i];  // DeviceEntry 已是 POD
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  6. scan-iat → CbnIatResult
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetScanIatData(const wchar_t* filePath, uint32_t* outSize) {
    std::wstring path = filePath ? filePath : L"";

    std::vector<das::IatEntry> iat;
    std::wstring errorReason;
    if (!das::ScanIat(path, iat, errorReason)) {
        return AllocErrorBuffer(6, 1, errorReason, outSize);
    }

    void* buf = AllocBuffer(6, 1, sizeof(CbnIatResult), outSize);
    if (!buf) return nullptr;

    auto* result = EntriesAfter<CbnIatResult>(static_cast<CbnResultHeader*>(buf));
    std::memset(result, 0, sizeof(CbnIatResult));

    WcsCpyTrunc(result->filePath, CBN_MAX_PATH, path);
    result->dllCount = static_cast<int32_t>(
        std::min(iat.size(), static_cast<size_t>(CBN_MAX_IAT_DLLS)));

    int32_t totalApis = 0;
    for (int32_t i = 0; i < result->dllCount; ++i) {
        FillIatEntry(result->entries[i], iat[i]);
        totalApis += result->entries[i].apiCount;
    }
    result->totalApiCount = totalApis;
    result->dangerousApiCount = 0;  // 当前不区分

    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  7. attach → CbnAttachResult
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetAttachData(const wchar_t* devicePath, uint32_t* outSize) {
    std::wstring path = devicePath ? devicePath : L"";
    if (path.empty() || path[0] != L'\\') {
        return AllocErrorBuffer(7, 1, L"设备路径必须以 \\ 开头", outSize);
    }

    void* hDevice = das::OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return AllocErrorBuffer(7, 2, L"无法打开 KernelService 设备", outSize);
    }

    unsigned long attachId = 0;
    unsigned long long filterAddr = 0, lowerAddr = 0;
    unsigned short newStack = 0, targetStack = 0;

    bool ok = das::AttachToDevice(hDevice, path, attachId,
                                  &filterAddr, &lowerAddr, &newStack, &targetStack);
    DWORD err = GetLastError();
    das::CloseKernelService(hDevice);

    void* buf = AllocBuffer(7, 1, sizeof(CbnAttachResult), outSize);
    if (!buf) return nullptr;

    auto* result = EntriesAfter<CbnAttachResult>(static_cast<CbnResultHeader*>(buf));
    std::memset(result, 0, sizeof(CbnAttachResult));

    if (!ok) {
        if (err == ERROR_ALREADY_EXISTS) {
            result->status = 0;  // 已附着, 视为成功
        } else {
            result->status = 1;
            auto* hdr = static_cast<CbnResultHeader*>(buf);
            hdr->errorCode = static_cast<int32_t>(err);
            std::wstring msg = L"附着失败 (GetLastError=" + std::to_wstring(err) + L")";
            WcsCpyTrunc(hdr->errorMessage, CBN_MAX_REASON, msg);
        }
    } else {
        result->status           = 0;
        result->attachId         = attachId;
        result->filterDeviceAddr = filterAddr;
        result->lowerDeviceAddr  = lowerAddr;
        result->newStackSize     = newStack;
        result->targetStackSize  = targetStack;
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  8. unattach → CbnDetachResult
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetUnattachData(const wchar_t* arg, uint32_t* outSize) {
    std::wstring a = arg ? arg : L"";

    void* hDevice = das::OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return AllocErrorBuffer(8, 1, L"无法打开 KernelService 设备", outSize);
    }

    // 解析参数: 数字 → AttachId, 否则 → 设备路径
    unsigned long attachId = 0;
    bool isNumeric = !a.empty();
    for (wchar_t c : a) {
        if (c < L'0' || c > L'9') { isNumeric = false; break; }
    }
    if (isNumeric && !a.empty()) {
        attachId = std::stoul(a);
    }

    unsigned long detachedId = 0;
    bool ok;
    if (isNumeric) {
        ok = das::DetachDevice(hDevice, attachId, detachedId);
    } else {
        ok = das::DetachDeviceByPath(hDevice, a, detachedId);
    }
    DWORD err = GetLastError();
    das::CloseKernelService(hDevice);

    void* buf = AllocBuffer(8, 1, sizeof(CbnDetachResult), outSize);
    if (!buf) return nullptr;

    auto* result = EntriesAfter<CbnDetachResult>(static_cast<CbnResultHeader*>(buf));
    std::memset(result, 0, sizeof(CbnDetachResult));
    result->status      = ok ? 0 : 1;
    result->detachedId  = detachedId;

    if (!ok) {
        auto* hdr = static_cast<CbnResultHeader*>(buf);
        hdr->errorCode = static_cast<int32_t>(err);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  9. list-attach → AttachEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetListAttachmentsData(uint32_t* outSize) {
    void* hDevice = das::OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return AllocErrorBuffer(9, 1, L"无法打开 KernelService 设备", outSize);
    }

    std::vector<das::AttachEntry> entries;
    bool ok = das::QueryAttachments(hDevice, entries);
    das::CloseKernelService(hDevice);

    if (!ok) {
        return AllocErrorBuffer(9, 2, L"QueryAttachments 失败", outSize);
    }

    uint32_t count = static_cast<uint32_t>(
        std::min(entries.size(), static_cast<size_t>(CBN_MAX_ATTACHMENTS)));
    void* buf = AllocBuffer(9, count, sizeof(das::AttachEntry), outSize);
    if (!buf) return nullptr;

    auto* dst = EntriesAfter<das::AttachEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        dst[i] = entries[i];  // AttachEntry 已是 POD
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  10. enum-classify → CbnClassifyEntry[] (PSAPI 模式)
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetEnumAndClassifyData(uint32_t* outSize) {
    std::vector<das::LoadedDriver> drivers;
    if (!das::EnumLoadedDrivers(drivers)) {
        return AllocErrorBuffer(10, 1, L"EnumLoadedDrivers 失败", outSize);
    }

    uint32_t total = static_cast<uint32_t>(
        std::min(drivers.size(), static_cast<size_t>(CBN_MAX_DRIVERS)));
    void* buf = AllocBuffer(10, total, sizeof(CbnClassifyEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnClassifyEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < total; ++i) {
        const auto& d = drivers[i];
        if (d.path.empty() ||
            GetFileAttributesW(d.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            das::ClassifyResult result;
            result.klass = das::DriverClass::UNTRUSTED;
            result.errorReason = L"无路径或文件不存在";
            FillClassifyEntry(entries[i], d.name, d.path, L"", result);
            continue;
        }
        das::ClassifyResult result = das::ClassifyDriver(d.path);
        FillClassifyEntry(entries[i], d.name, d.path, L"", result);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  11. scan-objects → CbnNtDirEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetScanObjectsData(const wchar_t* dirs, uint32_t* outSize) {
    if (!das::InitNtApi()) {
        return AllocErrorBuffer(11, 1, L"初始化 NTAPI 失败", outSize);
    }

    // 解析逗号分隔的目录列表
    std::vector<std::wstring> dirList;
    if (dirs && *dirs) {
        std::wistringstream stream(dirs);
        std::wstring token;
        while (std::getline(stream, token, L',')) {
            if (!token.empty()) dirList.push_back(token);
        }
    }
    if (dirList.empty()) {
        dirList.push_back(L"\\GLOBAL??");
        dirList.push_back(L"\\Device");
    }

    std::vector<das::NtDirEntry> allEntries;
    for (const auto& dir : dirList) {
        das::EnumDirectoryTreeData(dir, allEntries, 0);
    }

    uint32_t count = static_cast<uint32_t>(
        std::min(allEntries.size(), static_cast<size_t>(CBN_MAX_OBJECT_ENTRIES)));
    void* buf = AllocBuffer(11, count, sizeof(CbnNtDirEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnNtDirEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        WcsCpyTrunc(entries[i].name,       CBN_MAX_PATH, allEntries[i].name);
        WcsCpyTrunc(entries[i].typeName,   CBN_MAX_NAME, allEntries[i].typeName);
        WcsCpyTrunc(entries[i].linkTarget, CBN_MAX_PATH, allEntries[i].linkTarget);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  12. etw → CbnEtwEvent[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetEtwData(uint32_t durationSec, const wchar_t* etlPath, uint32_t* outSize) {
    std::wstring etl = etlPath ? etlPath : L"";

    // 设置收集模式
    das::SetEtwCollectionMode(true);
    das::ResetCollectedEtwEvents();

    // 静默模式运行
    das::SetSilentMode(true);
    int ret = das::RunEtwConsumer(durationSec, etl);
    das::SetSilentMode(false);

    das::SetEtwCollectionMode(false);

    if (ret != 0) {
        return AllocErrorBuffer(12, ret, L"RunEtwConsumer 失败", outSize);
    }

    std::vector<das::CollectedEtwEvent> events = das::GetCollectedEtwEvents();

    uint32_t count = static_cast<uint32_t>(
        std::min(events.size(), static_cast<size_t>(CBN_MAX_ETW_EVENTS)));
    void* buf = AllocBuffer(12, count, sizeof(CbnEtwEvent), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnEtwEvent>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        std::memset(&entries[i], 0, sizeof(CbnEtwEvent));
        entries[i].version           = events[i].version;
        entries[i].ioControlCode     = events[i].ioControlCode;
        entries[i].inputBufferLength = events[i].inputBufferLength;
        entries[i].captureSize       = events[i].captureSize;
        entries[i].requestorPid      = events[i].requestorPid;
        entries[i].targetDeviceAddr  = events[i].targetDeviceAddr;
        entries[i].filterDeviceAddr  = events[i].filterDeviceAddr;
        entries[i].attachId          = events[i].attachId;
        entries[i].majorFunction     = events[i].majorFunction;
        entries[i].method            = events[i].method;
        entries[i].stackFrameCount   = static_cast<int32_t>(
            std::min(events[i].stackFrames.size(), static_cast<size_t>(CBN_MAX_STACK_FRAMES)));
        // 过滤掉 0 值栈帧 (ETW 有时会填 0)
        int32_t validFrames = 0;
        for (int32_t j = 0; j < entries[i].stackFrameCount; ++j) {
            if (events[i].stackFrames[j] != 0) {
                entries[i].stackFrames[validFrames++] = events[i].stackFrames[j];
            }
        }
        entries[i].stackFrameCount = validFrames;
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  12b/c/d. ETW 实时回调
// ═══════════════════════════════════════════════════════════════════════

// 全局回调 (由 EventRecordCallback 调用)
static CBN_ETW_CALLBACK g_EtwCallback = nullptr;
static void*            g_EtwCallbackCtx = nullptr;

extern "C" CBN_DATA_API void CombNative_SetEtwCallback(CBN_ETW_CALLBACK callback, void* context) {
    g_EtwCallback    = callback;
    g_EtwCallbackCtx = context;
}

// 由 EtwConsumer 的事件回调调用 (通过 SetEtwCollectionMode 收集)
// 每收集到一个事件, 转换为 CbnEtwEvent 并调用注册的回调
static void DispatchEtwCallback(const das::CollectedEtwEvent& ev) {
    if (!g_EtwCallback) return;

    CbnEtwEvent out{};
    out.version           = ev.version;
    out.ioControlCode     = ev.ioControlCode;
    out.inputBufferLength = ev.inputBufferLength;
    out.captureSize       = ev.captureSize;
    out.requestorPid      = ev.requestorPid;
    out.targetDeviceAddr  = ev.targetDeviceAddr;
    out.filterDeviceAddr  = ev.filterDeviceAddr;
    out.attachId          = ev.attachId;
    out.majorFunction     = ev.majorFunction;
    out.method            = ev.method;
    out.stackFrameCount   = static_cast<int32_t>(
        std::min(ev.stackFrames.size(), static_cast<size_t>(CBN_MAX_STACK_FRAMES)));
    int32_t validFrames = 0;
    for (int32_t j = 0; j < out.stackFrameCount; ++j) {
        if (ev.stackFrames[j] != 0) {
            out.stackFrames[validFrames++] = ev.stackFrames[j];
        }
    }
    out.stackFrameCount = validFrames;

    g_EtwCallback(&out, g_EtwCallbackCtx);
}

extern "C" CBN_DATA_API int CombNative_RunEtwLive(uint32_t durationSec, const wchar_t* etlPath) {
    std::wstring etl = etlPath ? etlPath : L"";

    // 设置收集模式 + 注册一个轮询钩子
    das::SetEtwCollectionMode(true);
    das::ResetCollectedEtwEvents();

    // 静默模式运行 (不打印 C++ 端的输出)
    das::SetSilentMode(true);

    // 在另一个线程中运行 ETW, 主线程轮询已收集的事件并回调
    std::atomic<bool> etwDone{false};
    int ret = 0;

    std::thread etwThread([&]() {
        ret = das::RunEtwConsumer(durationSec, etl);
        etwDone.store(true);
    });

    // 轮询: 每次取出新事件并回调
    size_t lastDispatched = 0;
    while (!etwDone.load()) {
        std::vector<das::CollectedEtwEvent> events = das::GetCollectedEtwEvents();
        while (lastDispatched < events.size()) {
            DispatchEtwCallback(events[lastDispatched]);
            lastDispatched++;
        }
        Sleep(50);  // 50ms 轮询间隔
    }

    etwThread.join();

    // 取出最后一批
    std::vector<das::CollectedEtwEvent> events = das::GetCollectedEtwEvents();
    while (lastDispatched < events.size()) {
        DispatchEtwCallback(events[lastDispatched]);
        lastDispatched++;
    }

    das::SetEtwCollectionMode(false);
    das::SetSilentMode(false);
    g_EtwCallback = nullptr;
    g_EtwCallbackCtx = nullptr;

    return ret;
}

// ═══════════════════════════════════════════════════════════════════════
//  13. comms → CbnCommsSummary
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetCommsData(uint32_t durationSec, int enableJson,
                                                      int dumpMode, uint32_t* outSize) {
    das::MonitorOptions options;
    options.durationSec    = durationSec;
    options.enableJson     = (enableJson != 0);
    options.enableMinidump = (dumpMode == 1);
    options.enableMifudump = (dumpMode == 2);

    int ret = das::RunCommsMonitorCollect(options);
    if (ret != 0) {
        return AllocErrorBuffer(13, ret, L"RunCommsMonitorCollect 失败", outSize);
    }

    std::vector<das::PathEntry> paths = das::GetCollectedPaths();

    void* buf = AllocBuffer(13, 1, sizeof(CbnCommsSummary), outSize);
    if (!buf) return nullptr;

    auto* summary = EntriesAfter<CbnCommsSummary>(static_cast<CbnResultHeader*>(buf));
    std::memset(summary, 0, sizeof(CbnCommsSummary));

    summary->pathCount = static_cast<uint32_t>(
        std::min(paths.size(), static_cast<size_t>(CBN_MAX_PATHS)));

    uint32_t totalHits = 0;
    for (uint32_t i = 0; i < summary->pathCount; ++i) {
        const auto& p = paths[i];
        WcsCpyTrunc(summary->paths[i].path,        CBN_MAX_PATH, p.path);
        WcsCpyTrunc(summary->paths[i].tag,         64,           p.tag);
        summary->paths[i].pid        = p.pid;
        summary->paths[i].abnormal   = p.abnormal  ? 1 : 0;
        WcsCpyTrunc(summary->paths[i].note,        CBN_MAX_STR,  p.note);
        summary->paths[i].hitCount   = p.hitCount;
        summary->paths[i].dumped     = p.dumped    ? 1 : 0;
        WcsCpyTrunc(summary->paths[i].dumpFile,    CBN_MAX_PATH, p.dumpFile);
        summary->paths[i].fileCopied = p.fileCopied? 1 : 0;
        WcsCpyTrunc(summary->paths[i].fileCopyName, CBN_MAX_PATH, p.fileCopyName);
        totalHits += p.hitCount;
    }
    summary->totalIoctls = totalHits;
    summary->totalEvents = static_cast<uint32_t>(paths.size());

    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  14. scan-handles → CbnHandleEntry[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetScanHandlesData(uint32_t targetPid, uint32_t* outSize) {
    // 复用 ProcessTreeSnapshot 的 CollectHandles
    std::unordered_map<ULONG_PTR, std::wstring> pidToName;
    std::vector<ProcBrief> briefs;
    if (EnumProcessesBrief(briefs)) {
        for (const auto& b : briefs) {
            pidToName[b.pid] = U8ToW(b.name);
        }
    }

    std::vector<HandleEntry> handles;
    CollectHandles(targetPid, pidToName, handles);

    uint32_t count = static_cast<uint32_t>(
        std::min(handles.size(), static_cast<size_t>(CBN_MAX_HANDLES)));
    void* buf = AllocBuffer(14, count, sizeof(CbnHandleEntry), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnHandleEntry>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        FillHandleEntry(entries[i], handles[i]);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  15. tree → CbnProcBrief[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetTreeData(uint64_t pid, int maxDepth, int jsonOut, uint32_t* outSize) {
    (void)maxDepth;  // tree 模式只枚举进程列表, maxDepth 用于打印层级
    (void)jsonOut;   // 数据模式总是返回结构化数据

    std::vector<ProcBrief> procs;
    if (!EnumProcessesBrief(procs)) {
        return AllocErrorBuffer(15, 1, L"EnumProcessesBrief 失败", outSize);
    }

    uint32_t count = static_cast<uint32_t>(
        std::min(procs.size(), static_cast<size_t>(CBN_MAX_PROCESSES)));
    void* buf = AllocBuffer(15, count, sizeof(CbnProcBrief), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnProcBrief>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        FillProcBrief(entries[i], procs[i]);
    }
    return buf;
}

// ═══════════════════════════════════════════════════════════════════════
//  16. security → CbnProcDetail[]
// ═══════════════════════════════════════════════════════════════════════

extern "C" CBN_DATA_API void* CombNative_GetSecurityData(uint64_t pid, uint32_t flags, uint32_t* outSize) {
    bool noModules = (flags & 0x08) != 0;
    bool noThreads = (flags & 0x04) != 0;
    bool noMem     = (flags & 0x02) != 0;
    bool noHandles = (flags & 0x01) != 0;

    // 1. 枚举进程
    std::vector<ProcBrief> briefs;
    if (!EnumProcessesBrief(briefs)) {
        return AllocErrorBuffer(16, 1, L"EnumProcessesBrief 失败", outSize);
    }

    std::unordered_map<ULONG_PTR, ProcBrief*> briefByPid;
    for (auto& b : briefs) briefByPid[b.pid] = &b;

    // 2. 确定目标进程列表
    std::vector<ULONG_PTR> targetPids;
    if (pid != 0) {
        if (briefByPid.find(pid) == briefByPid.end()) {
            return AllocErrorBuffer(16, 2, L"PID 不存在", outSize);
        }
        targetPids.push_back(pid);
    } else {
        for (const auto& b : briefs) {
            if (b.pid != 0) targetPids.push_back(b.pid);
        }
    }

    // 3. 采集详情
    std::vector<ProcDetail> details;
    details.reserve(targetPids.size());

    for (ULONG_PTR tpid : targetPids) {
        ProcDetail d;
        auto it = briefByPid.find(tpid);
        if (it != briefByPid.end()) d.brief = *it->second;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)tpid);
        if (!hProc) {
            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)tpid);
        }
        if (!hProc) {
            details.push_back(std::move(d));
            continue;
        }

        CollectProcessDetails(hProc, d);
        if (!noModules) CollectModules(hProc, d);
        if (!noThreads) CollectThreads(d.brief, hProc, d.modules, d);
        if (!noMem)     CollectSuspiciousMemory(hProc, d.modules, d);

        CloseHandle(hProc);
        details.push_back(std::move(d));
    }

    // 4. 句柄表扫描 (附加到每个进程详情中)
    if (!noHandles) {
        std::unordered_map<ULONG_PTR, std::wstring> pidToName;
        for (const auto& b : briefs) pidToName[b.pid] = U8ToW(b.name);

        std::vector<HandleEntry> handles;
        ULONG_PTR handleTarget = (pid != 0) ? pid : 0;
        CollectHandles(handleTarget, pidToName, handles);

        // 将句柄分配到对应进程 (按 ownerPid)
        for (auto& d : details) {
            for (const auto& h : handles) {
                if (h.ownerPid == d.brief.pid) {
                    d.handles.push_back(h);
                }
            }
        }
    }

    // 5. 填充扁平化结构体
    uint32_t count = static_cast<uint32_t>(
        std::min(details.size(), static_cast<size_t>(CBN_MAX_PROCESSES)));
    void* buf = AllocBuffer(16, count, sizeof(CbnProcDetail), outSize);
    if (!buf) return nullptr;

    auto* entries = EntriesAfter<CbnProcDetail>(static_cast<CbnResultHeader*>(buf));
    for (uint32_t i = 0; i < count; ++i) {
        FillProcDetail(entries[i], details[i]);
    }
    return buf;
}
