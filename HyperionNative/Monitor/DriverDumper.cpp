// DriverDumper.cpp — 内核驱动内存 dump
//
// 拆分自 CommsMonitor.cpp:
//   - DumpTargetDriver: 按 AttachId 通过 KernelService 从内核 dump 被附着设备所属驱动内存
//   - InitDriverDumper: 由 RunCommsMonitor 传入 KernelService 句柄 + dumpfile/FileDump 路径

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "DriverDumper.h"
#include "Common.h"

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>

namespace das {

// 内核通信: IOCTL_DUMP_DRIVER_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 与 KernelService\DriverAttach.h 一致, 这里内联避免拖入 KernelComms.cpp 链接
//   = (0x22 << 16) | (0 << 14) | (0x809 << 2) | 0
//   = 0x220000 | 0x2024
//   = 0x222024
// (之前硬编码 0x22900C 是错的, 实际对应 function=0x2403 access=FILE_WRITE_DATA, 驱动认不出来)
#define HD_IOCTL_DUMP_DRIVER_MEMORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
struct HdDumpDriverMemReq {
    unsigned long AttachId;
};
struct HdDumpDriverMemResp {
    long                Status;
    unsigned long long  DriverObjectAddr;
    unsigned long long  ImageBase;
    unsigned long       ImageSize;
    unsigned long       BytesDumped;
    wchar_t             FullPath[260];
    wchar_t             BaseName[64];
};
#pragma pack(pop)

// 已 dump 的驱动 sys (按 AttachId 去重, 因为同一 AttachId 的对端驱动不变)
static std::unordered_set<unsigned long> g_driverDumped;

// 收集的驱动 dump 元数据 (供 FFI 数据导出使用)
static std::vector<DriverDumpEntry> g_collectedDriverDumps;

// KernelService 设备句柄 + dumpfile/FileDump 路径 (由 InitDriverDumper 设置)
static void* g_hKernelService = nullptr;
static std::wstring g_dumpDir;
static std::wstring g_fileDumpDir;

// ═══════════════════════════════════════════════════════════════════════
//  InitDriverDumper: 设置 KernelService 句柄 + dumpfile/FileDump 路径
// ═══════════════════════════════════════════════════════════════════════

void InitDriverDumper(void* hKs, const std::wstring& dumpDir,
                     const std::wstring& fileDumpDir)
{
    g_hKernelService = hKs;
    g_dumpDir = dumpDir;
    g_fileDumpDir = fileDumpDir;
}

// ═══════════════════════════════════════════════════════════════════════
//  对端驱动 dump: 按 AttachId 通过 KernelService 从内核 dump 驱动内存映像
//  - 同一 AttachId 只 dump 一次 (对端驱动不变)
//  - 内核返回 sys 路径 (FullPath/BaseName):
//      磁盘上有文件 → 拷贝到 FileDump\
//      磁盘上没有   → 内存 dump 到 dumpfile\ (文件名 MISSING_<BaseName>)
// ═══════════════════════════════════════════════════════════════════════

void DumpTargetDriver(unsigned long attachId)
{
    if (attachId == 0) return;
    if (!g_hKernelService) return;

    // 同一 AttachId 只处理一次
    if (g_driverDumped.count(attachId) > 0) return;
    g_driverDumped.insert(attachId);

    // 第一次: 探测响应头拿 ImageSize + 路径
    HdDumpDriverMemReq req{ attachId };
    std::vector<unsigned char> outBuf(sizeof(HdDumpDriverMemResp), 0);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl((HANDLE)g_hKernelService,
                              HD_IOCTL_DUMP_DRIVER_MEMORY,
                              &req, sizeof(req),
                              outBuf.data(), (DWORD)outBuf.size(),
                              &bytesReturned, nullptr);
    if (!ok || bytesReturned < sizeof(HdDumpDriverMemResp)) {
        WriteOut(L"  [驱动] dump 失败: DeviceIoControl 探测失败 err="
                 + std::to_wstring(GetLastError()) + L"\n");
        return;
    }

    HdDumpDriverMemResp resp{};
    memcpy(&resp, outBuf.data(), sizeof(resp));

    if (resp.Status != 0) {
        WriteOut(L"  [驱动] dump 失败: 内核返回 Status=0x"
                 + std::to_wstring(resp.Status) + L"\n");
        return;
    }

    std::wstring fullPath(resp.FullPath);
    std::wstring baseName(resp.BaseName);
    if (baseName.empty()) baseName = L"driver_" + std::to_wstring(attachId) + L".sys";

    // 内核返回的路径是 \SystemRoot\... 格式, 转成物理路径
    std::wstring physPath = fullPath;
    if (physPath.find(L"\\SystemRoot\\") == 0) {
        wchar_t sysRoot[MAX_PATH] = {0};
        GetWindowsDirectoryW(sysRoot, MAX_PATH);
        physPath = std::wstring(sysRoot) + L"\\" + physPath.substr(11);
    } else if (physPath.find(L"\\??\\") == 0) {
        physPath = physPath.substr(4);
    }

    WriteOut(L"  [驱动] 对端 sys: " + (physPath.empty() ? baseName : physPath)
             + L"  (ImageBase=0x" + std::to_wstring(resp.ImageBase)
             + L" Size=" + std::to_wstring(resp.ImageSize) + L")\n");

    // 检查磁盘是否有文件
    DWORD attr = GetFileAttributesW(physPath.c_str());
    bool diskHas = (attr != INVALID_FILE_ATTRIBUTES);

    if (diskHas) {
        // 磁盘有 → 拷贝到 FileDump
        std::wstring copyName = baseName;
        if (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            copyName = L"RHS_" + baseName;
        }
        std::wstring copyPath = g_fileDumpDir + L"\\" + copyName;
        BOOL cancel = FALSE;
        if (CopyFileExW(physPath.c_str(), copyPath.c_str(), NULL, NULL, &cancel, 0)) {
            WriteOut(L"  [file] 已拷贝驱动: filecopy\\" + copyName + L"\n");
        } else {
            WriteOut(L"  [file] 驱动拷贝失败: " + copyName
                     + L" err=" + std::to_wstring(GetLastError()) + L"\n");
        }
    }

    // 无论磁盘有没有, 都从内存 dump 一份到 dumpfile (内存态可能被 patch)
    if (resp.ImageSize > 0) {
        // 第二次: 拿完整映像
        outBuf.assign(sizeof(HdDumpDriverMemResp) + resp.ImageSize, 0);
        ok = DeviceIoControl((HANDLE)g_hKernelService,
                              HD_IOCTL_DUMP_DRIVER_MEMORY,
                              &req, sizeof(req),
                              outBuf.data(), (DWORD)outBuf.size(),
                              &bytesReturned, nullptr);
        if (!ok || bytesReturned < sizeof(HdDumpDriverMemResp)) {
            WriteOut(L"  [dump] 驱动内存 dump 失败: err="
                     + std::to_wstring(GetLastError()) + L"\n");
            return;
        }
        memcpy(&resp, outBuf.data(), sizeof(resp));
        if (resp.BytesDumped == 0) {
            WriteOut(L"  [dump] 驱动内存 dump: BytesDumped=0\n");
            return;
        }

        // 文件名: 磁盘有 → baseName, 磁盘没有 → MISSING_baseName
        std::wstring dumpName = baseName;
        if (!diskHas) dumpName = L"MISSING_" + baseName;
        std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

        HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            WriteOut(L"  [dump] 驱动 CreateFile 失败: " + dumpPath + L"\n");
            return;
        }
        DWORD written = 0;
        const unsigned char* imgStart = outBuf.data() + sizeof(HdDumpDriverMemResp);
        ok = WriteFile(hFile, imgStart, resp.BytesDumped, &written, NULL);
        CloseHandle(hFile);
        if (ok && written == resp.BytesDumped) {
            WriteOut(L"  [dump] 驱动内存已保存: dumpfile\\" + dumpName
                     + L" (" + std::to_wstring(resp.BytesDumped) + L" 字节)\n");
            // 收集元数据 (供 FFI 数据导出使用)
            DriverDumpEntry entry;
            entry.status          = 0;
            entry.attachId        = attachId;
            entry.driverObjectAddr= resp.DriverObjectAddr;
            entry.imageBase       = resp.ImageBase;
            entry.imageSize       = resp.ImageSize;
            entry.bytesDumped     = resp.BytesDumped;
            entry.fullPath        = fullPath;
            entry.baseName        = baseName;
            entry.dumpFile        = dumpName;
            g_collectedDriverDumps.push_back(std::move(entry));
        } else {
            WriteOut(L"  [dump] 驱动 WriteFile 失败\n");
        }
    }
}

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

std::vector<DriverDumpEntry> GetCollectedDriverDumps() {
    return g_collectedDriverDumps;
}

void ResetCollectedDriverDumps() {
    g_collectedDriverDumps.clear();
    g_driverDumped.clear();
}

} // namespace das
