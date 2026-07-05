// KernelComms.cpp — 与 KernelService 驱动通信实现

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include "KernelComms.h"

#include <windows.h>
#include <winioctl.h>
#include <sstream>
#include <iomanip>

namespace das {

// KernelService 符号链接 \\.\KernelService → \Device\KernelService
// 驱动用 \DosDevices\KernelService 创建
const wchar_t* KERNEL_SERVICE_DOS_NAME = L"\\\\.\\KernelService";

// IOCTL_SCAN_LOADED_DRIVERS
// 必须与驱动端 DriverScanner.h 中的定义完全一致:
//   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// CTL_CODE 宏展开:
//   ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method)
//   = (0x22 << 16) | (0 << 14) | (0x804 << 2) | 0
//   = 0x220000 | 0x2010
//   = 0x222010
//
// 注意:必须用 CTL_CODE 宏动态计算,不要手算硬编码
// (之前硬编码 0x222004 是错的,实际对应 function=0x801=IOCTL_TERMINATE_PROCESS)
const unsigned long IOCTL_SCAN_LOADED_DRIVERS =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS);

// 静态断言结构体大小与驱动端一致(避免 packing 差异)
// 驱动端用 #pragma pack 默认(8),应用端也用默认
static_assert(sizeof(ScanDriversRequest) == 4, "ScanDriversRequest size mismatch");
// LoadedDriverEntry: 8(基址) + 4(大小) + 2(序号) + 2(标志) + 128(短名) + 520(路径)
// = 664 字节 (8 字节自然对齐,无需补齐)
static_assert(sizeof(LoadedDriverEntry) == 664, "LoadedDriverEntry size mismatch");
static_assert(sizeof(ScanDriversResponse) == 16, "ScanDriversResponse size mismatch");

// ═══════════════════════════════════════════════════════════════════════
//  打开 / 关闭设备
// ═══════════════════════════════════════════════════════════════════════

void* OpenKernelService() {
    HANDLE h = CreateFileW(
        KERNEL_SERVICE_DOS_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,                          // 不共享
        nullptr,                    // 默认安全属性
        OPEN_EXISTING,              // 设备必须已存在
        FILE_ATTRIBUTE_NORMAL,
        nullptr);                   // 无模板

    return (void*)h; // 失败时返回 INVALID_HANDLE_VALUE
}

void CloseKernelService(void* hDevice) {
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle((HANDLE)hDevice);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  扫描已加载驱动
// ═══════════════════════════════════════════════════════════════════════

bool ScanLoadedDriversViaKernel(void* hDevice,
                                 unsigned long maxEntries,
                                 std::vector<LoadedDriverEntry>& outDrivers)
{
    outDrivers.clear();
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    // 第一次:用估算的输出缓冲区大小(假设 256 个驱动,~256 * 660B ≈ 165KB)
    // 不够则按驱动返回的 NeededOutputBytes 重试
    DWORD outSize = sizeof(ScanDriversResponse) + 256 * sizeof(LoadedDriverEntry);
    std::vector<BYTE> outBuffer(outSize);

    for (int retry = 0; retry < 3; retry++) {
        ScanDriversRequest req;
        req.MaxEntries = maxEntries;

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            (HANDLE)hDevice,
            IOCTL_SCAN_LOADED_DRIVERS,
            &req, sizeof(req),
            outBuffer.data(), (DWORD)outBuffer.size(),
            &bytesReturned,
            nullptr); // 同步

        if (ok) {
            // 成功,解析响应
            if (bytesReturned < sizeof(ScanDriversResponse)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            ScanDriversResponse resp;
            memcpy(&resp, outBuffer.data(), sizeof(resp));

            if (bytesReturned < sizeof(ScanDriversResponse) +
                resp.EntryCount * sizeof(LoadedDriverEntry)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            outDrivers.resize(resp.EntryCount);
            if (resp.EntryCount > 0) {
                memcpy(outDrivers.data(),
                       outBuffer.data() + sizeof(ScanDriversResponse),
                       resp.EntryCount * sizeof(LoadedDriverEntry));
            }

            return true;
        }

        DWORD err = GetLastError();

        // ERROR_INSUFFICIENT_BUFFER (122) — 缓冲区不够,按驱动提示大小重试
        if (err == ERROR_INSUFFICIENT_BUFFER ||
            err == ERROR_MORE_DATA) {
            // 解析响应头拿 NeededOutputBytes
            if (bytesReturned >= sizeof(ScanDriversResponse)) {
                ScanDriversResponse resp;
                memcpy(&resp, outBuffer.data(), sizeof(resp));
                if (resp.NeededOutputBytes > outBuffer.size() &&
                    resp.NeededOutputBytes < 16 * 1024 * 1024) { // 上限 16MB 防失控
                    outBuffer.resize(resp.NeededOutputBytes);
                    continue;
                }
            }
            // 没拿到 NeededOutputBytes,简单扩容重试
            outSize *= 2;
            if (outSize > 16 * 1024 * 1024) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return false;
            }
            outBuffer.resize(outSize);
            continue;
        }

        // 其他错误直接返回
        return false;
    }

    SetLastError(ERROR_RETRY);
    return false;
}

} // namespace das
