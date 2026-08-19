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

// IOCTL_ENUM_DRIVER_DEVICES
// 必须与驱动端 DriverDevices.h 中的定义完全一致:
//   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
const unsigned long IOCTL_ENUM_DRIVER_DEVICES =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

// IOCTL_ATTACH_DEVICE / IOCTL_DETACH_DEVICE / IOCTL_QUERY_ATTACHMENTS
// 必须与驱动端 DriverAttach.h 中的定义完全一致
const unsigned long IOCTL_ATTACH_DEVICE =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS);
const unsigned long IOCTL_DETACH_DEVICE =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS);
const unsigned long IOCTL_QUERY_ATTACHMENTS =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS);

// 静态断言结构体大小与驱动端一致(避免 packing 差异)
// 驱动端用 #pragma pack 默认(8),应用端也用默认
static_assert(sizeof(ScanDriversRequest) == 4, "ScanDriversRequest size mismatch");
// LoadedDriverEntry: 8(基址) + 4(大小) + 2(序号) + 2(标志) + 128(短名) + 520(路径) + 128(驱动对象名)
// = 792 字节 (8 字节自然对齐,无需补齐)
static_assert(sizeof(LoadedDriverEntry) == 792, "LoadedDriverEntry size mismatch");
static_assert(sizeof(ScanDriversResponse) == 16, "ScanDriversResponse size mismatch");

// EnumDevicesRequest: 128(短名 WCHAR[64]) + 4(MaxEntries) = 132 字节
// (4 字节自然对齐,132 已是 4 的倍数,无需 padding)
static_assert(sizeof(EnumDevicesRequest) == 132, "EnumDevicesRequest size mismatch");
// DeviceEntry: 8 + 4 + 4 + 4 + 2 + 2 + 520 = 544 字节
static_assert(sizeof(DeviceEntry) == 544, "DeviceEntry size mismatch");
// EnumDevicesResponse: 4 + 4 + 4 + 4 + 192(WCHAR[96]) = 208 字节 (8 字节对齐)
static_assert(sizeof(EnumDevicesResponse) == 208, "EnumDevicesResponse size mismatch");

// AttachDeviceRequest: 520 (WCHAR[260])
static_assert(sizeof(AttachDeviceRequest) == 520, "AttachDeviceRequest size mismatch");
// AttachDeviceResponse: 4 + 4 + 8 + 8 + 2 + 2 = 28, 8 字节对齐补齐到 32
static_assert(sizeof(AttachDeviceResponse) == 32, "AttachDeviceResponse size mismatch");
// DetachDeviceRequest: 4 + 520 = 524
static_assert(sizeof(DetachDeviceRequest) == 524, "DetachDeviceRequest size mismatch");
// DetachDeviceResponse: 4 + 4 = 8
static_assert(sizeof(DetachDeviceResponse) == 8, "DetachDeviceResponse size mismatch");
// AttachEntry: 8 + 8 + 520 + 4 + 2 = 542, 8 字节对齐补齐到 544
static_assert(sizeof(AttachEntry) == 544, "AttachEntry size mismatch");
// QueryAttachmentsResponse: 4 + 4 = 8
static_assert(sizeof(QueryAttachmentsResponse) == 8, "QueryAttachmentsResponse size mismatch");

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

// ═══════════════════════════════════════════════════════════════════════
//  扫描指定驱动创建的设备列表
// ═══════════════════════════════════════════════════════════════════════

bool EnumDriverDevices(void* hDevice,
                       const std::wstring& driverName,
                       unsigned long maxEntries,
                       std::vector<DeviceEntry>& outDevices,
                       std::wstring* foundPath)
{
    outDevices.clear();
    if (foundPath) foundPath->clear();

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    // 构造输入请求
    EnumDevicesRequest req = {};
    if (driverName.size() >= RTL_NUMBER_OF(req.DriverName)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    wcsncpy_s(req.DriverName, RTL_NUMBER_OF(req.DriverName),
              driverName.c_str(), _TRUNCATE);
    req.MaxEntries = maxEntries;

    // 估算输出大小:响应头 + 16 个设备(单驱动一般不会超过这么多)
    DWORD outSize = sizeof(EnumDevicesResponse) + 16 * sizeof(DeviceEntry);
    std::vector<BYTE> outBuffer(outSize);

    for (int retry = 0; retry < 3; retry++) {
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            (HANDLE)hDevice,
            IOCTL_ENUM_DRIVER_DEVICES,
            &req, sizeof(req),
            outBuffer.data(), (DWORD)outBuffer.size(),
            &bytesReturned,
            nullptr);

        if (ok) {
            if (bytesReturned < sizeof(EnumDevicesResponse)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            EnumDevicesResponse resp;
            memcpy(&resp, outBuffer.data(), sizeof(resp));

            if (foundPath) {
                *foundPath = resp.FoundPath;
            }

            // 驱动不存在的情况:outDevices 留空,返回 true(由调用方看 foundPath 区分)
            if (resp.Status != 0) {
                return true;
            }

            if (bytesReturned < sizeof(EnumDevicesResponse) +
                resp.EntryCount * sizeof(DeviceEntry)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            outDevices.resize(resp.EntryCount);
            if (resp.EntryCount > 0) {
                memcpy(outDevices.data(),
                       outBuffer.data() + sizeof(EnumDevicesResponse),
                       resp.EntryCount * sizeof(DeviceEntry));
            }
            return true;
        }

        DWORD err = GetLastError();

        // 缓冲区不够,按驱动提示大小重试
        if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_MORE_DATA) {
            if (bytesReturned >= sizeof(EnumDevicesResponse)) {
                EnumDevicesResponse resp;
                memcpy(&resp, outBuffer.data(), sizeof(resp));
                if (resp.NeededOutputBytes > outBuffer.size() &&
                    resp.NeededOutputBytes < 4 * 1024 * 1024) { // 上限 4MB
                    outBuffer.resize(resp.NeededOutputBytes);
                    continue;
                }
            }
            outSize *= 2;
            if (outSize > 4 * 1024 * 1024) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return false;
            }
            outBuffer.resize(outSize);
            continue;
        }

        return false;
    }

    SetLastError(ERROR_RETRY);
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
//  附着到指定设备
// ═══════════════════════════════════════════════════════════════════════

bool AttachToDevice(void* hDevice,
                    const std::wstring& devicePath,
                    unsigned long& outAttachId,
                    unsigned long long* outFilterAddr,
                    unsigned long long* outLowerAddr,
                    unsigned short* outNewStackSize,
                    unsigned short* outTargetStackSize)
{
    outAttachId = 0;
    if (outFilterAddr) *outFilterAddr = 0;
    if (outLowerAddr) *outLowerAddr = 0;
    if (outNewStackSize) *outNewStackSize = 0;
    if (outTargetStackSize) *outTargetStackSize = 0;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    AttachDeviceRequest req = {};
    if (devicePath.size() >= RTL_NUMBER_OF(req.DevicePath)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    wcsncpy_s(req.DevicePath, RTL_NUMBER_OF(req.DevicePath),
              devicePath.c_str(), _TRUNCATE);

    AttachDeviceResponse resp = {};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)hDevice, IOCTL_ATTACH_DEVICE,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned, nullptr);

    if (!ok || bytesReturned < sizeof(resp)) {
        return false;
    }

    if (resp.Status != 0) {
        // 精细化映射 NTSTATUS → Win32 错误码
        // STATUS_DUPLICATE_OBJECTID (0xC0000237) = 已附着过
        // 其他错误一律映射成 ERROR_GEN_FAILURE,并把 NTSTATUS 编码到 HRESULT 低 16 位
        //   (方便上层用 HRESULT_FROM_WIN32 反查,也方便日志打印)
        DWORD winErr;
        if ((unsigned long)resp.Status == 0xC0000237) {
            winErr = ERROR_ALREADY_EXISTS;
        } else if ((unsigned long)resp.Status == 0xC0000034L) {
            // STATUS_OBJECT_NAME_NOT_FOUND
            winErr = ERROR_FILE_NOT_FOUND;
        } else if ((unsigned long)resp.Status == 0xC0000035L) {
            // STATUS_OBJECT_NAME_COLLISION
            winErr = ERROR_ALREADY_EXISTS;
        } else if ((unsigned long)resp.Status == 0xC000003BL) {
            // STATUS_OBJECT_PATH_SYNTAX_BAD
            winErr = ERROR_INVALID_NAME;
        } else {
            // 兜底:把 NTSTATUS 原值塞进 HRESULT 返回,方便诊断
            // 注意:这里只设错误码,不返回 NTSTATUS 本身
            winErr = ERROR_GEN_FAILURE;
        }
        SetLastError(winErr);
        return false;
    }

    outAttachId = resp.AttachId;
    if (outFilterAddr) *outFilterAddr = resp.FilterDeviceAddr;
    if (outLowerAddr) *outLowerAddr = resp.LowerDeviceAddr;
    if (outNewStackSize) *outNewStackSize = resp.NewStackSize;
    if (outTargetStackSize) *outTargetStackSize = resp.TargetStackSize;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  按 ID 解绑
// ═══════════════════════════════════════════════════════════════════════

bool DetachDevice(void* hDevice,
                  unsigned long attachId,
                  unsigned long& outDetachedId)
{
    outDetachedId = 0;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    if (attachId == 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    DetachDeviceRequest req = {};
    req.AttachId = attachId;

    DetachDeviceResponse resp = {};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)hDevice, IOCTL_DETACH_DEVICE,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned, nullptr);

    if (!ok || bytesReturned < sizeof(resp)) {
        return false;
    }

    if (resp.Status != 0) {
        SetLastError(ERROR_NOT_FOUND);
        return false;
    }

    outDetachedId = resp.DetachedId;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  按路径解绑
// ═══════════════════════════════════════════════════════════════════════

bool DetachDeviceByPath(void* hDevice,
                        const std::wstring& devicePath,
                        unsigned long& outDetachedId)
{
    outDetachedId = 0;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    DetachDeviceRequest req = {};
    req.AttachId = 0;  // 按路径匹配
    if (devicePath.size() >= RTL_NUMBER_OF(req.DevicePath)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    wcsncpy_s(req.DevicePath, RTL_NUMBER_OF(req.DevicePath),
              devicePath.c_str(), _TRUNCATE);

    DetachDeviceResponse resp = {};
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)hDevice, IOCTL_DETACH_DEVICE,
        &req, sizeof(req),
        &resp, sizeof(resp),
        &bytesReturned, nullptr);

    if (!ok || bytesReturned < sizeof(resp)) {
        return false;
    }

    if (resp.Status != 0) {
        SetLastError(ERROR_NOT_FOUND);
        return false;
    }

    outDetachedId = resp.DetachedId;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  查询当前所有附着
// ═══════════════════════════════════════════════════════════════════════

bool QueryAttachments(void* hDevice,
                      std::vector<AttachEntry>& outEntries)
{
    outEntries.clear();

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    // 第一次用估算大小(假设 16 个附着,通常远不到)
    DWORD outSize = sizeof(QueryAttachmentsResponse) + 16 * sizeof(AttachEntry);
    std::vector<BYTE> outBuffer(outSize);

    for (int retry = 0; retry < 3; retry++) {
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            (HANDLE)hDevice, IOCTL_QUERY_ATTACHMENTS,
            nullptr, 0,
            outBuffer.data(), (DWORD)outBuffer.size(),
            &bytesReturned, nullptr);

        if (ok) {
            if (bytesReturned < sizeof(QueryAttachmentsResponse)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            QueryAttachmentsResponse resp;
            memcpy(&resp, outBuffer.data(), sizeof(resp));

            if (bytesReturned < sizeof(QueryAttachmentsResponse) +
                resp.Count * sizeof(AttachEntry)) {
                SetLastError(ERROR_BAD_FORMAT);
                return false;
            }

            outEntries.resize(resp.Count);
            if (resp.Count > 0) {
                memcpy(outEntries.data(),
                       outBuffer.data() + sizeof(QueryAttachmentsResponse),
                       resp.Count * sizeof(AttachEntry));
            }
            return true;
        }

        DWORD err = GetLastError();
        if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_MORE_DATA) {
            if (bytesReturned >= sizeof(QueryAttachmentsResponse)) {
                QueryAttachmentsResponse resp;
                memcpy(&resp, outBuffer.data(), sizeof(resp));
                if (resp.NeededOutputBytes > outBuffer.size() &&
                    resp.NeededOutputBytes < 1 * 1024 * 1024) {
                    outBuffer.resize(resp.NeededOutputBytes);
                    continue;
                }
            }
            outSize *= 2;
            if (outSize > 1 * 1024 * 1024) {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return false;
            }
            outBuffer.resize(outSize);
            continue;
        }

        return false;
    }

    SetLastError(ERROR_RETRY);
    return false;
}

// ============================================================
// IOCTL_DUMP_DRIVER_MEMORY — dump 被附着设备所属驱动的内存映像
// ============================================================

// IOCTL_DUMP_DRIVER_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
//   = (0x22 << 16) | (0 << 14) | (0x809 << 2) | 0
//   = 0x220000 | 0x2024
//   = 0x222024
// (之前硬编码 0x22900C 是错的, 驱动根本不识别这个码, 走 default 返回 STATUS_INVALID_DEVICE_REQUEST)
const unsigned long IOCTL_DUMP_DRIVER_MEMORY =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS);

static_assert(sizeof(DumpDriverMemoryRequest) == 4, "DumpDriverMemoryRequest size mismatch");
// 默认 8 字节对齐:
//   Status(4) + pad(4) + DriverObjectAddr(8) + ImageBase(8) +
//   ImageSize(4) + BytesDumped(4) + FullPath(520) + BaseName(128) = 680
static_assert(sizeof(DumpDriverMemoryResponse) == 680, "DumpDriverMemoryResponse size mismatch");

bool DumpDriverMemoryViaKernel(void* hDevice,
                                unsigned long attachId,
                                std::vector<unsigned char>& outImage,
                                DumpDriverMemoryResponse* outResp)
{
    outImage.clear();
    if (outResp) *outResp = DumpDriverMemoryResponse{};

    HANDLE hDev = (HANDLE)hDevice;
    if (!hDev || hDev == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    DumpDriverMemoryRequest req{ attachId };
    DumpDriverMemoryResponse resp{};

    // 先用响应头大小探测一次:拿 ImageSize
    DWORD outSize = sizeof(DumpDriverMemoryResponse);
    std::vector<unsigned char> outBuf(outSize, 0);

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_DUMP_DRIVER_MEMORY,
                               &req, sizeof(req),
                               outBuf.data(), outSize,
                               &bytesReturned, nullptr);
    if (!ok || bytesReturned < sizeof(DumpDriverMemoryResponse)) {
        SetLastError(GetLastError());
        return false;
    }

    memcpy(&resp, outBuf.data(), sizeof(resp));
    if (resp.Status != 0) {
        // 内核返回失败 (如 STATUS_NOT_FOUND)
        if (outResp) *outResp = resp;
        SetLastError(ERROR_NOT_FOUND);
        return false;
    }

    // 第二次:用 ImageSize + 响应头大小, 拿完整映像
    outSize = sizeof(DumpDriverMemoryResponse) + resp.ImageSize;
    outBuf.assign(outSize, 0);

    ok = DeviceIoControl(hDev, IOCTL_DUMP_DRIVER_MEMORY,
                         &req, sizeof(req),
                         outBuf.data(), outSize,
                         &bytesReturned, nullptr);
    if (!ok || bytesReturned < sizeof(DumpDriverMemoryResponse)) {
        SetLastError(GetLastError());
        return false;
    }

    memcpy(&resp, outBuf.data(), sizeof(resp));
    if (resp.BytesDumped == 0 || resp.BytesDumped > resp.ImageSize) {
        if (outResp) *outResp = resp;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }

    // 提取映像数据 (紧跟响应头之后)
    outImage.assign(outBuf.data() + sizeof(DumpDriverMemoryResponse),
                   outBuf.data() + sizeof(DumpDriverMemoryResponse) + resp.BytesDumped);

    if (outResp) *outResp = resp;
    return true;
}

// ============================================================
// IOCTL_GAMEPROTECT_START / IOCTL_GAMEPROTECT_STOP
// 游戏进程句柄降级保护
// ============================================================

// IOCTL_GAMEPROTECT_START = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, ...)
//   = (0x22 << 16) | (0 << 14) | (0x80A << 2) | 0 = 0x222028
// IOCTL_GAMEPROTECT_STOP  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, ...)
//   = (0x22 << 16) | (0 << 14) | (0x80B << 2) | 0 = 0x22202C
const unsigned long IOCTL_GAMEPROTECT_START =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS);
const unsigned long IOCTL_GAMEPROTECT_STOP =
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS);

// GameProtectRequest: ULONG_PTR Pid = 8 字节 (x64)
static_assert(sizeof(GameProtectRequest) == 8, "GameProtectRequest size mismatch");

bool GameProtectStart(void* hDevice, unsigned long pid)
{
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    GameProtectRequest req = {};
    req.Pid = pid;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)hDevice, IOCTL_GAMEPROTECT_START,
        &req, sizeof(req),
        nullptr, 0,
        &bytesReturned, nullptr);

    if (!ok) {
        return false;
    }

    return true;
}

bool GameProtectStop(void* hDevice)
{
    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        (HANDLE)hDevice, IOCTL_GAMEPROTECT_STOP,
        nullptr, 0,
        nullptr, 0,
        &bytesReturned, nullptr);

    if (!ok) {
        return false;
    }

    return true;
}

} // namespace das
