// KernelComms.h — 与 KernelService 驱动通信
//
// 通过 IOCTL 调用 KernelService 驱动,获取内核已加载驱动模块列表。
//
// 数据流:
//   1. 应用层 OpenKernelService() → 打开 \\.\KernelService
//   2. 应用层 ScanLoadedDriversViaKernel() → IOCTL_SCAN_LOADED_DRIVERS
//   3. 驱动用 ZwQuerySystemInformation(SystemModuleInformation) 扫描
//      PsLoadedModuleList 双向链表,返回模块列表
//   4. 应用层拿到列表后可做 WinVerifyTrust 验签决定附着候选
//
// 注意:
//   - 必须以管理员权限运行,否则 CreateFile 会返回 ERROR_ACCESS_DENIED
//   - KernelService 的 SDDL 是 D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;WD)
//     允许 SYSTEM/Admins 全访问,普通用户只能读(无法发 IOCTL)
//   - IOCTL 用 METHOD_BUFFERED,InputBufferLength/OutputBufferLength 必须正确

#pragma once

#include <string>
#include <vector>
#include "Common.h"

namespace das {

// KernelService 设备符号链接 \\.\KernelService → \Device\KernelService
// (驱动用 \DosDevices\KernelService 创建符号链接)
extern const wchar_t* KERNEL_SERVICE_DOS_NAME;

// IOCTL_SCAN_LOADED_DRIVERS = 0x222004
// 由驱动端定义,应用层必须保持一致
extern const unsigned long IOCTL_SCAN_LOADED_DRIVERS;

// 输入请求(与驱动端 SCAN_DRIVERS_REQUEST 一致)
struct ScanDriversRequest {
    unsigned long MaxEntries;   // 0 = 返回所有已加载模块
                                // >0 = 最多返回这么多条目
};

// 单条已加载驱动模块信息(与驱动端 LOADED_DRIVER_ENTRY 一致,定长便于序列化)
struct LoadedDriverEntry {
    unsigned long long ImageBase;          // 映像基址(内核地址)
    unsigned long       ImageSize;         // 映像大小(字节)
    unsigned short      LoadOrderIndex;    // 加载序号
    unsigned short      Flags;             // 模块标志
    wchar_t             ModuleName[64];    // 模块短名 (如 "ntoskrnl.exe")
    wchar_t             FullPath[260];     // 完整路径 (如 "\SystemRoot\System32\drivers\tcpip.sys")
};

// 输出响应(与驱动端 SCAN_DRIVERS_RESPONSE 一致,后跟 entries 数组)
struct ScanDriversResponse {
    unsigned long   EntryCount;         // 实际返回的条目数
    unsigned long   TotalCount;         // 内核扫描到的总数(可能 > EntryCount)
    unsigned long   NeededOutputBytes;  // 完整返回所需的总输出字节数
    long            ScanStatus;         // 扫描内部状态
    // 紧跟 LoadedDriverEntry entries[EntryCount]
};

// 打开 KernelService 设备句柄
// 返回 INVALID_HANDLE_VALUE 表示失败,用 GetLastError() 查错误码
//   常见错误:
//     ERROR_ACCESS_DENIED (5)   - 未以管理员权限运行
//     ERROR_FILE_NOT_FOUND (2)  - 驱动未加载
void* OpenKernelService();

// 关闭句柄
void CloseKernelService(void* hDevice);

// 调用驱动扫描已加载内核驱动模块
// hDevice: OpenKernelService 返回的句柄
// maxEntries: 0 = 返回所有;>0 = 限制返回数量
// outDrivers: 输出参数,扫描结果填入此 vector
// 返回 true 成功;false 失败(用 GetLastError() 查错误码)
//
// 内部会处理 STATUS_BUFFER_TOO_SMALL 自动重试:
//   第一次用 64KB 估算,不够则按驱动返回的 NeededOutputBytes 重发
bool ScanLoadedDriversViaKernel(void* hDevice,
                                 unsigned long maxEntries,
                                 std::vector<LoadedDriverEntry>& outDrivers);

} // namespace das
