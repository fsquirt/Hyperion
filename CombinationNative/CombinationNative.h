#pragma once

#include <string>

// ═════════════════════════════════════════════════════════════════════
//  CombinationNative DLL 导出接口
//  整合 DriverAttachSelector / HeuristicDumper / ProcessTreeSnapshot
//  三个子项目的核心功能, 统一暴露为 C 语言接口 (extern "C"),
//  方便被 C# / C++ 等调用方 LoadLibrary + GetProcAddress 调用。
// ═════════════════════════════════════════════════════════════════════

#ifdef COMBINATION_NATIVE_EXPORTS
#define COMB_API __declspec(dllexport)
#else
#define COMB_API __declspec(dllimport)
#endif

extern "C" {

// ─── 初始化 ──────────────────────────────────────────────────────────
// 初始化 ntdll API (ProcessTreeSnapshot 依赖)
COMB_API int CombNative_InitNtdll();

// ─── DriverAttachSelector 功能 ───────────────────────────────────────
// 通过 KernelService 驱动扫描已加载内核模块
COMB_API int CombNative_RunKernelScan();

// 驱动扫描 + 应用层签名分类, 给出附着清单
COMB_API int CombNative_RunScanAndClassify();

// 扫描 + 分类 + 对 THIRD_PARTY_WHQL 清单逐个扫设备列表 + IAT
COMB_API int CombNative_RunScanAndEnumDevices();

// 对单个驱动名扫设备列表 (调试用)
COMB_API int CombNative_RunEnumDevices(const wchar_t* driverName);

// 扫描单个 .sys 文件的完整 IAT, 标记高危函数
COMB_API int CombNative_RunScanIAT(const wchar_t* filePath);

// 附着到指定设备, 如 L"\\Device\\Tcp"
COMB_API int CombNative_RunAttachDevice(const wchar_t* devicePath);

// 按 ID 或路径解绑附着
COMB_API int CombNative_RunUnattachDevice(const wchar_t* arg);

// 查询当前所有附着列表
COMB_API int CombNative_RunListAttachments();

// 用 PSAPI 本地枚举已加载驱动并按签名分类
COMB_API int CombNative_RunEnumAndClassify();

// 扫描对象管理器命名空间 (如 \GLOBAL??, \Device, \Driver)
// dirs: 以逗号分隔的目录列表, 如 L"\\GLOBAL??,\\Device"
COMB_API int CombNative_ScanObjectNamespaces(const wchar_t* dirs);

// ETW 实时订阅 IOCTL 事件
// durationSec: 0 = 永久直到 Ctrl+C
// etlPath: 非空时事件同时落盘到该 .etl 文件
COMB_API int CombNative_RunEtwConsumer(unsigned int durationSec, const wchar_t* etlPath);

// ─── HeuristicDumper 功能 ────────────────────────────────────────────
// 启动 ETW 通信监控
// durationSec: 0 = 永久直到 Ctrl+C
// enableJson: 是否启用 JSON 通信日志
COMB_API int CombNative_RunCommsMonitor(unsigned int durationSec, int enableJson);

// 扫描全系统句柄, 找出持有目标 PID 的 VM_READ (及更高危) 句柄的所有进程
COMB_API int CombNative_ScanHandlesForPid(unsigned long targetPid);

// ─── ProcessTreeSnapshot 功能 ────────────────────────────────────────
// 进程树打印模式
// pid: 0 = 整树, 非 0 = 只打印指定进程子树
// maxDepth: 0 = 不限制
// jsonOut: 非 0 = 输出扁平 JSON
COMB_API int CombNative_RunTreeMode(unsigned long long pid, int maxDepth, int jsonOut);

// 安全采集模式 (完整 JSON 输出)
// pid: 0 = 全系统
// flags: 位掩码 (bit0=noHandles, bit1=noMem, bit2=noThreads, bit3=noModules, bit4=noToken)
COMB_API int CombNative_RunSecurityMode(unsigned long long pid, unsigned int flags);

} // extern "C"