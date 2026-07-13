// MonitorTypes.h — 通信监控共享类型
//
// 拆分自 CommsMonitor.cpp, 收纳所有模块共享的类型与全局声明:
//   - EtwIoctlEventHeader: 内核端 ETW 事件头 (与 EtwConsumer.cpp / EtwLogger.h 字节对齐一致)
//   - ModuleRange / StackModuleInfo: 目标进程模块表 + 调用栈命中模块
//   - PathEntry: 路径去重表条目
//   - MonitorOptions: 命令行解析后的监控选项
//
// 本头文件无实现, ETW 常量与 g_Stop 的定义留在 CommsMonitor.cpp。

#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <atomic>

namespace das {

// 内核端 ETW IOCTL 事件头 (与 EtwConsumer.cpp / EtwLogger.h 字节对齐一致, 56 字节)
#pragma pack(push, 8)
struct EtwIoctlEventHeader {
    unsigned long       Version;
    unsigned long       IoControlCode;
    unsigned long       InputBufferLength;
    unsigned long       CaptureSize;
    unsigned long long  RequestorPid;
    unsigned long long  TargetDeviceAddr;
    unsigned long long  FilterDeviceAddr;
    unsigned long long  AttachId;
    unsigned long       MajorFunction;
    unsigned long       Method;
};
#pragma pack(pop)
static_assert(sizeof(EtwIoctlEventHeader) == 56, "EtwIoctlEventHeader size mismatch");

// 目标进程模块表 (调用栈符号化用)
struct ModuleRange {
    unsigned long long base;
    unsigned long size;
    wchar_t path[MAX_PATH];
};

// 调用栈命中的业务模块
struct StackModuleInfo {
    std::wstring path;
    unsigned long long base = 0;
    unsigned long size = 0;
};

// 路径表条目 (Ctrl+C 汇总用)
struct PathEntry {
    std::wstring  path;            // 文件完整路径
    std::wstring  tag;             // 来源标记: "进程 exe" / "栈模块"
    unsigned long pid = 0;          // 首次命中时的进程 PID (诊断用)
    bool          abnormal = false; // 不存在 或 含 RHS
    std::wstring  note;            // 异常说明 (如 "[RHS: R H]" / "[磁盘上不存在!]")
    unsigned long hitCount = 1;    // 该路径被通信命中的次数
    bool          dumped = false;  // 是否已 dump 成功 (内存映像)
    std::wstring  dumpFile;        // dump 文件名 (相对 dumpfile/ 目录)
    bool          fileCopied = false;  // 是否已拷贝磁盘文件到 FileDump
    std::wstring  fileCopyName;   // FileDump 里的副本文件名
};

// 监控选项 (由命令行解析后传入 RunCommsMonitor)
struct MonitorOptions {
    unsigned int durationSec = 0;     // 0 = 永久直到 Ctrl+C
    bool         enableJson = false;   // 是否启用 JSON 通信日志 (默认关闭, --json 开启)
    bool         enableMinidump = false;  // --minidump: MiniDumpNormal (体积中)
    bool         enableMifudump = false;  // --mifudump: Full Minidump (体积大)
};

// ETW 常量 (与 EtwConsumer.h 一致)
extern const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR;
extern const wchar_t* SESSION_NAME;

// 全局停止信号 (ETW 回调线程与主线程共享)
extern std::atomic<bool> g_Stop;

} // namespace das
