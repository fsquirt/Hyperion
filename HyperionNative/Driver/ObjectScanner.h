// ObjectScanner.h — 对象管理器命名空间扫描模块
//
// 类 WinObj 的功能:遍历 Windows 内核对象管理器的命名空间。
// 用 NTAPI(NtOpenDirectoryObject / NtQueryDirectoryObject 等)
// 扫描 \GLOBAL?? / \Device 等目录,列出对象名、类型、符号链接目标。
//
// 用途:供 DriverFilter 决策"哪些驱动暴露了符号链接 → 应用层可达"
//
// 实现说明:
//   - 所有 NTAPI 通过 GetProcAddress 从 ntdll.dll 动态加载,不依赖 SDK 头
//   - UNICODE_STRING / OBJECT_ATTRIBUTES 自定义,避免不同 SDK 下的定义冲突

#pragma once

#include <string>
#include <vector>
#include "Common.h"

namespace das {

// 初始化 NTAPI(从 ntdll 动态加载)
// 必须在调用 ScanDirectory 前调用一次
// 返回 false 表示初始化失败(无法加载 ntdll 函数)
bool InitNtApi();

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 枚举单个对象目录,收集条目但不打印
// dirPath 必须以 '\' 开头
// 返回 true 表示成功 (entries 可能为空)
bool EnumDirectoryData(const std::wstring& dirPath, std::vector<NtDirEntry>& entries);

// 递归枚举对象目录,收集所有条目(含子目录)但不打印
// maxDepth > 0 时限制递归深度
// 返回收集到的总条目数
size_t EnumDirectoryTreeData(const std::wstring& dirPath,
                             std::vector<NtDirEntry>& outAll,
                             int maxDepth = 0);

} // namespace das
