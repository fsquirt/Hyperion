#pragma once
#include <string>
#include <vector>

namespace das {

// 单个 DLL 的导入项
struct IatEntry {
    std::string dllName;            // 如 "ntoskrnl.exe" / "HAL.dll"
    std::vector<std::string> apis;  // API 名(按名字导入);ordinal 导入显示为 "(ordinal N)"
};

// 扫描 PE 文件的完整导入表(IAT)
// filePath: .sys 文件绝对路径
// outIat: 输出每个 DLL 的导入列表
// errorReason: 失败时填错误说明
// 返回 true 表示扫描成功(可能是空 IAT,只要流程走通就算成功)
bool ScanIat(const std::wstring& filePath,
             std::vector<IatEntry>& outIat,
             std::wstring& errorReason);

// 检查 IAT 中是否含高危内存操作函数
// 高危列表(用户指定):
//   MmCopyMemory        — 可跨进程读内核内存
//   MmMapIoSpace        — 可映射物理内存到虚拟地址(直接硬件操作)
//   ZwMapViewOfSection  — 可映射 section 到进程(BYOVD 经典)
//   MmCopyVirtualMemory — 可跨进程读写虚拟内存(反作弊常用)
// foundApis: 输出命中的 "dll!api" 列表
// 返回 true 表示命中至少一个
bool HasDangerousImports(const std::vector<IatEntry>& iat,
                         std::vector<std::string>& foundApis);

} // namespace das
