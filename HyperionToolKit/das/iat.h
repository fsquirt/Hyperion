// iat.h — PE 导入表 IAT 扫描,原 IatScanner
//
// 手动解析 PE32+ 导入表, 标记四个高危内存操作函数:
//   MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory
// 危险清单集中在此, 供 das 单文件模式 / 批量模式 / RunScanIAT 共用。

#pragma once
#include <string>
#include <vector>

namespace das {

	// 单个 DLL 的导入项
	struct IatEntry {
		std::string dllName;            // 如 "ntoskrnl.exe" / "HAL.dll"
		std::vector<std::string> apis;  // API 名,按名字导入;ordinal 导入显示为 "(ordinal N)"
	};

	// 扫描 PE 文件的完整导入表,即 IAT
	// 返回 true 表示扫描成功,可能是空 IAT,只要流程走通就算成功
	bool ScanIat(const std::wstring& filePath,
		std::vector<IatEntry>& outIat,
		std::wstring& errorReason);

	// 判断单个 API 名是否高危,供 RunScanIAT 单文件模式逐条标记
	bool IsDangerousImport(const std::string& apiName);

	// 检查 IAT 中是否含高危内存操作函数
	// foundApis: 输出命中的 "dll!api" 列表
	// 返回 true 表示命中至少一个
	bool HasDangerousImports(const std::vector<IatEntry>& iat,
		std::vector<std::string>& foundApis);

} // namespace das