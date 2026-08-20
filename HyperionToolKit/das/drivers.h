// drivers.h — 已加载内核驱动枚举 (原 LoadedDrivers)
//
// 用 PSAPI 的 EnumDeviceDrivers 枚举当前已加载的所有内核驱动模块。
// 路径规范化 NormalizeDriverPath 供 das --ScanDriver / 批量分类共用。

#pragma once
#include <string>
#include <vector>
#include "../common/Common.h"

namespace das {

	// 枚举已加载的内核驱动
	bool EnumLoadedDrivers(std::vector<LoadedDriver>& drivers);

	// 把 PSAPI 返回的内核路径转换为可读的真实文件系统路径
	// 处理 \SystemRoot\... / \??\C:\... / \Device\HarddiskVolumeN\... 三种形式
	std::wstring NormalizeDriverPath(const std::wstring& raw);

} // namespace das