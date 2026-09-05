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