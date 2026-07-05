// LoadedDrivers.h — 已加载内核驱动枚举模块
//
// 用 PSAPI 的 EnumDeviceDrivers 枚举当前已加载的所有内核驱动模块,
// 返回每个驱动的模块名、文件路径、基址、大小。

#pragma once

#include <string>
#include <vector>
#include "Common.h"

namespace das {

// 枚举已加载的内核驱动
// 返回 true 表示成功(drivers 填充);false 表示 PSAPI 调用失败
bool EnumLoadedDrivers(std::vector<LoadedDriver>& drivers);

// 把 PSAPI 返回的内核路径转换为可读的真实文件系统路径
// 处理 \SystemRoot\... / \??\C:\... / \Device\HarddiskVolumeN\... 三种形式
std::wstring NormalizeDriverPath(const std::wstring& raw);

} // namespace das
