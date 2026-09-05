#pragma once
#include <string>
#include <vector>
#include "../common/Common.h"

namespace das {

	// 对单个驱动文件做签名分类
	// filePath: 驱动文件全路径,即 .sys 文件
	ClassifyResult ClassifyDriver(const std::wstring& filePath);

	// 打印分类结果到 stdout,给单文件模式用
	void PrintClassifyResult(const std::wstring& filePath, const ClassifyResult& result);

	// 批量分类循环的一条输入
	struct ClassifySource {
		std::wstring name;        // 模块名,如 "tcpip.sys"
		std::wstring rawPath;     // 原始路径,kernel: "\SystemRoot\..."; PSAPI: 绝对路径
		std::wstring objectName;  // 内核反查的 DriverObjectName,PSAPI 模式留空
	};

	// 批量分类 + 逐行打印 + 汇总 + 附着清单
	// entries:   待分类条目
	// psapiMode: true = PSAPI 本地模式,前缀 [----], 不打印对象名
	// 经引用返回:
	//   thirdPartyDriverObjectNames — 每个待附着驱动的 DriverObjectName,内核模式用
	//   thirdPartyFilePaths         — 每个待附着驱动的规范化路径,供 IAT 扫描
	// 返回值: thirdPartyList = {文件名, 厂商/备注}
	std::vector<std::pair<std::wstring, std::wstring>>
		ClassifyAndPrintDrivers(const std::vector<ClassifySource>& entries,
			bool psapiMode,
			std::vector<std::wstring>& thirdPartyDriverObjectNames,
			std::vector<std::wstring>& thirdPartyFilePaths);

} // namespace das