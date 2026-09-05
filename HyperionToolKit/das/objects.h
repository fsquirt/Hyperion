// objects.h — 对象管理器命名空间扫描
#pragma once
#include <string>
#include <vector>

namespace das {

	// 扫描并打印一个对象目录,返回总条目数
	// dirPath 必须以 '\' 开头,如 "\GLOBAL??" / "\Device"
	// maxDepth > 0 时递归子目录,限制深度避免无限递归
	size_t ScanAndPrintDirectory(const std::wstring& dirPath, int maxDepth = 0);

	// 主入口:扫描多个对象命名空间目录
	// 返回退出码,0 成功,1 初始化失败
	int ScanObjectNamespaces(const std::vector<std::wstring>& dirs);

} // namespace das