// objects.h — 对象管理器命名空间扫描 (原 ObjectScanner)
//
// 类 WinObj:用 NTAPI(NtOpenDirectoryObject / NtQueryDirectoryObject 等)
// 扫描 \GLOBAL?? / \Device 等目录。NTAPI 统一由 common/NtApi 动态加载,
// 本模块不再重复定义 NT 结构(用 winternl.h 的 UNICODE_STRING/OBJECT_ATTRIBUTES)。

#pragma once
#include <string>
#include <vector>

namespace das {

	// 扫描并打印一个对象目录,返回总条目数
	// dirPath 必须以 '\' 开头,如 "\GLOBAL??" / "\Device"
	// maxDepth > 0 时递归子目录(限制深度避免无限递归)
	size_t ScanAndPrintDirectory(const std::wstring& dirPath, int maxDepth = 0);

	// 主入口:扫描多个对象命名空间目录
	// 返回退出码(0 成功,1 初始化失败)
	int ScanObjectNamespaces(const std::vector<std::wstring>& dirs);

} // namespace das