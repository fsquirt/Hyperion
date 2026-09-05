// attach.h — 设备附着/解绑/查询

#pragma once
#include <string>

namespace das {

	// --attach <\Device\X> 附着到指定设备
	int RunAttachDevice(const std::wstring& devicePath);

	// --unattach <Id|路径> 解绑指定附着
	int RunUnattachDevice(const std::wstring& arg);

	// --list-attach 查询当前所有附着
	int RunListAttachments();

} // namespace das