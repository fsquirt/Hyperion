// attach.h — 设备附着/解绑/查询,原 Main.cpp 的 --attach / --unattach / --list-attach
//
// 数据流:应用层发 IOCTL_ATTACH_DEVICE → 驱动 IoCreateDevice (FiDO) →
// IoAttachDeviceToDeviceStack → IRP 透传。协议实现见 common/KernelComms。

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