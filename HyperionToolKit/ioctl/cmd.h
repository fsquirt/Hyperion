// cmd.h — ioctl 子命令入口
//
// 向 \?\GLOBALROOT\Device\OpenArkDrv 发一个随机的未知 IOCTL 测试包,
// 验证 ETW 拦截链路能否抓到包 (配合 das --etw 使用)。

#pragma once

namespace das {

// 主入口: 发一个随机 IOCTL 测试包后退出
int RunIoctlSender();

} // namespace das