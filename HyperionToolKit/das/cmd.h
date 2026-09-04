// cmd.h — das 子命令入口,原 DriverAttachSelector, 由 HyperionToolKit.cpp 分发

#pragma once

namespace das {

	// DriverAttachSelector 工具入口
	// argv[0]=="das", argv[1..] 为原 DriverAttachSelector 的命令行参数
	int RunDriverAttachSelector(int argc, wchar_t** argv);

} // namespace das