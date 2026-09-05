// moddump.h
//
// 三种 dump 模式, 由全局开关 SetDumpMode 控制:
//   - Raw,默认: 原始内存镜像 ReadProcessMemory, 按模块路径去重
//   - Mini:       MiniDumpNormal, 按 PID 去重,体积中
//   - Mifudump:   Full Minidump MiniDumpWriteDump, 按 PID 去重,体积大
// 磁盘上存在的文件拷贝到 FileDump\。

#pragma once

#include <string>
#include <windows.h>

namespace das {
	// dump 模式
	enum class DumpMode {
		Raw,       // 原始内存镜像,默认, 体积小
		Mini,      // MiniDumpNormal,基本线程/模块/堆栈, 体积中
		Mifudump,  // Full Minidump,MiniDumpWithFullMemory, 体积大
	};

	// 设置 dump 模式,RunCommsMonitor 启动时调用
	void SetDumpMode(DumpMode mode);

	// 初始化 dumpfile\ 目录
	bool InitDumpDir();

	// 初始化 FileDump\ 目录
	bool InitFileDumpDir();

	// dump 模块,按 SetDumpMode 走 Raw / Mini / Mifudump 分支
	//   Raw:      按 modulePath 去重, 需 base/size, abnormal/note 决定文件名前缀
	//   Mini/Mifudump: 按 pid 去重, 不需要 base/size
	// 成功返回 true, outDumpFile 填入相对文件名
	bool DumpModule(HANDLE hProcess, unsigned long pid,
		const std::wstring& modulePath,
		unsigned long long base, unsigned long size,
		bool abnormal, const std::wstring& note,
		std::wstring& outDumpFile);

	// 若磁盘有文件, 拷贝到 FileDump\,RHS 文件加前缀
	void CopyFileFromDisk(const std::wstring& modulePath, bool abnormal,
		std::wstring& outCopyName, bool& outCopied);

	// dump 目录访问器,供 drvdump / pathlog 等模块取路径用
	const std::wstring& GetDumpDir();
	const std::wstring& GetFileDumpDir();

} // namespace das