// ModuleDumper.h — 用户态模块内存 dump + 磁盘文件拷贝
//
// 从目标进程读模块内存映像写到 dumpfile\, 并把磁盘上存在的文件拷贝到 FileDump\。
// 实现在 ModuleDumper.cpp。

#pragma once

#include <string>
#include <windows.h>

namespace das {

// 初始化 dumpfile\ 目录 (内存映像输出)
bool InitDumpDir();

// 初始化 FileDump\ 目录 (磁盘文件副本)
bool InitFileDumpDir();

// 从目标进程读模块内存映像, 写到 dumpfile\
// abnormal/note 用于决定文件名前缀 (MISSING_ / RHS_)
// 成功返回 true, outDumpFile 填入相对文件名
bool DumpModule(HANDLE hProcess, unsigned long pid,
                const std::wstring& modulePath,
                unsigned long long base, unsigned long size,
                bool abnormal, const std::wstring& note,
                std::wstring& outDumpFile);

// 若磁盘有文件, 拷贝到 FileDump\ (RHS 加前缀)
void CopyFileFromDisk(const std::wstring& modulePath, bool abnormal,
                     std::wstring& outCopyName, bool& outCopied);

// dump 目录访问器 (供 DriverDumper / PathTracker 等模块取路径用)
const std::wstring& GetDumpDir();
const std::wstring& GetFileDumpDir();

} // namespace das
