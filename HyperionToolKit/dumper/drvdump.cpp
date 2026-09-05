#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "drvdump.h"
#include "../common/Out.h"
#include "../common/KernelComms.h"

#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>

namespace das {
	// 已 dump 的驱动 sys,按 AttachId 去重, 因为同一 AttachId 的对端驱动不变
	static std::unordered_set<unsigned long> g_driverDumped;

	// KernelService 设备句柄 + dumpfile/FileDump 路径,由 InitDriverDumper 设置
	// 这两个路径在 moddump.cpp 里是 static 的, drvdump 访问不到,
	// 所以这里维护一份副本, 通过 InitDriverDumper 传入。
	static void* g_hKernelService = nullptr;
	static std::wstring g_dumpDir;
	static std::wstring g_fileDumpDir;

	//  InitDriverDumper: 设置 KernelService 句柄 + dumpfile/FileDump 路径
	void InitDriverDumper(void* hKs, const std::wstring& dumpDir,
		const std::wstring& fileDumpDir)
	{
		g_hKernelService = hKs;
		g_dumpDir = dumpDir;
		g_fileDumpDir = fileDumpDir;
	}

	
	//  对端驱动 dump: 按 AttachId 通过 KernelService 从内核 dump 驱动内存映像
	//  - 同一 AttachId 只 dump 一次,对端驱动不变
	//  - 内核返回 sys 路径 (FullPath/BaseName):
	//      磁盘上有文件 → 拷贝到 FileDump\
	//      磁盘上没有   → 内存 dump 到 dumpfile\,文件名 MISSING_<BaseName>
	//  - 无论磁盘有没有, 都从内存 dump 一份到 dumpfile,内存态可能被 patch
	void DumpTargetDriver(unsigned long attachId)
	{
		if (attachId == 0) return;
		if (!g_hKernelService) return;

		// 同一 AttachId 只处理一次
		if (g_driverDumped.count(attachId) > 0) return;
		g_driverDumped.insert(attachId);

		// 复用 common/KernelComms: 内部两阶段,探测 ImageSize → 完整映像
		std::vector<unsigned char> image;
		DumpDriverMemoryResponse resp = {};
		if (!DumpDriverMemoryViaKernel(g_hKernelService, attachId, image, &resp)) {
			Out(L"  [驱动] dump 失败: err=" + std::to_wstring(GetLastError()) + L"\n");
			return;
		}

		std::wstring fullPath(resp.FullPath);
		std::wstring baseName(resp.BaseName);
		if (baseName.empty()) baseName = L"driver_" + std::to_wstring(attachId) + L".sys";

		// 内核返回的路径是 \SystemRoot\... 格式, 转成物理路径
		std::wstring physPath = fullPath;
		if (physPath.find(L"\\SystemRoot\\") == 0) {
			wchar_t sysRoot[MAX_PATH] = { 0 };
			GetWindowsDirectoryW(sysRoot, MAX_PATH);
			physPath = std::wstring(sysRoot) + L"\\" + physPath.substr(11);
		}
		else if (physPath.find(L"\\??\\") == 0) {
			physPath = physPath.substr(4);
		}

		Out(L"  [驱动] 对端 sys: " + (physPath.empty() ? baseName : physPath)
			+ L"  (ImageBase=0x" + std::to_wstring(resp.ImageBase)
			+ L" Size=" + std::to_wstring(resp.ImageSize) + L")\n");

		// 检查磁盘是否有文件
		DWORD attr = GetFileAttributesW(physPath.c_str());
		bool diskHas = (attr != INVALID_FILE_ATTRIBUTES);

		if (diskHas) {
			// 磁盘有 → 拷贝到 FileDump
			std::wstring copyName = baseName;
			if (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
				copyName = L"RHS_" + baseName;
			}
			std::wstring copyPath = g_fileDumpDir + L"\\" + copyName;
			BOOL cancel = FALSE;
			if (CopyFileExW(physPath.c_str(), copyPath.c_str(), NULL, NULL, &cancel, 0)) {
				Out(L"  [file] 已拷贝驱动: FileDump\\" + copyName + L"\n");
			}
			else {
				Out(L"  [file] 驱动拷贝失败: " + copyName
					+ L" err=" + std::to_wstring(GetLastError()) + L"\n");
			}
		}

		// 无论磁盘有没有, 都从内存 dump 一份到 dumpfile,内存态可能被 patch
		if (resp.ImageSize > 0 && !image.empty()) {
			// 文件名: 磁盘有 → baseName, 磁盘没有 → MISSING_baseName
			std::wstring dumpName = baseName;
			if (!diskHas) dumpName = L"MISSING_" + baseName;
			std::wstring dumpPath = g_dumpDir + L"\\" + dumpName;

			HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				Out(L"  [dump] 驱动 CreateFile 失败: " + dumpPath + L"\n");
				return;
			}
			DWORD written = 0;
			BOOL ok = WriteFile(hFile, image.data(), (DWORD)image.size(), &written, NULL);
			CloseHandle(hFile);
			if (ok && written == image.size()) {
				Out(L"  [dump] 驱动内存已保存: dumpfile\\" + dumpName
					+ L" (" + std::to_wstring(written) + L" 字节)\n");
			}
			else {
				Out(L"  [dump] 驱动 WriteFile 失败\n");
			}
		}
	}

} // namespace das