// LoadedDrivers.cpp — 已加载内核驱动枚举实现

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include "LoadedDrivers.h"

#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace das {

// 把 PSAPI 返回的内核路径转换为可读的真实文件系统路径
// 常见格式:
//   \SystemRoot\System32\drivers\xxx.sys
//   \??\C:\Windows\System32\drivers\xxx.sys
//   \Device\HarddiskVolumeN\Windows\...
std::wstring NormalizeDriverPath(const std::wstring& raw) {
    if (raw.empty()) return L"";

    // 已是绝对路径
    if (raw.size() >= 2 && raw[1] == L':') return raw;

    // \??\C:\... 前缀
    if (raw.rfind(L"\\??\\", 0) == 0) return raw.substr(4);

    // \SystemRoot\... → C:\Windows\...
    if (_wcsicmp(raw.c_str(), L"\\SystemRoot") == 0 ||
        raw.rfind(L"\\SystemRoot\\", 0) == 0) {
        wchar_t sysDir[MAX_PATH] = {};
        GetWindowsDirectoryW(sysDir, MAX_PATH);
        return std::wstring(sysDir) + L"\\" + raw.substr(11);
    }

    // \Device\HarddiskVolumeN\... → 用 QueryDosDevice 反查盘符
    if (raw.rfind(L"\\Device\\", 0) == 0) {
        size_t devEnd = raw.find(L'\\', 8); // 跳过 "\Device\"
        if (devEnd == std::wstring::npos) return raw;
        std::wstring devicePrefix = raw.substr(0, devEnd);
        std::wstring remaining = raw.substr(devEnd + 1);

        wchar_t drives[256] = {};
        DWORD len = GetLogicalDriveStringsW(255, drives);
        for (DWORD i = 0; i < len; ) {
            std::wstring drive(drives + i);
            i += drive.size() + 1;
            if (drive.empty()) continue;

            std::wstring driveLetter = drive.substr(0, 2); // "C:"
            wchar_t target[MAX_PATH] = {};
            if (QueryDosDeviceW(driveLetter.c_str(), target, MAX_PATH) > 0) {
                if (_wcsicmp(target, devicePrefix.c_str()) == 0) {
                    return drive + remaining;
                }
            }
        }
    }

    return raw;
}

bool EnumLoadedDrivers(std::vector<LoadedDriver>& drivers) {
    drivers.clear();

    // 第一次调用获取所需字节数
    DWORD needed = 0;
    if (!EnumDeviceDrivers(nullptr, 0, &needed) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        if (needed == 0) return false;
    }
    if (needed == 0) return false;

    std::vector<LPVOID> bases(needed / sizeof(LPVOID));
    if (!EnumDeviceDrivers(bases.data(), needed, &needed)) {
        return false;
    }

    DWORD count = needed / sizeof(LPVOID);
    drivers.reserve(count);

    wchar_t nameBuf[1024];
    wchar_t pathBuf[MAX_PATH];

    for (DWORD i = 0; i < count; i++) {
        if (!bases[i]) continue;

        nameBuf[0] = 0;
        pathBuf[0] = 0;

        std::wstring name, path;
        if (GetDeviceDriverBaseNameW(bases[i], nameBuf, 1024) > 0) {
            name = nameBuf;
        }
        if (GetDeviceDriverFileNameW(bases[i], pathBuf, MAX_PATH) > 0) {
            path = NormalizeDriverPath(pathBuf);
        }

        // 模块大小:PSAPI 的 GetModuleInformation 对内核驱动需要 hProcess = GetCurrentProcess()
        // 但驱动基址是内核地址,GetModuleInformation 可能失败,失败就 0
        DWORD size = 0;
        drivers.push_back({name, path, (ULONGLONG)bases[i], size});
    }

    return true;
}

} // namespace das
