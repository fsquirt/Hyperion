// Main.cpp — DriverAttachSelector 主入口
//
// 命令行用法:
//   DriverAttachSelector.exe                      通过 KernelService 驱动扫描已加载内核模块
//   DriverAttachSelector.exe --ScanDriver         用 PSAPI 本地枚举已加载驱动并按签名分类
//   DriverAttachSelector.exe --scan-objects       扫描 \GLOBAL?? 和 \Device 命名空间
//   DriverAttachSelector.exe --scan-objects \Driver  扫描指定目录
//   DriverAttachSelector.exe --scan-objects \GLOBAL?? \Device \Driver  扫描多个目录
//   DriverAttachSelector.exe --help               显示此帮助
//
// 设计说明:
//   - 无参数(默认)= 驱动通信模式,调 KernelService 扫描 PsLoadedModuleList
//     这是后续附着流程的入口:驱动扫 → 应用层验签 → 应用层把目标丢回驱动附着
//   - --ScanDriver = PSAPI 模式,仅本地枚举,不需要驱动,主要用于离线调试
//   - --scan-objects = NTAPI 对象管理器扫描,完全独立的功能

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "Common.h"
#include "DriverClassify.h"
#include "LoadedDrivers.h"
#include "ObjectScanner.h"
#include "KernelComms.h"

using namespace das;

// ═══════════════════════════════════════════════════════════════════════
//  帮助
// ═══════════════════════════════════════════════════════════════════════

static void PrintHelp() {
    WriteOut(L"用法:\n");
    WriteOut(L"  DriverAttachSelector.exe                      通过 KernelService 驱动扫描已加载内核模块\n");
    WriteOut(L"  DriverAttachSelector.exe --ScanDriver         用 PSAPI 本地枚举并按签名分类(离线调试)\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects       扫描 \\GLOBAL?? 和 \\Device 命名空间\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects \\Driver  扫描指定目录\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects \\GLOBAL?? \\Device \\Driver  扫描多个目录\n");
    WriteOut(L"  DriverAttachSelector.exe --help               显示此帮助\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 1:通过 KernelService 驱动扫描已加载内核模块
//  数据流:应用层发 IOCTL → 驱动 ZwQuerySystemInformation 扫 PsLoadedModuleList
//         → 应用层拿到模块列表(基址/大小/路径)
//  本步只做扫描和打印,不做验签和附着(后续步骤)
// ═══════════════════════════════════════════════════════════════════════

static int RunKernelScan() {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  通过 KernelService 驱动扫描已加载内核模块\n");
    WriteOut(L"  (驱动用 ZwQuerySystemInformation 扫 PsLoadedModuleList)\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // 1. 打开驱动设备
    WriteOut(L"[1/2] 打开 KernelService 设备...\n");
    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::wostringstream ss;
        ss << L"  失败: CreateFile 失败,错误码=" << err << L"\n";
        if (err == ERROR_ACCESS_DENIED) {
            ss << L"  原因: 需要管理员权限运行\n";
        } else if (err == ERROR_FILE_NOT_FOUND) {
            ss << L"  原因: KernelService 驱动未加载 (sc start KernelService)\n";
        }
        WriteOut(ss.str());
        return 1;
    }
    WriteOut(L"  成功打开设备 \\\\.\\KernelService\n\n");

    // 2. 调驱动扫描
    WriteOut(L"[2/2] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
    std::vector<LoadedDriverEntry> drivers;
    if (!ScanLoadedDriversViaKernel(hDevice, 0, drivers)) {
        DWORD err = GetLastError();
        std::wostringstream ss;
        ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
        WriteOut(ss.str());
        CloseKernelService(hDevice);
        return 1;
    }
    WriteOut(L"  成功扫描到 " + std::to_wstring(drivers.size()) + L" 个内核模块\n\n");
    CloseKernelService(hDevice);

    // 3. 打印列表
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    WriteOut(L"  序号  加载序  基址              大小        模块名\n");
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    std::wostringstream ss;
    for (size_t i = 0; i < drivers.size(); i++) {
        const auto& d = drivers[i];
        ss << L"[" << std::setw(4) << (i + 1) << L"] "
           << L"#" << std::setw(3) << std::left << d.LoadOrderIndex << L" "
           << L"0x" << std::hex << std::setw(12) << std::setfill(L'0') << d.ImageBase
           << std::dec << std::setfill(L' ')
           << L"  " << std::setw(10) << d.ImageSize
           << L"  " << d.ModuleName
           << L"\n";
    }
    WriteOut(ss.str());

    WriteOut(L"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    WriteOut(L"扫描完成,共 " + std::to_wstring(drivers.size()) + L" 个模块\n");

    // 完整路径单独打印一份(便于核对)
    WriteOut(L"\n完整路径清单:\n");
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    std::wostringstream pathSs;
    for (size_t i = 0; i < drivers.size(); i++) {
        const auto& d = drivers[i];
        pathSs << L"[" << std::setw(4) << (i + 1) << L"] "
               << std::left << std::setw(40) << d.ModuleName
               << L"  " << d.FullPath << L"\n";
    }
    WriteOut(pathSs.str());
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 2:--ScanDriver 用 PSAPI 本地枚举并按签名分类
// ═══════════════════════════════════════════════════════════════════════

static int RunEnumAndClassify() {
    WriteOut(L"枚举已加载的内核驱动模块(PSAPI 本地模式)...\n\n");

    std::vector<LoadedDriver> drivers;
    if (!EnumLoadedDrivers(drivers)) {
        WriteOut(L"EnumDeviceDrivers 失败,错误码: " + std::to_wstring(GetLastError()) + L"\n");
        return 1;
    }

    WriteOut(L"共枚举到 " + std::to_wstring(drivers.size()) + L" 个已加载驱动,开始分类...\n\n");

    int countInbox = 0, countMicrosoft = 0, countThirdParty = 0, countUntrusted = 0;
    int total = 0;
    int skipped = 0;

    std::vector<std::pair<std::wstring, std::wstring>> thirdPartyList;

    for (const auto& d : drivers) {
        std::wstring fileName = d.name;
        std::wstring filePath = d.path;

        if (filePath.empty() || GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            skipped++;
            std::wostringstream line;
            line << L"[----] " << std::left << std::setw(40) << fileName
                 << L"  (跳过:无文件路径)\n";
            WriteOut(line.str());
            continue;
        }

        ClassifyResult result = ClassifyDriver(filePath);
        total++;

        switch (result.klass) {
            case DriverClass::INBOX:            countInbox++; break;
            case DriverClass::MICROSOFT:        countMicrosoft++; break;
            case DriverClass::THIRD_PARTY_WHQL:
                countThirdParty++;
                thirdPartyList.push_back({fileName, result.vendorName});
                break;
            case DriverClass::UNTRUSTED:        countUntrusted++; break;
        }

        std::wostringstream line;
        line << L"[" << std::setw(4) << total << L"] "
             << std::left << std::setw(40) << fileName
             << L"  " << ClassToString(result.klass);
        if (result.klass == DriverClass::THIRD_PARTY_WHQL && !result.vendorName.empty()) {
            line << L"  厂商=" << result.vendorName;
        }
        if (result.klass == DriverClass::UNTRUSTED && !result.errorReason.empty()) {
            line << L"  (" << result.errorReason << L")";
        }
        line << L"\n";
        WriteOut(line.str());
    }

    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"汇总:\n";
    sum << L"  已加载驱动总数:  " << drivers.size() << L"\n";
    sum << L"  分类成功:        " << total << L"\n";
    sum << L"  跳过(无路径):   " << skipped << L"\n";
    sum << L"  INBOX:           " << countInbox << L"  (放过)\n";
    sum << L"  MICROSOFT:       " << countMicrosoft << L"  (放过)\n";
    sum << L"  THIRD_PARTY_WHQL:" << countThirdParty << L"  (待附着)\n";
    sum << L"  UNTRUSTED:       " << countUntrusted << L"  (异常)\n";
    sum << L"═══════════════════════════════════════════════════════\n";

    if (!thirdPartyList.empty()) {
        sum << L"待附着清单(THIRD_PARTY_WHQL):\n";
        for (const auto& [name, vendor] : thirdPartyList) {
            sum << L"  " << std::left << std::setw(40) << name;
            if (!vendor.empty()) sum << L"  " << vendor;
            sum << L"\n";
        }
        sum << L"═══════════════════════════════════════════════════════\n";
    }

    WriteOut(sum.str());
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  wmain
// ═══════════════════════════════════════════════════════════════════════

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    if (argc >= 2) {
        std::wstring arg1 = argv[1];

        if (arg1 == L"--help" || arg1 == L"-h") {
            PrintHelp();
            return 0;
        }

        if (arg1 == L"--ScanDriver") {
            // PSAPI 本地模式:不需要驱动,直接 EnumDeviceDrivers
            return RunEnumAndClassify();
        }

        if (arg1 == L"--scan-objects") {
            std::vector<std::wstring> dirs;
            for (int i = 2; i < argc; i++) {
                std::wstring d = argv[i];
                if (!d.empty() && d[0] != L'\\') d = L"\\" + d;
                dirs.push_back(d);
            }
            if (dirs.empty()) {
                dirs.push_back(L"\\GLOBAL??");
                dirs.push_back(L"\\Device");
            }
            return ScanObjectNamespaces(dirs);
        }
    }

    // 默认:驱动通信模式
    return RunKernelScan();
}
