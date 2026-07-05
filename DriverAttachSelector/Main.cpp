// Main.cpp — DriverAttachSelector 主入口
//
// 命令行用法:
//   DriverAttachSelector.exe                      枚举已加载驱动并按签名分类
//   DriverAttachSelector.exe --scan-objects       扫描 \GLOBAL?? 和 \Device 命名空间
//   DriverAttachSelector.exe --scan-objects \Driver  扫描指定目录
//   DriverAttachSelector.exe --scan-objects \GLOBAL?? \Device \Driver  扫描多个目录
//   DriverAttachSelector.exe --help               显示此帮助

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

using namespace das;

// ═══════════════════════════════════════════════════════════════════════
//  帮助
// ═══════════════════════════════════════════════════════════════════════

static void PrintHelp() {
    WriteOut(L"用法:\n");
    WriteOut(L"  DriverAttachSelector.exe                      枚举已加载驱动并按签名分类\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects       扫描 \\GLOBAL?? 和 \\Device 命名空间\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects \\Driver  扫描指定目录\n");
    WriteOut(L"  DriverAttachSelector.exe --scan-objects \\GLOBAL?? \\Device \\Driver  扫描多个目录\n");
    WriteOut(L"  DriverAttachSelector.exe --help               显示此帮助\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 1:枚举已加载驱动并按签名分类
// ═══════════════════════════════════════════════════════════════════════

static int RunEnumAndClassify() {
    WriteOut(L"枚举已加载的内核驱动模块...\n\n");

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

    return RunEnumAndClassify();
}
