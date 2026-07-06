// Main.cpp — DriverAttachSelector 主入口
//
// 命令行用法:
//   DriverAttachSelector.exe                      通过 KernelService 驱动扫描已加载内核模块
//   DriverAttachSelector.exe --ScanAndClassify    驱动扫描 + 应用层签名分类,给出附着清单
//   DriverAttachSelector.exe --ScanAndEnumDevices 扫描+分类+对 THIRD_PARTY_WHQL 清单逐个扫设备列表
//   DriverAttachSelector.exe --EnumDevices <Name> 对单个驱动名扫设备列表(调试用)
//   DriverAttachSelector.exe --ScanIAT <sys文件>  扫单个 .sys 的完整 IAT,标记高危函数
//   DriverAttachSelector.exe --attach <\Device\X> 附着到指定设备(如 --attach \Device\Tcp)
//   DriverAttachSelector.exe --unattach <Id|路径> 按 ID 或路径解绑附着
//   DriverAttachSelector.exe --list-attach       查询当前所有附着列表
//   DriverAttachSelector.exe --ScanDriver         用 PSAPI 本地枚举已加载驱动并按签名分类
//   DriverAttachSelector.exe --scan-objects       扫描 \GLOBAL?? 和 \Device 命名空间
//   DriverAttachSelector.exe --scan-objects \Driver  扫描指定目录
//   DriverAttachSelector.exe --scan-objects \GLOBAL?? \Device \Driver  扫描多个目录
//   DriverAttachSelector.exe --help               显示此帮助
//
// 设计说明:
//   - 无参数(默认)= 驱动通信模式,调 KernelService 扫描 PsLoadedModuleList
//     这是后续附着流程的入口:驱动扫 → 应用层验签 → 应用层把目标丢回驱动附着
//   - --ScanAndClassify = 在无参数基础上,对每个驱动做 WinVerifyTrust 验签,
//     按 INBOX/MICROSOFT/THIRD_PARTY_WHQL/UNTRUSTED 四类分类,产出 THIRD_PARTY_WHQL 附着清单
//   - --ScanAndEnumDevices = 在 --ScanAndClassify 基础上,对清单中每个驱动调
//     IOCTL_ENUM_DRIVER_DEVICES,内核用 ObReferenceObjectByName 找 DRIVER_OBJECT,
//     遍历 DeviceObject->NextDevice 链返回设备列表
//   - --EnumDevices <Name> = 单驱动调试模式,直接对指定驱动名扫设备列表
//   - --ScanIAT = 纯用户态扫 IAT
//   - --attach = 设备附着,内核用 IoCreateDriver 创建独立 DriverObject,
//     IoCreateDevice 创建 FiDO,IoAttachDeviceToDeviceStack 挂到设备栈顶,IRP 透传
//   - --unattach = IoDetachDevice + IoDeleteDevice 解绑
//   - --list-attach = 查询当前所有附着的列表(ID/路径/栈深/地址)
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
#include "IatScanner.h"

using namespace das;

// ═══════════════════════════════════════════════════════════════════════
//  帮助
// ═══════════════════════════════════════════════════════════════════════

static void PrintHelp() {
    WriteOut(L"用法:\n");
    WriteOut(L"  DriverAttachSelector.exe                      通过 KernelService 驱动扫描已加载内核模块\n");
    WriteOut(L"  DriverAttachSelector.exe --ScanAndClassify    驱动扫描 + 应用层签名分类,给出附着清单\n");
    WriteOut(L"  DriverAttachSelector.exe --ScanAndEnumDevices 扫描+分类+对 THIRD_PARTY_WHQL 清单逐个扫设备列表\n");
    WriteOut(L"  DriverAttachSelector.exe --EnumDevices <Name> 对单个驱动名扫设备列表(调试用,如 --EnumDevices tcpip)\n");
    WriteOut(L"  DriverAttachSelector.exe --ScanIAT <sys文件>  扫单个 .sys 的完整 IAT,标记高危函数(纯用户态)\n");
    WriteOut(L"  DriverAttachSelector.exe --attach <\\Device\\X> 附着到指定设备(如 --attach \\Device\\Tcp)\n");
    WriteOut(L"  DriverAttachSelector.exe --unattach <Id|路径> 按 ID 或路径解绑(如 --unattach 1 或 --unattach \\Device\\Tcp)\n");
    WriteOut(L"  DriverAttachSelector.exe --list-attach       查询当前所有附着列表\n");
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
    WriteOut(L"  序号  加载序  基址              大小        模块名                驱动对象名\n");
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    std::wostringstream ss;
    for (size_t i = 0; i < drivers.size(); i++) {
        const auto& d = drivers[i];
        ss << L"[" << std::setw(4) << (i + 1) << L"] "
           << L"#" << std::setw(3) << std::left << d.LoadOrderIndex << L" "
           << L"0x" << std::hex << std::setw(12) << std::setfill(L'0') << d.ImageBase
           << std::dec << std::setfill(L' ')
           << L"  " << std::setw(10) << d.ImageSize
           << L"  " << std::left << std::setw(20) << d.ModuleName;
        if (d.DriverObjectName[0] != L'\0') {
            ss << L"  " << d.DriverObjectName;
        } else {
            ss << L"  -";
        }
        ss << L"\n";
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
//  辅助:对已加载驱动列表做路径规范化 + 签名分类,逐行打印分类结果,
//        最后打印汇总 + 附着清单
//
//  调用方负责打印 "[N/M] 路径规范化 + 签名分类..." 这种步骤标题
//  本函数只做分类 + 逐行打印 + 汇总 + 附着清单输出
//
//  返回值:thirdPartyList = 待附着清单 vector<{fileName, vendorOrNote}>
//         同时通过引用参数返回:
//           thirdPartyDriverObjectNames:每个待附着驱动对应的 DriverObjectName
//                                        (内核用 ImageBase 反查,空表示没 DriverObject)
//           thirdPartyFilePaths:每个待附着驱动对应的规范化文件路径(空表示无路径)
//                                供后续 IAT 扫描使用
// ═══════════════════════════════════════════════════════════════════════

static std::vector<std::pair<std::wstring, std::wstring>>
ClassifyAndPrintDrivers(const std::vector<LoadedDriverEntry>& drivers,
                        std::vector<std::wstring>& thirdPartyDriverObjectNames,
                        std::vector<std::wstring>& thirdPartyFilePaths)
{
    thirdPartyDriverObjectNames.clear();
    thirdPartyFilePaths.clear();

    int countInbox = 0, countMicrosoft = 0, countThirdParty = 0, countUntrusted = 0;
    int total = 0, skipped = 0;
    std::vector<std::pair<std::wstring, std::wstring>> thirdPartyList;

    size_t idx = 0;

    for (const auto& d : drivers) {
        idx++;
        std::wstring fileName = d.ModuleName;
        std::wstring rawPath = d.FullPath;
        std::wstring driverObjName = d.DriverObjectName;

        // 规范化路径:\SystemRoot\... / \??\C:\... → C:\...
        std::wstring filePath = NormalizeDriverPath(rawPath);

        if (filePath.empty() || GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            // 无路径/文件不存在 — 归入待附着清单(异常驱动,需人工核查)
            skipped++;
            countThirdParty++;
            thirdPartyList.push_back({fileName, L"(无路径,需人工核查)"});
            thirdPartyDriverObjectNames.push_back(driverObjName);
            thirdPartyFilePaths.push_back(L"");   // 无路径

            std::wostringstream line;
            line << L"[" << std::setw(4) << idx << L"] "
                 << std::left << std::setw(40) << fileName
                 << L"  THIRD_PARTY_WHQL  (无路径,归入待附着 raw=" << rawPath << L")\n";
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
                thirdPartyDriverObjectNames.push_back(driverObjName);
                thirdPartyFilePaths.push_back(filePath);
                break;
            case DriverClass::UNTRUSTED:
                // 无签名/验签失败 — HVCI 下不应存在,归入待附着清单(异常驱动)
                countUntrusted++;
                countThirdParty++;
                thirdPartyList.push_back({fileName, result.errorReason.empty() ? L"(UNTRUSTED)" : L"(UNTRUSTED: " + result.errorReason + L")"});
                thirdPartyDriverObjectNames.push_back(driverObjName);
                thirdPartyFilePaths.push_back(filePath);
                break;
        }

        std::wostringstream line;
        line << L"[" << std::setw(4) << idx << L"] "
             << std::left << std::setw(40) << fileName
             << L"  " << ClassToString(result.klass);
        if (result.klass == DriverClass::THIRD_PARTY_WHQL && !result.vendorName.empty()) {
            line << L"  厂商=" << result.vendorName;
        }
        if (result.klass == DriverClass::UNTRUSTED && !result.errorReason.empty()) {
            line << L"  (" << result.errorReason << L")  → 已归入待附着";
        }
        line << L"\n";
        WriteOut(line.str());
    }

    // 汇总 + 附着清单
    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"汇总:\n";
    sum << L"  已加载驱动总数:  " << drivers.size() << L"\n";
    sum << L"  分类成功:        " << total << L"\n";
    sum << L"  无路径(归入待附着): " << skipped << L"\n";
    sum << L"  INBOX:           " << countInbox << L"  (放过)\n";
    sum << L"  MICROSOFT:       " << countMicrosoft << L"  (放过)\n";
    sum << L"  THIRD_PARTY_WHQL:" << countThirdParty << L"  (待附着,含无路径/UNTRUSTED)\n";
    sum << L"    其中 UNTRUSTED: " << countUntrusted << L"  (异常,需人工核查)\n";
    sum << L"═══════════════════════════════════════════════════════\n";

    if (!thirdPartyList.empty()) {
        sum << L"附着清单(THIRD_PARTY_WHQL,共 " << countThirdParty << L" 个):\n";
        sum << L"───────────────────────────────────────────────────────\n";
        for (size_t i = 0; i < thirdPartyList.size(); i++) {
            const auto& [name, vendor] = thirdPartyList[i];
            sum << L"  " << std::left << std::setw(40) << name;
            if (!vendor.empty()) sum << L"  " << vendor;
            // 附着清单也带上内核解析出来的驱动对象名,便于核对
            const auto& drvObj = thirdPartyDriverObjectNames[i];
            if (!drvObj.empty()) {
                sum << L"  [对象名=" << drvObj << L"]";
            } else {
                sum << L"  [无 DriverObject]";
            }
            sum << L"\n";
        }
        sum << L"═══════════════════════════════════════════════════════\n";
    }

    WriteOut(sum.str());
    return thirdPartyList;
}

// ═══════════════════════════════════════════════════════════════════════
//  辅助:把 DEVICE_ENTRY 一条记录格式化成单行字符串(用于表格输出)
// ═══════════════════════════════════════════════════════════════════════

static std::wstring DeviceTypeToString(ULONG deviceType)
{
    // 常见 FILE_DEVICE_* 类型转可读名,未知返回十六进制
    switch (deviceType) {
        case 0x00000001: return L"BEEP";
        case 0x00000002: return L"CD_ROM";
        case 0x00000003: return L"CONTROLLER";
        case 0x00000004: return L"DATALINK";
        case 0x00000005: return L"DFS";
        case 0x00000006: return L"DISK";
        case 0x00000007: return L"DISK_FILE_SYSTEM";
        case 0x00000008: return L"FILE_SYSTEM";
        case 0x00000009: return L"INPORT_PORT";
        case 0x0000000A: return L"KEYBOARD";
        case 0x0000000B: return L"MAILSLOT";
        case 0x0000000C: return L"MIDI_IN";
        case 0x0000000D: return L"MIDI_OUT";
        case 0x0000000E: return L"MOUSE";
        case 0x0000000F: return L"MULTI_UNC_PROVIDER";
        case 0x00000010: return L"NAMED_PIPE";
        case 0x00000011: return L"NETWORK";
        case 0x00000012: return L"NETWORK_BROWSER";
        case 0x00000013: return L"NETWORK_FILE_SYSTEM";
        case 0x00000014: return L"NULL";
        case 0x00000015: return L"PARALLEL_PORT";
        case 0x00000016: return L"PHYSICAL_NETCARD";
        case 0x00000017: return L"PRINTER";
        case 0x00000018: return L"SCANNER";
        case 0x00000019: return L"SERIAL_MOUSE_PORT";
        case 0x0000001A: return L"SERIAL_PORT";
        case 0x0000001B: return L"SCREEN";
        case 0x0000001C: return L"SOUND";
        case 0x0000001D: return L"STREAMS";
        case 0x0000001E: return L"TAPE";
        case 0x0000001F: return L"TAPE_FILE_SYSTEM";
        case 0x00000020: return L"TRANSPORT";
        case 0x00000021: return L"UNKNOWN";
        case 0x00000022: return L"VIDEO";
        case 0x00000023: return L"VIRTUAL_DISK";
        case 0x00000024: return L"WAVE_IN";
        case 0x00000025: return L"WAVE_OUT";
        case 0x00000026: return L"FS_CONTROL";
        case 0x00000027: return L"CD_ROM_FILE_SYSTEM";
        case 0x00000028: return L"CHANGER";
        case 0x00000029: return L"SMARTCARD";
        case 0x0000002A: return L"ACPI";
        case 0x0000002B: return L"DVD";
        case 0x0000002C: return L"FULLSCREEN_VIDEO";
        case 0x0000002D: return L"DFS_FILE_SYSTEM";
        case 0x0000002E: return L"DFS_VOLUME";
        case 0x0000002F: return L"SERENUM";
        case 0x00000030: return L"TERMSRV";
        case 0x00000031: return L"KSEC";
        case 0x00000032: return L"FILE_SYSTEM_CONTROL";
        case 0x00000033: return L"VIRTUAL_BLOCK";
        case 0x00000034: return L"PCI";
        case 0x00000035: return L"NETWORK_DISPLAY";
        case 0x00000036: return L"NETWORK_REDIRECTOR";
        case 0x00000037: return L"BATTERY";
        case 0x00000038: return L"BUS_EXTENDER";
        case 0x00000039: return L"MODEM";
        case 0x0000003A: return L"VDM";
        case 0x0000003B: return L"MISC";
        case 0x0000003C: return L"SD";
        case 0x0000003D: return L"IRDA";
        case 0x0000003E: return L"IMAGE";
        case 0x0000003F: return L"HARDWARE";
        case 0x00000040: return L"KS";
        case 0x00000041: return L"CHANGER_FILE_SYSTEM";
        case 0x00000042: return L"BUSLOGIC";
        case 0x00000043: return L"VMRING3";
        case 0x00000044: return L"PNP";
        case 0x00000045: return L"KS_STREAM";
        case 0x00000046: return L"TCPIP";
        case 0x00000047: return L"NULL_FILE_SYSTEM";
        case 0x00000048: return L"SECURITY";
        case 0x00000049: return L"NETBT";
        case 0x0000004A: return L"BUSREPORT";
        case 0x0000004B: return L"VMSERVICE";
        case 0x0000004C: return L"MUP";
        case 0x0000004D: return L"NDIS";
        case 0x0000004E: return L"UDFS";
        case 0x0000004F: return L"BIOMETRIC";
        case 0x00000050: return L"BOOT";
        case 0x00000051: return L"BOOT_FILE_SYSTEM";
        case 0x00000052: return L"BLOCKING_IO";
        case 0x00000053: return L"WFP";
        case 0x00000054: return L"SECURITY_STREAM";
        case 0x00000055: return L"CD_CHANGER";
        case 0x00000056: return L"TUNNEL";
        case 0x00000057: return L"COMPORT";
        case 0x00000058: return L"FILE_SYSTEM_VIRTUALIZER";
        case 0x00000059: return L"HID";
        case 0x0000005A: return L"MSGPORT";
        case 0x0000005B: return L"NDNP";
        case 0x0000005C: return L"PRINT_QUEUE";
        case 0x0000005D: return L"NFP";
        case 0x0000005E: return L"CRYPTO";
        case 0x0000005F: return L"CRYPTO_ESCROW";
        case 0x00000060: return L"CRYPTO_KEYS";
        case 0x00000061: return L"FSWRAPPER";
        case 0x00000062: return L"PMEM";
        case 0x00000063: return L"FSRDR";
        case 0x00000064: return L"DXD";
        case 0x00000065: return L"FSRVP";
        case 0x00000066: return L"WORM";
        case 0x00000067: return L"DMA";
        case 0x00000068: return L"FWDN";
        case 0x00000069: return L"FWDEVICE";
        case 0x0000006A: return L"FWCALL";
        case 0x0000006B: return L"FWPROXY";
        case 0x0000006C: return L"FWDRIVER";
        case 0x0000006D: return L"FWMEM";
        case 0x0000006E: return L"FWPORT";
        case 0x0000006F: return L"NDISPROXY";
        case 0x00000070: return L"WPD";
        case 0x00000071: return L"BLUETOOTH";
        case 0x00000072: return L"MTCOMPOSITE";
        case 0x00000073: return L"MTCLUSTER";
        case 0x00000074: return L"FLTPORT";
        case 0x00000075: return L"FLT_VOLUMES";
        case 0x00000076: return L"FLT_FILTERS";
        case 0x0000007A: return L"TAPE_ENUM";
        case 0x00000080: return L"GPIO";
        case 0x00000081: return L"SPI";
        case 0x00000082: return L"I2C";
        case 0x00000083: return L"UART";
        case 0x00000084: return L"PWM";
        case 0x00000085: return L"ADC";
        case 0x00000086: return L"DAC";
        case 0x00000087: return L"SENSOR";
        case 0x00000088: return L"HAPTICS";
        case 0x00008888: return L"DEVICEMEM";
        case 0x0000AAAA: return L"DEVICEMEM2";
        case 0x00010001: return L"KMDF";
        case 0x00010005: return L"UMDF";
        case 0x00010022: return L"VMBUS";
        case 0x00010023: return L"USB";
        case 0x00010024: return L"FILE_SYSTEM_FILTER";
        case 0x00010032: return L"DEVINTERFACE";
        default: {
            std::wostringstream ss;
            ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << deviceType;
            return ss.str();
        }
    }
}

static void PrintDeviceList(const std::wstring& driverName,
                             const std::wstring& foundPath,
                             const std::vector<DeviceEntry>& devices)
{
    std::wostringstream ss;
    ss << L"\n── 驱动 " << driverName << L"  (" << foundPath << L")  共 "
       << devices.size() << L" 个设备 ──\n";

    if (devices.empty()) {
        ss << L"  (无设备)\n";
        WriteOut(ss.str());
        return;
    }

    ss << L"  序号  设备对象地址      类型              Flags      Att  Stk  设备名\n";
    ss << L"  ────  ────────────────  ────────────────  ─────────  ───  ───  ────────────────────────────────\n";

    for (size_t i = 0; i < devices.size(); i++) {
        const auto& d = devices[i];
        ss << L"  [" << std::setw(3) << (i + 1) << L"] "
           << L"0x" << std::hex << std::setw(12) << std::setfill(L'0') << d.DeviceObject
           << std::dec << std::setfill(L' ')
           << L"  " << std::left << std::setw(16) << DeviceTypeToString(d.DeviceType)
           << L"  0x" << std::hex << std::setw(8) << std::setfill(L'0') << d.Flags
           << std::dec << std::setfill(L' ')
           << L"  " << std::setw(3) << d.AttachedCount
           << L"  " << std::setw(3) << d.StackSize
           << L"  " << d.DeviceName
           << L"\n";
    }

    WriteOut(ss.str());
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 2:--ScanAndClassify 驱动扫描 + 应用层签名分类,给出附着清单
//
//  数据流:
//    1. 应用层发 IOCTL 让 KernelService 扫描 PsLoadedModuleList,拿到模块列表
//    2. 应用层把每条模块路径(\SystemRoot\... / \??\C:\...)规范化为绝对路径
//    3. 应用层对每个 .sys 跑 ClassifyDriver (Authenticode + Catalog + 嵌套签名)
//    4. 按 INBOX/MICROSOFT/THIRD_PARTY_WHQL/UNTRUSTED 四类分类
//    5. 产出 THIRD_PARTY_WHQL 附着清单(应用层后续可把目标丢回驱动附着)
// ═══════════════════════════════════════════════════════════════════════

static int RunScanAndClassify() {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  驱动扫描 + 签名分类 (通过 KernelService 驱动)\n");
    WriteOut(L"  1. 驱动扫描 PsLoadedModuleList\n");
    WriteOut(L"  2. 应用层路径规范化\n");
    WriteOut(L"  3. 应用层 WinVerifyTrust 验签\n");
    WriteOut(L"  4. 输出 THIRD_PARTY_WHQL 附着清单\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // ── 步骤 1:打开驱动设备 ──────────────────────────────────────
    WriteOut(L"[1/4] 打开 KernelService 设备...\n");
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

    // ── 步骤 2:扫描已加载模块 ────────────────────────────────────
    WriteOut(L"[2/4] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
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

    // ── 步骤 3 + 4:路径规范化 + 签名分类 + 汇总输出 ──────────────
    WriteOut(L"[3/4] 路径规范化 + 签名分类...\n");
    {
        std::vector<std::wstring> dummyNames, dummyPaths;
        ClassifyAndPrintDrivers(drivers, dummyNames, dummyPaths);
    }
    WriteOut(L"\n[4/4] 分类完成\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 4:--EnumDevices <DriverName>
//  对单个驱动名调内核 IOCTL_ENUM_DRIVER_DEVICES,打印其创建的所有设备
//  用于调试:验证 IOCTL 通信、ObReferenceObjectByName、DeviceObject 链遍历
// ═══════════════════════════════════════════════════════════════════════

static int RunEnumDevices(const std::wstring& driverName)
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  扫描单个驱动的设备列表 (调试模式)\n");
    WriteOut(L"  驱动名: " + driverName + L"\n");
    WriteOut(L"  内核会依次尝试 \\Driver\\" + driverName + L" 和 \\FileSystem\\" + driverName + L"\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

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

    WriteOut(L"[2/2] 发送 IOCTL_ENUM_DRIVER_DEVICES...\n");
    std::vector<DeviceEntry> devices;
    std::wstring foundPath;
    if (!EnumDriverDevices(hDevice, driverName, 0, devices, &foundPath)) {
        DWORD err = GetLastError();
        std::wostringstream ss;
        ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
        WriteOut(ss.str());
        CloseKernelService(hDevice);
        return 1;
    }
    CloseKernelService(hDevice);

    PrintDeviceList(driverName, foundPath, devices);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 5:--ScanAndEnumDevices
//  整合模式:扫描已加载驱动 + 应用层签名分类 + 对 THIRD_PARTY_WHQL 清单
//  逐个调内核 IOCTL_ENUM_DRIVER_DEVICES,打印每个驱动的设备列表
//
//  数据流:
//    1. 应用层发 IOCTL_SCAN_LOADED_DRIVERS 拿到已加载模块列表
//    2. 应用层做路径规范化 + WinVerifyTrust 验签,产出 THIRD_PARTY_WHQL 附着清单
//    3. 对清单中每个驱动名(去掉 .sys 后缀)调 IOCTL_ENUM_DRIVER_DEVICES
//    4. 内核用 ObReferenceObjectByName 找 DRIVER_OBJECT,
//       遍历 DeviceObject->NextDevice 链,返回设备列表
//    5. 应用层打印每个驱动的设备列表(后续可基于此决定附着哪个设备)
// ═══════════════════════════════════════════════════════════════════════

static int RunScanAndEnumDevices()
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  驱动扫描 + 签名分类 + 设备列表扫描 + IAT 扫描 (整合模式)\n");
    WriteOut(L"  1. 驱动扫描 PsLoadedModuleList\n");
    WriteOut(L"  2. 应用层路径规范化 + WinVerifyTrust 验签\n");
    WriteOut(L"  3. 产出 THIRD_PARTY_WHQL 附着清单\n");
    WriteOut(L"  4. 对清单中每个驱动调 IOCTL_ENUM_DRIVER_DEVICES 扫设备列表\n");
    WriteOut(L"  5. 对有设备的待附着驱动扫 IAT,标记高危内存操作函数\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // ── 步骤 1:打开驱动设备 ──────────────────────────────────────
    WriteOut(L"[1/5] 打开 KernelService 设备...\n");
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

    // ── 步骤 2:扫描已加载模块 ────────────────────────────────────
    WriteOut(L"[2/5] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
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

    // ── 步骤 3:路径规范化 + 签名分类 + 汇总输出 ──────────────────
    WriteOut(L"[3/5] 路径规范化 + 签名分类...\n");
    std::vector<std::wstring> thirdPartyDriverObjectNames;
    std::vector<std::wstring> thirdPartyFilePaths;
    auto thirdPartyList = ClassifyAndPrintDrivers(drivers, thirdPartyDriverObjectNames, thirdPartyFilePaths);

    // ── 步骤 4:对 THIRD_PARTY_WHQL 清单逐个扫设备列表 ────────────
    WriteOut(L"\n[4/5] 对待附着清单逐个调 IOCTL_ENUM_DRIVER_DEVICES 扫设备列表...\n");

    if (thirdPartyList.empty()) {
        WriteOut(L"  待附着清单为空,跳过设备扫描\n");
        CloseKernelService(hDevice);
        return 0;
    }

    int totalDevices = 0;
    int driversWithDevices = 0;
    int driversNotFound = 0;
    int driversNoDevices = 0;
    int failed = 0;

    for (size_t i = 0; i < thirdPartyList.size(); i++) {
        const auto& [fileName, note] = thirdPartyList[i];

        // 从内核拿到的真实驱动对象名(由 DriverNameResolver 用 ImageBase 反查)
        // 直接拷贝过来用,不要从文件名砍后缀(会错,如 OpenArkDrv64.sys → OpenArkDrv)
        std::wstring drvName = thirdPartyDriverObjectNames[i];

        std::wostringstream hdr;
        hdr << L"\n[" << (i + 1) << L"/" << thirdPartyList.size() << L"] "
            << fileName;
        if (drvName.empty()) {
            hdr << L"  →  (内核未找到 DriverObject,跳过)";
        } else {
            hdr << L"  →  驱动对象名: " << drvName;
        }
        if (!note.empty()) hdr << L"  (" << note << L")";
        hdr << L"\n";
        WriteOut(hdr.str());

        // 内核没找到 DriverObject 的(如 ntoskrnl / HAL / 自身),跳过设备扫描
        if (drvName.empty()) {
            WriteOut(L"  跳过:无 DriverObject\n");
            driversNotFound++;
            continue;
        }

        std::vector<DeviceEntry> devices;
        std::wstring foundPath;
        if (!EnumDriverDevices(hDevice, drvName, 0, devices, &foundPath)) {
            DWORD err = GetLastError();
            std::wostringstream ss;
            ss << L"  失败: IOCTL_ENUM_DRIVER_DEVICES 失败,错误码=" << err << L"\n";
            WriteOut(ss.str());
            failed++;
            continue;
        }

        if (foundPath == L"(not found)" || devices.empty()) {
            if (foundPath == L"(not found)") {
                WriteOut(L"  驱动对象未找到 (在 \\Driver 和 \\FileSystem 都不存在)\n");
                driversNotFound++;
            } else {
                WriteOut(L"  驱动存在但未创建任何设备 (" + foundPath + L")\n");
                driversNoDevices++;
            }
            continue;
        }

        PrintDeviceList(drvName, foundPath, devices);
        totalDevices += (int)devices.size();
        driversWithDevices++;
    }

    CloseKernelService(hDevice);

    // 设备扫描汇总
    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"设备扫描汇总:\n";
    sum << L"  待附着驱动总数:    " << thirdPartyList.size() << L"\n";
    sum << L"  找到设备的驱动:    " << driversWithDevices << L"  (共 " << totalDevices << L" 个设备)\n";
    sum << L"  驱动存在但无设备:  " << driversNoDevices << L"\n";
    sum << L"  驱动对象未找到:    " << driversNotFound << L"  (无 DriverObject,可能已卸载)\n";
    sum << L"  IOCTL 调用失败:    " << failed << L"\n";
    sum << L"═══════════════════════════════════════════════════════\n";
    WriteOut(sum.str());

    // ── 步骤 5:对有设备的待附着驱动扫 IAT,标记高危函数 ───────────
    WriteOut(L"\n[5/5] 对有设备的待附着驱动扫 IAT,检查高危内存操作函数...\n");
    WriteOut(L"  高危列表: MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory\n\n");

    int iatScanned = 0;
    int iatSkipped = 0;
    int iatFailed = 0;
    int iatDangerous = 0;
    std::vector<std::pair<std::wstring, std::vector<std::string>>> dangerousDrivers;
    // dangerousDrivers[i] = {驱动文件名, 命中的 "dll!api" 列表}

    for (size_t i = 0; i < thirdPartyList.size(); i++) {
        const auto& [fileName, note] = thirdPartyList[i];
        const auto& filePath = thirdPartyFilePaths[i];

        if (filePath.empty()) {
            iatSkipped++;
            continue;
        }

        std::vector<IatEntry> iat;
        std::wstring err;
        if (!ScanIat(filePath, iat, err)) {
            std::wostringstream line;
            line << L"[" << std::setw(3) << (i + 1) << L"] "
                 << std::left << std::setw(40) << fileName
                 << L"  IAT 扫描失败: " << err << L"\n";
            WriteOut(line.str());
            iatFailed++;
            continue;
        }

        std::vector<std::string> foundApis;
        bool danger = HasDangerousImports(iat, foundApis);
        iatScanned++;

        std::wostringstream line;
        line << L"[" << std::setw(3) << (i + 1) << L"] "
             << std::left << std::setw(40) << fileName
             << L"  IAT: " << std::setw(3) << iat.size() << L" 个 DLL";
        if (danger) {
            line << L"  ← 命中 " << foundApis.size() << L" 个高危函数!";
            iatDangerous++;
            dangerousDrivers.push_back({fileName, foundApis});
        }
        line << L"\n";
        WriteOut(line.str());
    }

    // IAT 扫描汇总
    std::wostringstream iatSum;
    iatSum << L"\n═══════════════════════════════════════════════════════\n";
    iatSum << L"IAT 扫描汇总:\n";
    iatSum << L"  待附着驱动总数:    " << thirdPartyList.size() << L"\n";
    iatSum << L"  扫描成功:          " << iatScanned << L"\n";
    iatSum << L"  无路径跳过:        " << iatSkipped << L"\n";
    iatSum << L"  扫描失败:          " << iatFailed << L"\n";
    iatSum << L"  命中高危函数的驱动: " << iatDangerous << L"\n";
    iatSum << L"═══════════════════════════════════════════════════════\n";

    if (!dangerousDrivers.empty()) {
        iatSum << L"高危驱动清单(命中 MmCopyMemory/MmMapIoSpace/ZwMapViewOfSection/MmCopyVirtualMemory):\n";
        iatSum << L"───────────────────────────────────────────────────────\n";
        for (const auto& [name, apis] : dangerousDrivers) {
            iatSum << L"  " << name << L"\n";
            for (const auto& a : apis) {
                iatSum << L"    * " << std::string(a.begin(), a.end()).c_str() << L"\n";
            }
        }
        iatSum << L"═══════════════════════════════════════════════════════\n";
    }

    WriteOut(iatSum.str());

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 5:--ScanIAT <sys文件>
//  扫描单个 .sys 文件的完整导入表(IAT),并标记四个高危内存操作函数:
//    MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory
//
//  用法:
//    DriverAttachSelector.exe --ScanIAT C:\Windows\System32\drivers\tcpip.sys
//
//  纯用户态,不调驱动,不需要管理员(只要文件读权限)
// ═══════════════════════════════════════════════════════════════════════

static int RunScanIAT(const std::wstring& filePath)
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  扫描 PE 导入表 (IAT) — 单文件模式\n");
    WriteOut(L"  文件: " + filePath + L"\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // 诊断 1:文件是否存在、能否访问
    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        WriteOut(L"[诊断] GetFileAttributes 失败,错误码=" + std::to_wstring(e) + L"\n");
        if (e == ERROR_FILE_NOT_FOUND) WriteOut(L"       → 文件不存在\n");
        if (e == ERROR_ACCESS_DENIED)  WriteOut(L"       → 无访问权限\n");
        return 1;
    }
    std::wostringstream diag1;
    diag1 << L"[诊断] 文件存在,属性=0x" << std::hex << attr << std::dec
          << (attr & FILE_ATTRIBUTE_DIRECTORY ? L" (目录!)" : L" (普通文件)") << L"\n";
    WriteOut(diag1.str());

    std::vector<IatEntry> iat;
    std::wstring err;
    if (!ScanIat(filePath, iat, err)) {
        WriteOut(L"[诊断] ScanIat 返回 false\n");
        WriteOut(L"[诊断] 错误说明: " + (err.empty() ? L"(空)" : err) + L"\n");
        return 1;
    }

    WriteOut(L"[诊断] ScanIat 返回 true,导入 DLL 数=" + std::to_wstring(iat.size()) + L"\n");
    if (!err.empty()) {
        WriteOut(L"[诊断] 附加说明: " + err + L"\n");
    }

    if (iat.empty()) {
        WriteOut(L"扫描成功,但无导入项。\n");
        return 0;
    }

    // ── 完整 IAT 输出 ────────────────────────────────────────────
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    WriteOut(L"  完整 IAT\n");
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    int totalApis = 0;
    int totalDangerous = 0;

    for (size_t i = 0; i < iat.size(); i++) {
        const auto& entry = iat[i];

        std::wostringstream hdr;
        hdr << L"\n[" << std::setw(3) << (i + 1) << L"] "
            << L"DLL: " << std::string(entry.dllName.begin(), entry.dllName.end()).c_str()
            << L"  (" << entry.apis.size() << L" 个 API)\n";
        WriteOut(hdr.str());

        WriteOut(L"───────────────────────────────────────────────────────\n");

        for (size_t j = 0; j < entry.apis.size(); j++) {
            const std::string& api = entry.apis[j];

            // 检查高危
            bool danger = false;
            static const char* dangerousList[] = {
                "MmCopyMemory", "MmMapIoSpace",
                "ZwMapViewOfSection", "MmCopyVirtualMemory"
            };
            for (const char* d : dangerousList) {
                if (_stricmp(api.c_str(), d) == 0) {
                    danger = true;
                    break;
                }
            }

            std::wostringstream line;
            line << L"    " << std::setw(4) << (j + 1) << L". "
                 << std::left << std::setw(40)
                 << std::string(api.begin(), api.end()).c_str();
            if (danger) {
                line << L"  ← 高危!";
                totalDangerous++;
            }
            line << L"\n";
            WriteOut(line.str());

            totalApis++;
        }
    }

    // ── 高危函数汇总 ────────────────────────────────────────────
    WriteOut(L"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    WriteOut(L"  高危函数汇总\n");
    WriteOut(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    std::vector<std::string> foundApis;
    HasDangerousImports(iat, foundApis);

    if (foundApis.empty()) {
        WriteOut(L"  未发现高危内存操作函数\n");
    } else {
        std::wostringstream ss;
        ss << L"  命中 " << foundApis.size() << L" 个:\n";
        for (const auto& s : foundApis) {
            ss << L"    * " << std::string(s.begin(), s.end()).c_str() << L"\n";
        }
        WriteOut(ss.str());
    }

    // ── 总计 ────────────────────────────────────────────────────
    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"汇总:\n";
    sum << L"  导入 DLL 数:  " << iat.size() << L"\n";
    sum << L"  导入 API 总数: " << totalApis << L"\n";
    sum << L"  高危函数命中: " << totalDangerous << L"\n";
    sum << L"═══════════════════════════════════════════════════════\n";
    WriteOut(sum.str());

    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式 3:--ScanDriver 用 PSAPI 本地枚举并按签名分类
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
            // 无路径/文件不存在 — 归入待附着清单(异常驱动,需人工核查)
            skipped++;
            countThirdParty++;
            thirdPartyList.push_back({fileName, L"(无路径,需人工核查)"});

            std::wostringstream line;
            line << L"[----] " << std::left << std::setw(40) << fileName
                 << L"  THIRD_PARTY_WHQL  (无路径,归入待附着)\n";
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
            case DriverClass::UNTRUSTED:
                // 无签名/验签失败 — HVCI 下不应存在,归入待附着清单(异常驱动)
                countUntrusted++;
                countThirdParty++;
                thirdPartyList.push_back({fileName, result.errorReason.empty() ? L"(UNTRUSTED)" : L"(UNTRUSTED: " + result.errorReason + L")"});
                break;
        }

        std::wostringstream line;
        line << L"[" << std::setw(4) << total << L"] "
             << std::left << std::setw(40) << fileName
             << L"  " << ClassToString(result.klass);
        if (result.klass == DriverClass::THIRD_PARTY_WHQL && !result.vendorName.empty()) {
            line << L"  厂商=" << result.vendorName;
        }
        if (result.klass == DriverClass::UNTRUSTED && !result.errorReason.empty()) {
            line << L"  (" << result.errorReason << L")  → 已归入待附着";
        }
        line << L"\n";
        WriteOut(line.str());
    }

    std::wostringstream sum;
    sum << L"\n═══════════════════════════════════════════════════════\n";
    sum << L"汇总:\n";
    sum << L"  已加载驱动总数:  " << drivers.size() << L"\n";
    sum << L"  分类成功:        " << total << L"\n";
    sum << L"  无路径(归入待附着): " << skipped << L"\n";
    sum << L"  INBOX:           " << countInbox << L"  (放过)\n";
    sum << L"  MICROSOFT:       " << countMicrosoft << L"  (放过)\n";
    sum << L"  THIRD_PARTY_WHQL:" << countThirdParty << L"  (待附着,含无路径/UNTRUSTED)\n";
    sum << L"    其中 UNTRUSTED: " << countUntrusted << L"  (异常,需人工核查)\n";
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
//  模式:--attach <\Device\X>
//  附着到指定设备
//  数据流:应用层发 IOCTL_ATTACH_DEVICE → 驱动 IoGetDeviceObjectPointer
//         → IoCreateDevice (FiDO) → IoAttachDeviceToDeviceStack
//         → IRP 透传 (IoSkipCurrentIrpStackLocation + IoCallDriver)
// ═══════════════════════════════════════════════════════════════════════

static int RunAttachDevice(const std::wstring& devicePath) {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  设备附着\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");

    if (devicePath.empty() || devicePath[0] != L'\\') {
        WriteOut(L"  错误: 设备路径必须以 \\ 开头,如 \\Device\\Tcp\n");
        return 1;
    }

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        WriteOut(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
                 std::to_wstring(err) + L")\n");
        if (err == ERROR_ACCESS_DENIED) {
            WriteOut(L"  请以管理员权限运行\n");
        } else if (err == ERROR_FILE_NOT_FOUND) {
            WriteOut(L"  KernelService 驱动未加载,请先 sc start KernelService\n");
        }
        return 1;
    }

    WriteOut(L"  目标路径:        " + devicePath + L"\n");

    unsigned long attachId = 0;
    unsigned long long filterAddr = 0, lowerAddr = 0;
    unsigned short newStack = 0, targetStack = 0;

    if (!AttachToDevice(hDevice, devicePath, attachId,
                        &filterAddr, &lowerAddr, &newStack, &targetStack)) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS) {
            WriteOut(L"  该设备已被附着过,跳过\n");
        } else {
            WriteOut(L"  错误: 附着失败 (GetLastError=" + std::to_wstring(err) + L")\n");
        }
        CloseKernelService(hDevice);
        return (err == ERROR_ALREADY_EXISTS) ? 0 : 1;
    }

    std::wostringstream ss;
    ss << L"  附着 ID:         " << attachId << L"\n";
    ss << L"  过滤器设备地址:  0x" << std::hex << filterAddr << L"\n";
    ss << L"  下一层设备地址:   0x" << std::hex << lowerAddr << L"\n";
    ss << L"  新栈深度:        " << std::dec << newStack << L"\n";
    ss << L"  原栈深度:        " << std::dec << targetStack << L"\n";
    ss << L"═══════════════════════════════════════════════════════\n";
    WriteOut(ss.str());

    CloseKernelService(hDevice);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式:--unattach <Id|路径>
//  解绑指定附着
// ═══════════════════════════════════════════════════════════════════════

static int RunUnattachDevice(const std::wstring& arg) {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  解除附着\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        WriteOut(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
                 std::to_wstring(err) + L")\n");
        return 1;
    }

    unsigned long detachedId = 0;
    bool ok = false;

    // 判断参数是数字(ID)还是路径
    bool isNumeric = !arg.empty();
    for (wchar_t c : arg) {
        if (c < L'0' || c > L'9') { isNumeric = false; break; }
    }

    if (isNumeric) {
        unsigned long attachId = (unsigned long)_wtol(arg.c_str());
        if (attachId == 0) {
            WriteOut(L"  错误: ID 必须 > 0\n");
            CloseKernelService(hDevice);
            return 1;
        }
        WriteOut(L"  按 ID 解绑:       " + std::to_wstring(attachId) + L"\n");
        ok = DetachDevice(hDevice, attachId, detachedId);
    } else {
        if (arg.empty() || arg[0] != L'\\') {
            WriteOut(L"  错误: 参数必须是 ID(数字)或设备路径(以 \\ 开头)\n");
            CloseKernelService(hDevice);
            return 1;
        }
        WriteOut(L"  按路径解绑:      " + arg + L"\n");
        ok = DetachDeviceByPath(hDevice, arg, detachedId);
    }

    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_FOUND) {
            WriteOut(L"  错误: 未找到匹配的附着\n");
        } else {
            WriteOut(L"  错误: 解绑失败 (GetLastError=" + std::to_wstring(err) + L")\n");
        }
        CloseKernelService(hDevice);
        return 1;
    }

    std::wostringstream ss;
    ss << L"  已解绑 ID:       " << detachedId << L"\n";
    ss << L"═══════════════════════════════════════════════════════\n";
    WriteOut(ss.str());

    CloseKernelService(hDevice);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════
//  模式:--list-attach
//  查询当前所有附着
// ═══════════════════════════════════════════════════════════════════════

static int RunListAttachments() {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  当前附着列表\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        WriteOut(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
                 std::to_wstring(err) + L")\n");
        return 1;
    }

    std::vector<AttachEntry> entries;
    if (!QueryAttachments(hDevice, entries)) {
        DWORD err = GetLastError();
        WriteOut(L"  错误: 查询失败 (GetLastError=" + std::to_wstring(err) + L")\n");
        CloseKernelService(hDevice);
        return 1;
    }

    if (entries.empty()) {
        WriteOut(L"  (空,没有附着任何设备)\n");
    } else {
        std::wostringstream ss;
        ss << L"  共 " << entries.size() << L" 个附着\n\n";
        ss << L"  ID    栈深  过滤器地址          目标路径\n";
        ss << L"  ────  ────  ──────────────────  ────────────────────────────────\n";
        for (const auto& e : entries) {
            ss << L"  " << std::left << std::setw(5) << e.AttachId
               << L"  " << std::setw(4) << e.StackSize
               << L"  0x" << std::hex << std::setw(16) << std::setfill(L'0') << e.FilterDeviceAddr
               << std::setfill(L' ') << std::dec
               << L"  " << e.TargetPath << L"\n";
        }
        WriteOut(ss.str());
    }

    WriteOut(L"═══════════════════════════════════════════════════════\n");
    CloseKernelService(hDevice);
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

        if (arg1 == L"--ScanAndClassify") {
            // 驱动扫描 + 应用层签名分类,给出附着清单
            return RunScanAndClassify();
        }

        if (arg1 == L"--ScanAndEnumDevices") {
            // 扫描+分类+对 THIRD_PARTY_WHQL 清单逐个扫设备列表
            return RunScanAndEnumDevices();
        }

        if (arg1 == L"--EnumDevices") {
            // 单驱动扫设备列表(调试):--EnumDevices <DriverName>
            if (argc < 3) {
                WriteOut(L"用法: DriverAttachSelector.exe --EnumDevices <DriverName>\n");
                WriteOut(L"  DriverName 不含路径,如 tcpip / ahflt / null\n");
                return 1;
            }
            return RunEnumDevices(argv[2]);
        }

        if (arg1 == L"--ScanIAT") {
            // 单文件扫 IAT:--ScanIAT <sys文件路径>
            if (argc < 3) {
                WriteOut(L"用法: DriverAttachSelector.exe --ScanIAT <sys文件路径>\n");
                WriteOut(L"  如:--ScanIAT C:\\Windows\\System32\\drivers\\tcpip.sys\n");
                WriteOut(L"  纯用户态,不调驱动,输出完整 IAT + 标记高危函数\n");
                return 1;
            }
            return RunScanIAT(argv[2]);
        }

        if (arg1 == L"--attach") {
            // 附着到设备:--attach <\Device\X>
            if (argc < 3) {
                WriteOut(L"用法: DriverAttachSelector.exe --attach <设备路径>\n");
                WriteOut(L"  如:--attach \\Device\\Tcp\n");
                WriteOut(L"  内核用 IoCreateDriver + IoCreateDevice + IoAttachDeviceToDeviceStack\n");
                return 1;
            }
            return RunAttachDevice(argv[2]);
        }

        if (arg1 == L"--unattach") {
            // 解绑:--unattach <Id|路径>
            if (argc < 3) {
                WriteOut(L"用法: DriverAttachSelector.exe --unattach <Id|设备路径>\n");
                WriteOut(L"  如:--unattach 1 或 --unattach \\Device\\Tcp\n");
                return 1;
            }
            return RunUnattachDevice(argv[2]);
        }

        if (arg1 == L"--list-attach") {
            // 查询当前所有附着
            return RunListAttachments();
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
