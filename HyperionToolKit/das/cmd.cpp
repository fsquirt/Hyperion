// cmd.cpp — das 子命令入口,原 Main.cpp
//
// 原 Main.cpp 的 wmain 改名 RunDriverAttachSelector, 由 HyperionToolKit.cpp
// 分发器调用。所有 WriteOut 已迁移为 common/Out。批量分类循环下沉到 classify.cpp,
// 附着操作下沉到 attach.cpp, 本文件只保留模式编排。

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "../common/Common.h"
#include "../common/KernelComms.h"
#include "../common/Out.h"
#include "../common/Str.h"
#include "classify.h"
#include "drivers.h"
#include "iat.h"
#include "etw.h"
#include "objects.h"
#include "attach.h"

#include <cstdlib>

namespace das {

	// ═══════════════════════════════════════════════════════════════════════
	//  帮助
	// ═══════════════════════════════════════════════════════════════════════

	static void PrintHelp()
	{
		Out(L"用法:\n");
		Out(L"  DriverAttachSelector.exe                      通过 KernelService 驱动扫描已加载内核模块\n");
		Out(L"  DriverAttachSelector.exe --ScanAndClassify    驱动扫描 + 应用层签名分类,给出附着清单\n");
		Out(L"  DriverAttachSelector.exe --ScanAndEnumDevices 扫描+分类+对 THIRD_PARTY_WHQL 清单逐个扫设备列表\n");
		Out(L"  DriverAttachSelector.exe --EnumDevices <Name> 对单个驱动名扫设备列表,调试用,如 --EnumDevices tcpip\n");
		Out(L"  DriverAttachSelector.exe --ScanIAT <sys文件>  扫单个 .sys 的完整 IAT,标记高危函数,纯用户态\n");
		Out(L"  DriverAttachSelector.exe --attach <\\Device\\X> 附着到指定设备,如 --attach \\Device\\Tcp\n");
		Out(L"  DriverAttachSelector.exe --unattach <Id|路径> 按 ID 或路径解绑,如 --unattach 1 或 --unattach \\Device\\Tcp\n");
		Out(L"  DriverAttachSelector.exe --list-attach       查询当前所有附着列表\n");
		Out(L"  DriverAttachSelector.exe --etw [--duration N] [--out path.etl]\n");
		Out(L"                                                实时订阅 ETW,打印 IOCTL 拦截事件 + 跨态调用栈\n");
		Out(L"  DriverAttachSelector.exe --ScanDriver         用 PSAPI 本地枚举并按签名分类,离线调试\n");
		Out(L"  DriverAttachSelector.exe --scan-objects       扫描 \\GLOBAL?? 和 \\Device 命名空间\n");
		Out(L"  DriverAttachSelector.exe --scan-objects \\Driver  扫描指定目录\n");
		Out(L"  DriverAttachSelector.exe --scan-objects \\GLOBAL?? \\Device \\Driver  扫描多个目录\n");
		Out(L"  DriverAttachSelector.exe --help               显示此帮助\n");
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 1:通过 KernelService 驱动扫描已加载内核模块
	// ═══════════════════════════════════════════════════════════════════════

	static int RunKernelScan()
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  通过 KernelService 驱动扫描已加载内核模块\n");
		Out(L"  驱动用 ZwQuerySystemInformation 扫 PsLoadedModuleList\n");
		Out(L"═══════════════════════════════════════════════════════\n\n");

		Out(L"[1/2] 打开 KernelService 设备...\n");
		void* hDevice = OpenKernelService();
		if (hDevice == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: CreateFile 失败,错误码=" << err << L"\n";
			if (err == ERROR_ACCESS_DENIED) {
				ss << L"  原因: 需要管理员权限运行\n";
			}
			else if (err == ERROR_FILE_NOT_FOUND) {
				ss << L"  原因: KernelService 驱动未加载 (sc start KernelService)\n";
			}
			Out(ss.str());
			return 1;
		}
		Out(L"  成功打开设备 \\\\.\\KernelService\n\n");

		Out(L"[2/2] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
		std::vector<LoadedDriverEntry> drivers;
		if (!ScanLoadedDriversViaKernel(hDevice, 0, drivers)) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
			Out(ss.str());
			CloseKernelService(hDevice);
			return 1;
		}
		Out(L"  成功扫描到 " + std::to_wstring(drivers.size()) + L" 个内核模块\n\n");
		CloseKernelService(hDevice);

		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
		Out(L"  序号  加载序  基址              大小        模块名                驱动对象名\n");
		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

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
			}
			else {
				ss << L"  -";
			}
			ss << L"\n";
		}
		Out(ss.str());

		Out(L"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
		Out(L"扫描完成,共 " + std::to_wstring(drivers.size()) + L" 个模块\n");

		Out(L"\n完整路径清单:\n");
		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
		std::wostringstream pathSs;
		for (size_t i = 0; i < drivers.size(); i++) {
			const auto& d = drivers[i];
			pathSs << L"[" << std::setw(4) << (i + 1) << L"] "
				<< std::left << std::setw(40) << d.ModuleName
				<< L"  " << d.FullPath << L"\n";
		}
		Out(pathSs.str());
		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  辅助:把 DEVICE_ENTRY 一条记录格式化成单行字符串,用于表格输出
	// ═══════════════════════════════════════════════════════════════════════

	static std::wstring DeviceTypeToString(ULONG deviceType)
	{
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
			ss << L"  无设备\n";
			Out(ss.str());
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

		Out(ss.str());
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 2:--ScanAndClassify 驱动扫描 + 应用层签名分类,给出附着清单
	// ═══════════════════════════════════════════════════════════════════════

	static int RunScanAndClassify()
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  驱动扫描 + 签名分类,通过 KernelService 驱动\n");
		Out(L"  1. 驱动扫描 PsLoadedModuleList\n");
		Out(L"  2. 应用层路径规范化\n");
		Out(L"  3. 应用层 WinVerifyTrust 验签\n");
		Out(L"  4. 输出 THIRD_PARTY_WHQL 附着清单\n");
		Out(L"═══════════════════════════════════════════════════════\n\n");

		Out(L"[1/4] 打开 KernelService 设备...\n");
		void* hDevice = OpenKernelService();
		if (hDevice == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: CreateFile 失败,错误码=" << err << L"\n";
			if (err == ERROR_ACCESS_DENIED) {
				ss << L"  原因: 需要管理员权限运行\n";
			}
			else if (err == ERROR_FILE_NOT_FOUND) {
				ss << L"  原因: KernelService 驱动未加载 (sc start KernelService)\n";
			}
			Out(ss.str());
			return 1;
		}
		Out(L"  成功打开设备 \\\\.\\KernelService\n\n");

		Out(L"[2/4] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
		std::vector<LoadedDriverEntry> drivers;
		if (!ScanLoadedDriversViaKernel(hDevice, 0, drivers)) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
			Out(ss.str());
			CloseKernelService(hDevice);
			return 1;
		}
		Out(L"  成功扫描到 " + std::to_wstring(drivers.size()) + L" 个内核模块\n\n");
		CloseKernelService(hDevice);

		Out(L"[3/4] 路径规范化 + 签名分类...\n");
		{
			std::vector<ClassifySource> sources;
			sources.reserve(drivers.size());
			for (const auto& d : drivers) {
				ClassifySource src;
				src.name = d.ModuleName;
				src.rawPath = d.FullPath;
				src.objectName = d.DriverObjectName;
				sources.push_back(std::move(src));
			}
			std::vector<std::wstring> dummyNames, dummyPaths;
			ClassifyAndPrintDrivers(sources, false, dummyNames, dummyPaths);
		}
		Out(L"\n[4/4] 分类完成\n");
		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 4:--EnumDevices <DriverName>
	// ═══════════════════════════════════════════════════════════════════════

	static int RunEnumDevices(const std::wstring& driverName)
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  扫描单个驱动的设备列表,调试模式\n");
		Out(L"  驱动名: " + driverName + L"\n");
		Out(L"  内核会依次尝试 \\Driver\\" + driverName + L" 和 \\FileSystem\\" + driverName + L"\n");
		Out(L"═══════════════════════════════════════════════════════\n\n");

		Out(L"[1/2] 打开 KernelService 设备...\n");
		void* hDevice = OpenKernelService();
		if (hDevice == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: CreateFile 失败,错误码=" << err << L"\n";
			if (err == ERROR_ACCESS_DENIED) {
				ss << L"  原因: 需要管理员权限运行\n";
			}
			else if (err == ERROR_FILE_NOT_FOUND) {
				ss << L"  原因: KernelService 驱动未加载 (sc start KernelService)\n";
			}
			Out(ss.str());
			return 1;
		}
		Out(L"  成功打开设备 \\\\.\\KernelService\n\n");

		Out(L"[2/2] 发送 IOCTL_ENUM_DRIVER_DEVICES...\n");
		std::vector<DeviceEntry> devices;
		std::wstring foundPath;
		if (!EnumDriverDevices(hDevice, driverName, 0, devices, &foundPath)) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
			Out(ss.str());
			CloseKernelService(hDevice);
			return 1;
		}
		CloseKernelService(hDevice);

		PrintDeviceList(driverName, foundPath, devices);
		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 5:--ScanAndEnumDevices
	// ═══════════════════════════════════════════════════════════════════════

	static int RunScanAndEnumDevices()
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  驱动扫描 + 签名分类 + 设备列表扫描 + IAT 扫描,整合模式\n");
		Out(L"  1. 驱动扫描 PsLoadedModuleList\n");
		Out(L"  2. 应用层路径规范化 + WinVerifyTrust 验签\n");
		Out(L"  3. 产出 THIRD_PARTY_WHQL 附着清单\n");
		Out(L"  4. 对清单中每个驱动调 IOCTL_ENUM_DRIVER_DEVICES 扫设备列表\n");
		Out(L"  5. 对有设备的待附着驱动扫 IAT,标记高危内存操作函数\n");
		Out(L"═══════════════════════════════════════════════════════\n\n");

		Out(L"[1/5] 打开 KernelService 设备...\n");
		void* hDevice = OpenKernelService();
		if (hDevice == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: CreateFile 失败,错误码=" << err << L"\n";
			if (err == ERROR_ACCESS_DENIED) {
				ss << L"  原因: 需要管理员权限运行\n";
			}
			else if (err == ERROR_FILE_NOT_FOUND) {
				ss << L"  原因: KernelService 驱动未加载 (sc start KernelService)\n";
			}
			Out(ss.str());
			return 1;
		}
		Out(L"  成功打开设备 \\\\.\\KernelService\n\n");

		Out(L"[2/5] 发送 IOCTL_SCAN_LOADED_DRIVERS...\n");
		std::vector<LoadedDriverEntry> drivers;
		if (!ScanLoadedDriversViaKernel(hDevice, 0, drivers)) {
			DWORD err = GetLastError();
			std::wostringstream ss;
			ss << L"  失败: DeviceIoControl 失败,错误码=" << err << L"\n";
			Out(ss.str());
			CloseKernelService(hDevice);
			return 1;
		}
		Out(L"  成功扫描到 " + std::to_wstring(drivers.size()) + L" 个内核模块\n\n");

		Out(L"[3/5] 路径规范化 + 签名分类...\n");
		std::vector<ClassifySource> sources;
		sources.reserve(drivers.size());
		for (const auto& d : drivers) {
			ClassifySource src;
			src.name = d.ModuleName;
			src.rawPath = d.FullPath;
			src.objectName = d.DriverObjectName;
			sources.push_back(std::move(src));
		}
		std::vector<std::wstring> thirdPartyDriverObjectNames;
		std::vector<std::wstring> thirdPartyFilePaths;
		auto thirdPartyList = ClassifyAndPrintDrivers(sources, false, thirdPartyDriverObjectNames, thirdPartyFilePaths);

		Out(L"\n[4/5] 对待附着清单逐个调 IOCTL_ENUM_DRIVER_DEVICES 扫设备列表...\n");

		if (thirdPartyList.empty()) {
			Out(L"  待附着清单为空,跳过设备扫描\n");
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

			// 从内核拿到的真实驱动对象名,由 DriverNameResolver 用 ImageBase 反查
			std::wstring drvName = thirdPartyDriverObjectNames[i];

			std::wostringstream hdr;
			hdr << L"\n[" << (i + 1) << L"/" << thirdPartyList.size() << L"] "
				<< fileName;
			if (drvName.empty()) {
				hdr << L"  →  内核未找到 DriverObject,跳过";
			}
			else {
				hdr << L"  →  驱动对象名: " << drvName;
			}
			if (!note.empty()) hdr << L"  备注: " << note;
			hdr << L"\n";
			Out(hdr.str());

			if (drvName.empty()) {
				OutLine(L"  跳过:无 DriverObject");
				driversNotFound++;
				continue;
			}

			std::vector<DeviceEntry> devices;
			std::wstring foundPath;
			if (!EnumDriverDevices(hDevice, drvName, 0, devices, &foundPath)) {
				DWORD err = GetLastError();
				std::wostringstream ss;
				ss << L"  失败: IOCTL_ENUM_DRIVER_DEVICES 失败,错误码=" << err << L"\n";
				Out(ss.str());
				failed++;
				continue;
			}

			if (foundPath == L"(not found)" || devices.empty()) {
				if (foundPath == L"(not found)") {
					OutLine(L"  驱动对象未找到,在 \\Driver 和 \\FileSystem 都不存在");
					driversNotFound++;
				}
				else {
					Out(L"  驱动存在但未创建任何设备 (" + foundPath + L")\n");
					driversNoDevices++;
				}
				continue;
			}

			PrintDeviceList(drvName, foundPath, devices);
			totalDevices += (int)devices.size();
			driversWithDevices++;
		}

		CloseKernelService(hDevice);

		std::wostringstream sum;
		sum << L"\n═══════════════════════════════════════════════════════\n";
		sum << L"设备扫描汇总:\n";
		sum << L"  待附着驱动总数:    " << thirdPartyList.size() << L"\n";
		sum << L"  找到设备的驱动:    " << driversWithDevices << L"  共 " << totalDevices << L" 个设备\n";
		sum << L"  驱动存在但无设备:  " << driversNoDevices << L"\n";
		sum << L"  驱动对象未找到:    " << driversNotFound << L"  无 DriverObject,可能已卸载\n";
		sum << L"  IOCTL 调用失败:    " << failed << L"\n";
		sum << L"═══════════════════════════════════════════════════════\n";
		Out(sum.str());

		// ── 步骤 5:对有设备的待附着驱动扫 IAT,标记高危函数 ───────────
		Out(L"\n[5/5] 对有设备的待附着驱动扫 IAT,检查高危内存操作函数...\n");
		Out(L"  高危列表: MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory\n\n");

		int iatScanned = 0;
		int iatSkipped = 0;
		int iatFailed = 0;
		int iatDangerous = 0;
		std::vector<std::pair<std::wstring, std::vector<std::string>>> dangerousDrivers;

		for (size_t i = 0; i < thirdPartyList.size(); i++) {
			const auto& [fileName, note] = thirdPartyList[i];
			(void)note;
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
				Out(line.str());
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
				dangerousDrivers.push_back({ fileName, foundApis });
			}
			line << L"\n";
			Out(line.str());
		}

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
			iatSum << L"高危驱动清单,命中 MmCopyMemory/MmMapIoSpace/ZwMapViewOfSection/MmCopyVirtualMemory:\n";
			iatSum << L"───────────────────────────────────────────────────────\n";
			for (const auto& [name, apis] : dangerousDrivers) {
				iatSum << L"  " << name << L"\n";
				for (const auto& a : apis) {
					iatSum << L"    * " << U8ToW(a) << L"\n";
				}
			}
			iatSum << L"═══════════════════════════════════════════════════════\n";
		}

		Out(iatSum.str());

		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 5:--ScanIAT <sys文件>
	// ═══════════════════════════════════════════════════════════════════════

	static int RunScanIAT(const std::wstring& filePath)
	{
		Out(L"═══════════════════════════════════════════════════════\n");
		Out(L"  扫描 PE 导入表 (IAT) — 单文件模式\n");
		Out(L"  文件: " + filePath + L"\n");
		Out(L"═══════════════════════════════════════════════════════\n\n");

		DWORD attr = GetFileAttributesW(filePath.c_str());
		if (attr == INVALID_FILE_ATTRIBUTES) {
			DWORD e = GetLastError();
			Out(L"[诊断] GetFileAttributes 失败,错误码=" + std::to_wstring(e) + L"\n");
			if (e == ERROR_FILE_NOT_FOUND) OutLine(L"       → 文件不存在");
			if (e == ERROR_ACCESS_DENIED)  OutLine(L"       → 无访问权限");
			return 1;
		}
		std::wostringstream diag1;
		diag1 << L"[诊断] 文件存在,属性=0x" << std::hex << attr << std::dec
			<< (attr & FILE_ATTRIBUTE_DIRECTORY ? L",目录!" : L",普通文件") << L"\n";
		Out(diag1.str());

		std::vector<IatEntry> iat;
		std::wstring err;
		if (!ScanIat(filePath, iat, err)) {
			OutLine(L"[诊断] ScanIat 返回 false");
			Out(L"[诊断] 错误说明: " + (err.empty() ? L"空" : err) + L"\n");
			return 1;
		}

		Out(L"[诊断] ScanIat 返回 true,导入 DLL 数=" + std::to_wstring(iat.size()) + L"\n");
		if (!err.empty()) {
			Out(L"[诊断] 附加说明: " + err + L"\n");
		}

		if (iat.empty()) {
			OutLine(L"扫描成功,但无导入项。");
			return 0;
		}

		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
		Out(L"  完整 IAT\n");
		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

		int totalApis = 0;
		int totalDangerous = 0;

		for (size_t i = 0; i < iat.size(); i++) {
			const auto& entry = iat[i];

			std::wostringstream hdr;
			hdr << L"\n[" << std::setw(3) << (i + 1) << L"] "
				<< L"DLL: " << U8ToW(entry.dllName)
				<< L"  " << entry.apis.size() << L" 个 API\n";
			Out(hdr.str());

			Out(L"───────────────────────────────────────────────────────\n");

			for (size_t j = 0; j < entry.apis.size(); j++) {
				const std::string& api = entry.apis[j];

				bool danger = IsDangerousImport(api);

				std::wostringstream line;
				line << L"    " << std::setw(4) << (j + 1) << L". "
					<< std::left << std::setw(40)
					<< U8ToW(api);
				if (danger) {
					line << L"  ← 高危!";
					totalDangerous++;
				}
				line << L"\n";
				Out(line.str());

				totalApis++;
			}
		}

		Out(L"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
		Out(L"  高危函数汇总\n");
		Out(L"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

		std::vector<std::string> foundApis;
		HasDangerousImports(iat, foundApis);

		if (foundApis.empty()) {
			OutLine(L"  未发现高危内存操作函数");
		}
		else {
			std::wostringstream ss;
			ss << L"  命中 " << foundApis.size() << L" 个:\n";
			for (const auto& s : foundApis) {
				ss << L"    * " << U8ToW(s) << L"\n";
			}
			Out(ss.str());
		}

		std::wostringstream sum;
		sum << L"\n═══════════════════════════════════════════════════════\n";
		sum << L"汇总:\n";
		sum << L"  导入 DLL 数:  " << iat.size() << L"\n";
		sum << L"  导入 API 总数: " << totalApis << L"\n";
		sum << L"  高危函数命中: " << totalDangerous << L"\n";
		sum << L"═══════════════════════════════════════════════════════\n";
		Out(sum.str());

		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  模式 3:--ScanDriver 用 PSAPI 本地枚举并按签名分类
	// ═══════════════════════════════════════════════════════════════════════

	static int RunEnumAndClassify()
	{
		OutLine(L"枚举已加载的内核驱动模块,PSAPI 本地模式...");
		Out(L"\n");

		std::vector<LoadedDriver> drivers;
		if (!EnumLoadedDrivers(drivers)) {
			Out(L"EnumDeviceDrivers 失败,错误码: " + std::to_wstring(GetLastError()) + L"\n");
			return 1;
		}

		Out(L"共枚举到 " + std::to_wstring(drivers.size()) + L" 个已加载驱动,开始分类...\n\n");

		std::vector<ClassifySource> sources;
		sources.reserve(drivers.size());
		for (const auto& d : drivers) {
			ClassifySource src;
			src.name = d.name;
			src.rawPath = d.path;
			src.objectName = L"";
			sources.push_back(std::move(src));
		}

		std::vector<std::wstring> dummyNames, dummyPaths;
		ClassifyAndPrintDrivers(sources, true, dummyNames, dummyPaths);
		return 0;
	}

	// ═══════════════════════════════════════════════════════════════════════
	//  RunDriverAttachSelector — DriverAttachSelector 工具入口,原 wmain
	// ═══════════════════════════════════════════════════════════════════════

	int RunDriverAttachSelector(int argc, wchar_t** argv)
	{
		SetConsoleOutputCP(CP_UTF8);

		if (argc >= 2) {
			std::wstring arg1 = argv[1];

			if (arg1 == L"--help" || arg1 == L"-h") {
				PrintHelp();
				return 0;
			}

			if (arg1 == L"--ScanAndClassify") {
				return RunScanAndClassify();
			}

			if (arg1 == L"--ScanAndEnumDevices") {
				return RunScanAndEnumDevices();
			}

			if (arg1 == L"--EnumDevices") {
				if (argc < 3) {
					OutLine(L"用法: DriverAttachSelector.exe --EnumDevices <DriverName>");
					OutLine(L"  DriverName 不含路径,如 tcpip / ahflt / null");
					return 1;
				}
				return RunEnumDevices(argv[2]);
			}

			if (arg1 == L"--ScanIAT") {
				if (argc < 3) {
					OutLine(L"用法: DriverAttachSelector.exe --ScanIAT <sys文件路径>");
					OutLine(L"  如:--ScanIAT C:\\Windows\\System32\\drivers\\tcpip.sys");
					OutLine(L"  纯用户态,不调驱动,输出完整 IAT + 标记高危函数");
					return 1;
				}
				return RunScanIAT(argv[2]);
			}

			if (arg1 == L"--attach") {
				if (argc < 3) {
					OutLine(L"用法: DriverAttachSelector.exe --attach <设备路径>");
					OutLine(L"  如:--attach \\Device\\Tcp");
					OutLine(L"  内核用 IoCreateDriver + IoCreateDevice + IoAttachDeviceToDeviceStack");
					return 1;
				}
				return RunAttachDevice(argv[2]);
			}

			if (arg1 == L"--unattach") {
				if (argc < 3) {
					OutLine(L"用法: DriverAttachSelector.exe --unattach <Id|设备路径>");
					OutLine(L"  如:--unattach 1 或 --unattach \\Device\\Tcp");
					return 1;
				}
				return RunUnattachDevice(argv[2]);
			}

			if (arg1 == L"--list-attach") {
				return RunListAttachments();
			}

			if (arg1 == L"--etw") {
				unsigned int duration = 0;
				std::wstring outPath;
				for (int i = 2; i < argc; i++) {
					std::wstring a = argv[i];
					if (a == L"--duration" && i + 1 < argc) {
						duration = (unsigned int)_wtoi(argv[++i]);
					}
					else if (a == L"--out" && i + 1 < argc) {
						outPath = argv[++i];
					}
				}
				return RunEtwConsumer(duration, outPath);
			}

			if (arg1 == L"--ScanDriver") {
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

} // namespace das