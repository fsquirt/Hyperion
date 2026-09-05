#include "cmd.h"
#include "MonitorTypes.h"
#include "monitor.h"
#include "handle.h"
#include "../common/Out.h"

#include <windows.h>
#include <string>
#include <cstdlib>

namespace das {

	static void PrintHelp()
	{
		OutLine(L"用法:");
		OutLine(L"  HyperionToolKit.exe dumper                   永久订阅 ETW,Ctrl+C 退出");
		OutLine(L"  HyperionToolKit.exe dumper --duration N      订阅 N 秒后自动退出");
		OutLine(L"  HyperionToolKit.exe dumper --json            启用 JSON 通信日志,默认关闭以节省性能");
		OutLine(L"  HyperionToolKit.exe dumper --minidump        切换为 Minidump,MiniDumpNormal, 体积中");
		OutLine(L"  HyperionToolKit.exe dumper --mifudump        切换为 Full Minidump,默认 Raw 内存镜像");
		OutLine(L"  HyperionToolKit.exe dumper --handle <pid>    扫描持有目标 PID 的 VM_READ 句柄的进程,单次执行后退出");
		OutLine(L"  HyperionToolKit.exe dumper --help            显示此帮助");
		OutLine(L"");
		OutLine(L"功能:");
		OutLine(L"  引用 DriverAttachSelector 的 ETW 逻辑,监控被附着设备的通信事件。");
		OutLine(L"  从调用栈定位与驱动通信的磁盘文件,含进程 exe 与栈中业务模块,");
		OutLine(L"  若文件不存在或含 RHS,即只读/隐藏/系统属性,用红色输出。");
		OutLine(L"  栈模块/exe 首次出现时:");
		OutLine(L"    - 从内存 dump 到 dumpfile\\ 目录,默认 Raw 内存镜像, --minidump / --mifudump 切换");
		OutLine(L"    - 若磁盘上有文件,拷贝到 FileDump\\ 目录,磁盘副本,同名只拷贝一次");
		OutLine(L"  对端驱动 sys,按 AttachId 去重:");
		OutLine(L"    - 磁盘有文件 → 拷贝到 FileDump\\,内核 IOCTL_DUMP_DRIVER_MEMORY");
		OutLine(L"    - 磁盘缺失 → 按 PE 区段从内存 dump 到 dumpfile\\,跳过 DISCARDABLE");
		OutLine(L"  JSON 通信日志,可选, 加 --json 开启, 默认关闭以节省性能:");
		OutLine(L"    - 实时导出到 comms_log.json,直接写文件不缓存");
		OutLine(L"    - 时间戳/AttachId/PID/IOCTL码/InputBuffer(hex)/调用栈模块");
		OutLine(L"  异常文件名加前缀: MISSING_,磁盘不存在 / RHS_,含 RHS 属性。");
		OutLine(L"  --handle <pid> 模式: 单次全系统句柄扫描, 输出持有目标 PID 的");
		OutLine(L"    VM_READ 及更高危句柄的所有进程, 执行一次后退出,不走 ETW。");
	}

	int RunHeuristicDumper(int argc, wchar_t** argv)
	{
		SetConsoleOutputCP(CP_UTF8);

		MonitorOptions options;
		bool handleMode = false;
		unsigned long handlePid = 0;

		for (int i = 1; i < argc; i++) {
			std::wstring a = argv[i];
			if (a == L"--help" || a == L"-h") {
				PrintHelp();
				return 0;
			}
			if (a == L"--handle") {
				// --handle <pid>: 支持十进制或 0x 十六进制 PID
				if (i + 1 >= argc) {
					OutLine(L"[错误] --handle 需要一个 PID 参数");
					return 1;
				}
				handleMode = true;
				handlePid = wcstoul(argv[++i], nullptr, 0);
				continue;
			}
			if (a == L"--duration" && i + 1 < argc) {
				options.durationSec = (unsigned int)_wtoi(argv[++i]);
			}
			if (a == L"--json") {
				options.enableJson = true;
				continue;
			}
			if (a == L"--mifudump") {
				options.enableMifudump = true;
				continue;
			}
			if (a == L"--minidump") {
				options.enableMinidump = true;
				continue;
			}
		}

		// --handle 模式: 单次句柄扫描后退出, 不走 ETW 监控
		if (handleMode) {
			return ScanHandlesForPid(handlePid);
		}

		return RunCommsMonitor(options);
	}

} // namespace das