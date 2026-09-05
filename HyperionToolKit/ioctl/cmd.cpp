// cmd.cpp — IOCTLSender 子命令实现
//
// 向 \\?\GLOBALROOT\Device\OpenArkDrv 发一个随机的未知 IOCTL 测试包,

#include <windows.h>
#include <winioctl.h>
#include <vector>

#include "../common/Out.h"

namespace das {

	int RunIoctlSender()
	{
		SetConsoleOutputCP(CP_UTF8);

		// 随便捏造一个 IOCTL 码
		const unsigned long ioctlCode = CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

		// 使用 GLOBALROOT 穿透访问 NT 设备名
		const wchar_t* symLink = L"\\\\?\\GLOBALROOT\\Device\\OpenArkDrv";

		OutLine(L"[INFO] 尝试打开设备: \\\\?\\GLOBALROOT\\Device\\OpenArkDrv ...");

		HANDLE hDevice = CreateFileW(
			symLink,
			GENERIC_READ | GENERIC_WRITE,
			0,              // 0 表示独占访问
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hDevice == INVALID_HANDLE_VALUE) {
			OutLine(L"[ERROR] 打开设备失败, GetLastError = 0x" + std::to_wstring(GetLastError()));
			OutLine(L"[HINT] 请确认驱动已加载, 并且以管理员身份运行了此发包程序。");
			return 1;
		}

		OutLine(L"[OK] 设备打开成功!");
		OutLine(L"[INFO] 准备发送随机 IOCTL (Code: 0x" + std::to_wstring(ioctlCode) + L")...");

		// 构造一段随便的 Payload
		std::vector<unsigned char> inputBuf = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
		std::vector<unsigned char> outputBuf(1024, 0);
		DWORD bytesReturned = 0;

		// 发送 IOCTL
		BOOL result = DeviceIoControl(
			hDevice,
			ioctlCode,
			inputBuf.data(),
			(DWORD)inputBuf.size(),
			outputBuf.data(),
			(DWORD)outputBuf.size(),
			&bytesReturned,
			NULL
		);

		if (result) {
			OutLine(L"[OK] IOCTL 发送成功! 驱动返回了 " + std::to_wstring(bytesReturned) + L" 字节。");
		}
		else {
			// 因为这是一个捏造的未知 IOCTL, 驱动通常会返回 0x1 (ERROR_INVALID_FUNCTION)
			OutLine(L"[INFO] IOCTL 发送失败, 这是预期之内的");
			OutLine(L"       驱动拒绝了未知的控制码, GetLastError = 0x" + std::to_wstring(GetLastError()));
		}

		CloseHandle(hDevice);
		Pause();

		return 0;
	}

} // namespace das