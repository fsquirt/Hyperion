#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <vector>

// 随便捏造一个 IOCTL 码
#define IOCTL_DUMMY_RANDOM CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
    // 控制台输出/输入切到 UTF-8（65001 = CP_UTF8），保证 printf 中文正常显示。
    // 仅改 codepage 还不够：源文件须以 UTF-8 编译（见 IOCTLSender.vcxproj 的 /utf-8），
    // 否则中文字面量会被按系统代码页(GBK)误解，二进制里就是错的字节，怎么改控制台都乱码。
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    // 【核心魔法】使用 GLOBALROOT 强行穿透访问 NT 设备名，无需符号链接！
    const wchar_t* symLink = L"\\\\?\\GLOBALROOT\\Device\\OpenArkDrv";

    printf("[INFO] 尝试打开设备: \\\\?\\GLOBALROOT\\Device\\OpenArkDrv ...\n");

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
        printf("[ERROR] 打开设备失败, GetLastError = 0x%X\n", GetLastError());
        printf("[HINT] 请确认 OpenArk 驱动已加载，并且你以管理员身份运行了此发包程序。\n");
        return 1;
    }

    printf("[OK] 设备打开成功！\n");
    printf("[INFO] 准备发送随机 IOCTL (Code: 0x%X)...\n", IOCTL_DUMMY_RANDOM);

    // 构造一段随便的 Payload
    std::vector<unsigned char> inputBuf = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    std::vector<unsigned char> outputBuf(1024, 0);
    DWORD bytesReturned = 0;

    // 发送 IOCTL
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_DUMMY_RANDOM,
        inputBuf.data(),
        (DWORD)inputBuf.size(),
        outputBuf.data(),
        (DWORD)outputBuf.size(),
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("[OK] IOCTL 发送成功！驱动返回了 %u 字节。\n", bytesReturned);
    }
    else {
        // 因为这是一个捏造的未知 IOCTL，驱动通常会返回 0x1 (ERROR_INVALID_FUNCTION)
        printf("[INFO] IOCTL 发送失败，这是预期之内的！\n");
        printf("       驱动拒绝了未知的控制码，GetLastError = 0x%X\n", GetLastError());
    }

    CloseHandle(hDevice);
    printf("[INFO] 测试结束，请去查看 C# ETW 消费者的界面，应该已经抓到包了！\n");

    printf("[INFO] 按任意键退出...\n");
    getchar();

    return 0;
}