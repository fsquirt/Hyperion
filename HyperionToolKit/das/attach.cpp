// attach.cpp — 设备附着/解绑/查询实现

#include "attach.h"
#include "../common/KernelComms.h"
#include "../common/Out.h"
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdlib>

namespace das {

int RunAttachDevice(const std::wstring& devicePath)
{
    Out(L"═══════════════════════════════════════════════════════\n");
    Out(L"  设备附着\n");
    Out(L"═══════════════════════════════════════════════════════\n");

    if (devicePath.empty() || devicePath[0] != L'\\') {
        OutLine(L"  错误: 设备路径必须以 \\ 开头,如 \\Device\\Tcp");
        return 1;
    }

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Out(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
            std::to_wstring(err) + L")\n");
        if (err == ERROR_ACCESS_DENIED) {
            OutLine(L"  请以管理员权限运行");
        } else if (err == ERROR_FILE_NOT_FOUND) {
            OutLine(L"  KernelService 驱动未加载,请先 sc start KernelService");
        }
        return 1;
    }

    Out(L"  目标路径:        " + devicePath + L"\n");

    unsigned long attachId = 0;
    unsigned long long filterAddr = 0, lowerAddr = 0;
    unsigned short newStack = 0, targetStack = 0;

    if (!AttachToDevice(hDevice, devicePath, attachId,
                        &filterAddr, &lowerAddr, &newStack, &targetStack)) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS) {
            OutLine(L"  该设备已被附着过,跳过");
        } else {
            Out(L"  错误: 附着失败 (GetLastError=" + std::to_wstring(err) + L")\n");
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
    Out(ss.str());

    CloseKernelService(hDevice);
    return 0;
}

int RunUnattachDevice(const std::wstring& arg)
{
    Out(L"═══════════════════════════════════════════════════════\n");
    Out(L"  解除附着\n");
    Out(L"═══════════════════════════════════════════════════════\n");

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Out(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
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
            OutLine(L"  错误: ID 必须 > 0");
            CloseKernelService(hDevice);
            return 1;
        }
        Out(L"  按 ID 解绑:       " + std::to_wstring(attachId) + L"\n");
        ok = DetachDevice(hDevice, attachId, detachedId);
    } else {
        if (arg.empty() || arg[0] != L'\\') {
            OutLine(L"  错误: 参数必须是 ID(数字)或设备路径(以 \\ 开头)");
            CloseKernelService(hDevice);
            return 1;
        }
        Out(L"  按路径解绑:      " + arg + L"\n");
        ok = DetachDeviceByPath(hDevice, arg, detachedId);
    }

    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_FOUND) {
            OutLine(L"  错误: 未找到匹配的附着");
        } else {
            Out(L"  错误: 解绑失败 (GetLastError=" + std::to_wstring(err) + L")\n");
        }
        CloseKernelService(hDevice);
        return 1;
    }

    std::wostringstream ss;
    ss << L"  已解绑 ID:       " << detachedId << L"\n";
    ss << L"═══════════════════════════════════════════════════════\n";
    Out(ss.str());

    CloseKernelService(hDevice);
    return 0;
}

int RunListAttachments()
{
    Out(L"═══════════════════════════════════════════════════════\n");
    Out(L"  当前附着列表\n");
    Out(L"═══════════════════════════════════════════════════════\n");

    void* hDevice = OpenKernelService();
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        Out(L"  错误: 无法打开 KernelService 设备句柄 (GetLastError=" +
            std::to_wstring(err) + L")\n");
        return 1;
    }

    std::vector<AttachEntry> entries;
    if (!QueryAttachments(hDevice, entries)) {
        DWORD err = GetLastError();
        Out(L"  错误: 查询失败 (GetLastError=" + std::to_wstring(err) + L")\n");
        CloseKernelService(hDevice);
        return 1;
    }

    if (entries.empty()) {
        OutLine(L"  (空,没有附着任何设备)");
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
        Out(ss.str());
    }

    Out(L"═══════════════════════════════════════════════════════\n");
    CloseKernelService(hDevice);
    return 0;
}

} // namespace das