// JsonLogger.cpp — JSON 通信日志 (可选功能)
//
// 拆分自 CommsMonitor.cpp:
//   - InitJsonLog / WriteJsonEvent / CloseJsonLog: JSON 数组文件写入
//   - JsonEscape / BytesToHex: 辅助函数
//
// 默认关闭, 由 RunCommsMonitor 根据 MonitorOptions.enableJson 决定是否调用 InitJsonLog。
// 每次通信事件直接追加写文件, 不在内存缓存。
// ETW 回调是单线程串行 (ProcessTrace 专用线程), 无需加锁。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "JsonLogger.h"
#include "Common.h"

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace das {

// JSON 日志文件句柄 + 路径 + 首事件标记
static HANDLE g_hJsonFile = INVALID_HANDLE_VALUE;
static std::wstring g_jsonPath;
static bool g_jsonFirstEvent = true;  // 第一个事件不加前导逗号

// JSON 字符串转义 (路径等字符串里可能有 \ ")
static std::wstring JsonEscape(const std::wstring& s)
{
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
        case L'\\': out += L"\\\\"; break;
        case L'"':  out += L"\\\""; break;
        case L'\n': out += L"\\n";  break;
        case L'\r': out += L"\\r";  break;
        case L'\t': out += L"\\t";  break;
        default:
            if (c < 0x20) {
                wchar_t buf[8];
                swprintf_s(buf, L"\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// 字节数组 → hex 字符串 (用于 InputBuffer)
static std::wstring BytesToHex(const unsigned char* data, size_t len)
{
    if (!data || len == 0) return L"";
    // 限制最大输出 (避免超大 InputBuffer 导致 JSON 爆炸)
    size_t maxLen = (len > 4096) ? 4096 : len;
    std::wstring hex;
    hex.reserve(maxLen * 2);
    const wchar_t* digits = L"0123456789abcdef";
    for (size_t i = 0; i < maxLen; i++) {
        hex += digits[(data[i] >> 4) & 0xF];
        hex += digits[data[i] & 0xF];
    }
    if (len > maxLen) {
        hex += L"... (truncated, total " + std::to_wstring(len) + L" bytes)";
    }
    return hex;
}

// 初始化 JSON 日志文件: 创建 comms_log.json, 写入数组开头 "[\n"
bool InitJsonLog()
{
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (len == 0) return false;

    std::wstring dir(exePath);
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = dir.substr(0, slash);

    g_jsonPath = dir + L"\\comms_log.json";

    // 如果文件已存在, 覆盖 (CREATE_ALWAYS)
    g_hJsonFile = CreateFileW(g_jsonPath.c_str(), GENERIC_WRITE,
                               0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hJsonFile == INVALID_HANDLE_VALUE) return false;

    g_jsonFirstEvent = true;

    // 写入数组开头
    const char* header = "[\n";
    DWORD written = 0;
    WriteFile(g_hJsonFile, header, (DWORD)strlen(header), &written, NULL);
    return true;
}

// 追加一个通信事件到 JSON 文件 (直接写, 不缓存)
void WriteJsonEvent(
    const SYSTEMTIME& st,
    const EtwIoctlEventHeader* hdr,
    const std::wstring& exePath,
    const std::vector<StackModuleInfo>& stackModules,
    const unsigned char* inputBuffer,  // ETW UserData 紧跟 header 之后的 payload
    unsigned long inputBufferSize)     // 实际 payload 字节数
{
    if (g_hJsonFile == INVALID_HANDLE_VALUE) return;

    // 构造 JSON 对象 (UTF-8)
    std::ostringstream ss;

    // 前导逗号 (第一个事件不加)
    if (!g_jsonFirstEvent) {
        ss << ",\n";
    }
    g_jsonFirstEvent = false;

    ss << "  {\n";

    // 时间戳 ISO 格式
    ss << "    \"timestamp\": \""
       << std::setfill('0')
       << std::setw(4) << st.wYear << "-"
       << std::setw(2) << st.wMonth << "-"
       << std::setw(2) << st.wDay << "T"
       << std::setw(2) << st.wHour << ":"
       << std::setw(2) << st.wMinute << ":"
       << std::setw(2) << st.wSecond << "."
       << std::setw(3) << st.wMilliseconds
       << "\",\n";

    ss << "    \"attach_id\": " << hdr->AttachId << ",\n";
    ss << "    \"pid\": " << hdr->RequestorPid << ",\n";
    ss << "    \"ioctl_code\": \"0x"
       << std::hex << std::setw(8) << std::setfill('0') << hdr->IoControlCode
       << std::dec << "\",\n";
    ss << "    \"major_function\": " << hdr->MajorFunction << ",\n";
    ss << "    \"method\": " << hdr->Method << ",\n";

    // exe 路径 (wstring → UTF-8)
    std::wstring wexe = exePath;
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wexe.c_str(), -1,
                                      NULL, 0, NULL, NULL);
    std::string utf8Exe(utf8Len > 0 ? utf8Len : 1, '\0');
    if (utf8Len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, wexe.c_str(), -1,
                            &utf8Exe[0], utf8Len, NULL, NULL);
        utf8Exe.resize(utf8Len - 1);  // 去掉尾部 \0
    }
    ss << "    \"process_exe\": \"" << utf8Exe << "\",\n";

    // InputBuffer (hex)
    std::wstring hexInput = BytesToHex(inputBuffer, inputBufferSize);
    std::string utf8Hex(hexInput.begin(), hexInput.end());
    ss << "    \"input_buffer_hex\": \"" << utf8Hex << "\",\n";
    ss << "    \"input_buffer_size\": " << inputBufferSize << ",\n";

    // 栈模块数组
    ss << "    \"stack_modules\": [";
    for (size_t i = 0; i < stackModules.size(); i++) {
        // wstring → UTF-8
        const std::wstring& wmod = stackModules[i].path;
        int modLen = WideCharToMultiByte(CP_UTF8, 0, wmod.c_str(), -1,
                                         NULL, 0, NULL, NULL);
        std::string utf8Mod(modLen > 0 ? modLen : 1, '\0');
        if (modLen > 0) {
            WideCharToMultiByte(CP_UTF8, 0, wmod.c_str(), -1,
                                &utf8Mod[0], modLen, NULL, NULL);
            utf8Mod.resize(modLen - 1);
        }
        ss << (i > 0 ? ", " : "")
           << "{\"path\": \"" << utf8Mod << "\""
           << ", \"base\": " << stackModules[i].base
           << ", \"size\": " << stackModules[i].size
           << "}";
    }
    ss << "]\n";

    ss << "  }";

    // 直接写文件
    std::string json = ss.str();
    DWORD written = 0;
    WriteFile(g_hJsonFile, json.data(), (DWORD)json.size(), &written, NULL);
}

// 关闭 JSON 日志: 写入数组结尾 "]\n" 并关闭文件
void CloseJsonLog()
{
    if (g_hJsonFile == INVALID_HANDLE_VALUE) return;

    const char* footer = "\n]\n";
    DWORD written = 0;
    WriteFile(g_hJsonFile, footer, (DWORD)strlen(footer), &written, NULL);

    CloseHandle(g_hJsonFile);
    g_hJsonFile = INVALID_HANDLE_VALUE;
}

// JSON 日志文件路径访问器 (供 RunCommsMonitor 打印提示用)
const std::wstring& GetJsonPath() { return g_jsonPath; }

} // namespace das
