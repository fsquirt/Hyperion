// EtwConsumerStandalone.cpp — 独立复刻 DriverAttachSelector.exe --etw 功能
//
// 核心流程 (带详细输出):
//   1. 启用 SeSystemProfilePrivilege / SeDebugPrivilege
//   2. StartTraceW 开 Real-Time Session (事件回调 EventRecordCallback)
//   3. EnableTraceEx2 带 EVENT_ENABLE_PROPERTY_STACK_TRACE 启用 Provider
//   4. OpenTraceW 开实时消费者 (仅 EventRecordCallback, 不靠旧版回调)
//   5. ProcessTrace 阻塞消费, 直到 Ctrl+C 或超时
//   6. 回调里解析 ETW_IOCTL_EVENT_HEADER + Payload, 并从 ExtendedData 取调用栈
//
// 编译: 见 EtwConsumerStandalone.vcxproj (需要 Windows SDK, x64)
// 运行: EtwConsumerStandalone.exe [--duration 30] [--out C:\x.etl]
//
// 注意: 必须以管理员身份运行 (否则 StartTraceW 返回 0x57 / 0xB7 等)。

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <evntprov.h>
#include <tdh.h>
#include <psapi.h>

#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE32
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE32 5
#endif
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE64
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE64 6
#endif

// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
static const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR = L"{A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}";

// 内核端定义的 ETW_IOCTL_EVENT_HEADER 结构 (必须与内核 EtwLogger.h 字节对齐一致)
#pragma pack(push, 8)
struct EtwIoctlEventHeader {
    unsigned long       Version;
    unsigned long       IoControlCode;
    unsigned long       InputBufferLength;
    unsigned long       CaptureSize;
    unsigned long long  RequestorPid;
    unsigned long long  TargetDeviceAddr;
    unsigned long long  FilterDeviceAddr;
    unsigned long long  AttachId;
    unsigned long       MajorFunction;
    unsigned long       Method;
};
#pragma pack(pop)
static_assert(sizeof(EtwIoctlEventHeader) == 56, "EtwIoctlEventHeader size mismatch");

#define ETW_MAX_PAYLOAD_CAPTURE 4096

static std::atomic<bool> g_StopRequested{ false };
static const wchar_t* SESSION_NAME = L"KernelServiceIoctlTrace";

// ============================================================
// 输出 (UTF-8, 同时兼容控制台与重定向)
// ============================================================
static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int cb = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), cb, nullptr, nullptr);
    return s;
}
static void WriteOut(const std::wstring& s) {
    std::string u8 = ToUtf8(s);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    WriteFile(hOut, u8.data(), (DWORD)u8.size(), &written, nullptr);
}
// 带 [时间戳][TAG] 前缀的输出
static void Log(const std::wstring& tag, const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::wostringstream ss;
    ss << L"[" << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L"] "
       << L"[" << tag << L"] " << msg << L"\n";
    WriteOut(ss.str());
}

// 把将要传给 StartTraceW 的原始属性缓冲区逐字节 hex dump 出来,
// 用于与 C# 端逐字节对拍 (字段值打印看不出布局错位,必须看真实内存)。
static void DumpPropsBuffer(const unsigned char* data, size_t size) {
    std::wostringstream ss;
    ss << L"[PROPS] 属性缓冲区 hex dump (长度=" << (unsigned long)size << L", 偏移以字节计):\n";
    const size_t bytesPerLine = 16;
    for (size_t off = 0; off < size; off += bytesPerLine) {
        size_t lineLen = std::min(bytesPerLine, size - off);
        ss << L"  " << std::hex << std::setw(4) << std::setfill(L'0') << (unsigned long)off << L": ";
        for (size_t i = 0; i < bytesPerLine; i++) {
            if (i < lineLen)
                ss << std::hex << std::setw(2) << std::setfill(L'0') << (unsigned int)data[off + i] << L" ";
            else
                ss << L"   ";
            if (i == 7) ss << L" ";
        }
        ss << L" |";
        for (size_t i = 0; i < lineLen; i++) {
            unsigned char c = data[off + i];
            ss << (wchar_t)(c >= 32 && c < 127 ? c : L'.');
        }
        ss << L"|\n";
    }
    WriteOut(ss.str());
}

// ============================================================
// 工具: 启用权限
// ============================================================
static bool EnablePrivilege(LPCWSTR priv) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        Log(L"PRIV", L"OpenProcessToken 失败, lastError=0x" + std::to_wstring(GetLastError()));
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
        Log(L"PRIV", std::wstring(priv) + L": LookupPrivilegeValueW 失败, lastError=0x" + std::to_wstring(GetLastError()));
        CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);
    bool result = ok && err == ERROR_SUCCESS;
    Log(L"PRIV", std::wstring(priv) + L": AdjustTokenPrivileges ok=" + std::to_wstring(ok)
        + L", lastError=0x" + std::to_wstring(err) + L" -> " + std::wstring(result ? L"成功" : L"失败"));
    return result;
}

// ============================================================
// 工具: 调用栈 / payload 解析 (与 DriverAttachSelector/EtwConsumer.cpp 一致)
// ============================================================
static void PrintStackTrace(const EVENT_RECORD* record, unsigned long long requestorPid) {
    if (record->ExtendedDataCount == 0) {
        WriteOut(L"  调用栈: <无 ExtendedData — 栈未被捕获,检查 SeSystemProfilePrivilege>\n");
        return;
    }

    HANDLE hProcess = NULL;
    struct ModuleRange { unsigned long long base; unsigned long size; wchar_t name[MAX_PATH]; };
    std::vector<ModuleRange> modules;

    if (requestorPid != 0) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)requestorPid);
        if (hProcess) {
            HMODULE hMods[1024];
            DWORD cbNeeded = 0;
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                DWORD modCount = (DWORD)(cbNeeded / sizeof(HMODULE));
                if (modCount > 1024) modCount = 1024;
                for (DWORD m = 0; m < modCount; m++) {
                    MODULEINFO mi = {};
                    if (GetModuleInformation(hProcess, hMods[m], &mi, sizeof(mi))) {
                        ModuleRange mr = {};
                        mr.base = (unsigned long long)mi.lpBaseOfDll;
                        mr.size = mi.SizeOfImage;
                        GetModuleFileNameExW(hProcess, hMods[m], mr.name, MAX_PATH);
                        modules.push_back(mr);
                    }
                }
            }
        }
    }

    bool foundStack = false;
    for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record->ExtendedData[i];
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32 &&
            item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            continue;
        }
        if (item.DataSize < sizeof(unsigned long long)) continue;

        bool is64 = (item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64);
        const unsigned long long* pMatchId = (const unsigned long long*)item.DataPtr;
        const unsigned char* addrStart = (const unsigned char*)item.DataPtr + sizeof(unsigned long long);

        unsigned long frameCount = 0;
        const unsigned long long* frames64 = nullptr;
        const unsigned long* frames32 = nullptr;
        if (is64) {
            frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long long);
            frames64 = (const unsigned long long*)addrStart;
        } else {
            frameCount = (item.DataSize - sizeof(unsigned long long)) / sizeof(unsigned long);
            frames32 = (const unsigned long*)addrStart;
        }
        if (frameCount == 0) { WriteOut(L"  调用栈: <栈帧数为 0>\n"); continue; }

        foundStack = true;
        std::wostringstream ss;
        ss << L"  调用栈 (" << frameCount << L" 帧, " << (is64 ? L"64位" : L"32位") << L"):\n";
        unsigned long maxPrint = std::min(frameCount, (unsigned long)64);
        for (unsigned long f = 0; f < maxPrint; f++) {
            unsigned long long addr = is64 ? frames64[f] : frames32[f];
            ss << L"    [" << std::setw(2) << f << L"] " << std::hex
               << std::setw(16) << std::setfill(L'0') << addr;
            if (addr < 0x800000000000ULL) {
                bool resolved = false;
                for (const auto& mr : modules) {
                    if (addr >= mr.base && addr < mr.base + mr.size) {
                        const wchar_t* p = wcsrchr(mr.name, L'\\');
                        if (p) p++; else p = mr.name;
                        ss << L"  " << p << L"+0x" << std::hex << (addr - mr.base);
                        resolved = true;
                        break;
                    }
                }
                if (!resolved) ss << L"  <用户态:未解析>";
            } else {
                ss << L"  <内核态>";
            }
            ss << L"\n";
        }
        if (frameCount > maxPrint) ss << L"    ... 还有 " << (frameCount - maxPrint) << L" 帧未显示\n";
        WriteOut(ss.str());
        break;
    }

    if (!foundStack) {
        std::wostringstream dbg;
        dbg << L"  调用栈: <ExtendedData 里没有 STACK_TRACE32/64 条目>\n";
        dbg << L"  [诊断] ExtendedDataCount=" << record->ExtendedDataCount << L"\n";
        for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
            dbg << L"    [" << i << L"] ExtType=" << record->ExtendedData[i].ExtType
                << L" DataSize=" << record->ExtendedData[i].DataSize << L"\n";
        }
        WriteOut(dbg.str());
    }
    if (hProcess) CloseHandle(hProcess);
}

static const wchar_t* MethodName(unsigned long ioctl) {
    switch (ioctl & 3) {
    case 0: return L"BUFFERED";
    case 1: return L"IN_DIRECT";
    case 2: return L"OUT_DIRECT";
    case 3: return L"NEITHER";
    default: return L"?";
    }
}

static std::wstring HexDump(const unsigned char* data, unsigned long size) {
    if (size == 0) return L"";
    std::wostringstream ss;
    const unsigned long bytesPerLine = 16;
    for (unsigned long off = 0; off < size; off += bytesPerLine) {
        unsigned long lineLen = std::min(bytesPerLine, size - off);
        ss << L"    " << std::hex << std::setw(4) << std::setfill(L'0') << off << L": ";
        for (unsigned long i = 0; i < bytesPerLine; i++) {
            if (i < lineLen)
                ss << std::hex << std::setw(2) << std::setfill(L'0') << (unsigned int)data[off + i] << L" ";
            else
                ss << L"   ";
            if (i == 7) ss << L" ";
        }
        ss << L" |";
        for (unsigned long i = 0; i < lineLen; i++) {
            unsigned char c = data[off + i];
            ss << (wchar_t)(c >= 32 && c < 127 ? c : L'.');
        }
        ss << L"|\n";
    }
    return ss.str();
}

// 小工具: 安全地把 GUID 转成可读串 (避免依赖额外头)
static std::wstring GuidToStringSafe(const GUID& g);

// ============================================================
// 事件回调
// ============================================================
static void WINAPI EventRecordCallback(EVENT_RECORD* record) {
    if (g_StopRequested.load()) return;

    Log(L"CB", L"收到事件: ProviderId=" + GuidToStringSafe(record->EventHeader.ProviderId)
        + L" EventId=" + std::to_wstring(record->EventHeader.EventDescriptor.Id)
        + L" Version=" + std::to_wstring(record->EventHeader.EventDescriptor.Version)
        + L" UserDataLength=" + std::to_wstring(record->UserDataLength)
        + L" ExtendedDataCount=" + std::to_wstring(record->ExtendedDataCount));

    if (record->EventHeader.EventDescriptor.Id != 1) return;

    if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) {
        WriteOut(L"[ETW] 事件 UserData 太短,跳过\n");
        return;
    }

    const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;
    const unsigned char* payload = (const unsigned char*)record->UserData + sizeof(EtwIoctlEventHeader);
    unsigned long payloadLen = hdr->CaptureSize;
    if (sizeof(EtwIoctlEventHeader) + payloadLen > (unsigned long)record->UserDataLength)
        payloadLen = (unsigned long)record->UserDataLength - sizeof(EtwIoctlEventHeader);

    std::wostringstream ss;
    ss << L"\n═══════════════════════════════════════════════════════\n";
    ss << L"  IOCTL 拦截事件  (AttachId=" << hdr->AttachId << L")\n";
    ss << L"───────────────────────────────────────────────────────\n";
    ss << L"  IoControlCode:    0x" << std::hex << std::setw(8) << std::setfill(L'0') << hdr->IoControlCode
       << L"  (METHOD_" << MethodName(hdr->IoControlCode) << L")\n";
    ss << L"  MajorFunction:    0x" << std::hex << std::setw(2) << std::setfill(L'0') << hdr->MajorFunction;
    if (hdr->MajorFunction == 0x0E) ss << L" (DEVICE_CONTROL)";
    else if (hdr->MajorFunction == 0x00) ss << L" (CREATE)";
    else if (hdr->MajorFunction == 0x02) ss << L" (CLOSE)";
    else if (hdr->MajorFunction == 0x03) ss << L" (READ)";
    else if (hdr->MajorFunction == 0x04) ss << L" (WRITE)";
    ss << L"\n";
    ss << L"  发起进程 PID:     " << std::dec << hdr->RequestorPid << L"\n";
    ss << L"  InputBuffer 长度: " << hdr->InputBufferLength << L" 字节\n";
    ss << L"  实际抓取:         " << hdr->CaptureSize << L" 字节 (最多 " << ETW_MAX_PAYLOAD_CAPTURE << L")\n";
    ss << L"  FilterDevice:     0x" << std::hex << hdr->FilterDeviceAddr << L"\n";
    ss << L"  TargetDevice:     0x" << hdr->TargetDeviceAddr << L"\n";

    SYSTEMTIME st; FILETIME ft;
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);
    ss << L"  时间:             " << std::dec
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L"\n";
    WriteOut(ss.str());

    if (payloadLen > 0) {
        std::wostringstream ph;
        ph << L"  Payload (Hex Dump):\n";
        ph << HexDump(payload, payloadLen);
        WriteOut(ph.str());
    } else {
        WriteOut(L"  Payload: <空>\n");
    }
    PrintStackTrace(record, hdr->RequestorPid);
}

// 小工具: 安全地把 GUID 转成可读串 (避免依赖额外头)
static std::wstring GuidToStringSafe(const GUID& g) {
    wchar_t buf[64];
    swprintf_s(buf, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
               g.Data1, g.Data2, g.Data3,
               g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
               g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

static ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* logfile) {
    UNREFERENCED_PARAMETER(logfile);
    return g_StopRequested.load() ? FALSE : TRUE;
}

// ============================================================
// 主订阅逻辑
// ============================================================
static int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath) {
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  ETW 实时订阅 — IOCTL 拦截事件 + 跨态调用栈 (独立版)\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    Log(L"INIT", L"Provider GUID: " + std::wstring(ETW_IOCTL_PROVIDER_GUID_STR));
    Log(L"INIT", std::wstring(L"Session 名称: ") + SESSION_NAME);
    if (durationSec > 0)
        Log(L"INIT", L"持续时间: " + std::to_wstring(durationSec) + L" 秒");
    else
        Log(L"INIT", L"持续时间: 永久 (Ctrl+C 退出)");
    if (!etlPath.empty())
        Log(L"INIT", L"落盘文件: " + etlPath);

    // 1. 权限
    Log(L"INIT", L"正在启用权限...");
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME))
        WriteOut(L"[警告] 启用 SeSystemProfilePrivilege 失败,可能无法抓栈\n");
    if (!EnablePrivilege(SE_DEBUG_NAME))
        WriteOut(L"[警告] 启用 SeDebugPrivilege 失败 (非致命)");

    // 2. Ctrl+C
    g_StopRequested.store(false);
    auto handler = [](DWORD ctrl) -> BOOL {
        if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT) {
            g_StopRequested.store(true);
            WriteOut(L"\n[收到 Ctrl+C,正在停止订阅...]\n");
            return TRUE;
        }
        return FALSE;
    };
    SetConsoleCtrlHandler(handler, TRUE);

    // 3. 准备 EVENT_TRACE_PROPERTIES
    const size_t sessionNameLen = wcslen(SESSION_NAME) + 1;
    size_t logFileNameLen = 0;
    if (!etlPath.empty()) logFileNameLen = etlPath.length() + 1;

    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES)
                    + sessionNameLen * sizeof(wchar_t)
                    + logFileNameLen * sizeof(wchar_t);

    std::vector<unsigned char> propBuf(propSize, 0);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)propBuf.data();
    props->Wnode.BufferSize = (ULONG)propSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    if (!etlPath.empty()) {
        props->LogFileMode |= EVENT_TRACE_FILE_MODE_SEQUENTIAL;
        props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameLen * sizeof(wchar_t);
        wcscpy_s((LPWSTR)((unsigned char*)props + props->LogFileNameOffset), logFileNameLen, etlPath.c_str());
    } else {
        props->LogFileNameOffset = 0;
    }
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((LPWSTR)((unsigned char*)props + props->LoggerNameOffset), sessionNameLen, SESSION_NAME);
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 32;
    props->MaximumFileSize = 100;
    props->FlushTimer = 1;

    Log(L"PROPS", L"EVENT_TRACE_PROPERTIES 固定大小=" + std::to_wstring((unsigned long)sizeof(EVENT_TRACE_PROPERTIES))
        + L" 总缓冲区=" + std::to_wstring((unsigned long)propSize));
    Log(L"PROPS", L"Wnode.BufferSize=" + std::to_wstring(props->Wnode.BufferSize));
    Log(L"PROPS", L"Wnode.Flags=0x" + std::to_wstring(props->Wnode.Flags)
        + L" (WNODE_FLAG_TRACED_GUID=0x10000)");
    Log(L"PROPS", L"Wnode.ClientContext=" + std::to_wstring(props->Wnode.ClientContext) + L" (1=QPC)");
    Log(L"PROPS", L"LogFileMode=0x" + std::to_wstring(props->LogFileMode)
        + L" (REAL_TIME_MODE=0x100)");
    Log(L"PROPS", L"LoggerNameOffset=" + std::to_wstring(props->LoggerNameOffset)
        + L" LogFileNameOffset=" + std::to_wstring(props->LogFileNameOffset));
    Log(L"PROPS", L"BufferSize=" + std::to_wstring(props->BufferSize)
        + L" Min=" + std::to_wstring(props->MinimumBuffers)
        + L" Max=" + std::to_wstring(props->MaximumBuffers)
        + L" FlushTimer=" + std::to_wstring(props->FlushTimer));

    // 4. 先停残留 Session
    ULONG preStop = ControlTraceW((TRACEHANDLE)0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    Log(L"PROPS", L"预停止已有同名 Session: ControlTraceW 返回=0x" + std::to_wstring(preStop)
        + L" (0x0=成功, 0xC0000035/0xB7=不存在=正常)");

    // 5. hex dump 原始属性缓冲区 (与 C# 端逐字节对拍)
    DumpPropsBuffer(propBuf.data(), propBuf.size());

    // 6. StartTrace
    TRACEHANDLE sessionHandle = 0;
    Log(L"START", L"调用 StartTraceW(sessionName=" + std::wstring(SESSION_NAME) + L")...");
    ULONG status = StartTraceW(&sessionHandle, SESSION_NAME, props);
    Log(L"START", L"StartTraceW 返回 status=0x" + std::to_wstring(status)
        + L" sessionHandle=0x" + std::to_wstring(sessionHandle)
        + L" lastError=0x" + std::to_wstring(GetLastError()));
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] StartTraceW 失败: " + std::to_wstring(status) + L"\n");
        return 1;
    }
    WriteOut(L"[OK] ETW Session 已启动: " + std::wstring(SESSION_NAME) + L"\n");

    // 7. EnableTraceEx2
    GUID providerGuid;
    CLSIDFromString(ETW_IOCTL_PROVIDER_GUID_STR, &providerGuid);
    Log(L"ENABLE", L"Provider GUID 解析: " + GuidToStringSafe(providerGuid));

    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
    params.SourceId = providerGuid;

    Log(L"ENABLE", L"调用 EnableTraceEx2(level=VERBOSE, EnableProperty=STACK_TRACE)...");
    status = EnableTraceEx2(sessionHandle, &providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    Log(L"ENABLE", L"EnableTraceEx2 返回 status=0x" + std::to_wstring(status)
        + L" lastError=0x" + std::to_wstring(GetLastError()));
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] EnableTraceEx2 失败: " + std::to_wstring(status) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    WriteOut(L"[OK] Provider 已启用,带 EVENT_ENABLE_PROPERTY_STACK_TRACE\n");
    WriteOut(L"\n等待 IOCTL 事件...(attach 一个设备后,对其发 IOCTL 即可看到事件)\n\n");

    // 8. OpenTrace
    EVENT_TRACE_LOGFILE logFile{};
    logFile.LoggerName = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;
    logFile.IsKernelTrace = FALSE;

    Log(L"OPEN", L"调用 OpenTraceW(LoggerName=" + std::wstring(SESSION_NAME)
        + L", ProcessTraceMode=0x" + std::to_wstring(logFile.ProcessTraceMode) + L")...");
    TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG err = GetLastError();
        Log(L"OPEN", L"OpenTraceW 失败: lastError=0x" + std::to_wstring(err));
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    Log(L"OPEN", L"OpenTraceW 成功, consumerHandle=0x" + std::to_wstring(consumerHandle));

    // 9. 超时定时器
    HANDLE hTimer = NULL;
    if (durationSec > 0) {
        hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
        if (hTimer) {
            LARGE_INTEGER due;
            due.QuadPart = -((LONGLONG)durationSec * 10000000LL);
            SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
        }
    }

    // 10. ProcessTrace 在后台线程
    HANDLE hTraceThread = CreateThread(NULL, 0,
        [](LPVOID param) -> DWORD {
            TRACEHANDLE* ph = (TRACEHANDLE*)param;
            ULONG st = ProcessTrace(ph, 1, NULL, NULL);
            Log(L"PT", L"ProcessTrace 返回 status=0x" + std::to_wstring(st));
            return 0;
        }, &consumerHandle, 0, NULL);

    while (true) {
        HANDLE waits[2] = { hTraceThread, hTimer };
        DWORD waitCount = (hTimer != NULL) ? 2 : 1;
        DWORD waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, 200);
        if (waitResult != WAIT_TIMEOUT) break;
        if (g_StopRequested.load()) break;
    }

    g_StopRequested.store(true);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    if (hTraceThread) WaitForSingleObject(hTraceThread, 5000);
    if (hTraceThread) CloseHandle(hTraceThread);
    if (hTimer) CloseHandle(hTimer);
    CloseTrace(consumerHandle);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    SetConsoleCtrlHandler(handler, FALSE);
    WriteOut(L"\n[OK] ETW 订阅已停止\n");
    return 0;
}

// ============================================================
// main
// ============================================================
int wmain(int argc, wchar_t* argv[]) {
    // 让控制台按 UTF-8 解读输出,避免中文乱码 (源码以 UTF-8 字节写出)
    SetConsoleOutputCP(CP_UTF8);

    unsigned int durationSec = 30;   // 默认 30 秒 (与 DriverAttachSelector.exe --etw 一致)
    std::wstring etlPath;

    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--duration" && i + 1 < argc) {
            durationSec = (unsigned int)_wtoi(argv[++i]);
        } else if (a == L"--out" && i + 1 < argc) {
            etlPath = argv[++i];
        } else if (a == L"--help" || a == L"-h") {
            WriteOut(L"用法: EtwConsumerStandalone.exe [--duration 秒] [--out 文件.etl]\n");
            return 0;
        }
    }

    return RunEtwConsumer(durationSec, etlPath);
}
