// EtwConsumer.cpp — ETW 实时订阅实现
//
// 核心流程:
//   1. SeSystemProfilePrivilege + SeTraceLoggingPrivilege 启用权限
//   2. StartTraceW 开 Real-Time Session (事件回调 EventRecordCallback)
//   3. EnableTraceEx2 带 EVENT_ENABLE_PROPERTY_STACK_TRACE 启用 Provider
//   4. OpenTraceW 开实时消费者 (BufferCallback 不用,只用 EventCallback)
//   5. ProcessTrace 阻塞消费,直到 StopTrace 或超时
//   6. 回调里解析 UserData = ETW_IOCTL_EVENT_HEADER + Payload
//      并从 ExtendedData 取 STACK_TRACE 调用栈

// 必须在 windows.h 之前定义,避免 min/max 宏污染 std::min/std::max
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "EtwConsumer.h"
#include "Common.h"

#include <windows.h>
#include <evntcons.h>   // EVENT_RECORD, OpenTrace, ProcessTrace, EnableTraceEx2
#include <evntrace.h>   // StartTrace, EVENT_TRACE_PROPERTIES
#include <evntprov.h>   // EVENT_DATA_DESCRIPTOR (用于解析)
#include <tdh.h>        // TdhEnumerateProviders 等诊断 (可选)
#include <psapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>
#include <algorithm>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// EVENT_HEADER_EXT_TYPE_STACK_TRACE 在某些 SDK 版本里没定义
#ifndef EVENT_HEADER_EXT_TYPE_STACK_TRACE
#define EVENT_HEADER_EXT_TYPE_STACK_TRACE 2
#endif

// ============================================================
// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// 与内核 EtwLogger.c 完全一致
// ============================================================

namespace das {

const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR = L"{A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}";

// 内核端定义的 ETW_IOCTL_EVENT_HEADER 结构 (必须与 EtwLogger.h 字节对齐一致)
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

// 全局:控制 Ctrl+C 退出
static std::atomic<bool> g_StopRequested{ false };

// Session 名称 (与应用层命令行一致)
static const wchar_t* SESSION_NAME = L"KernelServiceIoctlTrace";

// ============================================================
// 工具:启用权限
// ============================================================

static bool EnablePrivilege(LPCWSTR priv)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, priv, &luid)) {
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
    return ok && err == ERROR_SUCCESS;
}

// ============================================================
// 工具:从 ExtendedData 里找调用栈 (EVENT_ENABLE_PROPERTY_STACK_TRACE 抓的)
//
// ETW 把栈作为 ExtendedData 返回,Type = EVENT_HEADER_EXT_TYPE_STACK_TRACE (2)
// 数据布局:ULONG Count,然后 Count 个 PVOID (栈帧地址)
// 这些地址可能是内核态或用户态,需要符号化 (这里只打印十六进制)
// ============================================================

static void PrintStackTrace(const EVENT_RECORD* record)
{
    if (record->ExtendedData == nullptr || record->ExtendedDataCount == 0) {
        return;
    }

    for (unsigned short i = 0; i < record->ExtendedDataCount; i++) {
        const EVENT_HEADER_EXTENDED_DATA_ITEM& item = record->ExtendedData[i];
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE) {
            continue;
        }
        if (item.DataSize < sizeof(ULONG)) {
            continue;
        }

        // 栈数据 = ULONG FrameCount + FrameCount*sizeof(PVOID) 字节
        const unsigned char* data = (const unsigned char*)item.DataPtr;
        unsigned long frameCount = *(const unsigned long*)data;
        const void* const* frames = (const void* const*)(data + sizeof(unsigned long));

        if (frameCount == 0) {
            continue;
        }

        std::wostringstream ss;
        ss << L"  调用栈 (" << frameCount << L" 帧):\n";

        // 每帧打印地址,并尝试用 GetModuleHandleEx 判断属于哪个模块
        // (用户态模块能查到,内核态地址 GetModuleHandleEx 查不到)
        for (unsigned long f = 0; f < frameCount && f < 64; f++) {
            void* addr = const_cast<void*>(frames[f]);
            ss << L"    [" << std::setw(2) << f << L"] " << std::hex
               << std::setw(16) << std::setfill(L'0') << (unsigned long long)addr;

            // 尝试查用户态模块
            HMODULE hMod = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)addr, &hMod) && hMod) {
                wchar_t modPath[MAX_PATH] = { 0 };
                if (GetModuleFileNameW(hMod, modPath, MAX_PATH) > 0) {
                    // 提取文件名
                    wchar_t* p = wcsrchr(modPath, L'\\');
                    if (p) p++; else p = modPath;
                    ss << L"  " << p;
                }
            }
            else {
                ss << L"  <内核态>";
            }
            ss << L"\n";
        }

        WriteOut(ss.str());
        break; // 只处理第一个栈追踪条目
    }
}

// ============================================================
// 工具:格式化 IOCTL 控制码的 METHOD
// ============================================================

static const wchar_t* MethodName(unsigned long ioctl)
{
    switch (ioctl & 3) {
    case 0: return L"BUFFERED";
    case 1: return L"IN_DIRECT";
    case 2: return L"OUT_DIRECT";
    case 3: return L"NEITHER";
    default: return L"?";
    }
}

// 工具:把 payload 格式化成 hex dump
static std::wstring HexDump(const unsigned char* data, unsigned long size)
{
    if (size == 0) return L"";

    std::wostringstream ss;
    const unsigned long bytesPerLine = 16;
    for (unsigned long off = 0; off < size; off += bytesPerLine) {
        unsigned long lineLen = std::min(bytesPerLine, size - off);

        ss << L"    " << std::hex << std::setw(4) << std::setfill(L'0') << off << L": ";

        // hex 部分
        for (unsigned long i = 0; i < bytesPerLine; i++) {
            if (i < lineLen) {
                ss << std::hex << std::setw(2) << std::setfill(L'0')
                   << (unsigned int)data[off + i] << L" ";
            }
            else {
                ss << L"   ";
            }
            if (i == 7) ss << L" ";
        }

        // ASCII 部分
        ss << L" |";
        for (unsigned long i = 0; i < lineLen; i++) {
            unsigned char c = data[off + i];
            ss << (wchar_t)(c >= 32 && c < 127 ? c : L'.');
        }
        ss << L"|\n";
    }
    return ss.str();
}

// ============================================================
// 事件回调 — 解析 UserData
// ============================================================

static void WINAPI EventRecordCallback(EVENT_RECORD* record)
{
    if (g_StopRequested.load()) return;

    // 只处理我们 Provider 的事件 (EventId == 1)
    if (record->EventHeader.EventDescriptor.Id != 1) {
        return;
    }

    // UserData = EtwIoctlEventHeader + Payload[CaptureSize]
    if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) {
        WriteOut(L"[ETW] 事件 UserData 太短,跳过\n");
        return;
    }

    const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;
    const unsigned char* payload = (const unsigned char*)record->UserData + sizeof(EtwIoctlEventHeader);
    unsigned long payloadLen = hdr->CaptureSize;

    // 校验 payload 长度
    if (sizeof(EtwIoctlEventHeader) + payloadLen > (unsigned long)record->UserDataLength) {
        payloadLen = (unsigned long)record->UserDataLength - sizeof(EtwIoctlEventHeader);
    }

    // 格式化输出
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

    // 时间戳
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);
    ss << L"  时间:             " << std::dec
       << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds << L"\n";

    WriteOut(ss.str());

    // 打印 payload
    if (payloadLen > 0) {
        std::wostringstream ph;
        ph << L"  Payload (Hex Dump):\n";
        ph << HexDump(payload, payloadLen);
        WriteOut(ph.str());
    }
    else {
        WriteOut(L"  Payload: <空>\n");
    }

    // 打印调用栈
    PrintStackTrace(record);
}

// ============================================================
// BufferCallback — 用于检测停止信号 (每次 flush 缓冲区时调用)
// 返回 FALSE 让 ProcessTrace 退出
// ============================================================

static ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* logfile)
{
    UNREFERENCED_PARAMETER(logfile);
    return g_StopRequested.load() ? FALSE : TRUE;
}

// ============================================================
// RunEtwConsumer — 主入口
// ============================================================

int RunEtwConsumer(unsigned int durationSec, const std::wstring& etlPath)
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  ETW 实时订阅 — IOCTL 拦截事件 + 跨态调用栈\n");
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  Provider GUID: " + std::wstring(ETW_IOCTL_PROVIDER_GUID_STR) + L"\n");
    if (durationSec > 0) {
        WriteOut(L"  持续时间: " + std::to_wstring(durationSec) + L" 秒\n");
    }
    else {
        WriteOut(L"  持续时间: 永久 (Ctrl+C 退出)\n");
    }
    if (!etlPath.empty()) {
        WriteOut(L"  落盘文件: " + etlPath + L"\n");
    }
    WriteOut(L"\n");

    // 1. 启用权限
    //    ETW StartTrace 只需管理员权限,抓栈靠 SeSystemProfilePrivilege
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME)) {
        WriteOut(L"[警告] 启用 SeSystemProfilePrivilege 失败,可能无法抓栈\n");
    }
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        WriteOut(L"[警告] 启用 SeDebugPrivilege 失败 (非致命)\n");
    }

    // 2. 设置 Ctrl+C 处理
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
    //    结构 = 固定头 + SessionName 字符串 + LogFileName 字符串
    const size_t sessionNameLen = wcslen(SESSION_NAME) + 1;
    size_t logFileNameLen = 0;
    if (!etlPath.empty()) {
        logFileNameLen = etlPath.length() + 1;
    }

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
        wcscpy_s((LPWSTR)((unsigned char*)props + props->LogFileNameOffset),
                 logFileNameLen, etlPath.c_str());
    }
    else {
        props->LogFileNameOffset = 0;
    }
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((LPWSTR)((unsigned char*)props + props->LoggerNameOffset),
             sessionNameLen, SESSION_NAME);
    props->BufferSize = 64;          // 64KB 缓冲区
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 32;
    props->MaximumFileSize = 100;    // 100 MB
    props->FlushTimer = 1;           // 1 秒强制 flush (实时性)

    // 4. 如果已有同名 Session,先停掉
    ControlTraceW((TRACEHANDLE)0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    // 5. StartTrace 开 Session
    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] StartTraceW 失败: " + std::to_wstring(status) + L"\n");
        return 1;
    }
    WriteOut(L"[OK] ETW Session 已启动: " + std::wstring(SESSION_NAME) + L"\n");

    // 6. EnableTraceEx2 启用 Provider,带 STACK_TRACE
    GUID providerGuid;
    CLSIDFromString(ETW_IOCTL_PROVIDER_GUID_STR, &providerGuid);

    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;  // 关键:抓跨态栈
    params.SourceId = providerGuid;

    status = EnableTraceEx2(
        sessionHandle,
        &providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,   // 接收所有级别事件
        0, 0, 0,
        &params);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] EnableTraceEx2 失败: " + std::to_wstring(status) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    WriteOut(L"[OK] Provider 已启用,带 EVENT_ENABLE_PROPERTY_STACK_TRACE\n");
    WriteOut(L"\n等待 IOCTL 事件...(attach 一个设备后,对其发 IOCTL 即可看到事件)\n\n");

    // 7. OpenTrace 开消费者 (实时模式)
    //    关键:必须用 ProcessTraceMode 而不是 LogFileMode,并叠加
    //    PROCESS_TRACE_MODE_EVENT_RECORD,否则 ETW 会用旧版 EventCallback
    //    (传 EVENT_TRACE*) 而不是 EventRecordCallback (传 EVENT_RECORD*),
    //    回调里读 EventDescriptor.Id 会读到垃圾值,所有事件被静默丢弃
    EVENT_TRACE_LOGFILE logFile{};
    logFile.LoggerName = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;  // 用于检测停止信号
    logFile.IsKernelTrace = FALSE;

    TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG err = GetLastError();
        WriteOut(L"[错误] OpenTraceW 失败: " + std::to_wstring(err) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    // 8. 启动超时计时线程 (如果 durationSec > 0)
    HANDLE hTimer = NULL;
    if (durationSec > 0) {
        hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
        if (hTimer) {
            LARGE_INTEGER due;
            due.QuadPart = -((LONGLONG)durationSec * 10000000LL);  // 负值=相对时间
            SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
        }
    }

    // 9. ProcessTrace 阻塞消费
    //    在独立线程里跑,主线程等超时或 Ctrl+C
    HANDLE hTraceThread = CreateThread(
        NULL, 0,
        [](LPVOID param) -> DWORD {
            TRACEHANDLE* ph = (TRACEHANDLE*)param;
            ProcessTrace(ph, 1, NULL, NULL);
            return 0;
        },
        &consumerHandle, 0, NULL);

    // 等待:超时 或 Ctrl+C
    HANDLE waits[2] = { hTraceThread, hTimer };
    DWORD waitCount = (hTimer != NULL) ? 2 : 1;
    DWORD waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, INFINITE);

    if (waitResult == WAIT_OBJECT_0 + 1 || g_StopRequested.load()) {
        // 超时或 Ctrl+C
        g_StopRequested.store(true);
        // 停止 Session,让 ProcessTrace 退出
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        // 等 ProcessTrace 线程退出
        if (hTraceThread) {
            WaitForSingleObject(hTraceThread, 5000);
        }
    }

    // 10. 清理
    if (hTraceThread) CloseHandle(hTraceThread);
    if (hTimer) CloseHandle(hTimer);
    CloseTrace(consumerHandle);

    // ControlTrace 再停一次 (确保 Session 关闭)
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    SetConsoleCtrlHandler(handler, FALSE);

    WriteOut(L"\n[OK] ETW 订阅已停止\n");
    return 0;
}

} // namespace das
