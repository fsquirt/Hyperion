// CommsMonitor.cpp — ETW 订阅管道 + 事件回调协调器
//
// 引用 DriverAttachSelector 的 ETW 订阅逻辑:
//   - Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C} (来自 EtwConsumer.h)
//   - 事件结构 EtwIoctlEventHeader (与 EtwConsumer.cpp 一致)
//   - 管道搭建: EnablePrivilege / StartTrace / EnableTraceEx2 / OpenTrace / ProcessTrace
//     (参考 EtwConsumer.cpp 的 RunEtwConsumer)
//
// 定制回调 (EventRecordCallback):
//   1. 只处理 AttachId != 0 的事件 (被 KernelService 附着的设备上的通信)
//   2. QueryFullProcessImageName 取发起进程主 exe 路径
//   3. 从调用栈 ExtendedData 符号化用户态模块,排除系统目录,收集业务模块
//   4. 对每个文件 (exe + 业务模块) 检查磁盘存在性 + RHS 属性
//   5. 登记去重路径表 + dump 内存映像 + 拷贝磁盘文件
//   6. 对端驱动 dump (按 AttachId 去重)
//   7. (可选) 写 JSON 通信日志 — 由 --json 开关控制
//
// 本文件只保留 ETW 管道 + 协调逻辑, 具体功能已拆分到:
//   ModuleDumper / DriverDumper / StackResolver / PathTracker / JsonLogger

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "CommsMonitor.h"
#include "MonitorTypes.h"
#include "PathTracker.h"
#include "ModuleDumper.h"
#include "DriverDumper.h"
#include "StackResolver.h"
#include "JsonLogger.h"
#include "Common.h"

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <atomic>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace das {

// Provider GUID: {A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}
// (来自 DriverAttachSelector/EtwConsumer.h, 与内核 EtwLogger.c 一致)
const wchar_t* ETW_IOCTL_PROVIDER_GUID_STR = L"{A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C}";

// 独立 Session 名,避免与 DriverAttachSelector 同时运行时冲突
const wchar_t* SESSION_NAME = L"HeuristicDumperIoctlTrace";

// 全局停止信号 (ETW 回调线程与主线程共享)
std::atomic<bool> g_Stop{ false };

// JSON 日志开关 (由 RunCommsMonitor 根据 options.enableJson 设置,
// EventRecordCallback 是回调访问不到 options, 所以用文件内 static 控制)
static bool g_jsonEnabled = false;

// ═══════════════════════════════════════════════════════════════════════
//  工具: 启用权限
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
//  事件回调 — 解析事件, 定位通信文件, 协调各拆分模块
// ═══════════════════════════════════════════════════════════════════════

static void WINAPI EventRecordCallback(EVENT_RECORD* record)
{
    if (g_Stop.load()) return;
    if (record->EventHeader.EventDescriptor.Id != 1) return;

    if (record->UserDataLength < (LONG)sizeof(EtwIoctlEventHeader)) return;

    const EtwIoctlEventHeader* hdr = (const EtwIoctlEventHeader*)record->UserData;

    // 只处理被附着的设备 (AttachId != 0 表示 KernelService FiDO 拦截到的事件)
    if (hdr->AttachId == 0) return;

    // 时间戳
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);

    // 事件头
    std::wostringstream head;
    head << L"\n───────────────────────────────────────────────────────\n";
    head << L"[" << std::setfill(L'0')
         << std::setw(2) << st.wHour << L":"
         << std::setw(2) << st.wMinute << L":"
         << std::setw(2) << st.wSecond << L"."
         << std::setw(3) << st.wMilliseconds << L"] ";
    head << L"AttachId=" << hdr->AttachId
        << L"  PID=" << hdr->RequestorPid
        << L"  IOCTL=0x" << std::hex << std::setw(8) << std::setfill(L'0') << hdr->IoControlCode;
    if (hdr->MajorFunction == 0x0E) head << L" (DEVICE_CONTROL)";
    else if (hdr->MajorFunction == 0x00) head << L" (CREATE)";
    else if (hdr->MajorFunction == 0x02) head << L" (CLOSE)";
    head << L"\n";
    WriteOut(head.str());

    // 打开进程 (需要 QUERY_INFORMATION 取 exe 路径 + VM_READ 建模块表/dump)
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               FALSE, (DWORD)hdr->RequestorPid);

    // 取发起进程主 exe 路径
    std::wstring exePath;
    if (hProc) {
        wchar_t buf[MAX_PATH];
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
            exePath.assign(buf, len);
        }
    }

    // 建模块表 + 从调用栈收集业务模块
    auto modules = BuildModuleTable(hdr->RequestorPid);
    auto stackModules = CollectStackModules(record, modules);

    // 查 exe 模块的基址/大小 (供 dump 用)
    unsigned long long exeBase = 0;
    unsigned long exeSize = 0;
    for (const auto& mr : modules) {
        if (mr.path == exePath) {
            exeBase = mr.base;
            exeSize = mr.size;
            break;
        }
    }

    WriteOut(L"  通信文件:\n");

    // 每事件都打印 (不去重, 显示哪个进程哪个模块)
    PrintFileLine(exePath, L"进程 exe");
    if (stackModules.empty()) {
        WriteOut(L"    调用栈业务模块: <无> (调用栈只有系统模块或未捕获)\n");
    } else {
        for (size_t i = 0; i < stackModules.size(); i++) {
            std::wostringstream tag;
            tag << L"栈模块[" << (i + 1) << L"]";
            PrintFileLine(stackModules[i].path, tag.str());
        }
    }

    // 登记 + dump (去重: 同一路径只 dump 一次)
    RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
                    exePath, L"进程 exe", exeBase, exeSize);
    for (size_t i = 0; i < stackModules.size(); i++) {
        std::wostringstream tag;
        tag << L"栈模块[" << (i + 1) << L"]";
        RegisterForDump(hProc, (unsigned long)hdr->RequestorPid,
                        stackModules[i].path, tag.str(),
                        stackModules[i].base, stackModules[i].size);
    }

    // 对端驱动 dump (按 AttachId 去重: 磁盘有拷 FileDump, 没有从内存 dump 到 dumpfile)
    DumpTargetDriver((unsigned long)hdr->AttachId);

    // (可选) 写 JSON 通信日志 — 由 --json 开关控制
    if (g_jsonEnabled) {
        // ETW UserData 布局: EtwIoctlEventHeader(56B) + CaptureSize 字节 InputBuffer
        const unsigned char* inputBuf = (const unsigned char*)record->UserData
                                       + sizeof(EtwIoctlEventHeader);
        unsigned long inputSize = hdr->CaptureSize;
        // 防止越界 (UserData 可能被截断)
        if (sizeof(EtwIoctlEventHeader) + inputSize > (unsigned long)record->UserDataLength) {
            inputSize = (unsigned long)record->UserDataLength - sizeof(EtwIoctlEventHeader);
        }
        WriteJsonEvent(st, hdr, exePath, stackModules, inputBuf, inputSize);
    }

    if (hProc) CloseHandle(hProc);
    WriteOut(L"───────────────────────────────────────────────────────\n");
}

// ═══════════════════════════════════════════════════════════════════════
//  BufferCallback — 检测停止信号
// ═══════════════════════════════════════════════════════════════════════

static ULONG WINAPI BufferCallback(EVENT_TRACE_LOGFILE* logfile)
{
    UNREFERENCED_PARAMETER(logfile);
    return g_Stop.load() ? FALSE : TRUE;
}

// ═══════════════════════════════════════════════════════════════════════
//  主入口 — ETW 管道搭建 (参考 EtwConsumer.cpp 的 RunEtwConsumer)
// ═══════════════════════════════════════════════════════════════════════

int RunCommsMonitor(const MonitorOptions& options)
{
    WriteOut(L"═══════════════════════════════════════════════════════\n");
    WriteOut(L"  通信文件监控 — ETW 订阅 + 调用栈定位 + RHS 属性告警\n");
    WriteOut(L"  引用 DriverAttachSelector 的 ETW 逻辑 (Provider ");
    WriteOut(ETW_IOCTL_PROVIDER_GUID_STR);
    WriteOut(L")\n");
    WriteOut(L"  只处理被附着设备 (AttachId != 0) 的通信事件\n");
    if (options.durationSec > 0) {
        WriteOut(L"  持续时间: " + std::to_wstring(options.durationSec) + L" 秒\n");
    } else {
        WriteOut(L"  持续时间: 永久 (Ctrl+C 退出)\n");
    }
    if (options.enableJson) {
        WriteOut(L"  JSON 通信日志: 已启用 (--json)\n");
    } else {
        WriteOut(L"  JSON 通信日志: 未启用 (默认关闭, 加 --json 开启)\n");
    }
    WriteOut(L"═══════════════════════════════════════════════════════\n\n");

    // 1. 启用权限 (抓栈靠 SeSystemProfilePrivilege)
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME)) {
        WriteOut(L"[警告] 启用 SeSystemProfilePrivilege 失败,可能无法抓栈\n");
    }
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        WriteOut(L"[警告] 启用 SeDebugPrivilege 失败 (跨进程读模块需要)\n");
    }

    // 1b. 初始化 dump 目录 (内存映像) + FileDump 目录 (磁盘文件副本)
    if (InitDumpDir()) {
        WriteOut(L"[OK] dump 目录: " + GetDumpDir() + L"\n");
    } else {
        WriteOut(L"[警告] dump 目录初始化失败,将跳过内存 dump\n");
    }
    if (InitFileDumpDir()) {
        WriteOut(L"[OK] FileDump 目录: " + GetFileDumpDir() + L"\n");
    } else {
        WriteOut(L"[警告] FileDump 目录初始化失败,将跳过磁盘文件拷贝\n");
    }

    // 1c. 打开 KernelService 句柄 (供 dump 对端驱动内存用)
    HANDLE hKs = CreateFileW(L"\\\\.\\KernelService", GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);
    if (hKs != INVALID_HANDLE_VALUE) {
        // 把 KernelService 句柄 + dumpfile/FileDump 路径传给 DriverDumper
        InitDriverDumper((void*)hKs, GetDumpDir(), GetFileDumpDir());
        WriteOut(L"[OK] 已连接 KernelService (驱动内存 dump 可用)\n");
    } else {
        WriteOut(L"[警告] 打开 KernelService 失败 err="
                 + std::to_wstring(GetLastError())
                 + L" (将跳过对端驱动 dump)\n");
    }

    // 1d. 初始化 JSON 通信日志 (仅在 --json 启用时)
    if (options.enableJson) {
        g_jsonEnabled = true;
        if (InitJsonLog()) {
            WriteOut(L"[OK] JSON 通信日志: " + GetJsonPath() + L"\n");
        } else {
            WriteOut(L"[警告] JSON 日志初始化失败 err="
                     + std::to_wstring(GetLastError()) + L"\n");
        }
    } else {
        g_jsonEnabled = false;
    }

    // 2. Ctrl+C 处理
    g_Stop.store(false);
    auto handler = [](DWORD ctrl) -> BOOL {
        if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT) {
            g_Stop.store(true);
            WriteOut(L"\n[收到 Ctrl+C,正在停止订阅...]\n");
            return TRUE;
        }
        return FALSE;
    };
    SetConsoleCtrlHandler(handler, TRUE);

    // 3. 准备 EVENT_TRACE_PROPERTIES
    const size_t sessionNameLen = wcslen(SESSION_NAME) + 1;
    size_t propSize = sizeof(EVENT_TRACE_PROPERTIES) + sessionNameLen * sizeof(wchar_t);
    std::vector<unsigned char> propBuf(propSize, 0);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)propBuf.data();
    props->Wnode.BufferSize = (ULONG)propSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  // QPC
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LogFileNameOffset = 0;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((LPWSTR)((unsigned char*)props + props->LoggerNameOffset),
             sessionNameLen, SESSION_NAME);
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 32;
    props->MaximumFileSize = 100;
    props->FlushTimer = 1;

    // 4. 停掉残留同名 Session
    ControlTraceW((TRACEHANDLE)0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

    // 5. StartTrace
    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, SESSION_NAME, props);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] StartTraceW 失败: " + std::to_wstring(status) + L"\n");
        return 1;
    }
    WriteOut(L"[OK] ETW Session 已启动: " + std::wstring(SESSION_NAME) + L"\n");

    // 6. EnableTraceEx2 带 STACK_TRACE
    GUID providerGuid;
    CLSIDFromString(ETW_IOCTL_PROVIDER_GUID_STR, &providerGuid);
    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;
    params.SourceId = providerGuid;
    status = EnableTraceEx2(sessionHandle, &providerGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    if (status != ERROR_SUCCESS) {
        WriteOut(L"[错误] EnableTraceEx2 失败: " + std::to_wstring(status) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }
    WriteOut(L"[OK] Provider 已启用,带 EVENT_ENABLE_PROPERTY_STACK_TRACE\n");
    WriteOut(L"\n等待被附着设备的通信事件...\n\n");

    // 7. OpenTrace (实时模式, 必须叠加 PROCESS_TRACE_MODE_EVENT_RECORD)
    EVENT_TRACE_LOGFILE logFile{};
    logFile.LoggerName = (LPWSTR)SESSION_NAME;
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EventRecordCallback;
    logFile.BufferCallback = BufferCallback;
    logFile.IsKernelTrace = FALSE;

    TRACEHANDLE consumerHandle = OpenTraceW(&logFile);
    if (consumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        ULONG err = GetLastError();
        WriteOut(L"[错误] OpenTraceW 失败: " + std::to_wstring(err) + L"\n");
        ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        return 1;
    }

    // 8. 超时计时器
    HANDLE hTimer = NULL;
    if (options.durationSec > 0) {
        hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
        if (hTimer) {
            LARGE_INTEGER due;
            due.QuadPart = -((LONGLONG)options.durationSec * 10000000LL);
            SetWaitableTimer(hTimer, &due, 0, NULL, NULL, FALSE);
        }
    }

    // 9. ProcessTrace 在独立线程跑, 主线程等超时/Ctrl+C
    HANDLE hTraceThread = CreateThread(
        NULL, 0,
        [](LPVOID param) -> DWORD {
            TRACEHANDLE* ph = (TRACEHANDLE*)param;
            ProcessTrace(ph, 1, NULL, NULL);
            return 0;
        },
        &consumerHandle, 0, NULL);

    HANDLE waits[2] = { hTraceThread, hTimer };
    DWORD waitCount = (hTimer != NULL) ? 2 : 1;

    // 短轮询 (Ctrl+C 后主动 Stop 踢醒卡死的 ProcessTrace)
    while (true) {
        DWORD waitResult = WaitForMultipleObjects(waitCount, waits, FALSE, 200);
        if (waitResult != WAIT_TIMEOUT) break;
        if (g_Stop.load()) break;
    }

    // 10. 清理
    g_Stop.store(true);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    if (hTraceThread) {
        WaitForSingleObject(hTraceThread, 5000);
        CloseHandle(hTraceThread);
    }
    if (hTimer) CloseHandle(hTimer);
    CloseTrace(consumerHandle);
    ControlTraceW(sessionHandle, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
    SetConsoleCtrlHandler(handler, FALSE);

    WriteOut(L"\n[OK] ETW 订阅已停止\n");

    // 关闭 KernelService 句柄
    if (hKs != INVALID_HANDLE_VALUE) {
        CloseHandle(hKs);
    }

    // 关闭 JSON 通信日志 (仅在启用时写入数组结尾并关闭句柄)
    if (g_jsonEnabled) {
        CloseJsonLog();
        if (!GetJsonPath().empty()) {
            WriteOut(L"[OK] JSON 通信日志已保存: " + GetJsonPath() + L"\n");
        }
    }

    // 输出去重汇总表
    PrintPathTable();
    return 0;
}

} // namespace das
