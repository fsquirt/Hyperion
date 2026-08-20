// getw.cpp — gameprotect --MonitorImageLoad <PID> 实现
//
// ETW 管道生命周期复用 common/Etw::RunEtwSession (StartTrace→EnableTraceEx2→
// OpenTrace→ProcessTrace→Ctrl+C/超时清理 全部在那里),本文件只负责:
//   - 过滤需要的 ETW 事件 ID (EventId=2 = ImageLoad)
//   - 解析 UserData = EtwImageLoadEventHeader + ImageName (深拷贝,安全)
//   - 打印 PID / Base / Size / 路径

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "getw.h"
#include "../common/Etw.h"
#include "../common/Out.h"

#include <windows.h>
#include <evntcons.h>
#include <string>
#include <sstream>
#include <iomanip>

namespace das {

// 与内核 EtwLogger.h 保持一致:
//   ETW_EVENT_IMAGELOAD = 2
//   ETW_MAX_IMAGENAME_BYTES = 512
#define ETW_EVENT_IMAGELOAD        2
#define ETW_MAX_IMAGENAME_BYTES    512

// 内核端 ETW_IMAGELOAD_EVENT_HEADER (与 EtwLogger.h 字节对齐一致)
#pragma pack(push, 8)
struct EtwImageLoadEventHeader {
    unsigned long long  ProcessId;         // 8
    unsigned long long  ImageBase;         // 8
    unsigned long       ImageSize;         // 4
    unsigned long       ImageNameBytes;    // 4
	unsigned long long  InitiatorPid;      // 8
};                                        // = 32
#pragma pack(pop)
static_assert(sizeof(EtwImageLoadEventHeader) == 32,
              "EtwImageLoadEventHeader size mismatch");

// 当前监控过滤的 PID (0 = 不过滤)
static unsigned long g_filterPid = 0;

// 事件回调 — 只处理 EventId=2 的 ImageLoad 事件
static void OnImageLoadEvent(const EVENT_RECORD* record)
{
    if (record->EventHeader.EventDescriptor.Id != ETW_EVENT_IMAGELOAD) {
        return;
    }

    if (record->UserDataLength < (LONG)sizeof(EtwImageLoadEventHeader)) {
        return;
    }

    const EtwImageLoadEventHeader* hdr =
        (const EtwImageLoadEventHeader*)record->UserData;

    // 按 PID 过滤 (用户指定的监控目标)
    if (g_filterPid != 0 &&
        (unsigned long long)g_filterPid != hdr->ProcessId) {
        return;
    }

    // 读取深拷贝的映像路径 (ImageNameBytes 字节, 后跟 WCHAR 数组)
    const unsigned char* data =
        (const unsigned char*)record->UserData + sizeof(EtwImageLoadEventHeader);
    unsigned long nameBytes = hdr->ImageNameBytes;
    long available = record->UserDataLength - (LONG)sizeof(EtwImageLoadEventHeader);
    if ((long)nameBytes > available) {
        nameBytes = (unsigned long)available;
    }

    std::wstring imageName;
    if (nameBytes >= sizeof(wchar_t)) {
        unsigned long chars = nameBytes / sizeof(wchar_t);
        imageName.assign((const wchar_t*)data, chars);
    }

    // 时间戳
    SYSTEMTIME st;
    FILETIME ft;
    ft.dwLowDateTime = record->EventHeader.TimeStamp.LowPart;
    ft.dwHighDateTime = record->EventHeader.TimeStamp.HighPart;
    FileTimeToSystemTime(&ft, &st);

    std::wostringstream ss;
    ss << L"["
       << std::dec << std::setw(2) << std::setfill(L'0') << st.wHour << L":"
       << std::setw(2) << std::setfill(L'0') << st.wMinute << L":"
       << std::setw(2) << std::setfill(L'0') << st.wSecond << L"."
       << std::setw(3) << std::setfill(L'0') << st.wMilliseconds
       << L"] ImageLoad PID=" << std::dec << (unsigned long long)hdr->ProcessId
       << L" InitiatorPid=" << std::dec << (unsigned long long)hdr->InitiatorPid
       << L" Base=0x" << std::hex << (unsigned long long)hdr->ImageBase
       << L" Size=0x" << std::hex << (unsigned long long)hdr->ImageSize
       << L" Path=" << imageName << L"\n";

    Out(ss.str());
}

int RunImageLoadMonitor(unsigned long pid)
{
    Out(L"═══════════════════════════════════════════════════════\n");
    Out(L"  ImageLoad 监控 — 订阅 KernelService ETW (EventId=2)\n");
    Out(L"═══════════════════════════════════════════════════════\n");
    if (pid != 0) {
        Out(L"  过滤 PID: " + std::to_wstring(pid) + L"\n");
    } else {
        OutLine(L"  过滤 PID: <不过滤>");
    }
    OutLine(L"  Ctrl+C 退出\n");

    g_filterPid = pid;

    EtwSessionConfig cfg;
    cfg.sessionName = L"KernelServiceImageLoadTrace";
    cfg.durationSec = 0;        // 0 = 永久直到 Ctrl+C
    cfg.enableStack = false;    // 不需要调用栈,加速订阅

    return RunEtwSession(cfg, OnImageLoadEvent);
}

} // namespace das