// CombinationNativeData.h — 扁平化 C 结构体 + 数据导出接口
//
// 本头文件定义所有跨 FFI 边界传递的扁平化 POD 结构体,
// 以及对应的数据导出函数声明。
//
// 设计原则:
//   - 所有结构体为纯 C 兼容 POD 类型 (无 std::string / std::vector)
//   - 字符串使用定长 wchar_t[] / char[] 数组, 超长截断
//   - 变长集合使用 count + 定长数组 (合理上限)
//   - 每个数据导出函数返回 malloc 分配的缓冲区,
//     调用方必须用 CombNative_FreeBuffer 释放
//   - 缓冲区布局: [CbnResultHeader] [Entry0] [Entry1] ... [EntryN-1]

#pragma once

#include <stdint.h>
#include <windows.h>

#ifdef COMBINATION_NATIVE_EXPORTS
#define CBN_DATA_API __declspec(dllexport)
#else
#define CBN_DATA_API __declspec(dllimport)
#endif

// ═══════════════════════════════════════════════════════════════════════
//  公共常量
// ═══════════════════════════════════════════════════════════════════════

#define CBN_MAX_PATH     260
#define CBN_MAX_NAME     64
#define CBN_MAX_SUBJECT  256
#define CBN_MAX_REASON   256
#define CBN_MAX_STR      128

// 各类集合上限
#define CBN_MAX_DRIVERS       512
#define CBN_MAX_DEVICES       128
#define CBN_MAX_ATTACHMENTS    64
#define CBN_MAX_SIGNERS         8
#define CBN_MAX_IAT_DLLS      128
#define CBN_MAX_IAT_APIS      256
#define CBN_MAX_OBJECT_ENTRIES 2048
#define CBN_MAX_HANDLES       1024
#define CBN_MAX_PROCESSES     1024
#define CBN_MAX_THREADS         64
#define CBN_MAX_MODULES        128
#define CBN_MAX_MEM_REGIONS     32
#define CBN_MAX_PRIVS           16
#define CBN_MAX_ETW_EVENTS    2048
#define CBN_MAX_STACK_FRAMES    32
#define CBN_MAX_PATHS         1024

// ═══════════════════════════════════════════════════════════════════════
//  通用结果头 (每个缓冲区开头)
// ═══════════════════════════════════════════════════════════════════════

#pragma pack(push, 8)

struct CbnResultHeader {
    int32_t  errorCode;     // 0 = 成功, 非 0 = 错误码
    uint32_t commandId;     // 命令 ID (1-16)
    uint32_t entryCount;    // 条目数量
    uint32_t entrySize;     // 每个条目字节数 (0 = 无条目)
    uint32_t totalSize;     // 整个缓冲区字节数 (含本头)
    wchar_t  errorMessage[CBN_MAX_REASON]; // errorCode != 0 时的错误说明
};

// ═══════════════════════════════════════════════════════════════════════
//  扁平化结构体定义
// ═══════════════════════════════════════════════════════════════════════

// ─── DriverClassify 相关 ──────────────────────────────────────────

struct CbnSignerInfo {
    wchar_t subject[CBN_MAX_SUBJECT];
    wchar_t issuer[CBN_MAX_SUBJECT];
    int32_t isMicrosoft;
    int32_t isWhql;
    int32_t isVendor;
};

// 分类条目 (对应一个驱动的分类结果)
struct CbnClassifyEntry {
    wchar_t fileName[CBN_MAX_NAME];        // 模块短名
    wchar_t filePath[CBN_MAX_PATH];        // 规范化后文件路径
    wchar_t driverObjectName[CBN_MAX_NAME]; // 驱动对象名
    int32_t klass;                          // DriverClass 枚举值 (0=INBOX,1=MICROSOFT,2=THIRD_PARTY_WHQL,3=UNTRUSTED)
    int32_t signerCount;
    CbnSignerInfo signers[CBN_MAX_SIGNERS];
    wchar_t vendorName[CBN_MAX_STR];
    wchar_t errorReason[CBN_MAX_REASON];
    int32_t hasCatalog;
    int32_t hasEmbedded;
};

// ─── IAT 扫描相关 ────────────────────────────────────────────────

struct CbnIatApi {
    char    name[CBN_MAX_NAME];  // API 名 (ASCII)
    int32_t isDangerous;         // 是否高危
};

struct CbnIatEntry {
    char    dllName[CBN_MAX_NAME]; // DLL 名 (ASCII)
    int32_t apiCount;
    CbnIatApi apis[CBN_MAX_IAT_APIS];
};

struct CbnIatResult {
    wchar_t filePath[CBN_MAX_PATH]; // 被扫描的文件路径
    int32_t dllCount;
    int32_t totalApiCount;
    int32_t dangerousApiCount;
    CbnIatEntry entries[CBN_MAX_IAT_DLLS];
};

// ─── 对象管理器扫描相关 ──────────────────────────────────────────

struct CbnNtDirEntry {
    wchar_t name[CBN_MAX_PATH];
    wchar_t typeName[CBN_MAX_NAME];
    wchar_t linkTarget[CBN_MAX_PATH];
};

// ─── 句柄扫描相关 ────────────────────────────────────────────────

struct CbnHandleEntry {
    uint64_t ownerPid;
    wchar_t  ownerName[CBN_MAX_NAME];
    uint64_t handleValue;
    uint32_t grantedAccess;
    wchar_t  accessStr[CBN_MAX_STR];
    uint64_t targetPid;
    wchar_t  typeName[CBN_MAX_NAME];
    int32_t  highRisk;
};

// ─── 进程树相关 ──────────────────────────────────────────────────

struct CbnProcThread {
    uint64_t tid;
    uint64_t startAddress;
};

struct CbnProcBrief {
    uint64_t pid;
    uint64_t ppid;
    char     name[CBN_MAX_NAME];    // UTF-8
    uint32_t threads;
    int64_t  createTime;            // FILETIME 格式
    uint32_t session;
    uint64_t workingSet;
    uint64_t privatePages;
    uint32_t handles;
    int32_t  basePriority;
    int32_t  threadCount;
    CbnProcThread threadList[CBN_MAX_THREADS];
};

// ─── 进程安全详情相关 ────────────────────────────────────────────

struct CbnThreadInfo {
    uint64_t tid;
    uint64_t startAddress;
    uint64_t win32StartAddress;
    int32_t  suspendCount;
    char     startModule[CBN_MAX_PATH]; // UTF-8
    int32_t  isSuspended;
};

struct CbnModuleInfo {
    uint64_t base;
    uint32_t size;
    char     name[CBN_MAX_NAME];
    char     path[CBN_MAX_PATH];
};

struct CbnMemRegion {
    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    char     protectStr[32];
    char     typeStr[32];
    char     reason[32];
};

struct CbnProcDetail {
    // 基础信息
    CbnProcBrief brief;

    // 详情
    char     imagePath[CBN_MAX_PATH];
    char     commandLine[512];
    char     protection[32];
    int32_t  pplBroken;

    // 特权
    int32_t  enabledPrivCount;
    char     enabledPrivs[CBN_MAX_PRIVS][48];
    int32_t  disabledPrivCount;
    char     disabledPrivs[CBN_MAX_PRIVS][48];

    // 线程详情
    int32_t  threadInfoCount;
    CbnThreadInfo threadInfos[CBN_MAX_THREADS];

    // 模块
    int32_t  moduleCount;
    CbnModuleInfo modules[CBN_MAX_MODULES];

    // 可疑内存
    int32_t  memRegionCount;
    CbnMemRegion memRegions[CBN_MAX_MEM_REGIONS];

    // 句柄
    int32_t  handleCount;
    CbnHandleEntry handles[CBN_MAX_HANDLES];
};

// ─── ETW 事件相关 ────────────────────────────────────────────────

struct CbnEtwEvent {
    uint32_t version;
    uint32_t ioControlCode;
    uint32_t inputBufferLength;
    uint32_t captureSize;
    uint64_t requestorPid;
    uint64_t targetDeviceAddr;
    uint64_t filterDeviceAddr;
    uint64_t attachId;
    uint32_t majorFunction;
    uint32_t method;
    int32_t  stackFrameCount;
    uint64_t stackFrames[CBN_MAX_STACK_FRAMES];
};

// ─── 通信监控相关 ────────────────────────────────────────────────

struct CbnPathEntry {
    wchar_t  path[CBN_MAX_PATH];
    wchar_t  tag[64];
    uint32_t pid;
    int32_t  abnormal;
    wchar_t  note[CBN_MAX_STR];
    uint32_t hitCount;
    int32_t  dumped;
    wchar_t  dumpFile[CBN_MAX_PATH];
    int32_t  fileCopied;
    wchar_t  fileCopyName[CBN_MAX_PATH];
};

struct CbnCommsSummary {
    uint32_t pathCount;
    uint32_t totalIoctls;
    uint32_t totalEvents;
    CbnPathEntry paths[CBN_MAX_PATHS];
};

// ─── 附着操作结果 (复用 KernelComms.h 的响应结构) ────────────────

struct CbnAttachResult {
    int32_t  status;
    uint32_t attachId;
    uint64_t filterDeviceAddr;
    uint64_t lowerDeviceAddr;
    uint16_t newStackSize;
    uint16_t targetStackSize;
};

struct CbnDetachResult {
    int32_t  status;
    uint32_t detachedId;
};

#pragma pack(pop)

// ═══════════════════════════════════════════════════════════════════════
//  数据导出函数声明
//
//  统一契约:
//    - 返回 malloc 分配的缓冲区指针 (nullptr = 失败)
//    - *outSize 写入缓冲区总字节数
//    - 缓冲区开头为 CbnResultHeader
//    - 调用方必须用 CombNative_FreeBuffer 释放
// ═══════════════════════════════════════════════════════════════════════

extern "C" {

// 释放任何 CombNative_Get* 返回的缓冲区
CBN_DATA_API void CombNative_FreeBuffer(void* buffer);

// 2. kernel-scan → CbnResultHeader + LoadedDriverEntry[count]
CBN_DATA_API void* CombNative_GetKernelScanData(uint32_t* outSize);

// 3. scan-classify → CbnResultHeader + CbnClassifyEntry[count]
CBN_DATA_API void* CombNative_GetScanAndClassifyData(uint32_t* outSize);

// 4. scan-enum-devices → CbnResultHeader + CbnClassifyEntry[count] (含设备+IAT信息)
CBN_DATA_API void* CombNative_GetScanAndEnumDevicesData(uint32_t* outSize);

// 5. enum-devices → CbnResultHeader + DeviceEntry[count] + foundPath
CBN_DATA_API void* CombNative_GetEnumDevicesData(const wchar_t* driverName, uint32_t* outSize);

// 6. scan-iat → CbnIatResult (单个, header 后跟一个 CbnIatResult)
CBN_DATA_API void* CombNative_GetScanIatData(const wchar_t* filePath, uint32_t* outSize);

// 7. attach → CbnResultHeader + CbnAttachResult
CBN_DATA_API void* CombNative_GetAttachData(const wchar_t* devicePath, uint32_t* outSize);

// 8. unattach → CbnResultHeader + CbnDetachResult
CBN_DATA_API void* CombNative_GetUnattachData(const wchar_t* arg, uint32_t* outSize);

// 9. list-attach → CbnResultHeader + AttachEntry[count]
CBN_DATA_API void* CombNative_GetListAttachmentsData(uint32_t* outSize);

// 10. enum-classify → CbnResultHeader + CbnClassifyEntry[count]
CBN_DATA_API void* CombNative_GetEnumAndClassifyData(uint32_t* outSize);

// 11. scan-objects → CbnResultHeader + CbnNtDirEntry[count]
CBN_DATA_API void* CombNative_GetScanObjectsData(const wchar_t* dirs, uint32_t* outSize);

// 12. etw → CbnResultHeader + CbnEtwEvent[count]
CBN_DATA_API void* CombNative_GetEtwData(uint32_t durationSec, const wchar_t* etlPath, uint32_t* outSize);

// 13. comms → CbnResultHeader + CbnCommsSummary
CBN_DATA_API void* CombNative_GetCommsData(uint32_t durationSec, int enableJson, uint32_t* outSize);

// 14. scan-handles → CbnResultHeader + CbnHandleEntry[count]
CBN_DATA_API void* CombNative_GetScanHandlesData(uint32_t targetPid, uint32_t* outSize);

// 15. tree → CbnResultHeader + CbnProcBrief[count]
CBN_DATA_API void* CombNative_GetTreeData(uint64_t pid, int maxDepth, int jsonOut, uint32_t* outSize);

// 16. security → CbnResultHeader + CbnProcDetail[count]
CBN_DATA_API void* CombNative_GetSecurityData(uint64_t pid, uint32_t flags, uint32_t* outSize);

} // extern "C"
