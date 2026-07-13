// DriverAttach.c — 设备附着模块实现
//
// 核心流程:
//   1. IoCreateDriver 创建独立 Filter DriverObject
//   2. IoGetDeviceObjectPointer 按名字拿目标设备
//   3. IoCreateDevice 创建匿名 FiDO,继承 DeviceType/Characteristics
//   4. IoAttachDeviceToDeviceStack 附着到设备栈顶
//   5. IRP 透传: IoSkipCurrentIrpStackLocation + IoCallDriver
//
// 同步:
//   - FAST_MUTEX 只保护链表遍历/查重、AttachId 分配、入链表这些极短操作。
//   - IoGetDeviceObjectPointer / IoCreateDevice / IoAttachDeviceToDeviceStack 等可等待调用
//     都在锁外(PASSIVE_LEVEL)执行,否则在 APC_LEVEL 下会死锁(曾卡死 KslD)。
//   - IoDetachDevice/IoDeleteDevice 不在持锁状态调用(可能等待 IRP 完成)
//   - IRP 透传函数只读 ext->LowerDeviceObject,不需要锁

#include "DriverAttach.h"
#include "EtwLogger.h"
#include <ntstrsafe.h>
#include <ntimage.h>

// ============================================================
// ZwQuerySystemInformation + SystemModuleInformation 声明
// (用于按 ImageBase 反查驱动文件路径)
// ============================================================

#define DUMPMOD_SystemModuleInformation 11

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef struct _DUMPMOD_MODULE_ENTRY {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} DUMPMOD_MODULE_ENTRY, *PDUMPMOD_MODULE_ENTRY;

typedef struct _DUMPMOD_MODULE_LIST {
    ULONG               Count;
    DUMPMOD_MODULE_ENTRY Modules[1];
} DUMPMOD_MODULE_LIST, *PDUMPMOD_MODULE_LIST;

// ============================================================
// 未文档化 API 声明 (ReactOS/phnt 有,WDK 头没有)
// ============================================================

// IoCreateDriver: 创建独立 DriverObject
// 2 个参数,DriverObject 在 InitializationFunction 回调里拿
NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction);

// IoDeleteDriver: 删除 IoCreateDriver 创建的 DriverObject
NTKERNELAPI VOID NTAPI IoDeleteDriver(_In_ PDRIVER_OBJECT DriverObject);

// ============================================================
// 全局状态
// ============================================================

#define ATTACH_POOL_TAG 'ADKS'   // 'SKDA' 倒过来

static FAST_MUTEX  g_AttachMutex;
static LIST_ENTRY  g_AttachListHead;
static LONG        g_NextAttachId = 1;
static PDRIVER_OBJECT g_FilterDriverObject = NULL;
static BOOLEAN     g_Initialized = FALSE;

// ============================================================
// IRP 透传函数
// 所有 MajorFunction 都指向这里,把 IRP 原封不动传给下一层
// ============================================================

static NTSTATUS FilterPassIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PATTACH_DEVICE_EXTENSION ext = (PATTACH_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // ── ETW 埋点:抓 IOCTL payload + 跨态调用栈 ──
    // 在透传前发事件,EtwWrite 内部:
    //   1. 无 Session 订阅时几乎零开销 (位掩码判断)
    //   2. 有订阅且开了 STACK_TRACE 时,ETW 同步抓 User→ntdll→ntoskrnl→驱动 完整调用链
    // 失败不影响 IRP 透传
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UCHAR majorFunction = stack->MajorFunction;
    EtwLogIrpEvent(
        DeviceObject,           // FilterDevice (我们的 FiDO)
        ext->TargetDevice,      // 被附着的原设备
        ext->AttachId,          // 附着 ID
        Irp,                    // IRP 指针 (内部读取 IoControlCode/InputBuffer)
        majorFunction);         // IRP_MJ_*

    // 跳过当前栈位置,直接传给下一层
    // IoSkipCurrentIrpStackLocation 会把 Irp->CurrentLocation 递减,
    // Irp->Tail.Overlay.CurrentStackLocation 指针前移
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDeviceObject, Irp);
}

// ============================================================
// IoCreateDriver 的回调函数
// 在 IoCreateDriver 内部被调用,传入新创建的 DriverObject
// ============================================================

static NTSTATUS FilterDriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // 保存到全局 (此时 g_AttachMutex 已被调用方持有,无需加锁)
    g_FilterDriverObject = DriverObject;

    // 所有 MajorFunction 都透传
    // 包括 IRP_MJ_CREATE / IRP_MJ_CLOSE / IRP_MJ_READ / IRP_MJ_WRITE /
    // IRP_MJ_DEVICE_CONTROL / IRP_MJ_PNP 等
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = FilterPassIrp;
    }

    // 设置 Unload (实际清理在 DriverAttachUnload 中做,这里只是防框架警告)
    DriverObject->DriverUnload = NULL;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Filter DriverObject created, MajorFunction set\n");

    return STATUS_SUCCESS;
}

// ============================================================
// 确保 Filter DriverObject 已创建 (惰性创建,首次 attach 时触发)
// ⚠️ 必须在 PASSIVE_LEVEL 调用(内部 IoCreateDriver 可等待),不能在持 FAST_MUTEX 时调用。
//   调用方在锁外调用,避免 APC_LEVEL 死锁。
// ============================================================

static NTSTATUS EnsureFilterDriverCreated(VOID)
{
    if (g_FilterDriverObject != NULL) {
        return STATUS_SUCCESS;
    }

    // 传 NULL 创建匿名 DriverObject:
    //   1. 不会出现在 \Driver 对象命名空间,彻底规避名字冲突
    //      (sc stop 后即使引用计数没归零,下次 sc start 也不报 STATUS_OBJECT_NAME_COLLISION)
    //   2. 对反作弊工具更隐蔽(对象管理器里看不到)
    //   3. IoCreateDriver 内部会分配 DRIVER_OBJECT,调用 FilterDriverEntry,
    //      把 DriverObject 加入 PsLoadedModuleList (匿名条目)
    NTSTATUS status = IoCreateDriver(NULL, FilterDriverEntry);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] IoCreateDriver failed: 0x%08X\n", status);
        return status;
    }

    // g_FilterDriverObject 已在 FilterDriverEntry 中保存
    if (g_FilterDriverObject == NULL) {
        // 理论上不应该发生
        return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

// ============================================================
// 内部:附着到指定设备
// 调用时必须已持有 g_AttachMutex
// ============================================================

static NTSTATUS AttachToDeviceInternal(
    _In_ PCWSTR DevicePath,
    _Out_ PATTACH_DEVICE_RESPONSE pResp)
{
    NTSTATUS status;
    PFILE_OBJECT pFileObj = NULL;
    PDEVICE_OBJECT pTargetDev = NULL;
    PDEVICE_OBJECT pFilterDev = NULL;
    PDEVICE_OBJECT pLowerDev = NULL;

    // ⚠️ METHOD_BUFFERED 陷阱: pReq 和 pResp 指向同一块 SystemBuffer!
    // 不能 RtlZeroMemory(pResp, ...) 否则会把 pReq->DevicePath 清零。
    // 用局部变量构建响应,最后统一拷贝。
    ATTACH_DEVICE_RESPONSE localResp = { 0 };

    UNICODE_STRING newPath;
    RtlInitUnicodeString(&newPath, DevicePath);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: ENTER path='%ws'\n", DevicePath);

    // 1. 查重 — 仅在持锁下做(锁内不做任何可能阻塞的 I/O)。
    ExAcquireFastMutex(&g_AttachMutex);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [1] mutex acquired (dedup scan)\n");
    for (PLIST_ENTRY p = g_AttachListHead.Flink; p != &g_AttachListHead; p = p->Flink) {
        PATTACH_DEVICE_EXTENSION ext = CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);
        UNICODE_STRING existingPath;
        RtlInitUnicodeString(&existingPath, ext->TargetPath);
        if (RtlEqualUnicodeString(&newPath, &existingPath, TRUE)) {
            // 已 attach 过
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[ATT] AttachInternal: duplicate (Id=%lu)\n", ext->AttachId);
            localResp.Status = STATUS_DUPLICATE_OBJECTID;
            localResp.AttachId = ext->AttachId;
            localResp.FilterDeviceAddr = (ULONGLONG)ext->FilterDevice;
            localResp.LowerDeviceAddr = (ULONGLONG)ext->LowerDeviceObject;
            localResp.NewStackSize = (USHORT)ext->FilterDevice->StackSize;
            localResp.TargetStackSize = (USHORT)ext->TargetDevice->StackSize;
            *pResp = localResp;
            ExReleaseFastMutex(&g_AttachMutex);
            return STATUS_DUPLICATE_OBJECTID;
        }
    }
    ExReleaseFastMutex(&g_AttachMutex);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [1] dedup done, not duplicate\n");

    // 2. 确保过滤器 DriverObject 已创建
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [2] EnsureFilterDriverCreated\n");
    status = EnsureFilterDriverCreated();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] AttachInternal: [2] EnsureFilterDriverCreated failed 0x%08X\n", status);
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [2] filter driver ok (g_FilterDriverObject=0x%p)\n", g_FilterDriverObject);

    // 3. 用 IoGetDeviceObjectPointer 按名字拿目标设备
    //    DesiredAccess 用 FILE_READ_ATTRIBUTES(最小权限):attach 只需拿 DeviceObject
    //    指针,不需要实际 I/O 访问。FILE_ALL_ACCESS 会被部分设备(如 KslD 这类 VIDEO
    //    设备)的 DACL 拒绝,返回 STATUS_ACCESS_DENIED。
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [3] IoGetDeviceObjectPointer('%ws') ... calling\n", DevicePath);
    status = IoGetDeviceObjectPointer(&newPath, FILE_READ_ATTRIBUTES, &pFileObj, &pTargetDev);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [3] IoGetDeviceObjectPointer returned 0x%08X (FileObj=0x%p TargetDev=0x%p)\n",
        status, pFileObj, pTargetDev);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] AttachInternal: [3] IoGetDeviceObjectPointer('%ws') failed: 0x%08X\n",
            DevicePath, status);
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }

    // 4. 创建过滤器设备 (FiDO)
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [4] IoCreateDevice (Type=0x%lX, Flags=0x%lX) ... calling\n",
        (ULONG)pTargetDev->DeviceType, (ULONG)pTargetDev->Characteristics);
    status = IoCreateDevice(
        g_FilterDriverObject,
        sizeof(ATTACH_DEVICE_EXTENSION),
        NULL,                        // 匿名设备
        pTargetDev->DeviceType,      // 继承目标设备类型
        pTargetDev->Characteristics, // 继承目标设备特征
        FALSE,                       // 非独占
        &pFilterDev);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [4] IoCreateDevice returned 0x%08X (FiDO=0x%p)\n", status, pFilterDev);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] AttachInternal: [4] IoCreateDevice failed: 0x%08X\n", status);
        ObDereferenceObject(pFileObj);
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }

    // 5. 附着到设备栈顶
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [5] IoAttachDeviceToDeviceStack(FiDO=0x%p, Target=0x%p) ... calling\n",
        pFilterDev, pTargetDev);
    pLowerDev = IoAttachDeviceToDeviceStack(pFilterDev, pTargetDev);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [5] IoAttachDeviceToDeviceStack returned Lower=0x%p\n", pLowerDev);
    if (pLowerDev == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] AttachInternal: [5] IoAttachDeviceToDeviceStack failed for '%ws'\n", DevicePath);
        IoDeleteDevice(pFilterDev);
        ObDereferenceObject(pFileObj);
        localResp.Status = STATUS_INSUFFICIENT_RESOURCES;
        *pResp = localResp;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 6. 清除 DO_DEVICE_INITIALIZING 标志
    pFilterDev->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [6] cleared DO_DEVICE_INITIALIZING\n");

    // 7. 填充设备扩展(除 AttachId 外都在锁外写;AttachId 在锁内分配)
    PATTACH_DEVICE_EXTENSION ext = (PATTACH_DEVICE_EXTENSION)pFilterDev->DeviceExtension;
    ext->FilterDevice = pFilterDev;
    ext->LowerDeviceObject = pLowerDev;
    ext->TargetDevice = pTargetDev;
    ext->TargetFileObject = pFileObj;
    wcsncpy_s(ext->TargetPath, RTL_NUMBER_OF(ext->TargetPath), DevicePath, _TRUNCATE);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [7] extension filled\n");

    // 8. 分配 ID + 入链表(极短,持锁)
    ExAcquireFastMutex(&g_AttachMutex);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [8] mutex acquired (id+list)\n");
    ext->AttachId = (ULONG)InterlockedIncrement(&g_NextAttachId);
    InsertTailList(&g_AttachListHead, &ext->ListEntry);
    ExReleaseFastMutex(&g_AttachMutex);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [8] inserted Id=%lu\n", ext->AttachId);

    // 9. 填充响应
    localResp.Status = STATUS_SUCCESS;
    localResp.AttachId = ext->AttachId;
    localResp.FilterDeviceAddr = (ULONGLONG)pFilterDev;
    localResp.LowerDeviceAddr = (ULONGLONG)pLowerDev;
    localResp.NewStackSize = (USHORT)pFilterDev->StackSize;
    localResp.TargetStackSize = (USHORT)pTargetDev->StackSize;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] AttachInternal: [9] SUCCESS Id=%lu FiDO=0x%p Lower=0x%p Stack %u->%u\n",
        ext->AttachId, pFilterDev, pLowerDev,
        localResp.TargetStackSize, localResp.NewStackSize);

    *pResp = localResp;
    return STATUS_SUCCESS;
}

// ============================================================
// 内部:解绑指定附着
// 调用时必须已持有 g_AttachMutex
// ============================================================

static NTSTATUS DetachDeviceInternal(
    _In_ ULONG AttachId,
    _In_opt_ PCWSTR DevicePath,
    _Out_ PDETACH_DEVICE_RESPONSE pResp)
{
    // ⚠️ METHOD_BUFFERED 陷阱: 同 AttachToDeviceInternal,用局部变量构建响应
    DETACH_DEVICE_RESPONSE localResp = { 0 };

    // 1. 锁内: 遍历查找 + 从链表移除 + 保存需在锁外使用的字段
    //    (IoDetachDevice/IoDeleteDevice/ObDereferenceObject 可能等待 IRP 完成,
    //     不能在 FAST_MUTEX/APC_LEVEL 下调用)
    PATTACH_DEVICE_EXTENSION target = NULL;
    UNICODE_STRING searchPath;
    if (AttachId == 0 && DevicePath != NULL) {
        RtlInitUnicodeString(&searchPath, DevicePath);
    }

    ExAcquireFastMutex(&g_AttachMutex);
    for (PLIST_ENTRY p = g_AttachListHead.Flink; p != &g_AttachListHead; p = p->Flink) {
        PATTACH_DEVICE_EXTENSION ext = CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);

        if (AttachId != 0 && ext->AttachId == AttachId) {
            target = ext;
            break;
        }
        if (AttachId == 0 && DevicePath != NULL) {
            UNICODE_STRING existingPath;
            RtlInitUnicodeString(&existingPath, ext->TargetPath);
            if (RtlEqualUnicodeString(&searchPath, &existingPath, TRUE)) {
                target = ext;
                break;
            }
        }
    }

    if (target == NULL) {
        ExReleaseFastMutex(&g_AttachMutex);
        localResp.Status = STATUS_NOT_FOUND;
        *pResp = localResp;
        return STATUS_NOT_FOUND;
    }

    // 锁内移除:之后其他线程不会再看到这个条目
    RemoveEntryList(&target->ListEntry);
    ExReleaseFastMutex(&g_AttachMutex);

    // 保存需要在删除设备后使用的字段
    // (IoDeleteDevice 后 ext 内存被释放,不能再访问)
    PFILE_OBJECT fileObj = target->TargetFileObject;
    PDEVICE_OBJECT lowerDev = target->LowerDeviceObject;
    PDEVICE_OBJECT filterDev = target->FilterDevice;
    ULONG detachedId = target->AttachId;

    // 2. 锁外: 解绑 + 删除设备 + 释放引用 (可能等待 IRP, 必须 PASSIVE_LEVEL)
    if (lowerDev) {
        IoDetachDevice(lowerDev);
    }
    if (filterDev) {
        IoDeleteDevice(filterDev);
    }
    if (fileObj) {
        ObDereferenceObject(fileObj);
    }

    localResp.Status = STATUS_SUCCESS;
    localResp.DetachedId = detachedId;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Detached Id=%lu\n", detachedId);

    *pResp = localResp;
    return STATUS_SUCCESS;
}

// ============================================================
// Init / Unload
// ============================================================

NTSTATUS DriverAttachInit(VOID)
{
    ExInitializeFastMutex(&g_AttachMutex);
    InitializeListHead(&g_AttachListHead);
    g_NextAttachId = 1;
    g_FilterDriverObject = NULL;
    g_Initialized = TRUE;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] DriverAttach: initialized\n");

    return STATUS_SUCCESS;
}

VOID DriverAttachUnload(VOID)
{
    if (!g_Initialized) return;

    // 先把所有条目从链表移到临时链表
    LIST_ENTRY tempList;
    InitializeListHead(&tempList);

    ExAcquireFastMutex(&g_AttachMutex);
    while (!IsListEmpty(&g_AttachListHead)) {
        PLIST_ENTRY p = RemoveHeadList(&g_AttachListHead);
        InsertTailList(&tempList, p);
    }
    ExReleaseFastMutex(&g_AttachMutex);

    // 逐个解绑 + 删除设备 (不持锁,因为 IoDetachDevice 可能等待)
    while (!IsListEmpty(&tempList)) {
        PLIST_ENTRY p = RemoveHeadList(&tempList);
        PATTACH_DEVICE_EXTENSION ext = CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);

        PFILE_OBJECT fileObj = ext->TargetFileObject;

        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[KernelService] Unload: detaching Id=%lu '%ws'\n",
            ext->AttachId, ext->TargetPath);

        if (ext->LowerDeviceObject) {
            IoDetachDevice(ext->LowerDeviceObject);
        }
        if (ext->FilterDevice) {
            IoDeleteDevice(ext->FilterDevice);
        }
        if (fileObj) {
            ObDereferenceObject(fileObj);
        }
    }

    // 删除过滤器 DriverObject
    if (g_FilterDriverObject) {
        IoDeleteDriver(g_FilterDriverObject);
        g_FilterDriverObject = NULL;
    }

    g_Initialized = FALSE;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] DriverAttach: unloaded\n");
}

// ============================================================
// IOCTL 处理函数
// ============================================================

static NTSTATUS HandleAttach(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength)
{
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] HandleAttach: ENTER InLen=%zu OutLen=%zu\n", InputBufferLength, OutputBufferLength);

    NTSTATUS status;

    // 1. 校验输入
    if (InputBufferLength < sizeof(ATTACH_DEVICE_REQUEST)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[ATT] HandleAttach: InLen < REQ\n");
        return STATUS_BUFFER_TOO_SMALL;
    }

    PATTACH_DEVICE_REQUEST pReq = NULL;
    status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(ATTACH_DEVICE_REQUEST), (PVOID*)&pReq, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] HandleAttach: RetrieveInputBuffer failed 0x%08X\n", status);
        return status;
    }

    // 强制 \0 结尾
    pReq->DevicePath[RTL_NUMBER_OF(pReq->DevicePath) - 1] = L'\0';
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] HandleAttach: DevicePath='%ws'\n", pReq->DevicePath);

    // 2. 校验输出 (至少能放下响应头)
    if (OutputBufferLength < sizeof(ATTACH_DEVICE_RESPONSE)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[ATT] HandleAttach: OutLen < RESP\n");
        WdfRequestSetInformation(Request, sizeof(ATTACH_DEVICE_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PATTACH_DEVICE_RESPONSE pResp = NULL;
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(ATTACH_DEVICE_RESPONSE), (PVOID*)&pResp, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[ATT] HandleAttach: RetrieveOutputBuffer failed 0x%08X\n", status);
        return status;
    }

    // 3. 执行附着
    //    ⚠️ 不能在此处持 g_AttachMutex:AttachToDeviceInternal 内部会自己 acquire
    //    (查重 + 入链表),FAST_MUTEX 非递归,二次获取会自死锁。
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] HandleAttach: -> AttachToDeviceInternal\n");
    status = AttachToDeviceInternal(pReq->DevicePath, pResp);
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[ATT] HandleAttach: AttachToDeviceInternal returned 0x%08X\n", status);

    WdfRequestSetInformation(Request, (ULONG_PTR)sizeof(ATTACH_DEVICE_RESPONSE));
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[ATT] HandleAttach: EXIT\n");
    return status;
}

static NTSTATUS HandleDetach(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength)
{
    NTSTATUS status;

    // 1. 校验输入
    if (InputBufferLength < sizeof(DETACH_DEVICE_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDETACH_DEVICE_REQUEST pReq = NULL;
    status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(DETACH_DEVICE_REQUEST), (PVOID*)&pReq, NULL);
    if (!NT_SUCCESS(status)) return status;

    pReq->DevicePath[RTL_NUMBER_OF(pReq->DevicePath) - 1] = L'\0';

    // 2. 校验输出
    if (OutputBufferLength < sizeof(DETACH_DEVICE_RESPONSE)) {
        WdfRequestSetInformation(Request, sizeof(DETACH_DEVICE_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDETACH_DEVICE_RESPONSE pResp = NULL;
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(DETACH_DEVICE_RESPONSE), (PVOID*)&pResp, NULL);
    if (!NT_SUCCESS(status)) return status;

    // 3. 执行解绑
    //    不在此处持锁:DetachDeviceInternal 内部自己管锁
    //    (锁内查找+移除,锁外做 IoDetachDevice/IoDeleteDevice 等可等待调用)
    status = DetachDeviceInternal(
        pReq->AttachId,
        (pReq->AttachId == 0) ? pReq->DevicePath : NULL,
        pResp);

    WdfRequestSetInformation(Request, (ULONG_PTR)sizeof(DETACH_DEVICE_RESPONSE));
    return status;
}

static NTSTATUS HandleQuery(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength)
{
    NTSTATUS status;

    // 1. 数链表有多少条目
    ExAcquireFastMutex(&g_AttachMutex);

    ULONG count = 0;
    for (PLIST_ENTRY p = g_AttachListHead.Flink; p != &g_AttachListHead; p = p->Flink) {
        count++;
    }

    ULONG neededBytes = sizeof(QUERY_ATTACHMENTS_RESPONSE) + count * sizeof(ATTACH_ENTRY);

    // 2. 校验输出缓冲区
    if (OutputBufferLength < sizeof(QUERY_ATTACHMENTS_RESPONSE)) {
        ExReleaseFastMutex(&g_AttachMutex);
        WdfRequestSetInformation(Request, (ULONG_PTR)sizeof(QUERY_ATTACHMENTS_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PQUERY_ATTACHMENTS_RESPONSE pResp = NULL;
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(QUERY_ATTACHMENTS_RESPONSE), (PVOID*)&pResp, NULL);
    if (!NT_SUCCESS(status)) {
        ExReleaseFastMutex(&g_AttachMutex);
        return status;
    }

    pResp->Count = 0;
    pResp->NeededOutputBytes = neededBytes;

    // 3. 输出缓冲区放得下所有条目 → 填充
    if (OutputBufferLength >= neededBytes) {
        PATTACH_ENTRY pEntry = (PATTACH_ENTRY)((PUCHAR)pResp + sizeof(QUERY_ATTACHMENTS_RESPONSE));
        ULONG i = 0;

        for (PLIST_ENTRY p = g_AttachListHead.Flink; p != &g_AttachListHead; p = p->Flink) {
            PATTACH_DEVICE_EXTENSION ext = CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);
            pEntry[i].FilterDeviceAddr = (ULONGLONG)ext->FilterDevice;
            pEntry[i].LowerDeviceAddr = (ULONGLONG)ext->LowerDeviceObject;
            wcsncpy_s(pEntry[i].TargetPath, RTL_NUMBER_OF(pEntry[i].TargetPath),
                      ext->TargetPath, _TRUNCATE);
            pEntry[i].AttachId = ext->AttachId;
            pEntry[i].StackSize = (USHORT)ext->FilterDevice->StackSize;
            i++;
        }

        pResp->Count = count;
        WdfRequestSetInformation(Request, (ULONG_PTR)neededBytes);
    } else {
        // 缓冲区不够,只填响应头,让应用层按 NeededOutputBytes 重试
        WdfRequestSetInformation(Request, (ULONG_PTR)sizeof(QUERY_ATTACHMENTS_RESPONSE));
    }

    ExReleaseFastMutex(&g_AttachMutex);

    return STATUS_SUCCESS;
}

// ============================================================
// 按 PE 区段安全 dump 驱动内存映像
//
// 背景:
//   RtlCopyMemory 暴力拷贝整个 DriverSize 字节会蓝屏 (PAGE_FAULT_IN_NONPAGED_AREA),
//   因为 .INIT 等 DISCARDABLE 区段在 DriverEntry 返回后已被系统释放回收.
//   内核态 __try/__except 也无法捕获内核地址的缺页异常 (直接 Bug Check).
//
// 方案 (反作弊标准做法):
//   1. 用 MmCopyMemory (不直接解引用) 读 PE 头, 不触发缺页异常
//   2. 遍历 IMAGE_SECTION_HEADER, 跳过 IMAGE_SCN_MEM_DISCARDABLE 区段
//   3. 对有效区段用 MmCopyMemory 逐个拷贝, 跳过的区段位置填 0
//   4. 输出映像布局与原内存映像一致 (SizeOfImage 大小, 跳过的区段是 0)
//
// 安全保证:
//   - 全程不直接解引用 imageBase 指针 (用 MmCopyMemory 拷到局部变量再解析)
//   - MmCopyMemory 遇到无效页返回错误码, 不触发蓝屏
//   - 每个区段独立拷贝, 单个区段失败不影响其他
// ============================================================

#ifndef IMAGE_SCN_MEM_DISCARDABLE
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#endif

// MmCopyMemory: Win8.1+ API, 安全拷贝可能无效的虚拟内存
// 如果 ntddk.h 未声明, 显式声明
#ifndef MM_COPY_MEMORY_VIRTUAL
#define MM_COPY_MEMORY_VIRTUAL 0
typedef union _MM_COPY_ADDRESS_HD {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
} MM_COPY_ADDRESS_HD;
NTKERNELAPI NTSTATUS NTAPI MmCopyMemory(
    _Out_writes_bytes_(NumberOfBytes) PVOID TargetAddress,
    _In_ MM_COPY_ADDRESS_HD SourceAddress,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Flags,
    _Out_ PSIZE_T NumberOfBytesTransferred);
#endif

// 用 MmCopyMemory 拷贝虚拟内存的包装
static NTSTATUS SafeVmCopy(
    _Out_writes_bytes_(Size) PVOID Dst,
    _In_ PVOID Src,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T pCopied)
{
    MM_COPY_ADDRESS src;
    src.VirtualAddress = Src;
    SIZE_T copied = 0;
    NTSTATUS st = MmCopyMemory(Dst, src, Size, MM_COPY_MEMORY_VIRTUAL, &copied);
    if (pCopied) *pCopied = copied;
    return st;
}

// 按 PE 区段安全 dump 驱动内存映像
// 返回:
//   STATUS_SUCCESS       — 成功 (或部分成功), *pBytesDumped = 实际写入字节数
//   STATUS_BUFFER_TOO_SMALL — 缓冲区不够, *pImageSize = 需要的大小 (SizeOfImage)
//   其他                 — PE 解析失败 (调用方可回退)
static NTSTATUS DumpDriverImageBySections(
    _In_ PVOID ImageBase,
    _Out_writes_bytes_(OutBufferSize) PUCHAR OutBuffer,
    _In_ ULONG OutBufferSize,
    _Out_ PULONG pBytesDumped,
    _Out_ PULONG pImageSize)
{
    *pBytesDumped = 0;
    *pImageSize = 0;

    if (!ImageBase || !OutBuffer) return STATUS_INVALID_PARAMETER;

    // 1. 用 MmCopyMemory 读 DOS 头 (不直接解引用 ImageBase!)
    IMAGE_DOS_HEADER dos;
    SIZE_T copied = 0;
    NTSTATUS status = SafeVmCopy(&dos, ImageBase, sizeof(dos), &copied);
    if (!NT_SUCCESS(status) || copied < sizeof(dos)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] DumpDriver: read DOS header failed 0x%08X\n", status);
        return status;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] DumpDriver: bad DOS magic 0x%04X\n", dos.e_magic);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // 2. 读 NT 头 (用 64 位结构, 大小够装 32 位)
    IMAGE_NT_HEADERS64 nt;
    PVOID ntAddr = (PUCHAR)ImageBase + dos.e_lfanew;
    status = SafeVmCopy(&nt, ntAddr, sizeof(nt), &copied);
    if (!NT_SUCCESS(status) || copied < sizeof(IMAGE_NT_HEADERS32)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] DumpDriver: read NT header failed 0x%08X\n", status);
        return status;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] DumpDriver: bad NT signature 0x%08X\n", nt.Signature);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // 判断 PE32 / PE32+
    BOOLEAN is64 = (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    ULONG  sizeOfImage;
    ULONG  sizeOfHeaders;
    USHORT numSections;
    USHORT sizeOfOptHdr;

    if (is64) {
        sizeOfImage   = nt.OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt.OptionalHeader.SizeOfHeaders;
        numSections   = nt.FileHeader.NumberOfSections;
        sizeOfOptHdr  = nt.FileHeader.SizeOfOptionalHeader;
    } else {
        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)&nt;
        sizeOfImage   = nt32->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
        numSections   = nt32->FileHeader.NumberOfSections;
        sizeOfOptHdr  = nt32->FileHeader.SizeOfOptionalHeader;
    }

    *pImageSize = sizeOfImage;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] DumpDriver: PE %s, SizeOfImage=%lu, %hu sections, SizeOfHeaders=%lu\n",
        is64 ? "64" : "32", sizeOfImage, numSections, sizeOfHeaders);

    // 3. 缓冲区不够 → 返回需要的 ImageSize 让应用层重发
    if (sizeOfImage > OutBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 4. 清零输出缓冲 (跳过的 DISCARDABLE 区段位置保持 0)
    RtlZeroMemory(OutBuffer, sizeOfImage);

    // 5. 拷贝 PE 头部 (DOS + NT + 区段表)
    if (sizeOfHeaders > 0 && sizeOfHeaders <= sizeOfImage) {
        status = SafeVmCopy(OutBuffer, ImageBase, sizeOfHeaders, &copied);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[KernelService] DumpDriver: copy PE headers failed 0x%08X (继续拷区段)\n", status);
        }
    }

    // 6. 区段表偏移 = e_lfanew + sizeof(IMAGE_FILE_HEADER) + SizeOfOptionalHeader
    ULONG sectionTableOff = dos.e_lfanew
                          + sizeof(IMAGE_FILE_HEADER)
                          + sizeOfOptHdr;

    // 7. 遍历每个区段, 跳过 DISCARDABLE, 其余用 MmCopyMemory 拷贝
    for (USHORT i = 0; i < numSections; i++) {
        IMAGE_SECTION_HEADER sec;
        PVOID secHdrAddr = (PUCHAR)ImageBase + sectionTableOff
                         + (ULONG)i * sizeof(IMAGE_SECTION_HEADER);
        status = SafeVmCopy(&sec, secHdrAddr, sizeof(sec), &copied);
        if (!NT_SUCCESS(status) || copied < sizeof(sec)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[KernelService] DumpDriver: section[%hu] header read failed\n", i);
            continue;
        }

        // 核心逻辑: 跳过可丢弃区段 (.INIT 等, 已被系统释放)
        if (sec.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] DumpDriver: SKIP discardable %.8s\n",
                (char*)sec.Name);
            continue;
        }

        ULONG va    = sec.VirtualAddress;
        ULONG vsize = sec.Misc.VirtualSize;

        // 边界安全检查
        if (va >= sizeOfImage || vsize == 0) continue;
        if (va + vsize > sizeOfImage) vsize = sizeOfImage - va;

        // 拷贝区段 (MmCopyMemory 遇到无效页返回错误, 不蓝屏)
        status = SafeVmCopy(OutBuffer + va,
                           (PUCHAR)ImageBase + va,
                           vsize, &copied);
        if (NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] DumpDriver: section %.8s VA=0x%lX size=%lu OK (%zu bytes)\n",
                (char*)sec.Name, va, vsize, copied);
        } else {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
                "[KernelService] DumpDriver: section %.8s copy failed 0x%08X (%zu bytes copied)\n",
                (char*)sec.Name, status, copied);
            // 拷失败也继续下一个区段, 尽最大努力 dump
        }
    }

    *pBytesDumped = sizeOfImage;
    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL_DUMP_DRIVER_MEMORY — dump 被附着设备所属驱动的内存映像
//
// 流程:
//   1. 按 AttachId 在 g_AttachListHead 找到 ATTACH_DEVICE_EXTENSION
//   2. ext->TargetDevice->DriverObject 拿到 PDRIVER_OBJECT
//   3. DriverObject->DriverStart 拿映像基址
//   4. 按 PE 区段安全 dump (跳过 DISCARDABLE, 用 MmCopyMemory 不蓝屏)
//
// 协议 (两趟探测):
//   - 第一趟: 应用层传 sizeof(RESPONSE) 大小, 内核读 PE 头返回 SizeOfImage + 路径
//   - 第二趟: 应用层传 sizeof(RESPONSE) + SizeOfImage, 内核按区段拷贝完整映像
// ============================================================

static NTSTATUS HandleDumpDriverMemory(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength)
{
    NTSTATUS status;

    // 1. 校验输入
    if (InputBufferLength < sizeof(DUMP_DRIVER_MEMORY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDUMP_DRIVER_MEMORY_REQUEST pReq = NULL;
    status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(DUMP_DRIVER_MEMORY_REQUEST), (PVOID*)&pReq, NULL);
    if (!NT_SUCCESS(status) || !pReq) {
        return status;
    }

    // 2. 校验输出至少能放响应头
    if (OutputBufferLength < sizeof(DUMP_DRIVER_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PDUMP_DRIVER_MEMORY_RESPONSE pResp = NULL;
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(DUMP_DRIVER_MEMORY_RESPONSE), (PVOID*)&pResp, NULL);
    if (!NT_SUCCESS(status) || !pResp) {
        return status;
    }

    // ⚠️ METHOD_BUFFERED 陷阱: pReq 和 pResp 指向同一块 SystemBuffer!
    // 必须先把 AttachId 存到局部变量, 再 RtlZeroMemory, 否则 AttachId 被清零
    ULONG queryAttachId = pReq->AttachId;

    RtlZeroMemory(pResp, sizeof(DUMP_DRIVER_MEMORY_RESPONSE));

    // 3. 按 AttachId 找 ext (持锁)
    ExAcquireFastMutex(&g_AttachMutex);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] DumpDriverMemory: AttachId=%lu, InLen=%zu OutLen=%zu\n",
        queryAttachId, InputBufferLength, OutputBufferLength);

    PATTACH_DEVICE_EXTENSION targetExt = NULL;
    for (PLIST_ENTRY p = g_AttachListHead.Flink;
         p != &g_AttachListHead;
         p = p->Flink)
    {
        PATTACH_DEVICE_EXTENSION ext =
            CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);
        if (ext->AttachId == queryAttachId) {
            targetExt = ext;
            break;
        }
    }

    if (!targetExt || !targetExt->TargetDevice || !targetExt->TargetDevice->DriverObject) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] DumpDriverMemory: AttachId=%lu NOT_FOUND\n", queryAttachId);
        ExReleaseFastMutex(&g_AttachMutex);
        pResp->Status = STATUS_NOT_FOUND;
        WdfRequestSetInformation(Request, sizeof(DUMP_DRIVER_MEMORY_RESPONSE));
        return STATUS_SUCCESS;
    }

    PDRIVER_OBJECT drvObj  = targetExt->TargetDevice->DriverObject;
    PVOID  imageBase       = drvObj->DriverStart;
    ULONG  driverSize      = drvObj->DriverSize;

    pResp->DriverObjectAddr = (ULONGLONG)drvObj;
    pResp->ImageBase        = (ULONGLONG)imageBase;
    pResp->ImageSize        = driverSize;  // 初始值, 后面 PE 解析会更新

    ExReleaseFastMutex(&g_AttachMutex);

    if (!imageBase) {
        pResp->Status = STATUS_INVALID_PARAMETER;
        WdfRequestSetInformation(Request, sizeof(DUMP_DRIVER_MEMORY_RESPONSE));
        return STATUS_SUCCESS;
    }

    // 4. 按 ImageBase 反查驱动文件路径 (ZwQuerySystemInformation)
    {
        ULONG needed = 0;
        ZwQuerySystemInformation(DUMPMOD_SystemModuleInformation, NULL, 0, &needed);
        if (needed > 0) {
            ULONG allocSize = needed + 0x1000;
            PDUMPMOD_MODULE_LIST pList = (PDUMPMOD_MODULE_LIST)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, 'pMOD');
            if (pList) {
                NTSTATUS qst = ZwQuerySystemInformation(
                    DUMPMOD_SystemModuleInformation, pList, allocSize, &needed);
                if (NT_SUCCESS(qst)) {
                    for (ULONG i = 0; i < pList->Count; i++) {
                        if (pList->Modules[i].ImageBase == imageBase) {
                            ANSI_STRING ansi;
                            RtlInitAnsiString(&ansi,
                                (PCSZ)pList->Modules[i].FullPathName);
                            UNICODE_STRING uni;
                            uni.Buffer = pResp->FullPath;
                            uni.Length = 0;
                            uni.MaximumLength = sizeof(pResp->FullPath);
                            RtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);

                            USHORT off = pList->Modules[i].OffsetToFileName;
                            if (off < sizeof(pList->Modules[i].FullPathName)) {
                                ANSI_STRING baseAnsi;
                                RtlInitAnsiString(&baseAnsi,
                                    (PCSZ)&pList->Modules[i].FullPathName[off]);
                                UNICODE_STRING baseUni;
                                baseUni.Buffer = pResp->BaseName;
                                baseUni.Length = 0;
                                baseUni.MaximumLength = sizeof(pResp->BaseName);
                                RtlAnsiStringToUnicodeString(
                                    &baseUni, &baseAnsi, FALSE);
                            }
                            break;
                        }
                    }
                }
                ExFreePoolWithTag(pList, 'pMOD');
            }
        }
    }

    // 5. 按 PE 区段安全 dump (跳过 DISCARDABLE 区段, 用 MmCopyMemory)
    PUCHAR outImg = (PUCHAR)pResp + sizeof(DUMP_DRIVER_MEMORY_RESPONSE);
    ULONG  availForData = (ULONG)OutputBufferLength - sizeof(DUMP_DRIVER_MEMORY_RESPONSE);

    ULONG peImageSize  = 0;
    ULONG bytesDumped  = 0;
    NTSTATUS dumpStatus = DumpDriverImageBySections(
        imageBase, outImg, availForData, &bytesDumped, &peImageSize);

    if (dumpStatus == STATUS_BUFFER_TOO_SMALL) {
        // 第一趟探测: 缓冲区不够, 但已拿到真实 SizeOfImage
        // 更新 ImageSize 为 PE 真实大小, 让应用层按此大小重发
        pResp->ImageSize    = peImageSize;
        pResp->BytesDumped  = 0;
        pResp->Status        = STATUS_SUCCESS;
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[KernelService] DumpDriverMemory: probe done, SizeOfImage=%lu (DriverSize=%lu)\n",
            peImageSize, driverSize);
        WdfRequestSetInformation(Request, sizeof(DUMP_DRIVER_MEMORY_RESPONSE));
        return STATUS_SUCCESS;
    }

    // 更新 ImageSize 为 PE 真实大小
    pResp->ImageSize = peImageSize;

    if (NT_SUCCESS(dumpStatus)) {
        pResp->Status       = STATUS_SUCCESS;
        pResp->BytesDumped  = bytesDumped;
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[KernelService] DumpDriverMemory: success, %lu bytes dumped\n", bytesDumped);
    } else {
        // PE 解析失败, 回退: 用 MmCopyMemory 尽可能多拷 (遇到无效页会停止)
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] DumpDriverMemory: PE parse failed 0x%08X, fallback to raw copy\n",
            dumpStatus);
        SIZE_T copied = 0;
        ULONG trySize = (driverSize < availForData) ? driverSize : availForData;
        NTSTATUS fb = SafeVmCopy(outImg, imageBase, trySize, &copied);
        if (NT_SUCCESS(fb) || copied > 0) {
            pResp->Status      = STATUS_SUCCESS;
            pResp->BytesDumped = (ULONG)copied;
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
                "[KernelService] DumpDriverMemory: fallback copied %zu bytes\n", copied);
        } else {
            pResp->Status      = dumpStatus;
            pResp->BytesDumped = 0;
        }
    }

    WdfRequestSetInformation(
        Request, sizeof(DUMP_DRIVER_MEMORY_RESPONSE) + pResp->BytesDumped);
    return STATUS_SUCCESS;
}

// ============================================================
// IOCTL 分发入口
// ============================================================

NTSTATUS DriverAttachHandleIoctl(
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength)
{
    if (!g_Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    switch (IoControlCode) {
    case IOCTL_ATTACH_DEVICE:
        return HandleAttach(Request, InputBufferLength, OutputBufferLength);

    case IOCTL_DETACH_DEVICE:
        return HandleDetach(Request, InputBufferLength, OutputBufferLength);

    case IOCTL_QUERY_ATTACHMENTS:
        return HandleQuery(Request, OutputBufferLength);

    case IOCTL_DUMP_DRIVER_MEMORY:
        return HandleDumpDriverMemory(Request, InputBufferLength, OutputBufferLength);

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}
