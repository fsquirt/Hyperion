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
//   - FAST_MUTEX 保护链表和 Filter DriverObject 创建
//   - IoDetachDevice/IoDeleteDevice 不在持锁状态调用(可能等待 IRP 完成)
//   - IRP 透传函数只读 ext->LowerDeviceObject,不需要锁

#include "DriverAttach.h"
#include "EtwLogger.h"
#include <ntstrsafe.h>

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
// 调用时必须已持有 g_AttachMutex
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

    // 1. 查重 — 遍历链表看是否已 attach 过同一路径
    UNICODE_STRING newPath;
    RtlInitUnicodeString(&newPath, DevicePath);

    for (PLIST_ENTRY p = g_AttachListHead.Flink; p != &g_AttachListHead; p = p->Flink) {
        PATTACH_DEVICE_EXTENSION ext = CONTAINING_RECORD(p, ATTACH_DEVICE_EXTENSION, ListEntry);
        UNICODE_STRING existingPath;
        RtlInitUnicodeString(&existingPath, ext->TargetPath);
        if (RtlEqualUnicodeString(&newPath, &existingPath, TRUE)) {
            // 已 attach 过
            localResp.Status = STATUS_DUPLICATE_OBJECTID;
            localResp.AttachId = ext->AttachId;
            localResp.FilterDeviceAddr = (ULONGLONG)ext->FilterDevice;
            localResp.LowerDeviceAddr = (ULONGLONG)ext->LowerDeviceObject;
            localResp.NewStackSize = (USHORT)ext->FilterDevice->StackSize;
            localResp.TargetStackSize = (USHORT)ext->TargetDevice->StackSize;
            *pResp = localResp;
            return STATUS_DUPLICATE_OBJECTID;
        }
    }

    // 2. 确保过滤器 DriverObject 已创建
    status = EnsureFilterDriverCreated();
    if (!NT_SUCCESS(status)) {
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }

    // 3. 用 IoGetDeviceObjectPointer 按名字拿目标设备
    // 这个 API 内部会打开设备(发 IRP_MJ_CREATE),返回 FileObject + DeviceObject
    // FileObject 引用持有期间 DeviceObject 有效
    status = IoGetDeviceObjectPointer(&newPath, FILE_ALL_ACCESS, &pFileObj, &pTargetDev);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] IoGetDeviceObjectPointer('%ws') failed: 0x%08X\n",
            DevicePath, status);
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }

    // 4. 创建过滤器设备 (FiDO)
    //    - 匿名(不命名)
    //    - 继承目标的 DeviceType / Characteristics
    //    - 设备扩展大小 = sizeof(ATTACH_DEVICE_EXTENSION)
    status = IoCreateDevice(
        g_FilterDriverObject,
        sizeof(ATTACH_DEVICE_EXTENSION),
        NULL,                        // 匿名设备
        pTargetDev->DeviceType,      // 继承目标设备类型
        pTargetDev->Characteristics, // 继承目标设备特征
        FALSE,                       // 非独占
        &pFilterDev);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] IoCreateDevice failed: 0x%08X\n", status);
        ObDereferenceObject(pFileObj);
        localResp.Status = status;
        *pResp = localResp;
        return status;
    }

    // 5. 附着到设备栈顶
    //    IoAttachDeviceToDeviceStack 内部会:
    //      - 把 pFilterDev 插入到 pTargetDev 的 AttachedDevice 链表头
    //      - pFilterDev->StackSize = pTargetDev->StackSize + 1
    //    返回值 = 附着之前的栈顶设备(也就是下一层)
    pLowerDev = IoAttachDeviceToDeviceStack(pFilterDev, pTargetDev);
    if (pLowerDev == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] IoAttachDeviceToDeviceStack failed for '%ws'\n", DevicePath);
        IoDeleteDevice(pFilterDev);
        ObDereferenceObject(pFileObj);
        localResp.Status = STATUS_INSUFFICIENT_RESOURCES;
        *pResp = localResp;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 6. 清除 DO_DEVICE_INITIALIZING 标志
    //    IoCreateDevice 会设置这个标志,清除后设备才能接收 IRP
    //    (IoAttachDeviceToDeviceStack 可能已经清了,但再清一次无害)
    pFilterDev->Flags &= ~DO_DEVICE_INITIALIZING;

    // 7. 填充设备扩展
    PATTACH_DEVICE_EXTENSION ext = (PATTACH_DEVICE_EXTENSION)pFilterDev->DeviceExtension;
    ext->FilterDevice = pFilterDev;
    ext->LowerDeviceObject = pLowerDev;
    ext->TargetDevice = pTargetDev;
    ext->TargetFileObject = pFileObj;
    ext->AttachId = (ULONG)InterlockedIncrement(&g_NextAttachId);
    wcsncpy_s(ext->TargetPath, RTL_NUMBER_OF(ext->TargetPath), DevicePath, _TRUNCATE);

    // 8. 加入链表
    InsertTailList(&g_AttachListHead, &ext->ListEntry);

    // 9. 填充响应
    localResp.Status = STATUS_SUCCESS;
    localResp.AttachId = ext->AttachId;
    localResp.FilterDeviceAddr = (ULONGLONG)pFilterDev;
    localResp.LowerDeviceAddr = (ULONGLONG)pLowerDev;
    localResp.NewStackSize = (USHORT)pFilterDev->StackSize;
    localResp.TargetStackSize = (USHORT)pTargetDev->StackSize;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Attached to '%ws' (Id=%lu, FiDO=0x%p, Lower=0x%p, StackSize %u→%u)\n",
        DevicePath, ext->AttachId, pFilterDev, pLowerDev,
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

    // 遍历查找
    PATTACH_DEVICE_EXTENSION target = NULL;
    UNICODE_STRING searchPath;
    if (AttachId == 0 && DevicePath != NULL) {
        RtlInitUnicodeString(&searchPath, DevicePath);
    }

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
        localResp.Status = STATUS_NOT_FOUND;
        *pResp = localResp;
        return STATUS_NOT_FOUND;
    }

    // 从链表移除
    RemoveEntryList(&target->ListEntry);

    // 保存需要在删除设备后使用的字段
    // (IoDeleteDevice 后 ext 内存被释放,不能再访问)
    PFILE_OBJECT fileObj = target->TargetFileObject;
    PDEVICE_OBJECT lowerDev = target->LowerDeviceObject;
    PDEVICE_OBJECT filterDev = target->FilterDevice;
    ULONG detachedId = target->AttachId;

    // 解绑 + 删除设备
    // 注意:不能在持锁状态调用这两个函数(可能等待 IRP 完成)
    // 但在 Unload 场景下所有用户句柄已关闭,应该没有在飞的 IRP
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
    NTSTATUS status;

    // 1. 校验输入
    if (InputBufferLength < sizeof(ATTACH_DEVICE_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PATTACH_DEVICE_REQUEST pReq = NULL;
    status = WdfRequestRetrieveInputBuffer(
        Request, sizeof(ATTACH_DEVICE_REQUEST), (PVOID*)&pReq, NULL);
    if (!NT_SUCCESS(status)) return status;

    // 强制 \0 结尾
    pReq->DevicePath[RTL_NUMBER_OF(pReq->DevicePath) - 1] = L'\0';

    // 2. 校验输出 (至少能放下响应头)
    if (OutputBufferLength < sizeof(ATTACH_DEVICE_RESPONSE)) {
        WdfRequestSetInformation(Request, sizeof(ATTACH_DEVICE_RESPONSE));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PATTACH_DEVICE_RESPONSE pResp = NULL;
    status = WdfRequestRetrieveOutputBuffer(
        Request, sizeof(ATTACH_DEVICE_RESPONSE), (PVOID*)&pResp, NULL);
    if (!NT_SUCCESS(status)) return status;

    // 3. 执行附着
    ExAcquireFastMutex(&g_AttachMutex);
    status = AttachToDeviceInternal(pReq->DevicePath, pResp);
    ExReleaseFastMutex(&g_AttachMutex);

    WdfRequestSetInformation(Request, (ULONG_PTR)sizeof(ATTACH_DEVICE_RESPONSE));
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
    //    注意: IoDetachDevice/IoDeleteDevice 可能等待 IRP 完成,
    //    但 FAST_MUTEX 是 APC_LEVEL,允许阻塞
    ExAcquireFastMutex(&g_AttachMutex);
    status = DetachDeviceInternal(
        pReq->AttachId,
        (pReq->AttachId == 0) ? pReq->DevicePath : NULL,
        pResp);
    ExReleaseFastMutex(&g_AttachMutex);

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

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}
