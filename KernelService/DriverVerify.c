#include <ntifs.h>      // PsReferenceProcessFilePointer / IoQueryFileDosDeviceName
                         // (必须在 ntddk.h/wdf.h 之前,见 Driver.c 顶部注释)
#include "DriverVerify.h"
#include <bcrypt.h>      // CNG SHA256 (BCryptOpenAlgorithmProvider ...)
#include <ntstrsafe.h>

// 池标签: 'DKVR' 倒过来
#define VERIFY_POOL_TAG 'RVKD'

// ntifs.h 未声明此内核 API (PsReferenceProcessFilePointer 在部分 WDK 中缺失声明),
// 手动 extern。它从 ntoskrnl 导出, 取进程映像对应的 FILE_OBJECT。
NTKERNELAPI NTSTATUS NTAPI PsReferenceProcessFilePointer(
    _In_ PEPROCESS Process,
    _Out_ PFILE_OBJECT* FileObject);

// ============================================================
// 允许与驱动交互的进程映像 SHA256 (32 字节)
//
//   4E8629C7CE9F9CC32D81FB91F8D5DE21CE6040FDF2E5469ED50A3EE0A4D4F1E5
//
// 若要放行新的受信任二进制,把它的 SHA256 填到这里即可。
// ============================================================
const UCHAR g_AllowedImageSha256[32] = {
    0x4E, 0x86, 0x29, 0xC7, 0xCE, 0x9F, 0x9C, 0xC3,
    0x2D, 0x81, 0xFB, 0x91, 0xF8, 0xD5, 0xDE, 0x21,
    0xCE, 0x60, 0x40, 0xFD, 0xF2, 0xE5, 0x46, 0x9E,
    0xD5, 0x0A, 0x3E, 0xE0, 0xA4, 0xD4, 0xF1, 0xE5
};

// ------------------------------------------------------------
// 内部: 对文件句柄做 SHA256 流式哈希
// 成功把 32 字节结果写入 Hash
// ------------------------------------------------------------
static NTSTATUS ComputeFileSha256(
    _In_ HANDLE FileHandle,
    _Out_writes_bytes_all_(32) UCHAR Hash[32])
{
    BCRYPT_ALG_HANDLE  hAlg    = NULL;
    BCRYPT_HASH_HANDLE hHash   = NULL;
    PUCHAR             pHashObj = NULL;
    NTSTATUS           status;

    // 预先清零,确保成功路径下 *Hash 始终被初始化 (消除 C6101)
    RtlZeroMemory(Hash, 32);

    // BCRYPT_PROV_DISPATCH: 内核态调用方必须指定,确保走 dispatch 表
    status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] Verify: BCryptOpenAlgorithmProvider failed 0x%08X\n", status);
        goto cleanup;
    }

    // 取算法对象大小,分配 hash 对象缓冲
    ULONG cbHashObj = 0, cbResult = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&cbHashObj, sizeof(cbHashObj), &cbResult, 0);
    if (!NT_SUCCESS(status) || cbHashObj == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] Verify: BCryptGetProperty(OBJECT_LENGTH) failed 0x%08X\n", status);
        goto cleanup;
    }

    pHashObj = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, cbHashObj, VERIFY_POOL_TAG);
    if (pHashObj == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = BCryptCreateHash(hAlg, &hHash, pHashObj, cbHashObj, NULL, 0, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "[KernelService] Verify: BCryptCreateHash failed 0x%08X\n", status);
        goto cleanup;
    }

    // 分块读文件并喂给 hash
    BYTE buf[4096];
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    offset.QuadPart = 0;

    for (;;) {
        status = ZwReadFile(FileHandle, NULL, NULL, NULL, &iosb,
            buf, sizeof(buf), &offset, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[KernelService] Verify: ZwReadFile failed 0x%08X\n", status);
            break;
        }

        ULONG cbRead = (ULONG)iosb.Information;
        if (cbRead == 0) {
            break; // 到达 EOF
        }

        status = BCryptHashData(hHash, buf, cbRead, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[KernelService] Verify: BCryptHashData failed 0x%08X\n", status);
            break;
        }

        offset.QuadPart += cbRead;
        if (status == STATUS_END_OF_FILE) {
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hHash, Hash, 32, 0);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                "[KernelService] Verify: BCryptFinishHash failed 0x%08X\n", status);
        }
    }

cleanup:
    if (hHash)    BCryptDestroyHash(hHash);
    if (pHashObj) ExFreePoolWithTag(pHashObj, VERIFY_POOL_TAG);
    if (hAlg)     BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

// ------------------------------------------------------------
// 校验发起 IOCTL 的进程映像文件 SHA256 是否匹配
// ------------------------------------------------------------
NTSTATUS VerifyRequestorImageHash(_In_ WDFREQUEST Request)
{
    PIRP      irp     = WdfRequestWdmGetIrp(Request);
    PEPROCESS process = (irp != NULL) ? IoGetRequestorProcess(irp) : NULL;

    if (process == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: cannot resolve requestor process -> DENIED\n");
        return STATUS_ACCESS_DENIED;
    }

    // 1. 取进程映像文件对象
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status = PsReferenceProcessFilePointer(process, &fileObject);
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: PsReferenceProcessFilePointer failed 0x%08X -> DENIED\n", status);
        return STATUS_ACCESS_DENIED;
    }

    // 2. 取映像完整磁盘路径
    // 注意: 本 WDK 的 IoQueryFileDosDeviceName 第二参为 POBJECT_NAME_INFORMATION*,
    //       返回的 OBJECT_NAME_INFORMATION.Name 即映像完整路径 (UNICODE_STRING)。
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    status = IoQueryFileDosDeviceName(fileObject, &nameInfo);
    ObDereferenceObject(fileObject); // fileObject 引用在拿到路径后即可释放
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: IoQueryFileDosDeviceName failed 0x%08X -> DENIED\n", status);
        return STATUS_ACCESS_DENIED;
    }

    // 3. 以内核句柄重新打开该磁盘文件
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    InitializeObjectAttributes(&oa, &nameInfo->Name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&fileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: open '%wZ' failed 0x%08X -> DENIED\n", &nameInfo->Name, status);
        ExFreePool(nameInfo);
        return STATUS_ACCESS_DENIED;
    }

    // 4. 计算 SHA256 并比对
    UCHAR actual[32];
    RtlZeroMemory(actual, sizeof(actual));

    status = ComputeFileSha256(fileHandle, actual);
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: ComputeFileSha256('%wZ') failed 0x%08X -> DENIED\n",
            &nameInfo->Name, status);
        ExFreePool(nameInfo);
        return STATUS_ACCESS_DENIED;
    }

    if (RtlCompareMemory(actual, g_AllowedImageSha256, 32) != 32) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[KernelService] Verify: SHA256 mismatch for '%wZ' -> DENIED\n", &nameInfo->Name);
        ExFreePool(nameInfo);
        return STATUS_ACCESS_DENIED;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[KernelService] Verify: SHA256 OK for '%wZ' -> ALLOWED\n", &nameInfo->Name);
    ExFreePool(nameInfo);
    return STATUS_SUCCESS;
}
