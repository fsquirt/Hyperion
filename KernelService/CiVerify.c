// ntifs.h 必须在 ntddk/wdm 之前 (PsReferenceProcessFilePointer)
#include <ntifs.h>
#include "CiVerify.h"
#include "SignerCert.h"
#include <ntstrsafe.h>

// ============================================================
// 调用方 Authenticode 校验实现 (内核 ci.dll)
//
// 核心调用: CiValidateFileObject (Win10+, ci.dll 导出,未文档化)
//   - 完整校验 PE 的 Authenticode 签名:摘要匹配 + 证书链终止于
//     内核 CI 信任的根 (含注册表 Root 存储导入的自签根,
//     testsigning 模式下有效)
//   - 输出 PolicyInfo,内含完整证书链 (signer 链 + TSA 链)
//   - 分页池分配,必须 IRQL < DISPATCH_LEVEL (IOCTL 派发满足)
//   - 输出的 PolicyInfo 用完必须 CiFreePolicyInfo 释放
//
// 结构体定义来自 CiDllDemo 项目 (逆向结果, MIT License):
//   https://github.com/Cybereason/CiDllDemo
// ============================================================

// ---------- ci.dll 返回的证书链结构 (来自 CiDllDemo 逆向) ----------

// ASN.1 blob 的位置和大小 (数据本体在 struct 之外)
typedef struct _CI_ASN1_BLOB_PTR {
    int   size;
    PVOID ptrToData;
} CI_ASN1_BLOB_PTR, *PCI_ASN1_BLOB_PTR;

// 证书 subject/issuer 名 (x64 下短字段后有 4 字节 padding,
// 必须保持 struct 布局与逆向结果一致)
typedef struct _CI_CERT_PARTY_NAME {
    PVOID pointerToName;
    short nameLen;
    short unknown;
} CI_CERT_PARTY_NAME, *PCI_CERT_PARTY_NAME;

// 链上单张证书的信息
// 注意 digestBuffer 里的 digest 是"这张证书本身的 digest",
// 不是签名文件用的 digest
typedef struct _CI_CERT_CHAIN_MEMBER {
    int                 digestIdentifier;   // 0x800C = SHA256, 0x8004 = SHA1
    int                 digestSize;
    BYTE                digestBuffer[64];
    CI_CERT_PARTY_NAME  subjectName;
    CI_CERT_PARTY_NAME  issuerName;
    CI_ASN1_BLOB_PTR    certificate;        // 指向完整 DER 证书
} CI_CERT_CHAIN_MEMBER, *PCI_CERT_CHAIN_MEMBER;

// PolicyInfo.certChainInfo 指向的缓冲区头
typedef struct _CI_CERT_CHAIN_INFO_HEADER {
    int                     bufferSize;
    PCI_ASN1_BLOB_PTR       ptrToPublicKeys;
    int                     numberOfPublicKeys;
    PCI_ASN1_BLOB_PTR       ptrToEkus;
    int                     numberOfEkus;
    PCI_CERT_CHAIN_MEMBER   ptrToCertChainMembers;
    int                     numberOfCertChainMembers;
    int                     unknown;
    CI_ASN1_BLOB_PTR        variousAuthenticodeAttributes;
} CI_CERT_CHAIN_INFO_HEADER, *PCI_CERT_CHAIN_INFO_HEADER;

// 内核头文件没有 FILETIME (demo 用 minwindef.h,内核态不可用),
// 自定义 8 字节布局与 win32 FILETIME 一致
typedef struct _CI_FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} CI_FILETIME;

// 签名/TSA 证书链信息 (访问前必须检查 structSize)
typedef struct _CI_POLICY_INFO {
    int                         structSize;
    NTSTATUS                    verificationStatus;
    int                         flags;
    PCI_CERT_CHAIN_INFO_HEADER  certChainInfo;
    CI_FILETIME                 revocationTime;
    CI_FILETIME                 notBeforeTime;
    CI_FILETIME                 notAfterTime;
} CI_POLICY_INFO, *PCI_POLICY_INFO;

// ---------- ci.dll 导入 (链接 ImportLibs/x64/ci.lib) ----------

// Win10 早期版本此 API 签名可能不同,仅支持 Win10+ x64
__declspec(dllimport) NTSTATUS CiValidateFileObject(
    _In_ struct _FILE_OBJECT* fileObject,
    _In_ int a2,                    // 未知 flag, 0 有效
    _In_ int a3,                    // 未知 flag, 0 有效
    _Out_ CI_POLICY_INFO* policyInfoForSigner,
    _Out_ CI_POLICY_INFO* policyInfoForTimestampingAuthority,
    _Out_ LARGE_INTEGER* signingTime,
    _Out_writes_bytes_(64) BYTE* digestBuffer,
    _Inout_ int* digestSize,        // 进:>=64, 出:实际 digest 长度
    _Out_ int* digestIdentifier);

// 释放 CiValidateFileObject 分配的 PolicyInfo 缓冲区
__declspec(dllimport) PVOID CiFreePolicyInfo(_In_ CI_POLICY_INFO* policyInfo);

// PsReferenceProcessFilePointer 部分版本 ntifs.h 未声明,手动 extern
NTKERNELAPI NTSTATUS NTAPI PsReferenceProcessFilePointer(
    _In_ PEPROCESS Process,
    _Out_ PFILE_OBJECT* FileObject);

// IoFileObjectType 是 ntoskrnl 导出的全局 (POBJECT_TYPE* 存储槽)。
// 重新打开文件后,用 ObReferenceObjectByHandle 拿 FILE_OBJECT 时需要
// 解引用 (*IoFileObjectType) 作为对象类型校验。
extern POBJECT_TYPE* IoFileObjectType;

// ObQueryNameString 部分 WDK 版本 ntddk.h 未声明,手动 extern。
// 用它拿 FILE_OBJECT 的内核对象路径 (\Device\HarddiskVolumeX\...),
// 这个路径 ZwCreateFile 能直接认; IoQueryFileDosDeviceName 拿的是
// C:\ 这种 Win32 DOS 路径, ZwCreateFile 会返回 STATUS_OBJECT_PATH_SYNTAX_BAD。
NTKERNELAPI NTSTATUS NTAPI ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION NameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength);

// 嵌入的证书必须与 CodeSign.cer 字节数一致
C_ASSERT(sizeof(g_SignerCertDer) == 1087);

// ============================================================
// 进程级验证缓存
//
// 每次 IOCTL 全量验签要读文件 + 建链,开销大。UserService 是长驻
// 进程,按 EPROCESS 指针缓存验证结果,同一进程对象只验一次。
//
// 并发: 缓存槽是单个对齐指针+标志,最坏竞态是两个线程同时未命中
// 各自做一次全量验证,结果幂等,不需要锁。
// 失效: EPROCESS 退出后对象指针可能被池复用造成误放行,所以缓存
// 键同时记录 PID,比较 (Process, Pid) 二元组。Unload 时清空。
// ============================================================

typedef struct _CI_VERIFY_CACHE {
    PEPROCESS Process;     // 验证通过时的进程对象
    HANDLE    Pid;         // 与 Process 一起比对,缓解对象指针复用
    BOOLEAN   Granted;
} CI_VERIFY_CACHE;

static volatile CI_VERIFY_CACHE g_Cache = { 0 };

VOID CiVerifyResetCache(VOID)
{
    g_Cache.Process = NULL;
    g_Cache.Pid = NULL;
    g_Cache.Granted = FALSE;
}

// 查缓存:当前进程是否已验证通过
static BOOLEAN CacheLookup(_In_ PEPROCESS Process, _In_ HANDLE Pid)
{
    CI_VERIFY_CACHE snapshot = g_Cache;
    return snapshot.Granted && snapshot.Process == Process && snapshot.Pid == Pid;
}

static VOID CacheStore(_In_ PEPROCESS Process, _In_ HANDLE Pid)
{
    g_Cache.Process = Process;
    g_Cache.Pid = Pid;
    g_Cache.Granted = TRUE;
}

// ============================================================
// 比对 signer 证书与嵌入的 CodeSign.cer
// ============================================================

static BOOLEAN MatchSignerCert(_In_ PCI_POLICY_INFO signerPolicy)
{
    if (signerPolicy == NULL || signerPolicy->structSize == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: signerPolicy NULL or empty (structSize=%d)\n",
            signerPolicy ? signerPolicy->structSize : -1);
        return FALSE;
    }

    PCI_CERT_CHAIN_INFO_HEADER chain = signerPolicy->certChainInfo;
    if (chain == NULL || chain->bufferSize <= 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: certChainInfo=%p bufferSize=%d\n",
            chain, chain ? chain->bufferSize : -1);
        return FALSE;
    }

    // 第一个链成员就是 signer 自己
    PCI_CERT_CHAIN_MEMBER signer = chain->ptrToCertChainMembers;
    if (signer == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: ptrToCertChainMembers=NULL (members=%d)\n",
            chain->numberOfCertChainMembers);
        return FALSE;
    }

    // 指针与大小防御:signer 结构和证书 blob 都必须落在 certChainInfo
    // 缓冲区内 (CI 分配的缓冲区, [chain, chain+bufferSize) )
    const BYTE* bufStart = (const BYTE*)chain;
    const BYTE* bufEnd = bufStart + chain->bufferSize;

    if ((const BYTE*)signer < bufStart ||
        (const BYTE*)signer + sizeof(CI_CERT_CHAIN_MEMBER) > bufEnd) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: signer %p out of buffer [%p,%p)\n",
            signer, bufStart, bufEnd);
        return FALSE;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] MatchSigner: chain members=%d, signer certDigestId=0x%X digestSize=%d certSize=%d (expected %zu)\n",
        chain->numberOfCertChainMembers,
        signer->digestIdentifier, signer->digestSize,
        signer->certificate.size, sizeof(g_SignerCertDer));

    // subject/issuer 名字 (CI_CERT_PARTY_NAME.pointerToName,
    // 指向 certChainInfo 缓冲区内的 ASN.1 字符串)
    if (signer->subjectName.pointerToName && signer->subjectName.nameLen > 0 &&
        (const BYTE*)signer->subjectName.pointerToName >= bufStart &&
        (const BYTE*)signer->subjectName.pointerToName + signer->subjectName.nameLen <= bufEnd) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[CiVerify] MatchSigner: subject='%.*hs' issuer='%.*hs'\n",
            signer->subjectName.nameLen, (char*)signer->subjectName.pointerToName,
            signer->issuerName.nameLen, (char*)signer->issuerName.pointerToName);
    }

    const BYTE* certStart = (const BYTE*)signer->certificate.ptrToData;
    int certSize = signer->certificate.size;
    if (certStart == NULL || certSize != (int)sizeof(g_SignerCertDer)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: certSize mismatch (got %d, want %zu) -> DENIED\n",
            certSize, sizeof(g_SignerCertDer));
        return FALSE;
    }
    if (certStart < bufStart || certStart + certSize > bufEnd) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: cert blob %p (+%d) out of buffer [%p,%p)\n",
            certStart, certSize, bufStart, bufEnd);
        return FALSE;
    }

    // 逐字节比对:signer 证书 DER == CodeSign.cer DER
    // 大小已相等,比较结果 1087 即完全匹配
    SIZE_T matched = RtlCompareMemory(certStart, g_SignerCertDer, certSize);
    if (matched != (SIZE_T)certSize) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] MatchSigner: DER mismatch at offset %zu -> DENIED\n", matched);
        return FALSE;
    }
    return TRUE;
}

// ============================================================
// 对进程映像做完整验签 + signer 比对
// PASSIVE_LEVEL 调用
// ============================================================

static BOOLEAN VerifyProcessImage(_In_ PEPROCESS Process)
{
    BOOLEAN result = FALSE;
    PFILE_OBJECT fileObject = NULL;        // PsReferenceProcessFilePointer 拿到的映像 FO (可能已 cleanup)
    PFILE_OBJECT verifyFileObject = NULL;  // 重新打开的"活跃"FO, 用于验签
    POBJECT_NAME_INFORMATION imageName = NULL;
    HANDLE hFile = NULL;

    CI_POLICY_INFO signerPolicy = { 0 };
    CI_POLICY_INFO tsaPolicy = { 0 };

    // 1. 取进程映像文件对象 (只用于拿路径)
    NTSTATUS status = PsReferenceProcessFilePointer(Process, &fileObject);
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] PsReferenceProcessFilePointer(PID %p) failed 0x%08X -> DENIED\n",
            PsGetProcessId(Process), status);
        return FALSE;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] PsReferenceProcessFilePointer OK: FileObject=%p (PID %p)\n",
        fileObject, PsGetProcessId(Process));

    // 2. 取映像内核路径 (重新打开文件要用)
    //    必须用 ObQueryNameString, 拿到 \Device\HarddiskVolumeX\... 这种内核对象路径。
    //    IoQueryFileDosDeviceName 拿的是 C:\ 这种 Win32 DOS 路径, ZwCreateFile 不认。
    ULONG nameLen = 0;
    status = ObQueryNameString(fileObject, NULL, 0, &nameLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH || nameLen == 0) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] ObQueryNameString(probe) failed 0x%08X (PID %p) -> DENIED\n",
            status, PsGetProcessId(Process));
        goto cleanup;
    }
    imageName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED, nameLen, 'CVIN');
    if (imageName == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] ExAllocatePool2(name) failed (PID %p) -> DENIED\n",
            PsGetProcessId(Process));
        goto cleanup;
    }
    status = ObQueryNameString(fileObject, imageName, nameLen, &nameLen);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] ObQueryNameString failed 0x%08X (PID %p) -> DENIED\n",
            status, PsGetProcessId(Process));
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] verifying image '%wZ' (PID %p)\n",
        &imageName->Name, PsGetProcessId(Process));

    // 3. 重新打开进程映像文件, 拿到"活跃"FILE_OBJECT
    //    原因: PsReferenceProcessFilePointer 返回的映像 FO 在映像加载完成后
    //    已被映像加载器 close 文件句柄 (FO 进入 cleanup 状态, 仅靠 image
    //    section 持有引用)。CiValidateFileObject 内部 (FsRtlGetFileSize /
    //    ZwCreateSection) 无法用这种 FO 重新读文件内容, 会返回
    //    STATUS_UNSUCCESSFUL (0xC0000001)。所以这里用 ZwCreateFile 按路径
    //    重新打开, 得到一个文件真正处于打开状态的 FO。
    IO_STATUS_BLOCK iosb;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &imageName->Name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&hFile,
        FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] ZwCreateFile reopen '%wZ' failed 0x%08X -> DENIED\n",
            &imageName->Name, status);
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] ZwCreateFile reopen OK: handle=%p\n", hFile);

    // 4. 用句柄拿 FILE_OBJECT (活跃的, 文件真正打开着)
    status = ObReferenceObjectByHandle(hFile, FILE_READ_DATA,
        *IoFileObjectType, KernelMode, (PVOID*)&verifyFileObject, NULL);
    if (!NT_SUCCESS(status) || verifyFileObject == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] ObReferenceObjectByHandle failed 0x%08X -> DENIED\n", status);
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] ObReferenceObjectByHandle OK: verifyFileObject=%p\n", verifyFileObject);

    // 5. 内核 CI 完整验签 (结构有效 + 链到受信根)
    BYTE digestBuffer[64] = { 0 };
    int digestSize = sizeof(digestBuffer);
    int digestIdentifier = 0;
    LARGE_INTEGER signingTime = { 0 };

    status = CiValidateFileObject(
        verifyFileObject, 0, 0,
        &signerPolicy, &tsaPolicy,
        &signingTime, digestBuffer, &digestSize, &digestIdentifier);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "[CiVerify] CiValidateFileObject -> 0x%08X\n"
        "[CiVerify]   signerPolicy: structSize=%d verificationStatus=0x%08X flags=0x%X certChainInfo=%p\n"
        "[CiVerify]   tsaPolicy:    structSize=%d certChainInfo=%p\n"
        "[CiVerify]   digestId=0x%X digestSize=%d signingTime=0x%08X%08X\n",
        status,
        signerPolicy.structSize, signerPolicy.verificationStatus,
        signerPolicy.flags, signerPolicy.certChainInfo,
        tsaPolicy.structSize, tsaPolicy.certChainInfo,
        digestIdentifier, digestSize,
        signingTime.HighPart, signingTime.LowPart);

    if (!NT_SUCCESS(status)) {
        // 常见: STATUS_INVALID_IMAGE_HASH (未签名/摘要不符),
        //        TRUST_E 相关 (链不到受信根),
        //        STATUS_UNSUCCESSFUL (读文件失败, 多为 FO 已 cleanup)
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
           "[CiVerify] CiValidateFileObject failed 0x%08X -> DENIED\n", status);
        goto cleanup;
    }

    // 6. 链有效还不够 (微软/商业 CA 签的程序都过),
    //    signer 必须是嵌入的 CodeSign 证书
    result = MatchSignerCert(&signerPolicy);
    if (!result) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] signature valid but signer is not CodeSign.cer -> DENIED\n");
    }
    else {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "[CiVerify] signer matched CodeSign.cer -> ALLOWED\n");
    }

cleanup:
    // 取到 PolicyInfo 就要负责释放 (structSize != 0 表示 CI 填充过)
    if (signerPolicy.structSize != 0) CiFreePolicyInfo(&signerPolicy);
    if (tsaPolicy.structSize != 0)    CiFreePolicyInfo(&tsaPolicy);
    if (verifyFileObject != NULL)     ObDereferenceObject(verifyFileObject);
    if (hFile != NULL)                ZwClose(hFile);
    if (imageName != NULL)            ExFreePoolWithTag(imageName, 'CVIN');
    if (fileObject != NULL)           ObDereferenceObject(fileObject);
    return result;
}

// ============================================================
// IOCTL 入口校验
// ============================================================

BOOLEAN CiVerifyRequestor(_In_ WDFREQUEST Request)
{
    PIRP irp = WdfRequestWdmGetIrp(Request);
    PEPROCESS process = (irp != NULL) ? IoGetRequestorProcess(irp) : NULL;

    if (process == NULL) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "[CiVerify] cannot resolve requestor process -> DENIED\n");
        return FALSE;
    }

    HANDLE pid = PsGetProcessId(process);
    if (CacheLookup(process, pid)) {
        return TRUE;
    }

    if (VerifyProcessImage(process)) {
        CacheStore(process, pid);
        return TRUE;
    }

    return FALSE;
}
