#pragma once

#include <ntddk.h>
#include <wdf.h>

// ============================================================
// 调用方 Authenticode 校验 (基于内核 ci.dll)
//
// 安全模型:
//   发起 IOCTL 的进程,其映像文件必须通过内核 CI 的 Authenticode
//   签名校验,且 signer 证书必须逐字节等于嵌入的 CodeSign.cer
//   (CN=VirtualEdgeCodeSign <- CN=VirtualEdgeTestSignCA)。
//   任一条件不满足一律拒绝 (STATUS_ACCESS_DENIED)。
//
//   ci.dll 是 ntoskrnl 的导入模块,开机即加载,无需初始化;
//   链接通过 ImportLibs/x64/ci.lib (由 ci.def 生成,见
//   ImportLibs/ci.def 注释)。
//
// 实现 (见 CiVerify.c):
//   1. IoGetRequestorProcess 拿发起请求的进程 (PEPROCESS)
//   2. 进程级缓存:已验证过的进程直接放行 (避免每次 IOCTL 全量验签)
//   3. PsReferenceProcessFilePointer 拿进程映像 FILE_OBJECT
//   4. CiValidateFileObject 完整验签 (签名结构 + 证书链到受信根)
//   5. signer 证书 DER 与 g_SignerCertDer 逐字节比对
// ============================================================

// 校验发起请求的进程。TRUE = 放行, FALSE = 拒绝。
BOOLEAN CiVerifyRequestor(_In_ WDFREQUEST Request);

// 清空进程验证缓存 (Unload 时调用)
VOID CiVerifyResetCache(VOID);
