#pragma once

#include <ntddk.h>
#include <wdf.h>

// ============================================================
// 调用方映像 SHA256 校验 (Caller Image SHA256 Verification)
//
// 安全模型:
//   任何与驱动交互(发 IOCTL)的进程,其映像文件(磁盘可执行文件)
//   的 SHA256 必须等于 g_AllowedImageSha256。不匹配一律拒绝
//   (STATUS_ACCESS_DENIED)。
//
//   这样即使 SDDL 允许 SYSTEM/Admins 打开设备,也能进一步限制
//   只有指定的受信任二进制(磁盘文件)才能实际驱动交互,避免任何
//   具有 SYSTEM/Admin 权限的进程随意调用驱动的敏感功能。
//
// 实现 (见 DriverVerify.c):
//   1. IoGetRequestorProcess 拿发起请求的进程 (PEPROCESS)
//   2. PsReferenceProcessFilePointer + IoQueryFileDosDeviceName
//      取该进程映像文件的完整磁盘路径
//   3. 重新打开文件,用 CNG (BCrypt) 流式计算 SHA256
//   4. 与 g_AllowedImageSha256 比对
// ============================================================

// 允许的调用方程序映像的 SHA256 (32 字节)
// 默认值:
//   4E8629C7CE9F9CC32D81FB91F8D5DE21CE6040FDF2E5469ED50A3EE0A4D4F1E5
extern const UCHAR g_AllowedImageSha256[32];

// 校验发起请求的进程映像文件 SHA256 是否匹配。
//   STATUS_SUCCESS            = 允许交互
//   STATUS_ACCESS_DENIED      = 映像不匹配/取映像失败,应拒绝请求
NTSTATUS VerifyRequestorImageHash(_In_ WDFREQUEST Request);
