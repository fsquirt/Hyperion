#pragma once

#include <ntddk.h>
#include <wdf.h>

// 校验发起请求的进程。TRUE = 放行, FALSE = 拒绝。
BOOLEAN CiVerifyRequestor(_In_ WDFREQUEST Request);

// 清空进程验证缓存，Unload 时调用
VOID CiVerifyResetCache(VOID);

BOOLEAN VerifyMicrosoftImageByPath(_In_ PUNICODE_STRING DosPath);
