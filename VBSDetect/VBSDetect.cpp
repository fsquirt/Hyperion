#include <windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <locale.h> 

#pragma comment(lib, "ncrypt.lib")

// 若旧版 Windows SDK 未定义此标志，手动补充定义
#ifndef NCRYPT_REQUIRE_VBS_FLAG
#define NCRYPT_REQUIRE_VBS_FLAG 0x00020000
#endif

BOOL IsSecureKernelRunningViaCNG() {
    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS status = ERROR_SUCCESS;
    BOOL isRunning = FALSE;

    // 1. 打开默认的 Microsoft Software Key Storage Provider
    status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[-] 打开 KSP 失败: 0x%08X\n", status);
        return FALSE;
    }

    // 2. 尝试创建一个强制要求 VBS 隔离保护的临时密钥
    LPCWSTR testKeyName = L"Probe_VBS_SecureKernel_Detection_Key";

    status = NCryptCreatePersistedKey(
        hProvider,
        &hKey,
        BCRYPT_RSA_ALGORITHM,
        testKeyName,
        0,
        NCRYPT_REQUIRE_VBS_FLAG // 核心参数：要求 Secure Kernel / VSM 隔离
    );

    if (status == ERROR_SUCCESS) {
        // 3. 完成密钥终结配置
        status = NCryptFinalizeKey(hKey, 0);
        if (status == ERROR_SUCCESS) {
            // 成功在 VTL 1 隔离环境中生成密钥，证明 Secure Kernel 正在运行
            isRunning = TRUE;
        }
        else {
            wprintf(L"[-] NCryptFinalizeKey 失败: 0x%08X\n", status);
        }

        // 4. 清理探测生成的临时密钥
        NCryptDeleteKey(hKey, 0);
        hKey = 0;
    }
    else {
        if (status == NTE_NOT_SUPPORTED) {
            wprintf(L"[*] Secure Kernel / VBS 未运行 (NTE_NOT_SUPPORTED: 0x80090029)\n");
        }
        else {
            wprintf(L"[-] 创建密钥失败: 0x%08X\n", status);
        }
    }

    // 释放资源句柄
    if (hKey != 0) {
        NCryptFreeObject(hKey);
    }
    if (hProvider != 0) {
        NCryptFreeObject(hProvider);
    }

    return isRunning;
}

int main() {
    setlocale(LC_ALL, "chs");
    if (IsSecureKernelRunningViaCNG()) {
        wprintf(L"[+] Secure Kernel (VBS) 正在正常运行。\n");
    }
    else {
        wprintf(L"[-] Secure Kernel (VBS) 未运行或不支持。\n");
    }
    return 0;
}