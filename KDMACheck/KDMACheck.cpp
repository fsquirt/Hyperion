#define INITGUID
#include <windows.h>
#include <setupapi.h>
#include <devpkey.h>
#include <stdio.h>
#include <clocale>

#pragma comment(lib, "setupapi.lib")

DEFINE_DEVPROPKEY(DEVPKEY_Device_DmaRemappingPolicy,
    0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 32);

typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

void CheckNativeDmaGuard() {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) {
        printf("[Native API] GetModuleHandleW(ntdll.dll) failed!\n\n");
        return;
    }

    using pfnNtQuerySystemInformation = NTSTATUS(NTAPI*)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    auto NtQuerySystemInformation =
        reinterpret_cast<pfnNtQuerySystemInformation>(
            GetProcAddress(hNtDll, "NtQuerySystemInformation"));

    if (!NtQuerySystemInformation) {
        printf("[Native API] GetProcAddress(NtQuerySystemInformation) failed!\n\n");
        return;
    }

    // SystemDmaGuardPolicyInformation = 202 = 0xCA
    UCHAR dmaGuardEnabled = 0;
    ULONG returnLength = 0;

    NTSTATUS status = NtQuerySystemInformation(
        0xCA,
        &dmaGuardEnabled,
        sizeof(dmaGuardEnabled),
        &returnLength
    );

    if (status == 0) {
        printf(
            "[Native API] Kernel DMA Protection Status: %s "
            "(ReturnLength: %lu byte)\n\n",
            dmaGuardEnabled ? "ENABLED" : "DISABLED",
            returnLength
        );
    }
    else {
        printf(
            "[Native API] NtQuerySystemInformation Failed! "
            "NTSTATUS: 0x%08X, ReturnLength: %lu\n\n",
            static_cast<unsigned>(status),
            returnLength
        );
    }
}

void ParseDmaPolicyFlags(ULONG policy) {
    printf("0x%02X [", policy);
    if (policy == 0) {
        printf("Disabled/PassThrough");
    }
    else {
        if (policy & 0x01) printf("OptIn ");
        if (policy & 0x02) printf("Force ");
        if (policy & 0x08) printf("Supported ");
        if (policy & 0x10) printf("Required ");
        if (policy & 0x20) printf("IsolationActive ");
    }
    printf("]\n");
}

void CheckPnpDeviceDmaPolicies() {
    HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, L"PCI", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };

    for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
        DEVPROPTYPE ulPropertyType;
        DWORD requiredSize = 0;
        WCHAR devName[256] = { 0 };

        SetupDiGetDevicePropertyW(hDevInfo, &devInfoData, &DEVPKEY_Device_DeviceDesc,
            &ulPropertyType, (PBYTE)devName, sizeof(devName), NULL, 0);

        // 两段式查询获取策略位掩码
        SetupDiGetDevicePropertyW(hDevInfo, &devInfoData, &DEVPKEY_Device_DmaRemappingPolicy,
            &ulPropertyType, NULL, 0, &requiredSize, 0);

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && requiredSize > 0) {
            PBYTE pBuffer = (PBYTE)malloc(requiredSize);
            if (pBuffer) {
                if (SetupDiGetDevicePropertyW(hDevInfo, &devInfoData, &DEVPKEY_Device_DmaRemappingPolicy,
                    &ulPropertyType, pBuffer, requiredSize, NULL, 0)) {

                    ULONG policy = 0;
                    if (requiredSize == 1) policy = *pBuffer;
                    else if (requiredSize >= 4) policy = *(PULONG)pBuffer;

                    printf("[%2d] %-45ws -> Policy: ", i, devName);
                    ParseDmaPolicyFlags(policy);
                }
                free(pBuffer);
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
}

int main() {
    setlocale(LC_ALL, "chs");

    printf("Native API 系统全局检测 \n");
    CheckNativeDmaGuard();

    printf("SetupAPI 设备树重定向策略解析 \n");
    CheckPnpDeviceDmaPolicies();

    return 0;
}