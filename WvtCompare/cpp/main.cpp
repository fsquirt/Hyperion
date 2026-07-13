// WvtCompare C++ — 对 KslD.sys 调用 WinVerifyTrust，dump WINTRUST_DATA 二进制对比
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "wintrust.lib")

static void HexDump(const char* tag, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    printf("=== %s (%zu bytes) ===\n", tag, len);
    for (size_t i = 0; i < len; i += 16) {
        printf("%04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", p[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                unsigned char c = p[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
        }
        printf("\n");
    }
}

static void DumpBin(const char* path, const void* data, size_t len) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") == 0 && f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("[dump] wrote %zu bytes to %s\n", len, path);
    }
}

int wmain(int argc, wchar_t** argv) {
    const wchar_t* file = L"C:\\Windows\\system32\\drivers\\wd\\KslD.sys";
    if (argc >= 2) file = argv[1];

    printf("[cpp] file=%ws\n", file);
    printf("[cpp] sizeof(WINTRUST_FILE_INFO)=%zu (expect 32)\n", sizeof(WINTRUST_FILE_INFO));
    printf("[cpp] sizeof(WINTRUST_DATA)=%zu (expect 88)\n", sizeof(WINTRUST_DATA));

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = file;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;          // 2
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE; // 0
    trustData.dwUnionChoice = WTD_CHOICE_FILE;   // 1
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_IGNORE; // 0
    trustData.dwProvFlags = WTD_SAFER_FLAG;      // 0x100

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    HexDump("WINTRUST_FILE_INFO (cpp)", &fileInfo, sizeof(fileInfo));
    HexDump("WINTRUST_DATA (cpp)", &trustData, sizeof(trustData));
    DumpBin("cpp_fileinfo.bin", &fileInfo, sizeof(fileInfo));
    DumpBin("cpp_trustdata.bin", &trustData, sizeof(trustData));

    printf("[cpp] pFile ptr value = 0x%p\n", (void*)trustData.pFile);
    printf("[cpp] &fileInfo       = 0x%p\n", (void*)&fileInfo);
    printf("[cpp] calling WinVerifyTrust(VERIFY)...\n");
    LONG hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &actionGuid, &trustData);
    DWORD le1 = GetLastError();
    printf("[cpp] VERIFY hr=0x%08X lastErr=0x%08X\n", (unsigned)hr, (unsigned)le1);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &actionGuid, &trustData);
    DWORD le2 = GetLastError();
    printf("[cpp] CLOSE lastErr=0x%08X\n", (unsigned)le2);

    printf("[cpp] DONE hr=0x%08X\n", (unsigned)hr);
    return 0;
}
