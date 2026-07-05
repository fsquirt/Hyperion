// IatScanner.cpp — PE 文件导入表 (IAT) 扫描实现
//
// 手动解析 PE 头 + 导入表,不依赖 ImageDirectoryEntryToData / ImageRvaToVa。
// 所有 RVA → 文件偏移的转换都自己做,并做严格的边界检查,
// 防止文件映射模式下越界读 / 死循环。
//
// 注意:
//   - 只支持 PE32+ (64 位),目标是 x64 内核驱动
//   - 文件映射模式 (PAGE_READONLY),只读
//   - 假设 PE 文件没有被 strip / 损坏

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include "IatScanner.h"

#include <windows.h>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>

namespace das {

// 高危内存操作函数列表(用户指定)
static const char* g_dangerousApis[] = {
    "MmCopyMemory",
    "MmMapIoSpace",
    "ZwMapViewOfSection",
    "MmCopyVirtualMemory",
};
static const size_t g_dangerousApiCount = sizeof(g_dangerousApis) / sizeof(g_dangerousApis[0]);

// ------------------------------------------------------------
// RVA → 文件偏移 (手动遍历 section table)
// 返回 false 表示 RVA 不在任何 section 内(可能在 header)
// ------------------------------------------------------------
static bool RvaToFileOffset(PIMAGE_NT_HEADERS64 pNt,
                            PVOID pBase, SIZE_T fileSize,
                            ULONG rva,
                            _Out_ SIZE_T& fileOffset)
{
    // 1. RVA 在 PE 头内(常见于某些早期绑定导入表)
    ULONG headerSize = pNt->OptionalHeader.SizeOfHeaders;
    if (rva < headerSize) {
        fileOffset = rva;
        return true;
    }

    // 2. 遍历 section table
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    USHORT numSections = pNt->FileHeader.NumberOfSections;

    for (USHORT i = 0; i < numSections; i++) {
        ULONG vaStart = pSection[i].VirtualAddress;
        ULONG vaSize  = pSection[i].Misc.VirtualSize;
        if (vaSize == 0) vaSize = pSection[i].SizeOfRawData;

        if (rva >= vaStart && rva < vaStart + vaSize) {
            // RVA 在这个 section 内
            ULONG rawStart = pSection[i].PointerToRawData;
            ULONG rawSize  = pSection[i].SizeOfRawData;
            ULONG delta    = rva - vaStart;

            // 检查 raw data 是否覆盖到这个偏移
            if (delta >= rawSize) {
                // RVA 在 VirtualSize 内但不在 RawData 内 — 文件里没这数据
                return false;
            }
            fileOffset = (SIZE_T)rawStart + delta;
            if (fileOffset >= fileSize) return false;
            return true;
        }
    }
    return false;
}

// ------------------------------------------------------------
// 安全读取:确保 [offset, offset+size) 在映射范围内
// ------------------------------------------------------------
static inline bool IsInBounds(SIZE_T offset, SIZE_T size, SIZE_T fileSize)
{
    return offset < fileSize && size <= fileSize && offset + size <= fileSize;
}

// ------------------------------------------------------------
// 扫描 PE 文件完整 IAT
// ------------------------------------------------------------
bool ScanIat(const std::wstring& filePath,
             std::vector<IatEntry>& outIat,
             std::wstring& errorReason)
{
    outIat.clear();
    errorReason.clear();

    // 1. 打开文件
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        errorReason = L"CreateFile 失败,错误码=" + std::to_wstring(err);
        if (err == ERROR_FILE_NOT_FOUND) errorReason += L" (文件不存在)";
        if (err == ERROR_ACCESS_DENIED) errorReason += L" (无权限)";
        return false;
    }

    LARGE_INTEGER fileSize = {};
    GetFileSizeEx(hFile, &fileSize);
    if (fileSize.QuadPart == 0) {
        errorReason = L"文件大小为 0";
        CloseHandle(hFile);
        return false;
    }

    // 2. 创建文件映射
    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        errorReason = L"CreateFileMapping 失败,错误码=" + std::to_wstring(GetLastError());
        CloseHandle(hFile);
        return false;
    }

    // 3. 映射到内存
    PVOID pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        errorReason = L"MapViewOfFile 失败,错误码=" + std::to_wstring(GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    SIZE_T viewSize = (SIZE_T)fileSize.QuadPart;

    // 用 lambda 简化清理
    auto cleanup = [&]() {
        UnmapViewOfFile(pBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
    };

    // 4. 校验 PE 头(带边界检查)
    if (!IsInBounds(0, sizeof(IMAGE_DOS_HEADER), viewSize)) {
        errorReason = L"文件太小,放不下 DOS 头";
        cleanup();
        return false;
    }

    auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] DOS magic=0x%04X (不是 PE)\n", pDos->e_magic);
        OutputDebugStringA(buf);
        errorReason = L"不是 PE 文件 (DOS magic 不对)";
        cleanup();
        return false;
    }

    // e_lfanew 检查
    if (!IsInBounds(pDos->e_lfanew, sizeof(IMAGE_NT_HEADERS64), viewSize)) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] e_lfanew=0x%X 越界\n", (unsigned)pDos->e_lfanew);
        OutputDebugStringA(buf);
        errorReason = L"e_lfanew 越界,PE 头损坏";
        cleanup();
        return false;
    }

    auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
        reinterpret_cast<ULONG_PTR>(pBase) + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] NT sig=0x%08X\n", pNt->Signature);
        OutputDebugStringA(buf);
        errorReason = L"PE NT 头 Signature 不对";
        cleanup();
        return false;
    }

    // 只支持 PE32+ (64 位)
    if (pNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] Magic=0x%04X (不是 PE32+)\n",
            pNt->OptionalHeader.Magic);
        OutputDebugStringA(buf);
        errorReason = L"不是 PE32+ (64 位) 文件,本扫描器不支持 32 位驱动";
        cleanup();
        return false;
    }

    {
        char buf[256];
        sprintf_s(buf, sizeof(buf),
            "[IatScanner] pBase=%p fileSize=%llu Sections=%u RvaAndSizes=%u\n",
            pBase, (unsigned long long)viewSize,
            pNt->FileHeader.NumberOfSections,
            pNt->OptionalHeader.NumberOfRvaAndSizes);
        OutputDebugStringA(buf);
    }

    // 5. 拿导入表 directory entry(OptionalHeader.DataDirectory[1])
    if (pNt->OptionalHeader.NumberOfRvaAndSizes < 2) {
        errorReason = L"PE 没有 DataDirectory[1] (导入表)";
        cleanup();
        return true;  // 不算错误,只是没导入表
    }

    ULONG impRva  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG impSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    {
        char buf[128];
        sprintf_s(buf, sizeof(buf),
            "[IatScanner] Import dir RVA=0x%X Size=%u\n", impRva, impSize);
        OutputDebugStringA(buf);
    }

    if (impRva == 0 || impSize == 0) {
        errorReason = L"(无导入表)";
        cleanup();
        return true;
    }

    // 6. RVA → 文件偏移
    SIZE_T impOffset = 0;
    if (!RvaToFileOffset(pNt, pBase, viewSize, impRva, impOffset)) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] RvaToFileOffset(impRva=0x%X) 失败\n", impRva);
        OutputDebugStringA(buf);
        errorReason = L"导入表 RVA 转文件偏移失败";
        cleanup();
        return false;
    }

    {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] Import fileOffset=0x%llX\n",
            (unsigned long long)impOffset);
        OutputDebugStringA(buf);
    }

    // 7. 遍历 IMAGE_IMPORT_DESCRIPTOR 数组(每项 20 字节,以全 0 项结尾)
    //    严格限制最多遍历 1024 项,防止损坏的 PE 导致死循环
    auto pImportBase = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<ULONG_PTR>(pBase) + impOffset);

    const DWORD MAX_DESCRIPTORS = 1024;
    for (DWORD descIdx = 0; descIdx < MAX_DESCRIPTORS; descIdx++) {
        SIZE_T off = impOffset + descIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        if (!IsInBounds(off, sizeof(IMAGE_IMPORT_DESCRIPTOR), viewSize)) {
            // 到文件末尾了,应该早就遇到终止符了;这里算异常
            errorReason = L"导入表未遇到终止符就到文件末尾";
            break;
        }

        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = &pImportBase[descIdx];
        if (pImportDesc->Name == 0 && pImportDesc->FirstThunk == 0) {
            // 正常终止符
            break;
        }
        if (pImportDesc->Name == 0) {
            // 异常项,跳过
            continue;
        }

        // 7.1 DLL 名
        SIZE_T nameOffset = 0;
        if (!RvaToFileOffset(pNt, pBase, viewSize, pImportDesc->Name, nameOffset) ||
            !IsInBounds(nameOffset, 1, viewSize)) {
            continue;
        }
        // 安全读取 DLL 名(最多 256 字符)
        const char* pName = reinterpret_cast<const char*>(
            reinterpret_cast<ULONG_PTR>(pBase) + nameOffset);
        char dllNameBuf[256] = {};
        size_t nameLen = 0;
        while (nameLen < 255 && IsInBounds(nameOffset + nameLen, 1, viewSize) &&
               pName[nameLen] != '\0') {
            dllNameBuf[nameLen] = pName[nameLen];
            nameLen++;
        }
        dllNameBuf[nameLen] = '\0';

        IatEntry entry;
        entry.dllName = dllNameBuf;

        // 7.2 拿 ILT (OriginalFirstThunk,没有则 fallback 到 FirstThunk)
        DWORD iltRva = pImportDesc->OriginalFirstThunk;
        if (iltRva == 0) iltRva = pImportDesc->FirstThunk;

        if (iltRva == 0) {
            outIat.push_back(entry);
            continue;
        }

        SIZE_T iltOffset = 0;
        if (!RvaToFileOffset(pNt, pBase, viewSize, iltRva, iltOffset)) {
            outIat.push_back(entry);
            continue;
        }

        // 7.3 遍历 ILT 的 thunk(每项 8 字节,以 0 终止)
        //     严格限制最多 8192 项
        const DWORD MAX_THUNKS = 8192;
        for (DWORD thunkIdx = 0; thunkIdx < MAX_THUNKS; thunkIdx++) {
            SIZE_T thunkOff = iltOffset + thunkIdx * sizeof(IMAGE_THUNK_DATA64);
            if (!IsInBounds(thunkOff, sizeof(IMAGE_THUNK_DATA64), viewSize)) {
                break;  // 越界
            }

            ULONGLONG thunkValue = *reinterpret_cast<ULONGLONG*>(
                reinterpret_cast<ULONG_PTR>(pBase) + thunkOff);

            if (thunkValue == 0) {
                break;  // 正常终止
            }

            if (thunkValue & IMAGE_ORDINAL_FLAG64) {
                // 按 ordinal 导入
                unsigned short ord = (unsigned short)IMAGE_ORDINAL64(thunkValue);
                char buf[40];
                sprintf_s(buf, sizeof(buf), "(ordinal %u)", ord);
                entry.apis.push_back(buf);
            } else {
                // 按名字导入 — 低 31 位是 RVA,指向 IMAGE_IMPORT_BY_NAME
                ULONG nameRva = (ULONG)(thunkValue & 0x7FFFFFFF);
                SIZE_T nameOff2 = 0;
                if (!RvaToFileOffset(pNt, pBase, viewSize, nameRva, nameOff2) ||
                    !IsInBounds(nameOff2, 2, viewSize)) {  // 至少 2 字节(WORD hint + 字符)
                    entry.apis.push_back("(invalid name rva)");
                } else {
                    // IMAGE_IMPORT_BY_NAME: WORD Hint; CHAR Name[];
                    const char* pApiName = reinterpret_cast<const char*>(
                        reinterpret_cast<ULONG_PTR>(pBase) + nameOff2 + 2);
                    // 安全读取(最多 256 字符)
                    char apiBuf[256] = {};
                    size_t apiLen = 0;
                    while (apiLen < 255 &&
                           IsInBounds(nameOff2 + 2 + apiLen, 1, viewSize) &&
                           pApiName[apiLen] != '\0') {
                        apiBuf[apiLen] = pApiName[apiLen];
                        apiLen++;
                    }
                    apiBuf[apiLen] = '\0';
                    entry.apis.push_back(apiBuf);
                }
            }
        }

        outIat.push_back(entry);
    }

    {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "[IatScanner] 扫描完成,DLL 数=%zu\n", outIat.size());
        OutputDebugStringA(buf);
    }

    cleanup();
    return true;
}

// ------------------------------------------------------------
// 检查高危函数
// ------------------------------------------------------------
bool HasDangerousImports(const std::vector<IatEntry>& iat,
                         std::vector<std::string>& foundApis)
{
    foundApis.clear();

    for (const auto& entry : iat) {
        for (const auto& api : entry.apis) {
            // 跳过 ordinal 导入和无效项
            if (api.empty() || api[0] == '(') continue;

            for (size_t i = 0; i < g_dangerousApiCount; i++) {
                if (_stricmp(api.c_str(), g_dangerousApis[i]) == 0) {
                    std::string full = entry.dllName + "!" + api;
                    foundApis.push_back(full);
                }
            }
        }
    }

    return !foundApis.empty();
}

} // namespace das
