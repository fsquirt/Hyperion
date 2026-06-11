#pragma once
// ════════════════════════════════════════════════════════════════
//  线程上下文注入用的 shellcode 模板
//  功能：LoadLibrary(dllPath) → ExitThread(0)
//
//  内存布局（x64）:
//    [0x00] 代码区 (21 bytes)
//    [0x15] LoadLibraryW 地址 (8 bytes)  ← 运行时 patch
//    [0x1D] ExitThread(0) 代码 (10 bytes)
//    [0x27] DLL 路径字符串 (宽字符)      ← 运行时写入
//
//  内存布局（x86）:
//    [0x00] 代码区 (19 bytes)
//    [0x13] LoadLibraryW 地址 (4 bytes)  ← 运行时 patch
//    [0x17] ExitThread(0) 代码 (10 bytes)
//    [0x21] DLL 路径字符串 (宽字符)      ← 运行时写入
// ════════════════════════════════════════════════════════════════

#ifdef _WIN64

// ── x64 shellcode ─────────────────────────────────────────────
// call +5          ; E8 00000000     → push rip (地址 @code+5)
// pop rbp          ; 5D              → rbp = @code+5
// mov rax,[rbp+13] ; 48 8B 45 13    → rax = LoadLibraryW
// lea rcx,[rbp+1B] ; 48 8D 4D 1B    → rcx = &dllPath
// call rax         ; FF D0           → LoadLibraryW(dllPath)
// xor ecx,ecx      ; 33 C9
// push rcx         ; 51
// mov rax,[rbp+19] ; 48 8B 45 19    → rax = @exitCode (code+0x1E)
// call rax         ; FF D0           → ExitThread(0)
// ──────────────────────────────────────────────────────────────
// 偏移: LoadLibraryW @ [rbp+0x13] (相对于 code+5)
//       ExitThread   @ [rbp+0x19] (相对于 code+5)
//       dllPath      @ [rbp+0x1B] (相对于 code+5)
//
// 实际内存:
//   code+0x00: E8 00 00 00 00
//   code+0x05: 5D
//   code+0x06: 48 8B 45 13
//   code+0x0A: 48 8D 4D 1B
//   code+0x0E: FF D0
//   code+0x10: 33 C9
//   code+0x12: 51
//   code+0x13: 48 8B 45 0A    ← patch: 替换为 mov rax, &exitCode
//   code+0x17: FF D0
//   code+0x19: [8 bytes]       ← LoadLibraryW 地址
//   code+0x21: 33 C9           ← xor ecx, ecx (ExitThread 入口)
//   code+0x23: 51              ← push rcx
//   code+0x24: 48 B8 [8 bytes] ← mov rax, &RtlExitUserThread
//   code+0x2E: FF D0           ← call rax
//   code+0x30: [dllPath bytes]

static constexpr int SHELLCODE_CODE_SIZE_X64   = 0x19;   // 代码区大小
static constexpr int SHELLCODE_LOADLIB_OFF_X64 = 0x19;   // LoadLibraryW 地址偏移
static constexpr int SHELLCODE_EXITCODE_OFF_X64= 0x21;   // ExitThread 代码起始偏移
static constexpr int SHELLCODE_STRING_OFF_X64  = 0x30;   // DLL 路径字符串偏移

static const uint8_t SHELLCODE_TEMPLATE_X64[] = {
    // ── 代码区 ──
    0xE8, 0x00, 0x00, 0x00, 0x00,       // call +0
    0x5D,                                 // pop rbp
    0x48, 0x8B, 0x45, 0x13,              // mov rax, [rbp+0x13]  → LoadLibraryW
    0x48, 0x8D, 0x4D, 0x1B,              // lea  rcx, [rbp+0x1B] → &dllPath
    0xFF, 0xD0,                           // call rax
    0x33, 0xC9,                           // xor  ecx, ecx
    0x51,                                 // push rcx

    // ── LoadLibraryW 地址 (8 bytes, patch) ──
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // ── ExitThread(0) 代码块 (10 bytes) ──
    0x33, 0xC9,                           // xor  ecx, ecx
    0x51,                                 // push rcx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,  // mov rax, &RtlExitUserThread (patch)
                0x00, 0x00, 0x00, 0x00,
    0xFF, 0xD0,                           // call rax
};

#else

// ── x86 shellcode ─────────────────────────────────────────────
// call +5          ; E8 00000000  → push eip (地址 @code+5)
// pop ebp          ; 5D           → ebp = @code+5
// mov eax,[ebp+0B] ; 8B 45 0B    → eax = LoadLibraryW
// push dword[ebp+10]; FF 75 10   → push &dllPath
// call eax         ; FF D0        → LoadLibraryW(dllPath)
// push 0           ; 6A 00
// mov eax,[ebp+0F] ; 8B 45 0F    → eax = @exitCode (code+0x17)
// call eax         ; FF D0        → ExitThread(0)
// ──────────────────────────────────────────────────────────────
// 实际内存:
//   code+0x00: E8 00 00 00 00
//   code+0x05: 5D
//   code+0x06: 8B 45 0B
//   code+0x09: FF 75 10
//   code+0x0C: FF D0
//   code+0x0E: 6A 00
//   code+0x10: 8B 45 04    ← patch: 替换为 mov eax, &exitCode
//   code+0x13: FF D0
//   code+0x15: [4 bytes]   ← LoadLibraryW 地址
//   code+0x19: 33 C0       ← xor eax, eax (ExitThread 入口)
//   code+0x1B: 50          ← push eax
//   code+0x1C: B8 [4 bytes]← mov eax, &ExitThread
//   code+0x21: FF D0       ← call eax
//   code+0x23: [dllPath bytes]

static constexpr int SHELLCODE_CODE_SIZE_X86   = 0x15;
static constexpr int SHELLCODE_LOADLIB_OFF_X86 = 0x15;
static constexpr int SHELLCODE_EXITCODE_OFF_X86= 0x19;
static constexpr int SHELLCODE_STRING_OFF_X86  = 0x23;

static const uint8_t SHELLCODE_TEMPLATE_X86[] = {
    // ── 代码区 ──
    0xE8, 0x00, 0x00, 0x00, 0x00,       // call +0
    0x5D,                                 // pop ebp
    0x8B, 0x45, 0x0B,                     // mov eax, [ebp+0x0B] → LoadLibraryW
    0xFF, 0x75, 0x10,                     // push dword [ebp+0x10] → &dllPath
    0xFF, 0xD0,                           // call eax
    0x6A, 0x00,                           // push 0

    // ── LoadLibraryW 地址 (4 bytes, patch) ──
    0x00, 0x00, 0x00, 0x00,

    // ── ExitThread(0) 代码块 (10 bytes) ──
    0x33, 0xC0,                           // xor eax, eax
    0x50,                                 // push eax
    0xB8, 0x00, 0x00, 0x00, 0x00,        // mov eax, &ExitThread (patch)
    0xFF, 0xD0,                           // call eax
};
#endif
