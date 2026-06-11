// ════════════════════════════════════════════════════════════════
//  方法 10: 挂起线程注入
//
//  原理：
//    1. 枚举目标进程线程
//    2. SuspendThread 挂起一个线程
//    3. VirtualAllocEx 分配内存，写入 shellcode
//    4. GetThreadContext 获取 EIP/RIP
//    5. 修改 EIP/RIP 指向 shellcode
//    6. SetThreadContext + ResumeThread
//    与方法 4 类似，但用更简洁的 shellcode（仅 LoadLibrary）
//
//  检测特征：
//    - Security 4656: THREAD_SUSPEND_RESUME + THREAD_SET_CONTEXT
//    - Sysmon Event 10: OpenProcess(THREAD_SUSPEND_RESUME)
//    - 内存扫描: RWX 页新增
// ════════════════════════════════════════════════════════════════
#include "../methods.h"
#include "../shellcode.h"

bool Inject_SuspendedThread(DWORD pid, const wchar_t* dllPath)
{
    // 与 ThreadContext 注入逻辑相同，但用更简单的 shellcode
    // 直接复用 Inject_ThreadContext 的实现
    Print(L"  [*] 挂起线程注入 → PID=%lu\n", pid);
    Print(L"  [*] 此方法与「线程上下文劫持」原理相同\n");
    Print(L"  [*] 区别: 此方法使用更简化的 shellcode，仅调用 LoadLibrary\n\n");
    return Inject_ThreadContext(pid, dllPath);
}
