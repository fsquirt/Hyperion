# Windows 进程访问权限参考表 (GrantedAccess)

## 进程特有权限 (低 16 位)

| 值 | 名称 | 含义 | 威胁级别 | 外挂用途 |
|------|------|------|---------|---------|
| `0x0001` | PROCESS_TERMINATE | 终止进程 | 🟡 低 | 强制关闭反作弊 |
| `0x0002` | PROCESS_CREATE_THREAD | 创建远程线程 | 🔴 高 | DLL注入/APC注入核心 |
| `0x0004` | PROCESS_SET_SESSIONID | 设置会话ID | 🟢 低 | - |
| `0x0008` | PROCESS_VM_OPERATION | VirtualAllocEx/VirtualProtectEx | 🔴 高 | 分配/修改内存页权限 |
| `0x0010` | PROCESS_VM_READ | ReadProcessMemory | 🔴 高 | 外挂读取游戏内存核心 |
| `0x0020` | PROCESS_VM_WRITE | WriteProcessMemory | 🔴 高 | 注入代码/修改内存核心 |
| `0x0040` | PROCESS_DUP_HANDLE | 复制句柄 | 🟢 低 | 句柄中继绕过 |
| `0x0080` | PROCESS_CREATE_PROCESS | 创建子进程 | 🟡 低 | - |
| `0x0100` | PROCESS_SET_QUOTA | 设置配额 | 🟢 低 | - |
| `0x0200` | PROCESS_SET_INFORMATION | 设置进程信息 | 🟡 低 | - |
| `0x0400` | PROCESS_QUERY_INFORMATION | 查询进程信息 | 🟢 低 | 查询进程状态 |
| `0x0800` | PROCESS_SUSPEND_RESUME | 挂起/恢复线程 | 🔴 高 | 线程劫持前置操作 |
| `0x1000` | PROCESS_QUERY_LIMITED_INFORMATION | 有限查询 | 🟢 低 | - |

## 标准权限 (高 16 位)

| 值 | 名称 | 含义 |
|------|------|------|
| `0x00010000` | DELETE | 删除对象 |
| `0x00020000` | READ_CONTROL | 读安全描述符 |
| `0x00040000` | WRITE_DAC | 修改 DACL |
| `0x00080000` | WRITE_OWNER | 修改所有者 |
| `0x00100000` | SYNCHRONIZE | 同步等待 |

## 常见组合值

| 值 | 组成 | 含义 | 典型场景 |
|------|------|------|---------|
| `0x0010` | VM_READ | 只读内存 | 外挂读取游戏数据 |
| `0x0030` | VM_READ \| VM_WRITE | 读写内存 | 外挂修改游戏数据 |
| `0x0040` | DUP_HANDLE | 只复制句柄 | Chrome 更新器等正常操作 |
| `0x0410` | VM_READ \| QUERY_INFORMATION | 读内存+查询 | 外挂查询+读取 |
| `0x1410` | VM_READ \| QUERY_INFORMATION \| QUERY_LIMITED_INFO | 读内存+查询 | WARP 等安全软件扫描 |
| `0x1FFFFF` | ALL_ACCESS | 全部权限 | Cheat Engine / 调试器 |

## 高危权限掩码

```csharp
// 用于快速判断是否包含危险权限
const uint DANGEROUS_MASK =
    PROCESS_VM_READ         |  // 0x0010 - 读内存
    PROCESS_VM_WRITE        |  // 0x0020 - 写内存
    PROCESS_VM_OPERATION    |  // 0x0008 - 内存操作
    PROCESS_CREATE_THREAD   |  // 0x0002 - 创建线程
    PROCESS_SUSPEND_RESUME;    // 0x0800 - 挂起恢复
```

## 当前过滤策略

```
ProcessAccess 事件
    ↓
GrantedAccess 解析
    ├─ 不含 DANGEROUS_MASK 任何位 → 无害，直接放行
    └─ 包含 DANGEROUS_MASK 位 → 检查 CallTrace
        ↓
    CallTrace 中每个 DLL
        ├─ 全部有签名 (Authenticode 或目录签名)
        │   └─ 且签名者是 Microsoft → 放行
        └─ 有未签名或非 Microsoft 签名 → HIGH 告警
```

## 已知正常进程访问模式

| 进程 | 典型权限 | 说明 |
|------|---------|------|
| csrss.exe | 0x1FFFFF | Windows 子系统，对所有进程有 ALL_ACCESS |
| lsass.exe | 0x1FFFFF | 安全子系统，正常操作 |
| WerFault.exe | 0x1FFFFF | 错误报告，调试时使用 |
| GoogleUpdater | 0x40 | DUP_HANDLE，管理子进程句柄 |
| Cloudflare WARP | 0x1410 | VM_READ + QUERY，安全扫描 |
| 安全软件 | 0x0410 | VM_READ + QUERY，扫描进程内存 |
| Cheat Engine | 0x1FFFFF | ALL_ACCESS，内存修改工具 |
