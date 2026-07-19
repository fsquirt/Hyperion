# Hyperion

[![主界面截图](https://www.cloudyou.top/images/ui.png)](https://www.cloudyou.top/files/sample.mp4)

> 基于开源项目 https://github.com/fsquirt/SEWindows

🎬 **[点击图片观看演示视频](https://img.wirebyte.online/%E6%BC%94%E7%A4%BA%E8%A7%86%E9%A2%91.mp4)**

---

## 项目定位

Hyperion 是一个以**成本不对等**为核心论证的反作弊平台。判断标准不是"能不能被破",而是**"破一次的代价 vs 防一次的代价"**。

**不上内核保护时**:每次玩家举报都要触发 AI 全链路分析,固定烧钱,且攻击者用公开脚本就能批量触发,防守方被动。

**上 PPL + HVCI + 易受攻击驱动阻止列表后**:99% 的攻击在门口被挡掉,**零 AI 成本**;只有真有未公开 0day 驱动打穿的那 <1%,才进入 AI 深度分析。AI 的算力只花在高价值目标上。

威胁模型上还有一个务实判断:**未公开漏洞驱动的黑市价 > 把它烧在外挂上的收益**。开外挂的黑产用公开 BYOVD 武器库就够了,他们不会把独家 0day 浪费在这。因此只要堵住**已知签名漏洞驱动**(微软 Blocklist + 自维护补充列表),剩余攻击面小到可以接受。

基于这套论证,项目围绕**三层纵深防御**展开,并配套一个攻击测试床用于持续验证防线。

---

## 架构总览

| 子项目 | 语言 | 职责 |
|--------|------|------|
| **Verifyer** | C# WinForms | TPM 度量启动验证客户端,本地 + 远程证明 |
| **Server** | C# ASP.NET | 验证后端 + Tracker 事件中心 + AI Agent 入口 |
| **Tracker** | C# Console | ETW / WinEvent 实时事件采集与上报(仅订阅,不做 dump) |
| **UserService** | C# Console | 常驻反作弊服务,命名管道等待游戏连入 |
| **KernelService** | WDF 驱动 (C) | PPL 保护 + 驱动附着 + ETW 拦截 IOCTL + 驱动内存 dump |
| **DriverAttachSelector** | C++ Console | 驱动分类 + 设备枚举 + 附着管理 + 内核通信封装 |
| **HeuristicDumper** | C++ Console | ETW 通信监控 + 用户态/内核态 dump + 句柄审计 |
| **ProcessTreeSnapshot** | C++ Console | 进程树快照 + 全系统句柄扫描 + 安全采集 |
| **MSAFReverseAgent** | C# Console | 基于 MSAF 的逆向分析 Agent(MCP + ida-pro-mcp) |
| **Attack/inject** | C++ | 14 种 DLL 注入手法测试器 |
| **Attack/payload** | C++ DLL | 注入载荷(弹窗 + 日志) |

---

## 三层防御体系

### 第一层:可信启动验证(TPM 远程证明)

确保客户端运行在**真实开启**了下列安全特性的硬件上,且状态未被篡改:

- CPU 虚拟化 / IOMMU
- 安全启动 (Secure Boot)
- VBS / HVCI(基于虚拟化的安全与内存完整性)
- 驱动强制签名 / 易受攻击驱动阻止列表

#### 本地验证

1. 直接向 TPM 硬件读取 PCR 真实值(PCR[7] 记录安全启动策略,PCR[11] 记录 Windows 引导环境等)。
2. 解析 Windows 维护的 TCG 度量启动日志(`tcglog`),按事件顺序逐个哈希重放,公式 `新PCR = Hash(旧PCR || 事件哈希)`。
3. 将重放得到的 PCR 预期值与硬件 PCR 比对。一致则日志可信,可放心解析 `SIPolicy` 等事件得出 VBS / 安全启动等开关状态。

#### 远程验证(防内核沦陷)

内核完全沦陷时(如 Rootkit 劫持 PCR 读取 API),本地验证不可信,需引入远程证明:

1. **身份密钥**:TPM 硬件固化的 EK(背书密钥)及派生的 AK(证明密钥)。
2. **服务器质询**:Server 生成高强度 Nonce 下发。
3. **硬件签名**:客户端把 Nonce 与待验 PCR 索引交 TPM,TPM 用私有 AK 对当前 PCR + Nonce 签名生成 Quote,连同 AK 公钥与 Event Log 回传。
4. **服务器四重校验**:EK 证书链验证 AK → AK 公钥验 Quote 签名 → Nonce 防重放 → 重放 Event Log 与 Quote 中 PCR 比对。

### 第二层:内核态进程保护(PPL)

游戏进程被设为 **Protected Process Light (Antimalware)** 后,**应用层程序无法再对其 OpenProcess**,等于直接锁死了 RPM 类读内存外挂的入口。这部分由 `KernelService.sys` 完成:

- **动态定位偏移**:扫描 `PsGetProcessProtection` 的机器码(`0F B6 81` / `8A 41` 等 opcode 模式)定位 `EPROCESS.Protection` 字段偏移,跨 Windows 版本兼容,不硬编码。
- **直接写 Protection 字节**:ARK 风格,把目标进程 Protection 设为 `PsProtectedTypeProtectedLight | (SignerType << 4)`。
- **控制设备 + IOCTL**:用户态 Service 通过 `\\.\KernelService` 设备以 `IOCTL_SET_PPL` 下发目标 PID 与 SignerType。

> 攻击者要从内核改回这个字节,必须先拿到内核态 R/W,而这又要求他加载一个漏洞驱动 —— 这条路被第一层(HVCI)和第三层(驱动加载监控)接力堵住。

### 第三层:行为检测与样本捕获

预防层不是终点,**预防被突破时的发现与取证能力**才是纵深防御的最后一道。这一层由多个组件协同:

#### Tracker — 事件订阅与上报

`Tracker` 只负责订阅系统事件并上报 Server,**不做 dump**,职责单一:

- **ETW 实时事件**:驱动加载/安装(驱动加载是游戏对局中的高危信号)、镜像加载等。
- **Windows Event Log**:CodeIntegrity(代码完整性违规)、Defender 告警等。
- **分级上报**:按事件类型分 HIGH / WARN / INFO 三级,高危实时上报,INFO 仅 `--debug` 显示。
- **签名验证**:Authenticode 内嵌签名 + Windows 目录签名(.cat Catalog)双路径 —— 很多系统 DLL 无 PE 内嵌签名但由 .cat 背书,单验 Authenticode 会漏判。验证引擎沉淀为独立 `SignatureVerifier`。
- **零安装**:不写注册表、不起服务,ETW + WinEvent 原生信号,不暴露自身存在。

#### KernelService — 内核态拦截与 dump

`KernelService.sys` 除了 PPL 保护,还提供:

- **驱动附着** (`IOCTL_ATTACH_DEVICE`):创建 FiDO 附着到目标设备,拦截所有 IRP_MJ_DEVICE_CONTROL 通信。
- **ETW 事件发射**:每次 IOCTL 通信发射带调用栈的 ETW 事件(Provider GUID `{A7B3C9D2-...}`),含 AttachId / RequestorPid / IoControlCode / 完整用户态调用栈。
- **驱动内存 dump** (`IOCTL_DUMP_DRIVER_MEMORY`):按 AttachId 找到对端驱动的 `DRIVER_OBJECT`,用 `MmCopyMemory` 按 PE 区段安全 dump(跳过 `IMAGE_SCN_MEM_DISCARDABLE` 的 `.INIT` 区段,避免读已释放内存蓝屏),同时用 `ZwQuerySystemInformation` 反查驱动文件路径。
- **设备枚举** (`IOCTL_ENUM_DRIVER_DEVICES`):枚举指定驱动创建的所有设备。
- **驱动扫描** (`IOCTL_SCAN_LOADED_DRIVERS`):扫描已加载内核驱动列表,反查 DriverObject 名。

#### HeuristicDumper — 通信监控与 dump

`HeuristicDumper` 是核心取证工具,订阅 KernelService 发射的 ETW 事件,实现:

- **通信定位**:从调用栈符号化(EnumProcessModules + GetModuleInformation 范围匹配)定位"与被附着驱动通信的磁盘文件"(进程 exe + 栈中业务模块)。
- **RHS 属性告警**:文件不存在或含 ReadOnly/Hidden/System 属性时红色输出。
- **用户态 dump**:首次出现的模块从内存 dump 到 `dumpfile\`(内存映像,同名只 dump 一次)。
- **磁盘文件副本**:磁盘上有文件的模块拷贝到 `FileDump\`(dll 拷 dll,exe 拷 exe)。
- **内核驱动 dump**:对端驱动 sys 文件,磁盘有就拷贝,磁盘缺失就走内核 IOCTL 按 PE 区段从内存 dump。
- **JSON 通信日志**(可选 `--json`):每次通信事件实时导出为 `comms_log.json`(时间戳/AttachId/PID/IOCTL 码/InputBuffer hex/调用栈模块),默认关闭以节省性能。
- **句柄审计**(`--handle <pid>`):扫描持有目标 PID 高危句柄(VM_READ 等)的所有进程,单次执行后退出,复用 ProcessTreeSnapshot 的全系统句柄枚举逻辑。

#### ProcessTreeSnapshot — 进程树快照

`ProcessTreeSnapshot` 提供系统级采集能力:

- **树形打印模式**:进程树结构,支持 `--pid` / `--depth` 过滤。
- **安全采集模式** (`--security`):进程详情 + 线程 + 模块 + 可疑内存 + 全系统句柄扫描。
- **全系统句柄扫描**:`NtQuerySystemInformation` 一次拿全系统句柄,用 `ObjectTypeIndex` 本地过滤 99% 非 Process 句柄,`DuplicateHandle` + `GetProcessId` 验证句柄指向。

---

## 攻击测试矩阵

`Attack/inject` 实现了 14 种主流 DLL 注入手法,作为验证防线的对照组:

| # | 方法 | 原理 |
|---|------|------|
| 1 | CreateRemoteThread | 经典 LoadLibrary 远程线程 |
| 2 | RtlCreateUserThread | 底层 API,绕过部分检测 |
| 3 | APC 注入 | 异步过程调用,不创建新线程 |
| 4 | 线程上下文劫持 | 挂起线程改 RIP,注入 shellcode |
| 5 | 反射式注入 | 手动映射 PE,DLL 不落地 |
| 6 | 全局钩子注入 | SetWindowsHookEx 消息机制 |
| 7 | 输入法注入 | IME 模块,切换输入法触发 |
| 8 | DLL 劫持 | 利用 DLL 搜索顺序,替换合法 DLL |
| 9 | 注册表注入 | AppInit_DLLs,所有加载 user32 的进程 |
| 10 | 挂起线程注入 | SuspendThread 改 EIP 后 Resume |
| 11 | 挂起进程注入 | CREATE_SUSPENDED 创建后注入 |
| 12 | 进程替换 | Process Hollowing,替换进程内存 |
| 13 | 调试器注入 | DEBUG_EVENT 写入 shellcode + CC 断点 |
| 14 | 导入表注入 | 静态修改 PE 导入表(文件操作) |

---

## AI 取证:从"通知封禁"到"出具报告"

这是本项目相对传统反作弊的**核心差异化卖点**。传统反作弊能告诉玩家的只有一句"你的账户已被封禁";本项目交付的是**一份证据链完整、可申诉可复核的封禁报告**。

### 多 Agent 协同工作流

PPL 被打穿(内核态证据)或玩家被举报(行为侧证据)时,HeuristicDumper 把外挂进程内存映像、注入模块、对端驱动 sys、通信内容 JSON 打包上传至 Server,由多个专业 Agent 协同分析:

```
   PPL 边界突破 / 通信异常 / 玩家举报
            │
            ▼
   HeuristicDumper 采集证据
     ├─ 用户态模块内存 dump (dumpfile\)
     ├─ 对端驱动 sys dump (FileDump\ / dumpfile\)
     ├─ 通信内容 JSON (comms_log.json)
     └─ 句柄审计 (持有高危句柄的进程)
            │
            ▼
   Server → Multi-Agent 接管
            │
            ├── Reverse Agent:IDA/Ghidra CLI Skill 反汇编、
            │                 提取字符串与导入导出函数、标记可疑函数
            │                 → LLM 阅读反编译伪代码,语义级理解功能
            ├── Data Agent:   事件流分析(异常访问时序、权限、频率、调用栈)
            ├── Behavior Agent:对局内 K/D、爆头率与历史战绩对比
            └── Report Agent:交叉验证 + IoC 关联 + 报告生成
            │
            ▼
   自动出具封禁报告(人类可读 + 证据可复核)
```

### 核心硬亮点:LLM 阅读反编译伪代码

1. **逆向 Skill 自动化**:Reverse Agent 通过 IDA / Ghidra 的 headless CLI(Skill 形式封装),对 dump 出来的可疑模块自动做反汇编、字符串提取、导入/导出函数枚举、调用图构建。
2. **LLM 语义级分析**:让 LLM **阅读反编译出来的伪代码,理解函数的真实语义** —— 它在调用哪些 Windows API?读取游戏内存的哪些偏移?是模拟输入、改判定,还是 ESP/自瞄?这一步把"代码"变成"行为意图"。
3. **多 Agent 交叉验证**:Reverse Agent 推断的"模块功能"、Data Agent 分析的"事件时序"、Behavior Agent 的"对局数据异常",三者交叉印证。**单点证据不可信,三路证据一致才出报告**。
4. **IoC 链 + 可申诉报告**:把"突破 PPL 的时间戳 → 漏洞驱动文件 hash → 外挂本体 hash → 关联玩家 ID → 行为证据"串成完整证据链,生成人类可读的封禁报告。

### MSAFReverseAgent

基于 Microsoft Agent Framework (MSAF) 实现的逆向分析 Agent,通过 MCP 协议连接 ida-pro-mcp 服务端,自动调用 IDA Pro 进行反汇编分析,把结果返回给 LLM 进行语义级理解。相比 LangChain,MSAF 对 MCP 工具返回 null 值的容错更好,不会因 JSON Schema 严格校验崩溃。

---

## 组件协作流程

### 正常对局准入

```
   游戏客户端启动
        │
        ▼
   UserService 命名管道 hyperion-anticheat 等待连入
        │
        ├─ 加载 KernelService.sys
        ├─ Verifyer 本地 TPM 验证 → (可选)远程证明
        ├─ KernelService 设游戏进程 PPL (Antimalware)
        └─ 托盘图标显示 "保护已启用"
        │
        ▼
   游戏正常运行,PPL 阻止 99% 的 OpenProcess 攻击
```

### 作弊检测与取证

```
   攻击者加载漏洞驱动 (BYOVD)
        │
        ▼
   Tracker ETW 捕获驱动加载事件 → 高危上报 Server
        │
        ▼
   DriverAttachSelector 附着可疑驱动设备
        │
        ▼
   HeuristicDumper 订阅 ETW 通信事件
     ├─ 定位通信进程 + 模块 (调用栈符号化)
     ├─ dump 用户态模块 → dumpfile\
     ├─ dump 对端驱动 sys → FileDump\ / dumpfile\
     ├─ (可选) JSON 通信日志 → comms_log.json
     └─ 句柄审计 → 持有高危句柄的进程列表
        │
        ▼
   证据上传 Server → Multi-Agent 分析 → 封禁报告
```

---

## 命令行用法

### HeuristicDumper

```bash
# ETW 通信监控 (永久, Ctrl+C 退出)
HeuristicDumper.exe

# 订阅 60 秒
HeuristicDumper.exe --duration 60

# 启用 JSON 通信日志 (默认关闭以节省性能)
HeuristicDumper.exe --json
HeuristicDumper.exe --duration 60 --json

# 句柄审计 (单次执行后退出)
HeuristicDumper.exe --handle 1234
HeuristicDumper.exe --handle 0x4d2

# 帮助
HeuristicDumper.exe --help
```

### DriverAttachSelector

```bash
# 扫描已加载驱动
DriverAttachSelector.exe --scan

# 枚举驱动设备
DriverAttachSelector.exe --devices <DriverName>

# 附着到设备
DriverAttachSelector.exe --attach <DevicePath>

# 查询当前附着
DriverAttachSelector.exe --query

# 解绑
DriverAttachSelector.exe --detach <AttachId>
```

### ProcessTreeSnapshot

```bash
# 树形打印全系统进程
ProcessTreeSnapshot.exe

# 安全采集模式 (JSON 输出)
ProcessTreeSnapshot.exe --security

# 句柄扫描只看指向 PID 1234 的句柄
ProcessTreeSnapshot.exe --security --handles-target 1234
```

### Tracker

```bash
# 正常运行 (仅高危事件)
Tracker.exe

# 调试模式 (显示全部事件)
Tracker.exe --debug
```

---

## TODO 路线图

### 可信验证层 (Verifyer / Server)
- [x] TPM PCR 读取 + Event Log 解析 + 哈希重放(本地验证)
- [x] EK 注册 → MakeCredential → ActivateCredential → Quote(远程证明)
- [x] AK 签名验证 + Nonce 防重放 + PCR 重放比对
- [x] 安全特性分析(VBS / HVCI / Secure Boot)
- [x] WebAuthn 管理后台 + SQLite 历史记录
- [x] 联网拉取并更新微软易受攻击驱动阻止列表
- [ ] 客户端产物接入 UserService 的对局准入校验

### 内核保护 (KernelService)
- [x] 动态定位 `EPROCESS.Protection` 偏移
- [x] IOCTL 设置目标进程 PPL
- [x] KMDF Non-PnP 控制设备
- [x] 驱动附着 + IRP 拦截 + ETW 事件发射
- [x] 驱动内存 dump (PE 区段安全拷贝, 跳过 DISCARDABLE)
- [x] 设备枚举 + 驱动扫描
- [ ] `ObRegisterCallbacks` 对游戏 PID pre-filter,捕获突破 PPL 边界的句柄请求

### 行为检测 (Tracker)
- [x] ETW + WinEvent 双路采集
- [x] Authenticode + Catalog 双重签名验证
- [x] 移除 Sysmon 依赖(零安装)
- [ ] 游戏进程内 unbacked memory 扫描(检测 shellcode 注入)
- [ ] 漏洞驱动样本回传 + 自动更新 Blocklist

### 取证工具 (HeuristicDumper)
- [x] ETW 通信监控 + 调用栈符号化
- [x] 用户态模块内存 dump + 磁盘文件拷贝
- [x] 内核驱动 sys dump (磁盘拷贝 / 内存 PE 区段 dump)
- [x] JSON 通信日志 (可选 --json)
- [x] 句柄审计 (--handle)
- [x] RHS 属性告警 + 异常文件标记
- [ ] 证据自动打包上传 Server

### 进程快照 (ProcessTreeSnapshot)
- [x] 进程树快照 + 安全采集模式
- [x] 全系统句柄扫描 (ObjectTypeIndex 过滤 + DuplicateHandle 验证)
- [ ] 接入 HeuristicDumper 作为句柄审计后端

### AI Agent (取证报告)
- [x] MSAF 逆向 Agent (MCP + ida-pro-mcp)
- [ ] Reverse Agent:LLM 阅读反编译伪代码,语义级理解功能
- [ ] Data Agent:事件流分析
- [ ] Behavior Agent:对局数据异常检测
- [ ] Report Agent:三 Agent 结果交叉验证 + IoC 链 + 封禁报告
- [ ] Skill 化扩展 + 自我进化

### 反作弊服务 (UserService)
- [x] 命名管道等待游戏连入
- [x] 驱动加载 + 托盘图标状态机
- [x] TEST MODE:跳过远程验证直接设 PPL
- [ ] 接入 Verifyer 远程证明作为对局准入门槛

### 攻防测试 (Attack)
- [x] 14 种注入手法 + 清理功能
- [x] 注入载荷(payload.dll)弹窗 + 日志
- [ ] BYOVD攻击测试

---

## 证书管理与信任链

进行远程验证时,服务端必须建立对客户端 TPM 硬件的信任链,要求导入并信任各 TPM 厂商的根证书。

### 受信任的 TPM 根证书下载

🔗 [Guarded fabric - Install trusted TPM root certificates](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)

### 为什么必须导出所有证书(嵌入式中间证书 EICA)

通常不仅需要根证书和终端证书,还必须从设备 NV 存储区完整提取所有中间证书。这对使用 Intel PTT(Platform Trust Technology)的现代设备尤为重要。

根据 Intel 工程师的[官方社区答复](https://community.intel.com/t5/Mobile-and-Desktop-Processors/How-to-verify-an-Intel-PTT-endorsement-key-certificate/m-p/1610198/highlight/true):

> 从第 11 代酷睿处理器开始,Intel PTT 的背书密钥(EK)改为使用 **Intel ODCA(On Die Certificate Authority)** 进行设备内认证,不再通过 EKOP 联网服务器下发。
>
> 为成功构建证书信任路径,必须获取嵌入式中间证书(Embedded Intermediate CAs, EICA)。这在 TCG 组织的 EK Credential Profile 规范第 2.2.1.5.2 节 "Handle Values for EK Certificate Chains" 中有详细规定。

签名信任链结构:

1. PTT 的 EK 证书由 PTT EICA(例如 `CSME ADL PTT 01SVN`)签名。
2. PTT CA 由 CSME Kernel EICA 签名。
3. Kernel EICA 由 CSME ROM EICA 签名。
4. ROM EICA 中包含指向其最终颁发者(Issuer)的 AIA URL,供继续追溯。

根据 TCG 规范,PTT、Kernel 以及 ROM 的 EICA 都存放在 TPM 专门分配给 EK 链的 NV 存储范围内。**提取并导出这一完整的嵌套证书链,是远程验证过程能正确校验 Intel 11 代及更新 CPU 硬件身份的先决条件。**

---

## License

详见 [LICENSE](LICENSE)。
