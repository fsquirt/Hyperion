# Hyperion

[![主界面截图](https://www.cloudyou.top/images/ui.png)](https://www.cloudyou.top/files/sample.mp4)

> 基于开源项目 https://github.com/fsquirt/SEWindows

🎬 **[点击图片观看演示视频](https://www.cloudyou.top/files/sample.mp4)**

---

## 项目定位

Hyperion 不是一个追求"理论完美安全"的学术系统,而是一个**以成本不对等为核心论证**的反作弊平台。判断标准不是"能不能被破",而是**"破一次的代价 vs 防一次的代价"**。

**不上内核保护时**:每次玩家举报都要触发 AI 全链路分析,固定烧钱,且攻击者用公开脚本就能批量触发,防守方被动。

**上 PPL + HVCI + 易受攻击驱动阻止列表后**:99% 的攻击在门口被挡掉,**零 AI 成本**;只有真有未公开 0day 驱动打穿的那 <1%,才进入 AI 深度分析。AI 的算力只花在高价值目标上。

威胁模型上还有一个务实判断:**未公开漏洞驱动的黑市价 > 把它烧在外挂上的收益**。开外挂的黑产用公开 BYOVD 武器库就够了,他们不会把独家 0day 浪费在这。因此只要堵住**已知签名漏洞驱动**(微软 Blocklist + 自维护补充列表),剩余攻击面小到可以接受。

基于这套论证,项目围绕**三层纵深防御**展开,并配套一个攻击测试床用于持续验证防线。

---

## 架构总览

| 子项目 | 语言 | 职责 |
|--------|------|------|
| **Client** | C# WinForms | TPM 度量启动验证客户端,本地 + 远程证明 |
| **Server** | C# ASP.NET | 验证后端 + Tracker 事件中心(SQLite + WebAuthn 后台) |
| **Tracker** | C# Console | ETW / WinEvent 实时事件采集与上报 |
| **Service** | C# Console | 常驻反作弊服务,命名管道等待游戏连入 |
| **KernelService** | WDF 驱动 (C) | 设置游戏进程 PPL,内核态进程保护 |
| **AI Agent** | LLM + IDA/Ghidra Skills | 服务端逆向分析 dump,出具证据链封禁报告 |
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

预防层不是终点,**预防被突破时的发现与取证能力**才是纵深防御的最后一道。`Tracker` 负责:

- **多源事件采集**:ETW(驱动加载、镜像加载)、Windows Event Log(CodeIntegrity、Defender)。游戏进程已由 KernelService 设为 PPL,ProcessAccess 不再依赖 Sysmon 监控,驱动加载/安装由 ETW 与 WinEvent 原生覆盖。
- **签名双重验证**:Authenticode 内嵌签名 + Windows 目录签名(.cat Catalog)双路径 —— 很多系统 DLL 无 PE 内嵌签名但由 .cat 背书,单验 Authenticode 会漏判。验证引擎已沉淀为独立 `SignatureVerifier`,供 ETW 驱动验签等场景复用。
- ~~**CallTrace 逐项验签 / 精准 MiniDump**~~:原依赖 Sysmon ProcessAccess/CreateRemoteThread/ImageLoad 触发链,已随 Sysmon 移除而休眠。MiniDumper 模块与签名引擎保留,待接入 KernelService ObRegisterCallbacks 句柄回调或 `Microsoft-Windows-Kernel-Image` ETW 提供者后唤醒。

---

## 攻击测试矩阵

`Attack/inject` 实现了 14 种主流 DLL 注入手法,作为验证防线的对照组 —— 每种手法的检测特征已在源码注释中标注(触发哪些 Sysmon Event、留下什么内存指纹):

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

### 传统反作弊 vs Hyperion

| 维度 | 传统反作弊 | Hyperion |
|------|-----------|-----------|
| 处置产出 | 一条"你的账户已被封禁"通知 | **一份证据链完整的封禁报告** |
| 玩家可申诉性 | 黑盒,玩家无法得知为何被封 | 报告含完整 IoC 链,可追溯可复核 |
| 误封责任 | 厂商承担舆论压力 | 误判证据自动留档,可复核可平反 |
| 反外挂演进 | 依赖逆向工程师手工分析新样本 | AI Agent 自动产出样本能力画像 |

### 多 Agent 协同工作流

PPL 被打穿(内核态证据)或玩家被举报(行为侧证据)时,Tracker 把外挂进程 MiniDump、可疑 DLL、shellcode 浮动内存页打包上传至 Server,由多个专业 Agent 协同分析:

```
   PPL 边界突破 / unbacked memory 命中 / 玩家举报
            │
            ▼
   Tracker 触发 MiniDump(外挂进程 + 注入模块 + 漏洞驱动)
            │
            ▼
   Server → Hermes Multi-Agent 接管
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

不是"用大模型扫日志"那种廉价 AI。真正的技术内核是:

1. **逆向 Skill 自动化**:Reverse Agent 通过 IDA / Ghidra 的 headless CLI(Skill 形式封装),对 dump 出来的可疑模块自动做反汇编、字符串提取、导入/导出函数枚举、调用图构建 —— 把传统逆向工程师的第一道工序自动化。
2. **LLM 语义级分析(关键)**:逆向工具只能给出反汇编和伪代码,无法判断"这段代码是不是外挂"。本项目让 LLM **阅读反编译出来的伪代码,理解函数的真实语义** —— 它在调用哪些 Windows API?读取游戏内存的哪些偏移?是模拟输入、改判定,还是 ESP/自瞄?这一步把"代码"变成"行为意图"。
3. **多 Agent 交叉验证**:Reverse Agent 推断的"模块功能"、Data Agent 分析的"事件时序"、Behavior Agent 的"对局数据异常",三者交叉印证。**单点证据不可信,三路证据一致才出报告**,大幅降低误判。
4. **IoC 链 + 可申诉报告**:把"突破 PPL 的时间戳 → 漏洞驱动文件 hash → 外挂本体 hash → 关联玩家 ID → 行为证据"串成完整证据链,最终生成一份人类可读的封禁报告 —— 告诉玩家"你在 X 时刻使用了基于 Y 漏洞驱动的 Z 类外挂,具体证据如下",而不是冷冰冰的封号通知。

### Skill 化扩展与自我进化

每类能力封装为独立 Skill(Reverse Skill / Event Analysis Skill / Game Behavior Skill / Report Generate Skill),**新增外挂类型时仅需新增 Skill 即可完成扩展**,无需重写主框架。配合 Hermes Agent 的自我进化能力,执行任务后自动复盘,把成功方法沉淀为可复用的"技能"文件,支持跨会话调用与迭代优化 —— 越用越聪明。

> 这套机制让 AI 只在**最值得处理的 <1% 事件**上启动(PPL 真被打穿的那一类),把算力成本控制在可承受范围 —— 与第二层 PPL 的"挡掉 99%"形成闭环。

---

## TODO 路线图

### Client / Server(可信验证层)
- [x] TPM PCR 读取 + Event Log 解析 + 哈希重放(本地验证)
- [x] EK 注册 → MakeCredential → ActivateCredential → Quote(远程证明)
- [x] AK 签名验证 + Nonce 防重放 + PCR 重放比对
- [x] 安全特性分析(VBS / HVCI / Secure Boot)
- [x] WebAuthn 管理后台 + SQLite 历史记录
- [ ] 客户端产物接入 Service 的对局准入校验

### KernelService(内核保护)
- [x] 动态定位 `EPROCESS.Protection` 偏移
- [x] IOCTL 设置目标进程 PPL
- [x] KMDF Non-PnP 控制设备(资源管理踩坑已修)
- [ ] `ObRegisterCallbacks` 对游戏 PID pre-filter,捕获突破 PPL 边界的句柄请求
- [ ] 游戏启动前枚举已加载驱动并验签(防提前加载漏洞驱动)
- [ ] 扫描所有 PPL 进程,清理"伪 PPL"(Protection 已设但 exe 无微软签名)样本
- [ ] 游戏启动前从驱动层面结束可疑 PPL 进程

### Tracker(行为检测)
- [x] ETW + WinEvent 双路采集(已移除 Sysmon 依赖,游戏进程由 KernelService PPL 保护)
- [x] Authenticode + Catalog 双重签名验证(独立 `SignatureVerifier`)
- [ ] CallTrace 逐项验签 + GrantedAccess 分级(随 Sysmon 移除,待 ETW ImageLoad 链路重建)
- [ ] CreateRemoteThread / ImageLoad 触发精准 MiniDump(MiniDumper 休眠,待触发源)
- [x] **移除 Sysmon 依赖**:Sysmon 安装需写注册表起服务,该安装动作本身可被对手监听,作为攻击线索。已改为 ETW + WinEvent 原生信号零安装
- [ ] 简化为"游戏进行时驱动加载 = 高危"作为主信号(谁打游戏时装驱动?)
- [ ] 游戏进程内 unbacked memory 扫描(检测 DLL 不落地的 shellcode 注入)
- [ ] 漏洞驱动样本回传 + 自动更新 Blocklist

### AI Agent(取证报告,基于 Hermes Multi-Agent)
- [ ] **Reverse Agent**:封装 IDA / Ghidra headless CLI 为 Skill,自动反汇编 + 字符串 + 导入/导出函数 + 调用图
- [ ] **Reverse Agent 核心能力**:LLM 阅读反编译伪代码,语义级理解函数真实功能(读取偏移 / 模拟输入 / 改判定 / 自瞄…)
- [ ] **Data Agent**:事件流分析(异常访问时序、申请权限、频率、调用栈来源地址)
- [ ] **Behavior Agent**:对局内 K/D、爆头率与历史战绩对比,侧面印证作弊
- [ ] **Report Agent**:三 Agent 结果交叉验证 + IoC 链关联 + 封禁报告生成
- [ ] Skill 化扩展:Reverse Skill / Event Analysis Skill / Game Behavior Skill / Report Generate Skill
- [ ] 自我进化:任务复盘沉淀"技能"文件,跨会话复用与迭代
- [ ] 反馈闭环:新样本反哺 Blocklist 更新

### Service(反作弊服务)
- [x] 命名管道 `hyperion-anticheat` 等待游戏连入
- [x] 驱动加载 + 托盘图标状态机
- [x] TEST MODE:跳过远程验证直接设 PPL
- [ ] 接入 Client 的远程证明作为对局准入门槛
- [ ] 联网拉取并更新微软易受攻击驱动阻止列表

### Attack(攻防测试床)
- [x] 14 种注入手法 + 清理功能
- [x] 注入载荷(payload.dll)弹窗 + 日志
- [x] 注入方法检测特征注释(Sysmon Event / 内存指纹)
- [ ] 针对 PPL 游戏的注入测试(验证第二层防线)
- [ ] 维护自研漏洞签名驱动列表(商业版补充微软 Blocklist)

---

## 证书管理与信任链

进行远程验证时,服务端必须建立对客户端 TPM 硬件的信任链,要求导入并信任各 TPM 厂商的根证书。

### 受信任的 TPM 根证书下载

为验证主流 TPM 厂商的 EK 证书合法性,可直接下载微软官方维护的 TPM 根证书包,内含主流 TPM 厂商根证书:

🔗 [Guarded fabric - Install trusted TPM root certificates](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates)

### 为什么必须导出所有证书(嵌入式中间证书 EICA)

通常不仅需要根证书和终端证书,还必须从设备 NV 存储区完整提取所有中间证书。这对使用 Intel PTT(Platform Trust Technology)的现代设备尤为重要。

根据 Intel 工程师的[官方社区答复](https://community.intel.com/t5/Mobile-and-Desktop-Processors/How-to-verify-an-Intel-PTT-endorsement-key-certificate/m-p/1610198/highlight/true):

> 从第 11 代酷睿处理器开始,Intel PTT 的背书密钥(EK)改为使用 **Intel ODCA(On Die Certificate Authority)** 进行设备内认证,不再通过 EKOP 联网服务器下发。
>
> 为成功构建证书信任路径,必须获取嵌入式中间证书(Embedded Intermediate CAs, EICA)。这在 TCG 组织的 EK Credential Profile 规范第 2.2.1.5.2 节 "Handle Values for EK Certificate Chains" 中有详细规定。

签名信任链结构如下:

1. PTT 的 EK 证书由 PTT EICA(例如 `CSME ADL PTT 01SVN`)签名。
2. PTT CA 由 CSME Kernel EICA 签名。
3. Kernel EICA 由 CSME ROM EICA 签名。
4. ROM EICA 中包含指向其最终颁发者(Issuer)的 AIA URL,供继续追溯。

根据 TCG 规范,PTT、Kernel 以及 ROM 的 EICA 都存放在 TPM 专门分配给 EK 链的 NV 存储范围内。**提取并导出这一完整的嵌套证书链,是远程验证过程能正确校验 Intel 11 代及更新 CPU 硬件身份的先决条件。**

---

## License

详见 [LICENSE](LICENSE)。
