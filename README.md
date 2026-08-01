# Hyperion

[![主界面截图](https://www.cloudyou.top/images/ui.png)](https://net.cloudyou.top/s/WBUw)

> 基于开源项目 https://github.com/fsquirt/SEWindows

🎬 **[点击图片观看演示视频](https://net.cloudyou.top/s/WBUw)**

---

# 这是什么？

**Hyperion 不是"一个帮忙看样本的逆向工具"。它是一套部署在真实对战环境、用于对抗**未知作弊技术**的主动式内核级纵深防御取证系统。** 它关心的是"这台机器此刻是否处于一个可被信任的运算环境中"——而不是"这个文件是不是病毒"。

它的核心命题是：**在网络对战场景下，攻击者可能拥有内核权限、加载自己的驱动、注入任意进程，且这些手段不断翻新，静态特征永远追不上。** Hyperion 的应对不是"等攻击者留下特征再去匹配"，而是：

> **在不可信的环境里，主动构造一个可被验证、可被观测、可被封锁的执行边界，然后把边界内发生的一切可疑行为"取证"下来，交给人脑 + 大模型研判。**

具体地，Hyperion 由四层能力闭环构成：

| 层 | 目的 | 对抗对象 |
|---|---|---|
| **① 信任准入（TPM 远程证明）** | 先证明"这台机器确实是它声称的硬件、且运行在受保护固件之上"，否则拒绝其接入对局 | 被篡改固件、虚拟机、被降级的硬件、伪造的客户端 |
| **② 主机加固（PPL + 驱动策略）** | 把用户服务与游戏进程提升为**受保护进程（PPL）**，锁死应用层对它们的访问；同时检测/拦截**已加载的 BYOVD 驱动** | 注入、内存读写、DLL 劫持、利用已知漏洞驱动提权 |
| **③ 内核对峙（驱动附着 + ETW 取证）** | 内核驱动**主动附着**到所有"暴露了设备接口、且导入过危险内核函数"的第三方驱动之上，实时记录每一个 IOCTL（控制码 / 载荷 / 请求进程 / 完整调用栈） | **未知 BYOVD**、未签名驱动、不落盘的内存驻留驱动 |
| **④ 云端研判（逆向 Agent）** | 把取证会话（行为证据 + 可疑样本 + IOCTL 通信记录）汇总，交由**逆向 Agent** 自动逆向、并配合人工研判，输出 `normal / suspicious / cheat` 判定入库 | 已知与未知的作弊载荷 |

它同时回答了现代反作弊面临的几个关键现实：

- **"静态库 / 云查杀"永远慢一步** —— 作弊样本可以现场编译、现场加壳、现场改哈希，任何基于"已知特征"的方案都会被绕过。Hyperion 转而监控**能力**（驱动是否具备任意内存读写原语、是否暴露危险 IOCTL），而不是**身份**（文件哈希 / 签名）。
- **"只防已知 BYOVD"不够** —— 微软的"易受攻击的驱动程序阻止列表"只覆盖已公开的漏洞驱动；对于尚未公开、或攻击者自行编译的驱动，Hyperion 通过**行为监控**（附着 + IAT 危险函数识别 + ETW 调用栈）来兜底。
- **"客户端安全了就行"不够** —— 分析机上的逆向 Agent 只是整个闭环的最后一环，它消费的原始证据来自内核驱动与 TPM 证明的**可信采集**；证据链一旦可信，判定才有意义。

---

# 他是怎么工作的？

Hyperion 的运行分**建立信任**与**维持观测**两个阶段，二者缺一不可。

## 阶段一：建立信任 —— 这台机器"可信"吗？

反作弊的第一步不是采集，而是**证明客户端处于一个可被信任的硬件与固件之上**。Hyperion 通过 **Verifyer** 对每台对局客户端执行 **TPM 远程证明（Remote Attestation）**，与服务器完成完整的 TPM 2.0 三层握手：

1. **EK 证书链验证** —— 读取设备 TPM 的**背书密钥（EK）**证书链，交给服务器校验。EK 由 TPM 厂商签发、锚定在硬件中，**只有真实 TPM 芯片才持有对应的私钥**。服务器据此把客户端写入可信 EK 名单（`valid_eks.txt`）。
2. **AK 证明（MakeCredential / ActivateCredential）** —— 服务器用该 EK 加密一段"挑战"（credential），客户端必须由**TPM 硬件内部**解密并回执，证明"我确实持有这把私钥"。只有解密成功，服务器才相信这台客户端对应一个**真实的、未被虚拟化/模拟的 TPM**，并注册其证明密钥（AK）。
3. **PCR Quote 校验** —— 客户端让 TPM 对 PCR 0–14 执行 `TPM2_Quote`（用 AK 签名、夹带服务器下发的 nonce 防重放），连同 **WBCL（Windows 引导日志）** 一起回传。服务器回放 PCR 值并与硬件实际 PCR 比对，同时解析出**安全特性**：`HVCI（内存完整性）`、`Secure Boot（安全启动）`、`Kernel DMA Protection（内核 DMA 保护 / IOMMU 是否启用）`、`VBS` 等是否开启。

> 为什么关心这些特性？因为它们共同定义了"内核被攻破的难度"：
> - **安全启动（Secure Boot）**：通过 UEFI 链式签名验证（`PK/KEK/db/dbx`），在操作系统加载前就阻止 Rootkit / 启动级恶意软件注入启动链，是内核完整性的信任起点。
> - **HVCI / 内存完整性**：利用硬件虚拟化把内核隔离，阻止低级驱动劫持内核。
> - **内核 DMA 保护 / IOMMU**：通过 IOMMU 重映射阻止外部设备（Thunderbolt/USB4/CFexpress）在用户离开时发起"路过式 DMA 攻击"，防止 DMA 直接读写内存。
>
> 服务器根据这些特性的开启情况，决定该客户端是否达到**进入对局的最低安全基线**；达不到则拒绝准入。

同时，**Verifyer** 还会通过 PSAPI 枚举本机已加载的内核驱动、计算哈希、读取签名，上传服务器与**已加载驱动拉黑列表**比对（`DriverBlocklistVerify`），主动确认"当前没有已知的漏洞驱动（BYOVD）正在运行"。

## 阶段二：维持观测 —— 在内核里"看着"一切

通过信任准入后，客户端正式进入对局。此阶段由 **UserService（用户态编排）+ KernelService（内核驱动）** 协同：

### 1. 自加固：先把"自己"保护起来

- **启动前防御**：`UserService` 启动先清除 `AppInit_DLLs` 注入（防止全局 DLL 注入），再校验自身所有已加载模块的签名（防 DLL 注入）。
- **自身 PPL 化**：加载 `KernelService` 驱动后，先把 **`UserService` 自己**提升为**受保护进程（PPL / Protected Process Light）**，无窗口期地锁死应用层对反作弊服务本身的访问（注入、内存读写、句柄窃取）。
- **游戏 PPL 化**：以 `CREATE_SUSPENDED` 启动游戏 → 拿监控句柄 → 同样将游戏进程提升为 PPL → 再恢复执行。此后普通应用层进程**无法打开游戏进程句柄、无法读写其内存**，从源头堵死"应用层注入 + 内存修改"这类最常见作弊路径。

  > PPL 在内核侧由 `ProcessProtect.c` 实现：通过 opcode 解析动态定位 `EPROCESS.Protection` 偏移（不依赖硬编码的 Windows 版本），直接写入保护位；内核态 `ZwTerminateProcess` 不受 PPL 限制，因此 Hyperion 可以**结束被 PPL 保护的目标进程**（游戏退出时的清理），而攻击者却动不了它。

### 2. 对已知威胁：扫描 + 检测已加载驱动

`KernelService` 用 `ZwQuerySystemInformation(SystemModuleInformation)` 枚举全部已加载内核模块（`DriverScanner`），对每个驱动做三件事：

- **签名分类**（`DriverClassifier`）：`WinVerifyTrust`（Authenticode 内嵌签名）+ Catalog 目录签名 → 分为 `Microsoft / Inbox / ThirdPartyWhql / Untrusted`。
- **IAT 危险函数扫描**（`IatScanner`）：纯托管解析 PE 导入表，检测是否导入了**危险内核函数**（如 `MmCopyMemory / MmMapIoSpace / ZwMapViewOfSection / MmCopyVirtualMemory`）。这套名单**可由服务器策略动态下发覆盖**。
- **BYOVD 判断**：`ThirdPartyWhql`（已知漏洞驱动几乎都是这种带有效 WHQL 签名的第三方驱动）与 `Untrusted`（未签名）被列为候选，再结合签名白名单 / 哈希判定是否为已知漏洞驱动。

### 3. 对未知威胁：主动"附着"并实时取证

这是 Hyperion 区别于传统反作弊的核心，也是它对抗**未知 BYOVD** 的关键：

- **驱动加载监控**：`KernelService` 注册 `PsSetLoadImageNotifyRoutine`，**任何新内核驱动被加载的瞬间**都会被感知（`DriverMonitor`），UserService 随即对该驱动做一次增量重扫。
- **设备附着（Filter 附着）**：对于"暴露了设备接口（`\Device` / `\FileSystem`）且 IAT 命中危险函数 / 未签名 / 磁盘无文件（内存驻留驱动）"的驱动，`KernelService` 会通过 `IoCreateDriver` 创建匿名过滤器驱动，并 `IoAttachDeviceToDeviceStack` **附着到该驱动的设备栈顶**。附着用匿名 DriverObject，不出现在 `\Driver` 命名空间，对反作弊工具与攻击者都更隐蔽。
- **ETW 通信取证**：附着后，凡是**任何进程**（包括未签名的可疑进程）对该设备发起的每一次 **IOCTL**，`EtwLogger` 都会实时记录：**IOCTL 控制码 + 输入载荷（≤4KB）+ 请求进程 PID + 完整的跨态调用栈（User → ntdll → ntoskrnl → 驱动）**。
- **内存取证**：需要时还可通过 `IOCTL_DUMP_DRIVER_MEMORY` 按 PE 区段安全 dump 被附着驱动的内存映像（用 `MmCopyMemory` 逐区段拷贝、跳过 DISCARDABLE 区段，避免蓝屏），供离线逆向。
- **进程树快照**：事件触发式采集进程树快照，记录"这个 IOCTL 是谁、在什么上下文里发起的"。

> 一句话概括本阶段：**"不知道你是谁的驱动，但我能看见你对系统设备做的每一件事。"**

## 阶段三：云端研判 —— 把证据变成结论

客户端把一次对局期间采集到的**全部行为证据**（Windows 事件、IOCTL 通信记录、附着设备列表、进程树快照）与**可疑样本文件**汇总为一个**取证会话**，上报服务器。

- **服务器（Server）** 维护取证队列（`pending → analyzing → done`），Web 端可查看队列、研判回放与报告。
- **逆向 Agent（opencode 魔改版）** 运行在分析机上，通过 `HYPERION_WORKDIR` 只往工作目录写数据、不污染系统。它领取会话 → `swap_sample` 下载样本并挂载 **IDA Pro / WinDbg MCP** → 用集群大模型做反作弊向逆向（定位动态函数解析、跨进程内存读写原语、内核入口、BYOVD、载荷夹带、反调试对抗等）→ 关键结论**实时回传服务器**（`/log`）→ 最后提交 `normal / suspicious / cheat` 判定入库。
- **闭环**：判定结果回写会话状态，供平台后续处置（禁赛 / 复查 / 拉黑）。整个链路从**可信硬件证明**到**内核实时取证**再到**云端逆向判定**，环环相扣。

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
