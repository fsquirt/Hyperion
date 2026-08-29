# Hyperion

[![主界面截图](https://www.cloudyou.top/images/ui.png)](https://img.wirebyte.online/%E6%BC%94%E7%A4%BA%E8%A7%86%E9%A2%91.mp4)

> 基于开源项目 https://github.com/fsquirt/SEWindows

🎬 **[点击图片观看演示视频](https://img.wirebyte.online/%E6%BC%94%E7%A4%BA%E8%A7%86%E9%A2%91.mp4)**

---

# 这是什么？

**Hyperion 是一套面向 Windows 网络对战场景的主动防御与内核级取证系统。** 它不是单纯的样本查看器，也不是只依赖静态特征匹配的云查杀服务。系统关注的是：在一次对局或测试会话中，主机是否处于可观测、可验证的运行状态，以及可疑驱动、设备通信、进程行为和取证样本之间能否形成完整证据链。

Hyperion 的核心思路是：在客户端建立基础信任后，由用户态编排器和内核驱动持续采集运行时证据；当发现可疑驱动或设备通信时，系统不对所有已加载对象做盲目阻断，而是根据签名、IAT、设备接口和通信行为进行分类、附着与取证，最后将会话交给逆向 Agent 和人工进行研判。

系统由四个相互衔接的部分组成：

| 层次 | 主要能力 | 典型产物 |
|---|---|---|
| **信任准入** | 通过 Verifyer 和服务端完成 TPM 远程证明，校验 EK/AK、PCR、WBCL 以及安全启动相关状态 | 证明请求、PCR/WBCL、设备安全特性、已加载驱动列表 |
| **主机加固** | UserService 与 KernelService 协同完成用户服务和游戏进程保护、句柄控制、线程与映像加载观测 | 保护状态、进程/线程事件、驱动扫描结果 |
| **内核取证** | 对符合策略的第三方驱动进行设备枚举、过滤器附着和 IOCTL/ETW 取证 | IOCTL 控制码、输入载荷、请求进程、调用栈、设备列表、驱动内存 dump |
| **云端研判** | Server 保存取证会话，逆向 Agent 调用 IDA Pro / WinDbg MCP 分析样本和行为证据 | `normal`、`suspicious`、`cheat` 报告与研判日志 |

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


## 阶段三：云端研判 —— 把证据变成结论

客户端会把一次运行期间采集到的 Windows 事件、ETW 事件、IOCTL 统计、附着设备、进程树快照和可疑文件组织为一个取证会话，并上报到 Server。Server 维护 `pending → analyzing → done` 的研判状态，Web 界面可以查看会话详情、事件筛选、文件和 Agent 日志。

分析机上的 opencode 定制版本通过 TUI 首页领取任务。Agent 可以将取证文件下载到独立工作目录，按文件类型切换 IDA Pro 或 WinDbg MCP，调用逆向工具完成分析，实时回传日志，并在会话结束时提交 `normal`、`suspicious` 或 `cheat` 报告。

- **服务器（Server）** 维护取证队列（`pending → analyzing → done`），Web 端可查看队列、研判回放与报告。
- **逆向 Agent（opencode 魔改版）** 运行在分析机上，通过 `HYPERION_WORKDIR` 只往工作目录写数据、不污染系统。它领取会话 → `swap_sample` 下载样本并挂载 **IDA Pro / WinDbg MCP** → 用大模型做反作弊向逆向（定位动态函数解析、跨进程内存读写原语、内核入口、BYOVD、载荷夹带、反调试对抗等）→ 关键结论**实时回传服务器**（`/log`）→ 最后提交 `normal / suspicious / cheat` 判定入库。

---

## 编译

Hyperion 是 Windows 混合解决方案，包含 KMDF 内核驱动、C++ 用户态工具、.NET 10 Windows 应用和 Bun/TypeScript Agent。相关功能不适合在 Linux 或非 Windows 环境中构建和运行和测试。

在编译运行客户端前，你需要先编译发布Server端

### 编译并部署 Server

获取代码

```powershell
git clone https://github.com/fsquirt/Hyperion.git
cd Hyperion
```

Server 是 ASP.NET Core 10 应用，默认配置监听 `http://0.0.0.0:5000`。

先发布到独立目录：

```powershell
dotnet publish .\Server\Hyperion.Server.csproj `
  -c Release `
  -o .\artifacts\Server
```

将 `Server/appsettings.json` 复制到发布目录并按部署环境修改。至少检查以下配置：

```json
{
  "Kestrel": {
    "Endpoints": {
      "Http": {
        "Url": "http://0.0.0.0:5000"
      }
    }
  },
  "Attestation": {
    "TrustedRootDir": "D:\\Hyperion\\TrustTPMCA",
    "ValidEksFile": "Data/valid_eks.txt",
    "ValidAksFile": "Data/valid_aks.txt",
    "HistoryFile": "Data/attestation_history.json"
  },
  "WebAuthn": {
    "ServerName": "Hyperion Attestation Server",
    "ServerDomain": "localhost",
    "Origin": "http://localhost:5000"
  }
}
```

根据你的实际需要修改`appsettings.json`的内容

启动 Server：

```powershell
cd .\artifacts\Server
 dotnet .\Hyperion.Server.dll
```

**注意:** 你需要自行配置HTTPS证书，且HTTPS证书是**必须的**，并且修改`ServerDomain`，`Origin`，`Url` 为你的域名，否则通行密钥登录无法使用，且UserService无法正常编译

### 编译客户端

**替换你的服务端地址**
 - 修改 `UserService/Program.cs` 中的 `serverUrl` 为你的服务器地址。该地址为外网域名/IP 时,编译脚本 `UserService/update_cert_pin.py` 会自动获取你服务器的HTTPS证书替换 `UserService/Comm/CertPinning.cs` 中的 `EmbeddedServerCertPem` 值，UserService 将指定使用此HTTPS证书与服务器通信;若为 `192.168.0.0/16` 内网开发地址,则自动跳过 HTTPS/TLS 证书校验(开发模式)
 - 修改 `Verifyer\RemoteVerify\Remoteattestation.cs` 中的 `serverBase` 为你的服务器地址

**自定义游戏路径**
 - 修改 `UserService\AntiCheatService.cs` 中的 `_gameExePath`，把这里传入你想保护的游戏路径

然后就可以编译了
```
cd UserService
msbuild Hyperion.UserService.csproj /p:Configuration=Release /p:Platform=x64
cd ..
cd Verifyer
msbuild Hyperion.Verifyer.csproj /p:Configuration=Release /p:Platform=x64
```

### 编译内核驱动

你需要生成一个测试用的代码签名证书，并且测试时需要将你的证书安装到测试机的受信任的根证书签发机构中。这个证书不仅是测试模式签名需要，**而且是用户层调用者身份验证**

生成证书的逻辑这里不赘述，进入你的证书目录并执行下面的命令，将`CodeSign.cer`替换为你的证书文件

```powershell
$bytes = [System.IO.File]::ReadAllBytes("CodeSign.cer"); $hex = ($bytes | ForEach-Object { "0x{0:x2}" -f $_ }) -join ", "; "static const unsigned char g_SignerCertDer[] = { `n$($hex -replace '((0x[0-9a-f]{2},\s*){12})', "`$1`n") `n};"
```

用上面命令的输出替换 `Hyperion\KernelService\SignerCert.h` 全文，然后开始编译

```powershell
cd KernelService
msbuild Hyperion.KernelService.csproj /p:Configuration=Release /p:Platform=x64
```

在开始测试前，你需要把生成的sys用你的证书签名，并且创建一个名为`kmdf`的服务，用`sc`创建的命令是

```powershell
sc create kmdf binPath= "自定义路径\KernelService.sys" type= kernel start= auto
```

你需要用你的证书签名UserService所有未签名模块，UserService才能正常启动并且和驱动通信

### 编译逆向Agent

你需要先安装IDA Pro 9.4 和 WinDbg 

然后需要安装下面两个MCP工具
```
pip install mcp-windbg
pip install ida-pro-mcp
```

Opencode逆向Agent项目并不在Hyperion.slnx解决方案中，需要单独通过bun编译

```powershell
cd opencode
build.bat
```

生成的逆向Agent在Hyperion\opencode\packages\opencode\dist\opencode-windows-x64\bin下

```powershell
cd .\opencode
Copy-Item .\appsettings.json.sample .\appsettings.json
```

编辑 `opencode/appsettings.json`：

```json
{
  "ServerUrl": "https://hyperion.example.com",
  "CredentialToken": "<YOUR_CREDENTIAL_TOKEN>",
  "WorkDir": "D:\\ReverseAgentWork",
  "IdaPath": "D:\\Program Files\\IDA Professional 9.4\\ida.exe",
  "IdaMcpCommand": "ida-pro-mcp.exe",
  "IdaMcpUrl": "http://127.0.0.1:13337/sse",
  "IdaAnalysisWaitSeconds": 10,
  "IdaReadyTimeoutSeconds": 120,
  "WinDbgMcpCommand": "mcp-windbg",
  "WinDbgMcpArgs": ["--transport", "stdio"],
  "SymbolPath": "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
  "EnableShellTool": true
}
```

将 `ServerUrl` 替换为你的服务器地址，`CredentialToken` 替换为你的在服务端生成的Token
其中 `WorkDir` 用于隔离 Agent 的配置、缓存、样本和运行时状态；该目录应具有足够磁盘空间，并且只授予分析机用户访问权限。`IdaPath`、IDA MCP、WinDbg MCP 和符号路径必须根据分析机实际安装位置修改。

构建完成后，直接启动构建输出中的脚本：

```powershell
cd opencode\packages\opencode\dist\opencode-windows-x64\bin\
.\run-agent.bat
```

编译脚本会自动把 `run-agent.bat` 和 `run-agent.ps1` 放到该目录。Agent 启动脚本会读取 `appsettings.json`，向 Server 请求可用的集群模型配置，并设置 `HYPERION_WORKDIR`，然后启动 TUI。
Agent 首页支持普通任务模式、连续任务模式、测试模式、IDA 测试和 WinDbg 测试。连续任务模式由 TUI 领取一轮、派发一轮、等待报告完成后再继续；返回首页或停止任务时会主动断联 Agent，避免服务端等待心跳超时回收。

在服务器配置好大模型API，并且在逆向客户端测试IDA Windbg的MCP工具工作正常后，就可以开始测试了

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
