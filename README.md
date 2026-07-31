# Hyperion

[![主界面截图](https://www.cloudyou.top/images/ui.png)](https://net.cloudyou.top/s/WBUw)

> 基于开源项目 https://github.com/fsquirt/SEWindows

🎬 **[点击图片观看演示视频](https://net.cloudyou.top/s/WBUw)**

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
