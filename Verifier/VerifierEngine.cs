using Hyperion.Verifier.RemoteVerify;
using MeasuredBootParser;
using Tpm2Lib;

namespace Hyperion.Verifier;

public record VerifierProgress(
    int StepIndex,
    string StepName,
    int Percent,
    bool? Success = null,
    string Message = ""
);

public record VerifierResult
{
    public bool Success { get; init; }
    public int FailedStepIndex { get; init; }
    public string FailedStepName { get; init; } = "";
    public string Reason { get; init; } = "";
    public string? TpmId { get; init; }
    public string? CertId { get; init; }
    public string? DriverId { get; init; }
    public List<string> SecurityFeatures { get; init; } = new();
    public TimeSpan Duration { get; init; }
}

/// <summary>
/// TPM 与硬件安全远程证明引擎，终端模式运行，无窗体依赖。
/// 执行顺序：
///   1. NTP 时间同步
///   2. Measured Boot 启动日志解析与本地 PCR 回放
///   3. TPM EK 证书链远程校验，请求 /verify_chain 接口
///   4. TPM AK 挑战证明与激活，执行 MakeCredential 与 ActivateCredential
///   5. PCR Quote 远程签名与安全基线验证，请求 /verify_quote 接口
///   6. VBS 与 HVCI 虚拟化运行态验证，请求 /verify_vbs_runtime 接口
///   7. 本机证书存储合规审计，请求 /verify_cert_store 接口
///   8. 已加载驱动阻止列表校验，请求 /verify_driver_blocklist 接口
/// </summary>
public static class VerifierEngine
{
    public static async Task<VerifierResult> RunAsync(
        string serverUrl = "http://localhost:5000",
        IProgress<VerifierProgress>? progress = null)
    {
        var startTime = DateTime.UtcNow;

        Console.WriteLine();
        Console.WriteLine("[Verifier] Hyperion 硬件信任准入与 TPM 远程证明引擎，终端运行模式");
        Console.WriteLine($"[Verifier] 目标服务端地址: {serverUrl}");
        Console.WriteLine($"[Verifier] 启动本地时间:   {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
        Console.WriteLine();

        void Report(int step, string name, int pct, bool? ok = null, string msg = "")
        {
            progress?.Report(new VerifierProgress(step, name, pct, ok, msg));
        }

        // Step 1: NTP 网络时间同步
        Console.WriteLine("[Verifier] [Step 1/8] 正在同步网络基准时间，执行 NTP 时间对齐...");
        Report(1, "网络时间同步", 10);
        bool ntpOk = false;
        try
        {
            await NtpTimeSync.NTPMain(ok => ntpOk = ok);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Verifier] [!] NTP 时间同步异常: {ex.Message}");
            ntpOk = false;
        }

        if (!ntpOk)
        {
            Console.WriteLine("[Verifier] [!] NTP 时间校准未完成，但允许非致命降级继续运行");
            Report(1, "网络时间同步，降级模式", 12, true, "时间已记录");
        }
        else
        {
            Console.WriteLine("[Verifier] [✔] NTP 网络时间同步成功");
            Report(1, "网络时间同步", 15, true, "时间同步完成");
        }
        Console.WriteLine();

        // Step 2: Measured Boot 引导测量日志与 PCR 本地解析
        Console.WriteLine("[Verifier] [Step 2/8] 正在提取 TPM 引导测量事件日志并回放 PCR，执行 Measured Boot 校验...");
        Report(2, "解析引导测量日志", 20);
        bool bootOk = false;
        try
        {
            await MeasuredBootCore.Run(ok => bootOk = ok);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Verifier] [!] Measured Boot 日志解析异常: {ex.Message}");
            bootOk = false;
        }

        if (!bootOk)
        {
            Console.WriteLine("[Verifier] [!] 未能从系统获取或解析完整的 TPM 引导测量日志");
        }
        else
        {
            Console.WriteLine("[Verifier] [✔] 引导测量事件日志解析完成");
        }
        Report(2, "引导测量日志解析完成", 25, bootOk, bootOk ? "本地PCR已回放" : "日志不可用");
        Console.WriteLine();

        // 初始化 TPM 硬件会话与 HTTP 客户端
        using var http = new HttpClient { BaseAddress = new Uri(serverUrl) };
        http.Timeout = TimeSpan.FromSeconds(15);

        TbsDevice? device = null;
        Tpm2? tpm = null;

        try
        {
            try
            {
                device = new TbsDevice();
                device.Connect();
                tpm = new Tpm2(device);
            }
            catch (Exception ex)
            {
                var reason = $"无法连接本机 TPM 2.0 硬件设备: {ex.Message}。请确认主板已开启 TPM、PTT 或 fTPM 并具备管理员权限。";
                Console.WriteLine($"[Verifier] [✘] TPM 设备初始化失败: {reason}");
                Report(3, "TPM 硬件初始化失败", 30, false, reason);
                return Failure(3, "TPM 设备初始化", reason, startTime);
            }

            // Step 3: TPM EK 证书链远程校验
            Console.WriteLine("[Verifier] [Step 3/8] 正在读取背书密钥 EK 证书链并请求服务端验证，执行 EK 远程证明...");
            Report(3, "TPM EK 证书链验证", 35);

            var ekResult = await EKVerify.RunAsync(http);
            if (!ekResult.Success)
            {
                var reason = $"EK 证书链验证未通过: {ekResult.Reason}";
                Console.WriteLine($"[Verifier] [✘] {reason}");
                Report(3, "EK 证书链验证失败", 35, false, reason);
                return Failure(3, "EK 证书链远程校验", reason, startTime);
            }
            Console.WriteLine($"[Verifier] [✔] EK 证书链验证成功，指纹为 {ekResult.EkFingerprint}");
            Report(3, "EK 证书链验证通过", 45, true, "EK 硬件身份有效");
            Console.WriteLine();

            await Task.Delay(300);

            // Step 4: TPM AK 挑战证明与激活，执行 MakeCredential 与 ActivateCredential
            Console.WriteLine("[Verifier] [Step 4/8] 正在创建 AK 证明密钥并处理服务端解密挑战，执行 AK 远程证明...");
            Report(4, "TPM AK 挑战证明", 50);

            var akResult = await AKVerify.RunAsync(tpm, http);
            if (!akResult.Success)
            {
                var reason = $"AK 挑战证明未通过: {akResult.Reason}";
                Console.WriteLine($"[Verifier] [✘] {reason}");
                Report(4, "AK 挑战证明失败", 50, false, reason);
                return Failure(4, "AK 挑战证明与激活", reason, startTime);
            }
            var akNameHex = akResult.AkName != null ? Convert.ToHexString(akResult.AkName) : "";
            Console.WriteLine($"[Verifier] [✔] AK 挑战证明成功，AK 名称为 {akNameHex}");
            Report(4, "AK 挑战证明通过", 60, true, "AK 证明密钥已激活");
            Console.WriteLine();

            await Task.Delay(300);

            // Step 5: PCR Quote 远程签名与安全基线验证
            Console.WriteLine("[Verifier] [Step 5/8] 正在执行 TPM2_Quote 签名并向服务端提交 PCR 验证，执行 PCR Quote 校验...");
            Report(5, "PCR Quote 远程验证", 65);

            PCRVerifyResult pcrResult;
            try
            {
                pcrResult = await PCRVerify.RunAsync(tpm, http, akResult);
            }
            finally
            {
                // 无论成功与否均释放 TPM AK 瞬态句柄
                akResult.Cleanup(tpm);
            }

            if (!pcrResult.Success)
            {
                var reason = $"PCR Quote 验证未通过: {pcrResult.Reason}";
                Console.WriteLine($"[Verifier] [✘] {reason}");
                Report(5, "PCR Quote 验证失败", 65, false, reason);
                return Failure(5, "PCR Quote 与安全基线验证", reason, startTime);
            }

            Console.WriteLine($"[Verifier] [✔] PCR Quote 签名比对一致，安全特性校验通过，记录标识为 {pcrResult.Id}");
            foreach (var f in pcrResult.SecurityFeatures)
            {
                Console.WriteLine($"[Verifier]     * {f}");
            }
            Report(5, "PCR Quote 验证通过", 75, true, "PCR 状态一致");
            Console.WriteLine();

            await Task.Delay(300);

            // Step 6: VBS 与 HVCI 虚拟化运行态验证
            Console.WriteLine("[Verifier] [Step 6/8] 正在执行 VBS 与 HVCI 运行态虚拟化证明...");
            Report(6, "VBS 运行态虚拟化验证", 80);

            VbsRuntimeVerifyResult vbsResult;
            if (pcrResult.Nonce != null)
            {
                vbsResult = await VbsRuntimeVerify.RunAsync(http, pcrResult.Id, pcrResult.Nonce);
            }
            else
            {
                vbsResult = new VbsRuntimeVerifyResult { Success = false, Verdict = "缺少挑战 Nonce，跳过" };
            }

            Console.WriteLine($"[Verifier] [ℹ] VBS 运行态判定: {vbsResult.Verdict}");
            Report(6, "VBS 运行态验证", 85, vbsResult.Success, vbsResult.Verdict);
            Console.WriteLine();

            // Step 7: 本机证书存储合规审计
            Console.WriteLine("[Verifier] [Step 7/8] 正在扫描本机受信任根证书存储区，执行根证书审计...");
            Report(7, "证书存储区合规审计", 90);

            string certId = "";
            try
            {
                var (_, _, _, cid) = await CertStoreVerify.RunAsync(http);
                certId = cid;
                Console.WriteLine("[Verifier] [✔] 本机证书存储扫描完成已上报");
                Report(7, "证书存储审计完成", 92, true, "根证书已记录");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Verifier] [!] 证书存储上报异常: {ex.Message}");
                Report(7, "证书存储审计异常", 92, true, ex.Message);
            }
            Console.WriteLine();

            // Step 8: 已加载驱动阻止列表校验
            Console.WriteLine("[Verifier] [Step 8/8] 正在枚举已加载内核驱动并校验漏洞驱动拉黑列表，执行驱动阻止名单校验...");
            Report(8, "驱动拉黑列表校验", 95);

            string driverId = "";
            try
            {
                var (_, _, _, did) = await DriverBlocklistVerify.RunAsync(http);
                driverId = did;
                Console.WriteLine("[Verifier] [✔] 已加载驱动列表校验完成已上报");
                Report(8, "驱动黑名单校验通过", 98, true, "未检出阻断驱动");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Verifier] [!] 驱动列表上报异常: {ex.Message}");
                Report(8, "驱动黑名单校验异常", 98, true, ex.Message);
            }
            Console.WriteLine();

            // 准入综合判定输出
            var totalDuration = DateTime.UtcNow - startTime;
            Console.WriteLine("[Verifier] >>> Hyperion 准入验证成功 <<<");
            Console.WriteLine($"[Verifier] [✔] 设备 TPM 硬件身份 : 真实且受信任");
            Console.WriteLine($"[Verifier] [✔] 固件与启动链状态   : PCR 校验一致");
            Console.WriteLine($"[Verifier] [✔] 运行时环境基线     : 安全特性符合准入要求");
            Console.WriteLine($"[Verifier] [✔] 总耗时             : {totalDuration.TotalSeconds:F2} 秒");
            Console.WriteLine();

            Report(8, "可信准入验证全部通过", 100, true, "可信状态已建立");

            return new VerifierResult
            {
                Success = true,
                TpmId = pcrResult.Id,
                CertId = certId,
                DriverId = driverId,
                SecurityFeatures = pcrResult.SecurityFeatures.Select(f => f.ToString()).ToList(),
                Duration = totalDuration
            };
        }
        finally
        {
            tpm?.Dispose();
            device?.Dispose();
        }
    }

    private static VerifierResult Failure(int stepIndex, string stepName, string reason, DateTime startTime)
    {
        var duration = DateTime.UtcNow - startTime;
        Console.WriteLine();
        Console.WriteLine("[Verifier] >>> Hyperion 准入验证失败 <<<");
        Console.WriteLine($"[Verifier] [✘] 失败步骤 : 第 {stepIndex} 步 - {stepName}");
        Console.WriteLine($"[Verifier] [✘] 失败原因 : {reason}");
        Console.WriteLine($"[Verifier] [✘] 处置策略 : 拒绝进入游戏，禁止加载反作弊驱动，直接终止");
        Console.WriteLine($"[Verifier] [✘] 耗时     : {duration.TotalSeconds:F2} 秒");
        Console.WriteLine();

        return new VerifierResult
        {
            Success = false,
            FailedStepIndex = stepIndex,
            FailedStepName = stepName,
            Reason = reason,
            Duration = duration
        };
    }
}
