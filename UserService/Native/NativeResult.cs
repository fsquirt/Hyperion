// NativeResult — CombinationNative 操作的结构化结果
//
// 取代原先直接打印 int 返回码的做法: 每个服务方法均返回 NativeResult 实例,
// 调用方 (Program) 只需消费结构化字段, 不再接触裸退出码。

namespace UserService.Native;

/// <summary>
/// 表示一次 CombinationNative 操作的结构化结果。
/// 封装原生 DLL 返回的整数退出码, 同时附带命令名、执行耗时、
/// 完成时间戳与可选的错误/诊断信息。
/// </summary>
public sealed class NativeResult
{
    /// <summary>产生该结果的命令名称 (如 "kernel-scan")。</summary>
    public string Command { get; }

    /// <summary>CombinationNative 返回的原始退出码 (0 = 成功)。</summary>
    public int ExitCode { get; }

    /// <summary>当 ExitCode == 0 时为 true。</summary>
    public bool Success => ExitCode == 0;

    /// <summary>原生调用的墙钟耗时。</summary>
    public TimeSpan Duration { get; }

    /// <summary>调用完成时的 UTC 时间戳。</summary>
    public DateTime CompletedAtUtc { get; }

    /// <summary>可选的人类可读错误 / 警告信息。</summary>
    public string? Message { get; }

    /// <summary>可选的参数摘要, 便于诊断。</summary>
    public string? Arguments { get; }

    public NativeResult(
        string command,
        int exitCode,
        TimeSpan duration,
        string? message = null,
        string? arguments = null)
    {
        Command = command;
        ExitCode = exitCode;
        Duration = duration;
        CompletedAtUtc = DateTime.UtcNow;
        Message = message;
        Arguments = arguments;
    }

    /// <summary>构造一个表示成功的实例。</summary>
    public static NativeResult Ok(string command, TimeSpan duration, string? arguments = null)
        => new(command, 0, duration, null, arguments);

    /// <summary>构造一个表示失败的实例。</summary>
    public static NativeResult Fail(
        string command, int exitCode, TimeSpan duration, string message, string? arguments = null)
        => new(command, exitCode, duration, message, arguments);

    public override string ToString()
    {
        string status = Success ? "OK" : $"FAIL({ExitCode})";
        string msg = string.IsNullOrEmpty(Message) ? "" : $" | {Message}";
        string args = string.IsNullOrEmpty(Arguments) ? "" : $" | args: {Arguments}";
        return $"[{Command}] {status} ({Duration.TotalMilliseconds:F0} ms){msg}{args}";
    }
}
