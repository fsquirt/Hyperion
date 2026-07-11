// ServiceLogger — 轻量级日志记录器
//
// 提供 Info / Warning / Error 三个严重级别, 带时间戳输出到控制台。
// 线程安全 (内部加锁), 供 SuperUserService 及 NativeBridge 共用。

namespace SuperUserService.Logging;

/// <summary>日志严重级别。</summary>
public enum LogLevel
{
    Info = 0,
    Warning = 1,
    Error = 2,
}

/// <summary>
/// 轻量级服务日志记录器。所有日志输出统一带时间戳与级别前缀,
/// 便于在 CombinationNative 的大量 stdout 输出中区分托管层信息。
/// </summary>
public sealed class ServiceLogger
{
    private readonly object _gate = new();

    /// <summary>最低输出级别, 低于此级别的日志将被丢弃。</summary>
    public LogLevel MinimumLevel { get; set; } = LogLevel.Info;

    public void Info(string message) => Write(LogLevel.Info, message);

    public void Warning(string message) => Write(LogLevel.Warning, message);

    public void Error(string message) => Write(LogLevel.Error, message);

    public void Error(string message, Exception ex)
        => Write(LogLevel.Error, $"{message}{Environment.NewLine}  -> {ex.GetType().Name}: {ex.Message}");

    private void Write(LogLevel level, string message)
    {
        if (level < MinimumLevel) return;
        lock (_gate)
        {
            string prefix = level switch
            {
                LogLevel.Info    => "[INFO]",
                LogLevel.Warning => "[WARN]",
                LogLevel.Error   => "[ERR ]",
                _                => "[????]",
            };
            Console.WriteLine($"{DateTime.Now:HH:mm:ss.fff} {prefix} {message}");
        }
    }
}
