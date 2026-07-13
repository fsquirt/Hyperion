namespace Hyperion.UserService.Tracking.WinEventTracker;

/// <summary>
/// 统一的事件模型，所有 Windows 事件订阅器产出此对象。
/// </summary>
public sealed record MonitoredEvent
{
    /// <summary>事件时间 (UTC)</summary>
    public required DateTime TimeCreated { get; init; }

    /// <summary>事件通道，如 "Security", "System", "Microsoft-Windows-CodeIntegrity/Operational"</summary>
    public required string Channel { get; init; }

    /// <summary>事件 ID</summary>
    public required int EventId { get; init; }

    /// <summary>事件级别 (Critical=1, Error=2, Warning=3, Information=4, Verbose=5)</summary>
    public required byte Level { get; init; }

    /// <summary>Provider 名称</summary>
    public required string Provider { get; init; }

    /// <summary>格式化后的事件描述</summary>
    public required string Description { get; init; }

    /// <summary>事件原始 XML (供深度解析)</summary>
    public required string RawXml { get; init; }
}
