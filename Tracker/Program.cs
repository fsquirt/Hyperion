using SEWindows.Tracker.EtwTracker;
using SEWindows.Tracker.Services;
using SEWindows.Tracker.SysmonEventTracker;
using SEWindows.Tracker.WinEventTracker;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       SEWindows.Tracker - 事件监控           ║");
Console.WriteLine("╚══════════════════════════════════════════════╝\n");

// ── 参数解析 ────────────────────────────────────────────────────────
var debug = args.Contains("--debug");

// ── Sysmon 部署 ─────────────────────────────────────────────────────
const string ServerBase = "http://localhost:5000";

await SysmonInstaller.DownloadAsync(ServerBase);
SysmonInstaller.Install();

// ── Server 连接 ────────────────────────────────────────────────────
using var serverConn = new ServerConnection(ServerBase);
if (await serverConn.StartSessionAsync())
    Console.WriteLine("[*] 已连接到服务端，实时事件上报已启用\n");
else
    Console.WriteLine("[!] 服务端连接失败，仅本地输出\n");

// ── Windows 事件日志 ───────────────────────────────────────────────
Console.WriteLine("[*] Windows 事件日志订阅:");
var winTracker = new WinEventTrackerManager();

winTracker.OnEvent += evt =>
{
    // ── Sysmon 事件：分类 + 签名验证 ───────────────────────────────
    if (SysmonEventClassifier.ClassifyAndPrint(evt, debug))
    {
        serverConn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "sysmon",
            timestamp = evt.TimeCreated.ToString("o"),
            level = SysmonEventClassifier.GetEventLevel(evt),
            source = "Sysmon",
            title = $"ID={evt.EventId}",
            detail = evt.Description,
            xml = evt.RawXml,
        });
        return;
    }

    // ── 非 Sysmon 事件 ─────────────────────────────────────────────

    // CodeIntegrity：未签名驱动被阻止 → 直接算高危
    if (evt.Channel.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("[WIN-HIGH] ");
        Console.ResetColor();
        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"         ⚠ 代码完整性违规");
        Console.ResetColor();
        Console.WriteLine($"         {evt.Description}");
        Console.WriteLine();
        serverConn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "winevent", timestamp = evt.TimeCreated.ToString("o"),
            level = "HIGH", source = evt.Channel, title = "代码完整性违规",
            detail = evt.Description,
        });
        return;
    }

    // Defender 检测到恶意软件 → 高危
    if (evt.Channel.Contains("Defender", StringComparison.OrdinalIgnoreCase))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("[WIN-HIGH] ");
        Console.ResetColor();
        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"         ⚠ Defender 告警");
        Console.ResetColor();
        Console.WriteLine($"         {evt.Description}");
        Console.WriteLine();
        serverConn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "winevent", timestamp = evt.TimeCreated.ToString("o"),
            level = "HIGH", source = evt.Channel, title = "Defender 告警",
            detail = evt.Description,
        });
        return;
    }

    // 其他事件：按 Windows Event Level 分级
    var level = evt.Level switch
    {
        1 => "CRIT",
        2 => "ERR ",
        3 => "WARN",
        _ => "INFO",
    };

    // 默认不显示 INFO 级别，--debug 才显示
    if (level == "INFO" && !debug) return;

    var color = evt.Level switch
    {
        1 => ConsoleColor.Red,
        2 => ConsoleColor.Red,
        3 => ConsoleColor.Yellow,
        _ => ConsoleColor.Cyan,
    };

    Console.ForegroundColor = color;
    Console.Write($"[WIN-{level}] ");
    Console.ResetColor();

    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");
    Console.WriteLine($"         {evt.Description}");
    Console.WriteLine();

    if (level != "INFO" || debug)
    {
        serverConn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "winevent", timestamp = evt.TimeCreated.ToString("o"),
            level = level.Trim(), source = evt.Channel, title = $"ID={evt.EventId} ({evt.Provider})",
            detail = evt.Description,
        });
    }
};

winTracker.Start();

// ── ETW 实时事件 ───────────────────────────────────────────────────
Console.WriteLine("\n[*] ETW 实时事件订阅:");
var etwTracker = new EtwTrackerManager();

etwTracker.OnEvent += evt =>
{
    // 驱动加载 / 驱动安装 → 高危（BYOVD 检测核心）
    if (evt.EventName is "DriverLoad" or "DriverInstall" or "DriverInstallComplete")
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write($"[ETW-HIGH] ");
        Console.ResetColor();
        Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.EventName}  ID={evt.EventId}");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"         ⚠ 驱动事件");
        Console.ResetColor();
        Console.WriteLine($"         Process: {evt.ProcessName} (PID={evt.ProcessId})");
        foreach (var kv in evt.Details)
            Console.WriteLine($"         {kv.Key}: {kv.Value}");
        Console.WriteLine();
        serverConn.PostEvent(new ServerConnection.TrackedEventDto
        {
            type = "etw", timestamp = evt.TimeCreated.ToString("o"),
            level = "HIGH", source = evt.ProviderName, title = $"⚠ {evt.EventName}",
            detail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                     string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}")),
        });
        return;
    }

    // 其他 ETW 事件 → INFO，仅 --debug
    if (!debug) return;

    var color = ConsoleColor.DarkCyan;
    Console.ForegroundColor = color;
    Console.Write($"[ETW-INFO] ");
    Console.ResetColor();

    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.EventName}  ID={evt.EventId}");
    Console.WriteLine($"         Process: {evt.ProcessName} (PID={evt.ProcessId})");
    foreach (var kv in evt.Details)
        Console.WriteLine($"         {kv.Key}: {kv.Value}");
    Console.WriteLine();

    serverConn.PostEvent(new ServerConnection.TrackedEventDto
    {
        type = "etw", timestamp = evt.TimeCreated.ToString("o"),
        level = "INFO", source = evt.ProviderName, title = evt.EventName,
        detail = $"Process: {evt.ProcessName} (PID={evt.ProcessId})\n" +
                 string.Join("\n", evt.Details.Select(kv => $"{kv.Key}: {kv.Value}")),
    });
};

etwTracker.Start();

// ── 等待退出 ───────────────────────────────────────────────────────
if (debug)
    Console.WriteLine("\n[*] 等待事件... [DEBUG 模式] (Ctrl+C 退出)\n");
else
    Console.WriteLine("\n[*] 等待事件... (Ctrl+C 退出, --debug 显示全部)\n");

var tcs = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    tcs.SetResult();
};
await tcs.Task;

// ── 退出清理（按顺序：释放订阅 → 清理事件 → 卸载 Sysmon）──────────
Console.WriteLine("\n[*] 正在退出...");

// 1. 释放事件订阅
winTracker.Dispose();
etwTracker.Dispose();
Console.WriteLine("  ├─ 事件订阅已释放");

// 2. 结束服务端会话
await serverConn.EndSessionAsync();
Console.WriteLine("  ├─ 服务端会话已结束");

// 3. 清理 Sysmon 事件日志
SysmonInstaller.ClearEventLog();
Console.WriteLine("  ├─ Sysmon 事件日志已清理");

// 4. 卸载 Sysmon 服务
SysmonInstaller.Uninstall();
Console.WriteLine("  └─ Sysmon 服务已卸载");

Console.WriteLine("[SEWindows.Tracker] 已停止。");
