using SEWindows.Tracker.EtwTracker;
using SEWindows.Tracker.WinEventTracker;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       SEWindows.Tracker - 事件监控           ║");
Console.WriteLine("╚══════════════════════════════════════════════╝\n");

// ── Windows 事件日志 ───────────────────────────────────────────────
Console.WriteLine("[*] Windows 事件日志订阅:");
using var winTracker = new WinEventTrackerManager();

winTracker.OnEvent += evt =>
{
    var levelStr = evt.Level switch
    {
        1 => "CRIT",
        2 => "ERR ",
        3 => "WARN",
        _ => "INFO",
    };

    var color = evt.Level switch
    {
        1 => ConsoleColor.Red,
        2 => ConsoleColor.Red,
        3 => ConsoleColor.Yellow,
        _ => ConsoleColor.Cyan,
    };

    Console.ForegroundColor = color;
    Console.Write($"[WIN-{levelStr}] ");
    Console.ResetColor();

    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");

    var desc = evt.Description;
    if (desc.Length > 300) desc = desc[..300] + "...";
    Console.WriteLine($"         {desc}");
    Console.WriteLine();
};

winTracker.Start();

// ── ETW 实时事件 ───────────────────────────────────────────────────
Console.WriteLine("\n[*] ETW 实时事件订阅:");
using var etwTracker = new EtwTrackerManager();

etwTracker.OnEvent += evt =>
{
    var color = evt.ProviderName switch
    {
        "Kernel" => ConsoleColor.Yellow,
        "UserPnP" => ConsoleColor.Magenta,
        _ => ConsoleColor.DarkCyan,
    };

    Console.ForegroundColor = color;
    Console.Write($"[ETW-{evt.ProviderName}] ");
    Console.ResetColor();

    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.EventName}  ID={evt.EventId}");
    Console.WriteLine($"         Process: {evt.ProcessName} (PID={evt.ProcessId})");
    foreach (var kv in evt.Details)
        Console.WriteLine($"         {kv.Key}: {kv.Value}");
    Console.WriteLine();
};

etwTracker.Start();

// ── 等待退出 ───────────────────────────────────────────────────────
Console.WriteLine("\n[*] 等待事件... (Ctrl+C 退出)\n");

var tcs = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    tcs.SetResult();
};
await tcs.Task;

Console.WriteLine("\n[SEWindows.Tracker] 已停止。");
