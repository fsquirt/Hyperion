using SEWindows.Tracker.Events;

Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine("╔══════════════════════════════════════════════╗");
Console.WriteLine("║       SEWindows.Tracker - 事件监控           ║");
Console.WriteLine("╚══════════════════════════════════════════════╝\n");

using var manager = new EventSubscriptionManager();

manager.OnEvent += evt =>
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
    Console.Write($"[{levelStr}] ");
    Console.ResetColor();

    Console.WriteLine($"{evt.TimeCreated:HH:mm:ss.fff}  {evt.Channel}  ID={evt.EventId}  {evt.Provider}");

    var desc = evt.Description;
    if (desc.Length > 300) desc = desc[..300] + "...";
    Console.WriteLine($"         {desc}");
    Console.WriteLine();
};

manager.Start();

Console.WriteLine("\n[*] 等待事件... (Ctrl+C 退出)\n");

var tcs = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    tcs.SetResult();
};
await tcs.Task;

Console.WriteLine("\n[SEWindows.Tracker] 已停止。");
