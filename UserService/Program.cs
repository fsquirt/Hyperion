using Hyperion.UserService;
using System.Text.Json;

// ═══════════════════════════════════════════════════════════════
//  Hyperion Anti-Cheat Service
//  负责：驱动加载、等待 osu! 连接、设置 PPL
// ═══════════════════════════════════════════════════════════════
// Load configuration
var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
string serverUrl = "http://192.168.31.207:5000";

if (File.Exists(configPath))
{
    try
    {
        var configJson = File.ReadAllText(configPath);
        var config = JsonSerializer.Deserialize<JsonElement>(configJson);
        if (config.TryGetProperty("Server", out var server))
            serverUrl = server.TryGetProperty("Url", out var url) ? url.GetString() ?? serverUrl : serverUrl;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[Config] Warning: {ex.Message}");
    }
}

// Also check command-line args
var cmdArgs = Environment.GetCommandLineArgs();
for (int i = 1; i < cmdArgs.Length; i++)
{
    if (cmdArgs[i] == "--server" && i + 1 < cmdArgs.Length)
        serverUrl = cmdArgs[++i];
}

Console.Error.WriteLine($"[Config] Server: {serverUrl}");
Console.Error.WriteLine();

// Run the anti-cheat service
using var service = new AntiCheatService(serverUrl);

// Handle graceful shutdown
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    service.Shutdown();
};

Application.ApplicationExit += (_, _) => service.Shutdown();

service.Run();

Console.Error.WriteLine("[Service] Exited.");
