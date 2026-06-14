using System.Text.Json;
using SEWindows.Service;

// ═══════════════════════════════════════════════════════════════
//  SEWindows Anti-Cheat Service
//  负责：驱动加载、等待 osu! 连接、拉起 Client 验证、设置 PPL
// ═══════════════════════════════════════════════════════════════

Console.Error.WriteLine("╔══════════════════════════════════════════════════╗");
Console.Error.WriteLine("║       SEWindows Anti-Cheat Service               ║");
Console.Error.WriteLine("╚══════════════════════════════════════════════════╝");

// Load configuration
var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
string serverUrl = "http://192.168.31.207:5000";
string credentialSecret = "";

if (File.Exists(configPath))
{
    try
    {
        var configJson = File.ReadAllText(configPath);
        var config = JsonSerializer.Deserialize<JsonElement>(configJson);
        if (config.TryGetProperty("Server", out var server))
            serverUrl = server.TryGetProperty("Url", out var url) ? url.GetString() ?? serverUrl : serverUrl;
        if (config.TryGetProperty("CredentialSecret", out var secret))
            credentialSecret = secret.GetString() ?? "";
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
    if (cmdArgs[i] == "--secret" && i + 1 < cmdArgs.Length)
        credentialSecret = cmdArgs[++i];
}

// Validate credential secret
if (string.IsNullOrEmpty(credentialSecret))
{
    Console.Error.WriteLine("[!] WARNING: No credential secret configured!");
    Console.Error.WriteLine("    Set CredentialSecret in appsettings.json or --secret <hex>");
    Console.Error.WriteLine("    Credential verification will fail without this.");
}

Console.Error.WriteLine($"[Config] Server: {serverUrl}");
Console.Error.WriteLine($"[Config] Secret: {(credentialSecret.Length > 8 ? credentialSecret[..8] + "..." : "(empty)")}");
Console.Error.WriteLine();

// Run the anti-cheat service
using var service = new AntiCheatService(serverUrl, credentialSecret);

// Handle graceful shutdown
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    service.Stop();
};

Application.ApplicationExit += (_, _) => service.Stop();

service.Run();

Console.Error.WriteLine("[Service] Exited.");
