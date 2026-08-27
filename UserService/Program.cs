using Hyperion.UserService;

// ═══════════════════════════════════════════════════════════════
//  Hyperion Anti-Cheat Service
//  负责：驱动加载、PPL 自保护、游戏启动与多重保护、运行时取证上报
// ═══════════════════════════════════════════════════════════════

// 服务端地址(硬编码常量)
// 内网开发地址(192.168.0.0/16)自动跳过 HTTPS/TLS 证书校验,见 Comm/CertPinning.cs
const string serverUrl = "http://192.168.31.207:5000";

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
