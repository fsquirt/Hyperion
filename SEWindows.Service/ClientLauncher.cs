using System.Diagnostics;

namespace SEWindows.Service;

/// <summary>
/// 启动 SEWindows.Client 执行远程验证（带 UI 窗口），通过临时文件获取凭证
/// </summary>
public static class ClientLauncher
{
    private static readonly string CredentialFile =
        Path.Combine(Path.GetTempPath(), "sewindows_credential.json");

    public class ClientResult
    {
        public bool Success { get; set; }
        public string? CredentialJson { get; set; }
        public string? Error { get; set; }
    }

    /// <summary>
    /// 启动 Client.exe 执行远程验证，等待完成后读取凭证文件
    /// </summary>
    public static async Task<ClientResult> RunAsync(
        string clientExePath,
        string serverUrl,
        int timeoutMs = 120_000)
    {
        // 清理上次的凭证文件
        TryDelete(CredentialFile);

        if (!File.Exists(clientExePath))
            return new ClientResult { Success = false, Error = $"Client not found: {clientExePath}" };

        Console.Error.WriteLine($"[Client] Launching: {clientExePath}");
        Console.Error.WriteLine($"[Client] Server: {serverUrl}");
        Console.Error.WriteLine($"[Client] Credential file: {CredentialFile}");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = clientExePath,
                Arguments = $"--server {serverUrl} --credential-file \"{CredentialFile}\"",
                UseShellExecute = true,   // 让 WinForms 窗口正常显示
                CreateNoWindow = false
            };

            Console.Error.WriteLine($"[Client] Arguments: {psi.Arguments}");

            using var process = Process.Start(psi);

            if (process == null)
                return new ClientResult { Success = false, Error = "Process.Start returned null" };

            Console.Error.WriteLine($"[Client] Started, PID={process.Id}");

            // 轮询等待：进程退出 或 超时
            var sw = Stopwatch.StartNew();
            while (!process.HasExited)
            {
                if (sw.ElapsedMilliseconds > timeoutMs)
                {
                    try { process.Kill(); } catch { }
                    return new ClientResult { Success = false, Error = $"Client timed out ({timeoutMs}ms)" };
                }
                await Task.Delay(500);
            }

            Console.Error.WriteLine($"[Client] Exited with code {process.ExitCode}");

            if (process.ExitCode != 0)
                return new ClientResult { Success = false, Error = $"Client exited with code {process.ExitCode}" };

            // 读取凭证文件
            if (!File.Exists(CredentialFile))
                return new ClientResult { Success = false, Error = "Credential file not created by Client" };

            var json = File.ReadAllText(CredentialFile);
            TryDelete(CredentialFile);

            if (string.IsNullOrWhiteSpace(json))
                return new ClientResult { Success = false, Error = "Credential file is empty" };

            Console.Error.WriteLine($"[Client] Credential received ({json.Length} bytes)");
            return new ClientResult { Success = true, CredentialJson = json };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Client] Error: {ex.Message}");
            return new ClientResult { Success = false, Error = ex.Message };
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
