namespace SEWindows.Service;

/// <summary>
/// 反作弊服务主控制器 — 协调驱动加载、管道通信、PPL 设置
/// </summary>
public sealed class AntiCheatService : IDisposable
{
    private readonly string _serverUrl;
    private readonly string _driverPath;
    private readonly PipeServer _pipeServer;
    private readonly TrayIcon _trayIcon;
    private bool _driverLoaded;
    private bool _running;

    public AntiCheatService(string serverUrl)
    {
        _serverUrl = serverUrl;

        var baseDir = AppContext.BaseDirectory;
        _driverPath = Path.Combine(baseDir, "KernelService.sys");

        _pipeServer = new PipeServer();
        _trayIcon = new TrayIcon(Stop);

        // Wire up the verification handler
        _pipeServer.OnVerifyRequest += HandleVerifyRequest;
    }

    public void Run()
    {
        _running = true;

        // Show tray icon
        _trayIcon.Show();
        _trayIcon.UpdateStatus("Starting...");

        // Load kernel driver
        _trayIcon.UpdateStatus("Loading driver...");
        _driverLoaded = DriverLoader.LoadDriver(_driverPath);
        if (!_driverLoaded)
        {
            _trayIcon.UpdateStatus("Driver failed!");
            _trayIcon.ShowBalloon("SEWindows", "Failed to load kernel driver", System.Windows.Forms.ToolTipIcon.Error);
            Console.Error.WriteLine("[Service] WARNING: Driver load failed. PPL protection unavailable.");
        }
        else
        {
            Console.Error.WriteLine("[Service] Driver loaded");
        }

        // Start pipe server
        _pipeServer.Start();
        _trayIcon.UpdateStatus("Waiting for game...");

        Console.Error.WriteLine("[Service] Ready. Waiting for osu! connection...");

        // Keep running until exit
        while (_running)
        {
            Application.DoEvents();
            Thread.Sleep(100);
        }
    }

    public void Stop()
    {
        _running = false;
        Console.Error.WriteLine("[Service] Stopping...");
        _trayIcon.UpdateStatus("Stopping...");
    }

    public void Dispose()
    {
        _pipeServer.Dispose();
        _trayIcon.Dispose();
        DriverLoader.UnloadDriver();
    }

    /// <summary>
    /// 处理 osu! 发来的验证请求
    /// </summary>
    private async Task<(bool success, bool testMode, string reason)> HandleVerifyRequest(
        uint pid, string exePath)
    {
        Console.Error.WriteLine($"[Service] Verify request: PID={pid}, Exe={exePath}");
        _trayIcon.UpdateStatus("Verifying...");
        _trayIcon.ShowBalloon("SEWindows", $"Game requesting verification (PID {pid})");

        try
        {
            // 跳过 Client 远程验证，直接设置 PPL
            if (_driverLoaded)
            {
                _trayIcon.UpdateStatus("Setting PPL...");
                Console.Error.WriteLine($"[Service] Setting PPL on PID={pid}");
                bool pplOk = PplSetter.SetPpl(pid, PplSetter.PsProtectedSignerAntimalware);
                if (!pplOk)
                {
                    Console.Error.WriteLine("[Service] PPL set failed");
                    _trayIcon.UpdateStatus("PPL failed!");
                    _trayIcon.ShowBalloon("SEWindows", "Failed to set process protection", System.Windows.Forms.ToolTipIcon.Error);
                    return (false, true, "PPL set failed");
                }
                Console.Error.WriteLine("[Service] PPL set successfully");
            }
            else
            {
                Console.Error.WriteLine("[Service] Skipping PPL (driver not loaded)");
            }

            _trayIcon.UpdateStatus("Verified (TEST MODE)", true);
            _trayIcon.ShowBalloon("SEWindows", "Game verified (test mode) and protected",
                System.Windows.Forms.ToolTipIcon.Warning);

            Console.Error.WriteLine("[Service] Verification complete: success, test=True");
            return (true, true, "ok");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Verification error: {ex}");
            _trayIcon.UpdateStatus("Error!");
            _trayIcon.ShowBalloon("SEWindows", $"Verification error: {ex.Message}", System.Windows.Forms.ToolTipIcon.Error);
            return (false, false, ex.Message);
        }
    }
}
