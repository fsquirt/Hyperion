namespace SEWindows.UserService;

/// <summary>
/// 反作弊服务主控制器 — 协调驱动加载、自身 PPL 保护、游戏启动与 PPL 设置
/// 流程:
///   Service 启动 → 加载驱动(失败则不启动游戏) → 设 UserService 自己 PPL
///   → CREATE_SUSPENDED 启动游戏 → SetPpl → Resume
/// 退出: 用户点"退出"时先杀游戏再退出服务(同生共死)
/// </summary>
public sealed class AntiCheatService : IDisposable
{
    private readonly string _serverUrl;
    private readonly string _driverPath;
    private readonly string _gameExePath;
    private readonly TrayIcon _trayIcon;
    private bool _driverLoaded;
    private bool _running;
    private uint _protectedPid;        // 当前已保护的游戏 PID,0 表示无游戏运行
    private string _protectedExe = ""; // 当前已保护的游戏可执行路径

    public AntiCheatService(string serverUrl)
    {
        _serverUrl = serverUrl;

        var baseDir = AppContext.BaseDirectory;
        _driverPath = Path.Combine(baseDir, "KernelService.sys");
        // 游戏放在 current 子目录,避免 osu! 自带的 .NET 8 runtime 接管 UserService
        _gameExePath = Path.Combine(baseDir, "current", "osu!.exe");

        // 退出时先杀游戏再退出服务
        _trayIcon = new TrayIcon(Shutdown);
    }

    public void Run()
    {
        _running = true;

        // Show tray icon
        _trayIcon.Show();
        _trayIcon.UpdateStatus("启动中...");

        // Load kernel driver
        _trayIcon.UpdateStatus("加载驱动中...");
        _driverLoaded = DriverLoader.LoadDriver(_driverPath);
        if (!_driverLoaded)
        {
            _trayIcon.UpdateStatus("驱动加载失败");
            _trayIcon.ShowBalloon("SEWindows", "驱动加载失败,游戏不会启动", System.Windows.Forms.ToolTipIcon.Error);
            Console.Error.WriteLine("[Service] Driver load failed. Game will NOT start.");
            // 驱动失败不启动游戏,但仍进入消息循环让用户能看到托盘并退出
        }
        else
        {
            Console.Error.WriteLine("[Service] Driver loaded");

            // 先把 UserService 自己提升为 PPL(Antimalware),无窗口期被攻击
            _trayIcon.UpdateStatus("保护服务中...");
            uint selfPid = (uint)Environment.ProcessId;
            Console.Error.WriteLine($"[Service] Setting PPL on self PID={selfPid}");
            bool selfPplOk = PplSetter.SetPpl(selfPid, PplSetter.PsProtectedSignerAntimalware);
            if (!selfPplOk)
            {
                Console.Error.WriteLine("[Service] WARNING: Self PPL set failed, continuing anyway");
                _trayIcon.ShowBalloon("SEWindows", "服务自身 PPL 设置失败,继续运行",
                    System.Windows.Forms.ToolTipIcon.Warning);
            }
            else
            {
                Console.Error.WriteLine("[Service] Self PPL set successfully");
            }

            // 延迟 2 秒,给驱动初始化缓冲
            _trayIcon.UpdateStatus("准备启动游戏...");
            Console.Error.WriteLine("[Service] Waiting 2s before launching game...");
            Thread.Sleep(2000);

            // 启动游戏并设置 PPL
            StartGameAndProtect();
        }

        // Keep running until exit
        while (_running)
        {
            Application.DoEvents();
            Thread.Sleep(100);
        }
    }

    /// <summary>
    /// 以 CREATE_SUSPENDED 启动游戏 → 设置 PPL → 恢复主线程
    /// 这样游戏从第一条指令开始就是 PPL,无保护窗口期
    /// </summary>
    private void StartGameAndProtect()
    {
        _trayIcon.UpdateStatus("启动游戏中...");
        Console.Error.WriteLine($"[Service] Launching game: {_gameExePath}");

        var (ok, pid, hProcess, hThread) = GameLauncher.StartSuspended(_gameExePath);
        if (!ok)
        {
            _trayIcon.UpdateStatus("游戏启动失败");
            _trayIcon.ShowBalloon("SEWindows", $"无法启动游戏: {_gameExePath}", System.Windows.Forms.ToolTipIcon.Error);
            return;
        }

        try
        {
            // 进程已挂起,记录 PID 用于退出时杀游戏
            _protectedPid = pid;
            _protectedExe = _gameExePath;

            // 立即设置 PPL(进程还在挂起状态,无窗口期)
            Console.Error.WriteLine($"[Service] Setting PPL on suspended game PID={pid}");
            _trayIcon.UpdateStatus("设置游戏 PPL 中...");
            bool pplOk = PplSetter.SetPpl(pid, PplSetter.PsProtectedSignerAntimalware);
            if (!pplOk)
            {
                Console.Error.WriteLine("[Service] Game PPL set failed, killing suspended process");
                _trayIcon.UpdateStatus("游戏 PPL 设置失败");
                _trayIcon.ShowBalloon("SEWindows", "游戏 PPL 设置失败,游戏将被终止",
                    System.Windows.Forms.ToolTipIcon.Error);
                // PPL 失败时终止挂起的进程,避免无保护运行
                PplSetter.KillProcess(pid);
                _protectedPid = 0;
                _protectedExe = "";
                return;
            }
            Console.Error.WriteLine("[Service] Game PPL set successfully");

            // 恢复主线程,游戏开始执行
            GameLauncher.Resume(hThread);

            _trayIcon.UpdateStatus("运行中 (测试模式)", true);
            _trayIcon.ShowBalloon("SEWindows", $"游戏已启动并保护 (PID {pid})",
                System.Windows.Forms.ToolTipIcon.Info);

            Console.Error.WriteLine($"[Service] Game started: PID={pid}, PPL=on");
        }
        finally
        {
            GameLauncher.CloseHandles(hProcess, hThread);
        }
    }

    /// <summary>
    /// 退出 — 服务和游戏同生共死
    /// 先杀游戏(若仍在运行),再退出服务
    /// </summary>
    public void Shutdown()
    {
        Console.Error.WriteLine("[Service] Shutdown requested");

        // 先杀游戏
        if (_protectedPid != 0)
        {
            if (!_driverLoaded)
            {
                Console.Error.WriteLine("[Service] Driver not loaded, cannot kill game PPL process");
            }
            else
            {
                // PID 复用安全检查: 游戏可能已自己退出,PID 被分配给其他进程(如杀软)
                // 必须先验证 PID 仍是 osu!.exe,避免误杀其他 PPL 进程
                string expectedExe = Path.GetFileName(_protectedExe);
                if (string.IsNullOrEmpty(expectedExe))
                {
                    Console.Error.WriteLine("[Service] No expected exe name recorded, skipping kill");
                    _trayIcon.ShowBalloon("SEWindows", "无游戏路径记录,跳过结束进程",
                        System.Windows.Forms.ToolTipIcon.Warning);
                }
                else if (!PplSetter.VerifyProcessExeName(_protectedPid, expectedExe))
                {
                    Console.Error.WriteLine($"[Service] PID {_protectedPid} is no longer '{expectedExe}', skipping kill to avoid PID reuse");
                    _trayIcon.ShowBalloon("SEWindows",
                        $"PID {_protectedPid} 已不是游戏进程({expectedExe}),跳过结束以防误杀",
                        System.Windows.Forms.ToolTipIcon.Warning);
                }
                else
                {
                    Console.Error.WriteLine($"[Service] Killing game PID {_protectedPid} on shutdown");
                    bool ok = PplSetter.KillProcess(_protectedPid);
                    if (ok)
                    {
                        _trayIcon.ShowBalloon("SEWindows", $"游戏进程已结束 (PID {_protectedPid})",
                            System.Windows.Forms.ToolTipIcon.Info);
                    }
                    else
                    {
                        _trayIcon.ShowBalloon("SEWindows", "结束游戏进程失败,请查看日志",
                            System.Windows.Forms.ToolTipIcon.Error);
                    }
                }
                _protectedPid = 0;
                _protectedExe = "";
            }
        }

        // 再退出服务
        _trayIcon.UpdateStatus("退出中...");
        _running = false;
        Console.Error.WriteLine("[Service] Stopping...");
    }

    public void Dispose()
    {
        _trayIcon.Dispose();
        DriverLoader.UnloadDriver();
    }
}
