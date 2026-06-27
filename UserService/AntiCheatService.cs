using System.Runtime.InteropServices;

namespace SEWindows.UserService;

/// <summary>
/// 反作弊服务主控制器 — 协调驱动加载、自身 PPL 保护、游戏启动与 PPL 设置、游戏退出监控
/// 流程:
///   Service 启动 → 加载驱动(失败则不启动游戏) → 设 UserService 自己 PPL
///   → CREATE_SUSPENDED 启动游戏 → OpenProcess(SYNCHRONIZE) 拿监控句柄 → SetPpl → Resume
///   → RegisterWaitForSingleObject 监控游戏退出
/// 退出(同生共死):
///   游戏自己退出 → 回调触发 → 关闭 kmdf → 退出服务
///   用户右键退出 → 验证 PID → kill 游戏 → 关闭 kmdf → 退出服务
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
    private IntPtr _gameProcessHandle; // 游戏进程句柄(带 SYNCHRONIZE,用于等待)
    private IntPtr _waitHandle;        // RegisterWaitForSingleObject 返回的等待句柄
    private bool _gameExited;          // 游戏是否已自己退出(区别于用户主动 kill)
    private bool _cleanupDone;         // 清理是否已完成(防重入)

    // P/Invoke for process monitoring
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool RegisterWaitForSingleObject(
        out IntPtr phNewWaitObject, IntPtr hObject,
        WaitOrTimerCallback Callback, IntPtr Context,
        uint dwMilliseconds, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UnregisterWait(IntPtr WaitHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UnregisterWaitEx(IntPtr WaitHandle, IntPtr CompletionEvent);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private delegate void WaitOrTimerCallback(IntPtr Context, bool TimerOrWaitFired);

    private const uint WT_EXECUTEONLYONCE = 0x00000008;
    private const uint WT_EXECUTEINWAITTHREAD = 0x00000004;
    private const uint INFINITE = 0xFFFFFFFF;

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

        // 主循环退出,统一清理(游戏退出或用户点退出都会走到这里)
        Cleanup();
    }

    /// <summary>
    /// 以 CREATE_SUSPENDED 启动游戏 → 拿 SYNCHRONIZE 句柄 → 注册等待 → SetPpl → Resume
    /// 句柄权限在 OpenProcess 时固化,PPL 升级后仍可 WaitForSingleObject
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
            // 保留 hProcess 用于 RegisterWaitForSingleObject (CreateProcess 返回的句柄带 SYNCHRONIZE)
            _gameProcessHandle = hProcess;

            // 注册等待:游戏退出(signaled)时触发回调,WT_EXECUTEONLYONCE 只触发一次
            // 注意:必须在 SetPpl 之前注册,因为句柄权限此时已固化
            Console.Error.WriteLine($"[Service] Registering wait on game process handle");
            WaitOrTimerCallback cb = OnGameExited;
            bool waitOk = RegisterWaitForSingleObject(
                out _waitHandle,
                _gameProcessHandle,
                cb,
                IntPtr.Zero,
                INFINITE,
                WT_EXECUTEONLYONCE);
            if (!waitOk)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[Service] RegisterWaitForSingleObject failed: error {err}");
                // 等待注册失败不影响主流程,但失去游戏退出监控能力
            }
            else
            {
                Console.Error.WriteLine("[Service] Wait registered, will exit when game exits");
            }

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

            Console.Error.WriteLine($"[Service] Game started: PID={pid}, PPL=on, monitored");
        }
        finally
        {
            // 只关 thread handle,process handle 保留给 wait 用(Cleanup 时再关)
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
        }
    }

    /// <summary>
    /// 游戏退出回调(由系统线程池触发)
    /// 不直接做 UI 操作,只设置标志让主循环退出,统一在主线程 Cleanup
    /// </summary>
    private void OnGameExited(IntPtr context, bool timedOut)
    {
        Console.Error.WriteLine("[Service] Game process exited (wait callback), signaling shutdown");
        _gameExited = true;
        _running = false;  // 让主循环退出,主线程走 Cleanup
    }

    /// <summary>
    /// 退出 — 用户右键点击"退出"时调用
    /// 只设置标志让主循环退出,真正的清理在 Cleanup 里做
    /// </summary>
    public void Shutdown()
    {
        Console.Error.WriteLine("[Service] Shutdown requested by user");
        _running = false;
    }

    /// <summary>
    /// 统一清理流程(在主线程执行,避免线程安全问题)
    /// 1. 注销等待注册
    /// 2. 若游戏还活着且用户主动退出(非游戏自己退出),验证 PID + kill 游戏
    /// 3. 关闭游戏进程句柄
    /// 4. 关闭 kmdf 驱动服务
    /// </summary>
    private void Cleanup()
    {
        if (_cleanupDone) return;
        _cleanupDone = true;

        Console.Error.WriteLine("[Service] Cleanup started");

        // 1. 注销等待(防止后续操作触发回调)
        if (_waitHandle != IntPtr.Zero)
        {
            // UnregisterWaitEx with INVALID_HANDLE_VALUE 等待正在执行的回调完成
            UnregisterWaitEx(_waitHandle, new IntPtr(-1));
            _waitHandle = IntPtr.Zero;
            Console.Error.WriteLine("[Service] Wait unregistered");
        }

        // 2. 若游戏还活着(用户主动退出,非游戏自己退出),验证 PID + kill
        if (_protectedPid != 0 && !_gameExited)
        {
            if (!_driverLoaded)
            {
                Console.Error.WriteLine("[Service] Driver not loaded, cannot kill game PPL process");
            }
            else
            {
                // PID 复用安全检查: 游戏可能已自己退出但回调还没触发,PID 被复用
                string expectedExe = Path.GetFileName(_protectedExe);
                if (string.IsNullOrEmpty(expectedExe))
                {
                    Console.Error.WriteLine("[Service] No expected exe name recorded, skipping kill");
                }
                else if (!PplSetter.VerifyProcessExeName(_protectedPid, expectedExe))
                {
                    Console.Error.WriteLine($"[Service] PID {_protectedPid} is no longer '{expectedExe}', skipping kill (PID reuse)");
                    _trayIcon.ShowBalloon("SEWindows",
                        $"PID {_protectedPid} 已不是游戏进程,跳过结束以防误伤",
                        System.Windows.Forms.ToolTipIcon.Warning);
                }
                else
                {
                    Console.Error.WriteLine($"[Service] Killing game PID {_protectedPid}");
                    bool killOk = PplSetter.KillProcess(_protectedPid);
                    if (killOk)
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
            }
        }
        else if (_gameExited)
        {
            Console.Error.WriteLine("[Service] Game exited on its own, no kill needed");
            _trayIcon.ShowBalloon("SEWindows", "游戏已退出,服务即将关闭",
                System.Windows.Forms.ToolTipIcon.Info);
        }

        _protectedPid = 0;
        _protectedExe = "";

        // 3. 关闭游戏进程句柄
        if (_gameProcessHandle != IntPtr.Zero)
        {
            CloseHandle(_gameProcessHandle);
            _gameProcessHandle = IntPtr.Zero;
            Console.Error.WriteLine("[Service] Game process handle closed");
        }

        // 4. 关闭 kmdf 驱动服务
        _trayIcon.UpdateStatus("关闭驱动中...");
        DriverLoader.UnloadDriver();

        _trayIcon.UpdateStatus("已退出");
        Console.Error.WriteLine("[Service] Cleanup done");
    }

    public void Dispose()
    {
        _trayIcon.Dispose();
    }
}
