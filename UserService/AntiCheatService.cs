using System.Runtime.InteropServices;
using Hyperion.UserService.Modules;

namespace Hyperion.UserService;

/// <summary>
/// 反作弊服务主控制器 — 协调驱动加载、自身 PPL 保护、游戏启动与多重保护、游戏退出监控
/// 流程:
///   Service 启动 → 加载驱动(失败则不启动游戏) → 设 UserService 自己 PPL
///   → CREATE_SUSPENDED 启动游戏 → OpenProcess(SYNCHRONIZE) 拿监控句柄
///   → 对游戏执行保护链(趁挂起时): 句柄降级保护 → ImageLoad 监控 → 新线程反调试
///     → 已有线程反调试 → 丢弃其他进程高危句柄
///   → RegisterWaitForSingleObject 监控游戏退出 → Resume
/// 注意:游戏本身不再设置 PPL(由上述 GameProtect 内核保护链代替),但 UserService 自身仍设 PPL。
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
    private RuntimeDetectionEngine? _runtimeEngine; // 运行时检测引擎(集成式 BYOVD 反制)

    // 驱动加载监控(反向调用)
    private Thread? _loadImageThread;
    private IntPtr _loadImageCancelEvent;  // 手动复位事件,信号后通知监控线程退出
    private IntPtr _loadImageDeviceHandle; // 长生命周期设备句柄
    private volatile bool _loadImageMonitorStarted;

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr hEvent);

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

        // ═══════════════════════════════════════════════════════════════
        // 启动前防御 1: AppInit_DLLs 注入检查
        // 必须在任何后续操作(加载驱动、启动游戏)之前执行
        // ═══════════════════════════════════════════════════════════════
        _trayIcon.UpdateStatus("检查 AppInit_DLLs...");
        Console.Error.WriteLine("[Service] Pre-flight: AppInit_DLLs check");
        if (!AppInitCheck.CheckAndClean(out string appInitCleared))
        {
            Console.Error.WriteLine($"[Service] AppInit_DLLs injection detected: \"{appInitCleared}\"");
            _trayIcon.UpdateStatus("发现注入攻击");
            _trayIcon.ShowBalloon(
                "Hyperion - 发现注入攻击",
                $"检测到 AppInit_DLLs 注入,已自动清除。游戏不会启动。\n注入内容: {appInitCleared}",
                System.Windows.Forms.ToolTipIcon.Error);
            // 不进入后续流程,直接退出
            _running = false;
            return;
        }
        Console.Error.WriteLine("[Service] AppInit_DLLs clean");

        // ═══════════════════════════════════════════════════════════════
        // 启动前防御 2: 自身模块签名校验
        // 遍历本进程所有模块(本体 EXE + 已加载 DLL),逐一验证有效签名
        // (Authenticode 内嵌签名 或 Windows 目录签名)
        // ═══════════════════════════════════════════════════════════════
        _trayIcon.UpdateStatus("校验自身模块签名...");
        Console.Error.WriteLine("[Service] Pre-flight: self signature check");
        if (!SelfSignatureCheck.Check(out List<string> unsignedModules))
        {
            string moduleList = string.Join("\n  - ", unsignedModules);
            Console.Error.WriteLine($"[Service] Unsigned modules detected:\n  - {moduleList}");
            _trayIcon.UpdateStatus("发现被注入 DLL");
            _trayIcon.ShowBalloon(
                "Hyperion - 发现被注入 DLL",
                $"检测到本进程存在未签名模块,可能已被注入。游戏不会启动。\n未签名模块:\n  - {moduleList}",
                System.Windows.Forms.ToolTipIcon.Error);
            _running = false;
            return;
        }
        Console.Error.WriteLine("[Service] All self modules trusted");

        // Load kernel driver
        _trayIcon.UpdateStatus("加载驱动中...");
        _driverLoaded = DriverLoader.LoadDriver(_driverPath);
        if (!_driverLoaded)
        {
            _trayIcon.UpdateStatus("驱动加载失败");
            _trayIcon.ShowBalloon("Hyperion", "驱动加载失败,游戏不会启动", System.Windows.Forms.ToolTipIcon.Error);
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
                _trayIcon.ShowBalloon("Hyperion", "服务自身 PPL 设置失败,继续运行",
                    System.Windows.Forms.ToolTipIcon.Warning);
            }
            else
            {
                Console.Error.WriteLine("[Service] Self PPL set successfully");
            }

            // 延迟 2 秒,给驱动初始化缓冲
            _trayIcon.UpdateStatus("准备启动检测引擎...");
            Console.Error.WriteLine("[Service] Waiting 2s before starting engine...");
            Thread.Sleep(2000);

            // 先启动集成式运行时检测引擎（BYOVD 反制：附着 + ETW 通信监控 + 进程树快照）
            // 引擎失败仅记日志、游戏继续运行（非致命）。放在启动游戏之前，确保引擎已就位再放行游戏。
            try
            {
                _runtimeEngine = new RuntimeDetectionEngine(serverUrl: _serverUrl);
                if (_runtimeEngine.Start())
                {
                    Console.Error.WriteLine("[Service] Runtime detection engine started");
                    _trayIcon.UpdateStatus("运行中 (检测引擎已启用)", true);
                }
                else
                {
                    Console.Error.WriteLine("[Service] Runtime detection engine failed to start (non-fatal)");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Service] Runtime engine exception (non-fatal):");
                Console.Error.WriteLine(LogUtil.Detail(ex));
                _runtimeEngine = null;
            }

            // 最后再启动游戏并执行 GameProtect 保护链(创建游戏进程 + 挂起 + 多重保护放在检测引擎之后)
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
    /// 以 CREATE_SUSPENDED 启动游戏 → 拿 SYNCHRONIZE 句柄 → 注册等待 → 执行 GameProtect 保护链 → Resume
    /// 保护链(趁挂起): 句柄降级保护 → ImageLoad 监控 → 新线程反调试 → 已有线程反调试 → 丢弃高危句柄
    /// 句柄权限在 OpenProcess 时固化,后续仍可 WaitForSingleObject
    /// </summary>
    private void StartGameAndProtect()
    {
        _trayIcon.UpdateStatus("启动游戏中...");
        Console.Error.WriteLine($"[Service] Launching game: {_gameExePath}");

        var (ok, pid, hProcess, hThread) = GameLauncher.StartSuspended(_gameExePath);
        if (!ok)
        {
            _trayIcon.UpdateStatus("游戏启动失败");
            _trayIcon.ShowBalloon("Hyperion", $"无法启动游戏: {_gameExePath}", System.Windows.Forms.ToolTipIcon.Error);
            return;
        }

        try
        {
            // 进程已挂起,记录 PID 用于退出时杀游戏
            _protectedPid = pid;
            _protectedExe = _gameExePath;
            // 告知运行时检测引擎游戏 PID(供 ETW ID3 线程反调试事件判定是否属于游戏进程)
            _runtimeEngine?.SetProtectedGamePid(pid);
            // 保留 hProcess 用于 RegisterWaitForSingleObject (CreateProcess 返回的句柄带 SYNCHRONIZE)
            _gameProcessHandle = hProcess;

            // 注册等待:游戏退出(signaled)时触发回调,WT_EXECUTEONLYONCE 只触发一次
            // 注意:必须在保护链之前注册,因为句柄权限此时已固化
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

            // 立即对游戏执行保护链(进程还在挂起状态,无窗口期)
            // 游戏本身不设 PPL,由内核 GameProtect 系列替代(句柄降级/ImageLoad/线程反调试/高危句柄丢弃)
            // 策略:保护链任一步失败 → 终止游戏(避免在无完整保护下运行)
            Console.Error.WriteLine($"[Service] Applying GameProtect protection chain to suspended game PID={pid}");
            _trayIcon.UpdateStatus("设置游戏保护中...");

            // ① 句柄降级保护(Ob 回调,剥夺外部高危进程/线程句柄权限)
            if (!PplSetter.GameProtectStart(pid))
            {
                AbortGameStart("句柄降级保护", pid);
                return;
            }

            //// ② ImageLoad 监控(目标 PID,用户态 DLL 加载事件经 ETW ID2 回传引擎做签名校验)
            if (!PplSetter.SetImageLoadMonitor(pid))
            {
                AbortGameStart("ImageLoad 监控", pid);
                return;
            }

            //// ③ 新线程反调试(目标进程新建线程执行 ThreadHideFromDebugger,远程注入线程由内核强杀,事件经 ETW ID3 回传)
            if (!PplSetter.SetThreadAntiDebug(pid))
            {
                AbortGameStart("新线程反调试", pid);
                return;
            }

            //// ④ 已有线程反调试(枚举目标进程全部现有线程执行 ThreadHideFromDebugger)
            if (!PplSetter.HideExistingThreads(pid))
            {
                AbortGameStart("已有线程反调试", pid);
                return;
            }

            //// ⑤ 丢弃其他进程握有的指向游戏进程的高危句柄(VM_READ/WRITE/OPERATION)
            if (!PplSetter.GameProtectDropHandles(pid))
            {
                AbortGameStart("丢弃高危句柄", pid);
                return;
            }

            Console.Error.WriteLine("[Service] GameProtect protection chain applied");

            // 恢复主线程,游戏开始执行
            if(GameLauncher.Resume(hThread) == uint.MaxValue)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[Service] ResumeThread failed: error {err}");
                AbortGameStart("ResumeThread", pid);
                return;
            }

            // 启动驱动加载监控(反向调用)
            // 任何新 .sys 加载 → 内核完成 IRP → 监控线程唤醒 → 仅记录,游戏继续运行
            StartLoadImageMonitor();

            _trayIcon.UpdateStatus("运行中 (测试模式)", true);
            _trayIcon.ShowBalloon("Hyperion", $"游戏已启动并保护 (PID {pid})",
                System.Windows.Forms.ToolTipIcon.Info);

            Console.Error.WriteLine($"[Service] Game started: PID={pid}, GameProtect=on, monitored");
        }
        finally
        {
            // 只关 thread handle,process handle 保留给 wait 用(Cleanup 时再关)
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
        }
    }

    /// <summary>
    /// 保护链某一步失败时中止游戏启动:终止挂起的游戏进程,清空保护记录,并提示用户。
    /// 调用方随后应 return,不再 Resume 游戏。
    /// </summary>
    /// <param name="step">失败的保护步骤名称(用于日志/托盘提示)</param>
    /// <param name="pid">挂起的游戏进程 PID</param>
    private void AbortGameStart(string step, uint pid)
    {
        Console.Error.WriteLine($"[Service] {step} failed, killing suspended process");
        _trayIcon.UpdateStatus("游戏保护设置失败");
        _trayIcon.ShowBalloon("Hyperion", $"游戏保护({step})失败,游戏将被终止",
            System.Windows.Forms.ToolTipIcon.Error);
        PplSetter.KillProcess(pid);
        _protectedPid = 0;
        _protectedExe = "";
    }

    /// <summary>
    /// 启动驱动加载监控线程
    /// 通过反向调用(IOCTL_WAIT_LOADIMAGE)挂起一个 IRP,等待内核 PsSetLoadImageNotifyRoutine 回调完成
    /// 收到通知 = 有新 .sys 加载 = 仅记录到日志和托盘提示,游戏继续运行(不触发 Shutdown)
    /// </summary>
    private void StartLoadImageMonitor()
    {
        _loadImageDeviceHandle = PplSetter.OpenDeviceHandle();
        if (_loadImageDeviceHandle == IntPtr.Zero || _loadImageDeviceHandle == new IntPtr(-1))
        {
            Console.Error.WriteLine("[Service] LoadImage monitor: failed to open device");
            return;
        }

        _loadImageCancelEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (_loadImageCancelEvent == IntPtr.Zero)
        {
            Console.Error.WriteLine("[Service] LoadImage monitor: CreateEvent failed");
            CloseHandle(_loadImageDeviceHandle);
            _loadImageDeviceHandle = IntPtr.Zero;
            return;
        }

        _loadImageMonitorStarted = true;
        _loadImageThread = new Thread(LoadImageMonitorProc)
        {
            Name = "LoadImageMonitor",
            IsBackground = true
        };
        _loadImageThread.Start();
        Console.Error.WriteLine("[Service] LoadImage monitor started");
    }

    /// <summary>
    /// 驱动加载监控线程主体
    /// 收到任何新 .sys 加载通知 → 仅记录到日志 + 托盘气球提示,继续循环监听下一个加载
    /// </summary>
    private void LoadImageMonitorProc()
    {
        try
        {
            while (_running)
            {
                bool ok = PplSetter.WaitLoadImageOnce(
                    _loadImageDeviceHandle,
                    _loadImageCancelEvent,
                    out PplSetter.LoadImageNotify notify);

                if (!ok)
                {
                    // 取消或出错,退出循环
                    break;
                }

                // 收到新驱动加载通知 → 仅记录,游戏继续运行
                string imageName = notify.ImageName ?? "(null)";
                Console.Error.WriteLine($"[Service] LoadImage monitor: NEW DRIVER LOADED -> {imageName} (recorded, game continues)");

                // 方案X:驱动加载即触发引擎对新驱动做 IAT/签名/设备扫描 + 附着
                // (后台线程执行,不阻塞本监控线程继续监听下一个加载)
                var engine = _runtimeEngine;
                if (engine != null)
                {
                    string name = imageName;
                    _ = ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try { engine.RescanDriverByImage(name); }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"[Service] RescanDriverByImage 异常: {ex.Message}");
                        }
                    });
                }

                // 异步弹气球提示(本线程不能直接调 UI)
                _ = ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        _trayIcon.ShowBalloon("Hyperion - 检测到新驱动加载",
                            $"检测到新驱动加载:\n{imageName}\n已记录,游戏继续运行",
                            System.Windows.Forms.ToolTipIcon.Warning);
                    }
                    catch { }
                });
                // 不调 Shutdown,继续 while 循环监听下一个驱动加载
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] LoadImage monitor thread exception: {ex.Message}");
        }
        finally
        {
            Console.Error.WriteLine("[Service] LoadImage monitor thread exiting");
        }
    }

    /// <summary>
    /// 停止驱动加载监控(由 Cleanup 调用)
    /// 流程:
    /// 1. 信号取消事件(cancelEvent) - 让 WaitLoadImageOnce 的 WaitForMultipleObjects 返回 1
    /// 2. 调 PplSetter.CancelLoadImage() 同步通知驱动完成挂起的 IRP
    ///    (绕过 WDF cancel 机制,驱动直接 WdfRequestCompleteWithInformation(STATUS_CANCELLED))
    /// 3. 监控线程的 WaitForSingleObject(hEvent) 立即返回 → 线程退出
    /// 4. Join 监控线程(此时应秒退)
    /// 5. 关闭设备句柄(IRP 已完成,CloseHandle 不阻塞)
    /// </summary>
    private void StopLoadImageMonitor()
    {
        if (!_loadImageMonitorStarted) return;

        Console.Error.WriteLine("[Service] StopLoadImageMonitor: signaling cancelEvent");
        // 1. 信号取消事件 (让 WaitLoadImageOnce 走取消分支)
        if (_loadImageCancelEvent != IntPtr.Zero)
        {
            SetEvent(_loadImageCancelEvent);
        }

        // 2. 通知驱动同步完成所有挂起的 IOCTL_WAIT_LOADIMAGE IRP
        // 这一步是关键:驱动收到 IOCTL_CANCEL_LOADIMAGE 后会调
        // DriverMonitorCancelAllPendingRequests,直接 WdfRequestCompleteWithInformation
        // 完成挂起的 WDFREQUEST,监控线程的 hEvent 立即信号。
        // 必须用独立句柄:同一句柄上有挂起的 overlapped IRP 时,同步 IO 会被阻塞。
        // Exclusive=FALSE 允许同时打开多个句柄;安全由 SDDL + 后续证书校验保证。
        Console.Error.WriteLine("[Service] StopLoadImageMonitor: calling CancelLoadImage (driver will complete pending IRPs)");
        PplSetter.CancelLoadImage();
        Console.Error.WriteLine("[Service] StopLoadImageMonitor: CancelLoadImage returned");

        // 3. 等待监控线程退出(IRP 已完成,线程应立即返回)
        if (_loadImageThread != null && _loadImageThread.IsAlive)
        {
            try
            {
                if (!_loadImageThread.Join(3000))
                {
                    Console.Error.WriteLine("[Service] LoadImage monitor thread did not exit in 3s after CancelLoadImage");
                }
            }
            catch { }
        }

        // 4. 关闭句柄(IRP 已完成,CloseHandle 不会阻塞)
        if (_loadImageDeviceHandle != IntPtr.Zero &&
            _loadImageDeviceHandle != new IntPtr(-1))
        {
            CloseHandle(_loadImageDeviceHandle);
            _loadImageDeviceHandle = IntPtr.Zero;
        }
        if (_loadImageCancelEvent != IntPtr.Zero)
        {
            CloseHandle(_loadImageCancelEvent);
            _loadImageCancelEvent = IntPtr.Zero;
        }

        _loadImageMonitorStarted = false;
        Console.Error.WriteLine("[Service] LoadImage monitor stopped");
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
    /// 0.  停止驱动加载监控 → 停止 GameProtect 保护链(句柄降级/ImageLoad/新线程反调试) → 退订 ETW(引擎 Stop)
    /// 1. 注销等待注册
    /// 2. 若游戏还活着且用户主动退出(非游戏自己退出),验证 PID + kill 游戏(驱动强杀)
    /// 3. 关闭游戏进程句柄
    /// 4. 关闭 kmdf 驱动服务
    /// </summary>
    private void Cleanup()
    {
        if (_cleanupDone) return;
        _cleanupDone = true;

        Console.Error.WriteLine("[Service] Cleanup started");

        // 0. 停止驱动加载监控(必须最先,因为关闭设备句柄会触发内核取消 pending IRP)
        StopLoadImageMonitor();

        // 0.3 停止 GameProtect 内核保护链(趁驱动仍加载,按序关闭):
        //     停止句柄降级保护 → 关闭 ImageLoad 监控 → 停止新线程反调试
        Console.Error.WriteLine("[Service] Tearing down GameProtect protection chain");
        PplSetter.GameProtectStop();          // 停止句柄降级保护
        PplSetter.SetImageLoadMonitor(0);     // 关闭 ImageLoad 监控(清空目标 PID)
        PplSetter.StopThreadAntiDebug();      // 停止新线程反调试

        // 0.5 停止运行时检测引擎(退订 ETW ID1/2/3 + 关闭 KernelService 句柄,
        //      否则驱动卸载时句柄悬空;引擎 Stop 内已完成订阅清理)
        try
        {
            _runtimeEngine?.Stop();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Runtime engine stop exception: {ex.Message}");
        }

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
                Console.Error.WriteLine("[Service] Driver not loaded, cannot kill game process");
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
                    _trayIcon.ShowBalloon("Hyperion",
                        $"PID {_protectedPid} 已不是游戏进程,跳过结束以防误伤",
                        System.Windows.Forms.ToolTipIcon.Warning);
                }
                else
                {
                    Console.Error.WriteLine($"[Service] Killing game PID {_protectedPid}");
                    bool killOk = PplSetter.KillProcess(_protectedPid);
                    if (killOk)
                    {
                        _trayIcon.ShowBalloon("Hyperion", $"游戏进程已结束 (PID {_protectedPid})",
                            System.Windows.Forms.ToolTipIcon.Info);
                    }
                    else
                    {
                        _trayIcon.ShowBalloon("Hyperion", "结束游戏进程失败,请查看日志",
                            System.Windows.Forms.ToolTipIcon.Error);
                    }
                }
            }
        }
        else if (_gameExited)
        {
            Console.Error.WriteLine("[Service] Game exited on its own, no kill needed");
            _trayIcon.ShowBalloon("Hyperion", "游戏已退出,服务即将关闭",
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
