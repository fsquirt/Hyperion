using System.Runtime.InteropServices;
using Hyperion.UserService.Comm;
using Hyperion.UserService.Modules;

namespace Hyperion.UserService;

/// <summary>
/// 反作弊服务主控制器 — 协调驱动加载、自身 PPL 保护、游戏启动与多重保护、游戏退出监控
/// 流程:
///   Service 启动 → 加载驱动,失败则不启动游戏 → 设 UserService 自己 PPL
///   → CREATE_SUSPENDED 启动游戏 → 创建作业对象 Job 并 Assign
///   → 对游戏执行保护链,趁挂起时: 句柄降级保护 → ImageLoad 监控 → 新线程反调试
///     → 已有线程反调试 → 丢弃其他进程高危句柄 → Resume
///   → Job 监听:后代进程,含孙进程,创建即自动执行保护链;多进程游戏如 HL/CS 全覆盖
/// 注意:游戏本身不再设置 PPL,由上述 GameProtect 内核保护链代替,但 UserService 自身仍设 PPL。
/// 退出时同生共死:
///   Job 内活动进程清零,即游戏整体退出 → 关闭 kmdf → 退出服务
///   用户右键退出 → TerminateJobObject 终止 Job 内全部进程 → 关闭 kmdf → 退出服务
///   UserService 异常退出 → KILL_ON_JOB_CLOSE 兜底,系统自动终止整个 Job
/// </summary>
public sealed class AntiCheatService : IDisposable
{
    private readonly string _serverUrl;
    private readonly string _driverPath;
    private readonly string _gameExePath;
    private readonly TrayIcon _trayIcon;
    private bool _driverLoaded;
    private bool _running;
    private uint _protectedPid;        // 当前已保护的游戏主进程 PID,0 表示无游戏运行
    private string _protectedExe = ""; // 当前已保护的游戏可执行路径
    private bool _gameExited;          // 游戏是否已全部退出,即 Job 内活动进程清零,区别于用户主动 kill
    private bool _cleanupDone;         // 清理是否已完成,防重入
    private RuntimeDetectionEngine? _runtimeEngine; // 运行时检测引擎,集成式 BYOVD 反制
    private GameJobMonitor? _gameJob;  // 游戏作业对象,后代进程自动限制在 Job 内并通知保护

    // 驱动加载监控,反向调用
    private Thread? _loadImageThread;
    private IntPtr _loadImageCancelEvent;  // 手动复位事件,信号后通知监控线程退出
    private IntPtr _loadImageDeviceHandle; // 长生命周期设备句柄
    private volatile bool _loadImageMonitorStarted;

    // P/Invoke for process monitoring
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr hEvent);

    public AntiCheatService(string serverUrl)
    {
        _serverUrl = serverUrl;

        var baseDir = AppContext.BaseDirectory;
        _driverPath = Path.Combine(baseDir, "KernelService.sys");
        // 游戏放在 current 子目录,避免 osu! 自带的 .NET 8 runtime 接管 UserService
        _gameExePath = "D:\\CS16_chs_setup\\game\\cstrike.exe";//Path.Combine(baseDir, "current", "osu!.exe");

        // 退出时先杀游戏再退出服务
        _trayIcon = new TrayIcon(Shutdown);
    }

    public void Run()
    {
        _running = true;

        // Show tray icon
        _trayIcon.Show();
        _trayIcon.UpdateStatus("启动中...");

        
        // 启动前防御 1: AppInit_DLLs 注入检查
        // 必须在加载驱动、启动游戏等任何后续操作之前执行
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

        
        // 启动前防御 2: 自身模块签名校验
        // 遍历本进程所有模块,含本体 EXE 与已加载 DLL,逐一验证有效签名
        // 有效签名：Authenticode 内嵌签名，或 Windows 目录签名
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
            if (!PplSetter.SetPpl(selfPid, PplSetter.PsProtectedSignerAntimalware))
            {
                Console.Error.WriteLine("[Service] Self PPL set failed, aborting");
                FailAndExit(
                    "反作弊服务自保护失败",
                    "反作弊运行要求对反作弊服务启用自保护,但是设置失败。\n游戏不会启动。");
                return;
            }
            Console.Error.WriteLine("[Service] Self PPL set successfully");

            // 延迟 2 秒,给驱动初始化缓冲
            _trayIcon.UpdateStatus("准备启动检测引擎...");
            Console.Error.WriteLine("[Service] Waiting 2s before starting engine...");
            Thread.Sleep(2000);

            // 先启动集成式运行时检测引擎，即 BYOVD 反制：附着 + ETW 通信监控 + 进程树快照
            // 引擎启动失败为致命错误:提示用户后退出服务,不启动游戏。
            try
            {
                _runtimeEngine = new RuntimeDetectionEngine(serverUrl: _serverUrl);
                if (_runtimeEngine.Start())
                {
                    Console.Error.WriteLine("[Service] Runtime detection engine started");
                    _trayIcon.UpdateStatus("运行中,检测引擎已启用", true);
                }
                else
                {
                    Console.Error.WriteLine("[Service] Runtime detection engine failed to start");
                    FailAndExit(
                        "运行时检测引擎启动失败",
                        $"反作弊运行要求启用运行时检测引擎,但是失败了:\n{_runtimeEngine.StatusMessage}\n游戏不会启动。");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Service] Runtime engine exception:");
                Console.Error.WriteLine(LogUtil.Detail(ex));
                FailAndExit(
                    "运行时检测引擎启动失败",
                    $"反作弊运行要求启用运行时检测引擎,但是失败:\n{ex.Message}\n游戏不会启动。");
                return;
            }

            // 最后再启动游戏并执行 GameProtect 保护链,创建游戏进程 + 挂起 + 多重保护放在检测引擎之后
            StartGameAndProtect();
        }

        // Keep running until exit
        while (_running)
        {
            Application.DoEvents();
            Thread.Sleep(100);
        }

        // 主循环退出,统一清理,游戏退出或用户点退出都会走到这里
        Cleanup();
    }

    /// <summary>
    /// 以 CREATE_SUSPENDED 启动游戏 → 拿 SYNCHRONIZE 句柄 → 注册等待 → 执行 GameProtect 保护链 → Resume
    /// 保护链,趁挂起执行: 句柄降级保护 → ImageLoad 监控 → 新线程反调试 → 已有线程反调试 → 丢弃高危句柄
    /// 句柄权限在 OpenProcess 时固化,后续仍可 WaitForSingleObject
    /// </summary>
    private void StartGameAndProtect()
    {
        _trayIcon.UpdateStatus("启动游戏中...");
        Console.Error.WriteLine($"[Service] Launching game: {_gameExePath}");

        // 按服务端策略在游戏启动前更新 SiPolicy.p7b,免重启即可刷新驱动阻止策略
        // 失败为致命错误:提示用户后退出服务,不启动游戏。
        if (_runtimeEngine?.SiPolicyUpdateRequired == true)
        {
            _trayIcon.UpdateStatus("更新驱动阻止策略...");
            try
            {
                SiPolicyUpdater.UpdateAsync(_serverUrl).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Service] SiPolicy update failed: {ex.Message}");
                FailAndExit(
                    "驱动阻止策略更新失败",
                    $"你的游戏运营商要求更新驱动阻止策略,但是失败:\n{ex.Message}\n游戏不会启动。");
                return;
            }
        }

        // 按服务端策略选择启动权限,两种模式都是 CREATE_SUSPENDED 挂起创建,保护链与 Job 流程完全一致:
        //   Inherit  — 直接 CreateProcess,游戏进程继承 UserService 自身的提升令牌,即管理员
        //   Explorer — 以当前会话 explorer.exe 为父进程创建,系统按父进程令牌降权 → 标准用户令牌
        // 策略拉取失败时 _runtimeEngine 为 null,按 Explorer 处理,即最小权限。
        var launchMode = _runtimeEngine?.LaunchMode ?? LaunchMode.Explorer;
        Console.Error.WriteLine($"[Service] Launch mode: {launchMode}");

        var (ok, pid, hProcess, hThread) = launchMode == LaunchMode.Explorer
            ? GameLauncher.StartSuspendedAsExplorer(_gameExePath)
            : GameLauncher.StartSuspended(_gameExePath);

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
            // 告知运行时检测引擎游戏 PID,供 ETW ID3 线程反调试事件判定是否属于游戏进程
            _runtimeEngine?.SetProtectedGamePid(pid);

            // 立即对游戏执行保护链,进程还在挂起状态,无窗口期
            // 游戏本身不设 PPL,由内核 GameProtect 系列替代,涵盖句柄降级/ImageLoad/线程反调试/高危句柄丢弃
            // 策略:按服务端开关决定施加哪些保护;启用的项任一步失败 → 终止游戏,避免在无完整保护下运行
            //       关闭的项整段跳过,零开销。
            var protect = _runtimeEngine?.ProtectPolicy ?? new GameProtectPolicy();
            Console.Error.WriteLine(
                $"[Service] Applying GameProtect protection chain to suspended game PID={pid} " +
                $"(handle_downgrade={protect.HandleDowngrade}, image_load_monitor={protect.ImageLoadMonitor}, " +
                $"thread_anti_debug={protect.ThreadAntiDebug}, hide_existing_threads={protect.HideExistingThreads}, " +
                $"drop_handles={protect.DropHandles})");
            _trayIcon.UpdateStatus("设置游戏保护中...");

            // ① 句柄降级保护:Ob 回调,剥夺外部高危进程/线程句柄权限
            if (protect.HandleDowngrade && !PplSetter.GameProtectStart(pid))
            {
                AbortGameStart("句柄降级保护", pid);
                return;
            }

            // ② ImageLoad 监控:目标 PID,用户态 DLL 加载事件经 ETW ID2 回传引擎做签名校验
            if (protect.ImageLoadMonitor && !PplSetter.SetImageLoadMonitor(pid))
            {
                AbortGameStart("ImageLoad 监控", pid);
                return;
            }

            // ③ 新线程反调试:目标进程新建线程执行 ThreadHideFromDebugger,远程注入线程由内核强杀,事件经 ETW ID3 回传
            if (protect.ThreadAntiDebug && !PplSetter.SetThreadAntiDebug(pid))
            {
                AbortGameStart("新线程反调试", pid);
                return;
            }

            // ④ 已有线程反调试:枚举目标进程全部现有线程执行 ThreadHideFromDebugger
            if (protect.HideExistingThreads && !PplSetter.HideExistingThreads(pid))
            {
                AbortGameStart("已有线程反调试", pid);
                return;
            }

            // ⑤ 丢弃其他进程握有的指向游戏进程的高危句柄,即 VM_READ/WRITE/OPERATION
            if (protect.DropHandles && !PplSetter.GameProtectDropHandles(pid))
            {
                AbortGameStart("丢弃高危句柄", pid);
                return;
            }

            Console.Error.WriteLine("[Service] GameProtect protection chain applied");

            // ⑥ 创建作业对象:主进程加入 Job,后代进程如 CS 挂在 HL 下,自动被限制在同一 Job 内。
            //    后代进程创建经完成端口通知 → 自动执行保护链;Job 内活动进程清零 → 游戏整体退出。
            //    必须在 Resume 之前 Assign,趁挂起无窗口期。失败为致命错误。
            _trayIcon.UpdateStatus("创建游戏作业对象...");
            _gameJob = GameJobMonitor.Create(hProcess, pid);
            if (_gameJob == null)
            {
                Console.Error.WriteLine("[Service] Game job creation failed");
                FailAndExit(
                    "游戏作业对象创建失败",
                    "你的游戏运营商要求游戏运行在受保护的作业对象 Job 内,但是创建失败了。\n游戏不会启动。");
                return;
            }
            _gameJob.DescendantProcessCreated += OnDescendantProcessCreated;
            _gameJob.AllProcessesExited += OnGameJobEmpty;

            // 恢复主线程,游戏开始执行
            if(GameLauncher.Resume(hThread) == uint.MaxValue)
            {
                var err = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"[Service] ResumeThread failed: error {err}");
                AbortGameStart("ResumeThread", pid);
                return;
            }

            // 启动驱动加载监控,反向调用
            // 任何新 .sys 加载 → 内核完成 IRP → 监控线程唤醒 → 仅记录,游戏继续运行
            StartLoadImageMonitor();

            // 托盘状态按服务器类型区分:内网开发地址显示"开发模式",此类地址已自动关闭 TLS 证书校验,
            // 外网正式服务器显示"工作",采用强制 HTTPS + 证书固定
            bool lanDev = CertPinning.IsLanDevServerUrl(_serverUrl);
            _trayIcon.UpdateStatus(lanDev ? "运行中,开发模式" : "运行中,工作模式", lanDev);
            _trayIcon.ShowBalloon("Hyperion", $"游戏已启动并保护, PID {pid}",
                System.Windows.Forms.ToolTipIcon.Info);

            Console.Error.WriteLine($"[Service] Game started: PID={pid}, GameProtect=on, Job monitored");
        }
        finally
        {
            // 句柄权限已在保护链时固化,Job 也已 Assign,两个句柄都可关闭
            GameLauncher.CloseHandles(hProcess, hThread);
        }
    }

    /// <summary>
    /// 保护链某一步失败时中止游戏启动:终止挂起的游戏进程,清空保护记录,并提示用户。
    /// 调用方随后应 return,不再 Resume 游戏。
    /// </summary>
    /// <param name="step">失败的保护步骤名称,用于日志/托盘提示</param>
    /// <param name="pid">挂起的游戏进程 PID</param>
    private void AbortGameStart(string step, uint pid)
    {
        Console.Error.WriteLine($"[Service] {step} failed, killing suspended process");
        _trayIcon.UpdateStatus("游戏保护设置失败");
        _trayIcon.ShowBalloon("Hyperion", $"游戏保护 {step} 失败,游戏将被终止",
            System.Windows.Forms.ToolTipIcon.Error);
        PplSetter.KillProcess(pid);
        _protectedPid = 0;
        _protectedExe = "";
    }

    /// <summary>
    /// 致命错误统一出口:托盘气泡告知用户"游戏不会启动",短暂停留确保气泡可见,
    /// 然后执行清理并退出服务。Cleanup 幂等,重复调用无副作用。
    /// 调用方随后应 return,若在 Run 主流程中则直接退出。
    /// </summary>
    /// <param name="title">失败标题,即托盘气泡标题</param>
    /// <param name="detail">完整提示,含运营商要求 + 报错详情 + "游戏不会启动"</param>
    private void FailAndExit(string title, string detail)
    {
        _trayIcon.UpdateStatus("启动失败");
        _trayIcon.ShowBalloon($"Hyperion - {title}", detail, System.Windows.Forms.ToolTipIcon.Error);
        Console.Error.WriteLine($"[Service] FATAL - {title}: {detail.Replace("\n", " | ")}");
        // 气泡通知由 Explorer 展示,主线程必须存活一段时间用户才能看到
        Thread.Sleep(5000);
        Cleanup();
        _running = false;
    }

    /// <summary>
    /// 启动驱动加载监控线程
    /// 通过反向调用 IOCTL_WAIT_LOADIMAGE 挂起一个 IRP,等待内核 PsSetLoadImageNotifyRoutine 回调完成
    /// 收到通知 = 有新 .sys 加载 = 仅记录到日志和托盘提示,游戏继续运行,不触发 Shutdown
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
                // 后台线程执行,不阻塞本监控线程继续监听下一个加载
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

                // 异步弹气球提示,本线程不能直接调 UI
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
    /// 停止驱动加载监控,由 Cleanup 调用
    /// 流程:
    /// 1. 信号取消事件 cancelEvent - 让 WaitLoadImageOnce 的 WaitForMultipleObjects 返回 1
    /// 2. 调 PplSetter.CancelLoadImage() 同步通知驱动完成挂起的 IRP
    ///    绕过 WDF cancel 机制,驱动直接 WdfRequestCompleteWithInformation(STATUS_CANCELLED)
    /// 3. 监控线程的 WaitForSingleObject(hEvent) 立即返回 → 线程退出
    /// 4. Join 监控线程,此时应秒退
    /// 5. 关闭设备句柄,IRP 已完成,CloseHandle 不阻塞
    /// </summary>
    private void StopLoadImageMonitor()
    {
        if (!_loadImageMonitorStarted) return;

        Console.Error.WriteLine("[Service] StopLoadImageMonitor: signaling cancelEvent");
        // 1. 信号取消事件,让 WaitLoadImageOnce 走取消分支
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

        // 3. 等待监控线程退出,IRP 已完成,线程应立即返回
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

        // 4. 关闭句柄,IRP 已完成,CloseHandle 不会阻塞
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
    /// 游戏全部退出回调,Job 内活动进程清零,由 Job 监听线程触发
    /// 不直接做 UI 操作,只设置标志让主循环退出,统一在主线程 Cleanup
    /// </summary>
    private void OnGameJobEmpty()
    {
        Console.Error.WriteLine("[Service] Game job empty (all processes exited), signaling shutdown");
        _gameExited = true;
        _running = false;  // 让主循环退出,主线程走 Cleanup
    }

    /// <summary>
    /// Job 内后代进程创建回调,如 CS 挂在 HL 启动器进程下,由 Job 监听线程触发。
    /// 对新后代进程立即执行保护链,内核多目标,与主进程同时受保护。
    /// 后代进程已在运行中,无法趁挂起设置;启用的项任一步失败 → 终止该后代进程,游戏其余部分继续运行。
    /// 施加哪些保护与主进程一致,同样按服务端 protect 开关决定。
    /// </summary>
    private void OnDescendantProcessCreated(uint pid)
    {
        Console.Error.WriteLine($"[Service] Applying protection chain to descendant PID={pid}");

        // 后代进程可能在主进程保护链之前就已创建,理论上不会,但防御性取值,
        // 这里每次重新读取策略对象,保证与主进程使用同一套开关。
        var protect = _runtimeEngine?.ProtectPolicy ?? new GameProtectPolicy();

        try
        {
            // ① 句柄降级保护:内核 add 语义,主进程保护保持不变
            if (protect.HandleDowngrade && !PplSetter.GameProtectStart(pid)) { KillDescendant(pid, "句柄降级保护"); return; }

            // ② ImageLoad 监控,事件经 ETW ID2 回传引擎做签名校验
            if (protect.ImageLoadMonitor && !PplSetter.SetImageLoadMonitor(pid)) { KillDescendant(pid, "ImageLoad 监控"); return; }

            // ③ 新线程反调试,远程注入线程由内核强杀,事件经 ETW ID3 回传
            if (protect.ThreadAntiDebug && !PplSetter.SetThreadAntiDebug(pid)) { KillDescendant(pid, "新线程反调试"); return; }

            // ④ 已有线程反调试
            if (protect.HideExistingThreads) PplSetter.HideExistingThreads(pid);

            // ⑤ 丢弃其他进程握有的指向该进程的高危句柄
            if (protect.DropHandles) PplSetter.GameProtectDropHandles(pid);

            Console.Error.WriteLine($"[Service] Descendant PID={pid} protected");

            // 异步弹气球提示,本线程不能直接调 UI
            _ = ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    _trayIcon.ShowBalloon("Hyperion", $"游戏子进程已保护, PID {pid}",
                        System.Windows.Forms.ToolTipIcon.Info);
                }
                catch { }
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Descendant protect exception PID={pid}: {ex.Message}");
            KillDescendant(pid, "保护链异常");
        }
    }

    /// <summary>后代进程保护失败:终止该进程并提示,游戏其余部分继续运行。</summary>
    private void KillDescendant(uint pid, string step)
    {
        Console.Error.WriteLine($"[Service] {step} failed for descendant PID={pid}, killing it");
        PplSetter.KillProcess(pid);
        _ = ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                _trayIcon.ShowBalloon("Hyperion", $"游戏子进程保护 {step} 失败,该子进程已被终止",
                    System.Windows.Forms.ToolTipIcon.Error);
            }
            catch { }
        });
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
    /// 统一清理流程,在主线程执行,避免线程安全问题
    /// 0.  停止驱动加载监控 → 停止 GameProtect 保护链,即句柄降级/ImageLoad/新线程反调试 → 退订 ETW,即引擎 Stop
    /// 1. 若游戏还活着且用户主动退出,即非游戏自己退出,TerminateJobObject 终止 Job 内全部进程
    /// 2. 释放 Job 对象
    /// 3. 关闭 kmdf 驱动服务
    /// </summary>
    private void Cleanup()
    {
        if (_cleanupDone) return;
        _cleanupDone = true;

        Console.Error.WriteLine("[Service] Cleanup started");

        // 0. 停止驱动加载监控,必须最先,因为关闭设备句柄会触发内核取消 pending IRP
        StopLoadImageMonitor();

        // 0.3 停止 GameProtect 内核保护链,趁驱动仍加载,按序关闭:
        //     停止句柄降级保护 → 关闭 ImageLoad 监控 → 停止新线程反调试
        Console.Error.WriteLine("[Service] Tearing down GameProtect protection chain");
        PplSetter.GameProtectStop();          // 清空保护列表,多目标全部解除
        PplSetter.SetImageLoadMonitor(0);     // 关闭 ImageLoad 监控,清空目标列表
        PplSetter.StopThreadAntiDebug();      // 停止新线程反调试

        // 0.5 停止运行时检测引擎:退订 ETW ID1/2/3 + 关闭 KernelService 句柄,
        //      否则驱动卸载时句柄悬空;引擎 Stop 内已完成订阅清理。
        try
        {
            _runtimeEngine?.Stop();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Runtime engine stop exception: {ex.Message}");
        }

        // 1. 若游戏还活着,即用户主动退出而非游戏自己退出,终止 Job 内全部进程
        //    多进程游戏一次性全杀,主进程死不带动子进程的场景也覆盖
        if (_gameJob != null && !_gameExited)
        {
            Console.Error.WriteLine("[Service] Terminating game job (user exit)");
            _gameJob.Terminate();
            _trayIcon.ShowBalloon("Hyperion", "游戏进程已结束",
                System.Windows.Forms.ToolTipIcon.Info);
        }
        else if (_gameExited)
        {
            Console.Error.WriteLine("[Service] Game exited on its own, no kill needed");
            _trayIcon.ShowBalloon("Hyperion", "游戏已退出,服务即将关闭",
                System.Windows.Forms.ToolTipIcon.Info);
        }

        _protectedPid = 0;
        _protectedExe = "";

        // 2. 释放 Job 对象:结束监听线程,关闭 Job/完成端口句柄;
        //     KILL_ON_JOB_CLOSE 在此之后才生效,此时 Job 内已无进程,无副作用
        try { _gameJob?.Dispose(); } catch { }
        _gameJob = null;

        // 3. 关闭 kmdf 驱动服务
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
