using System.Net.Http.Json;
using System.Runtime.InteropServices;

namespace Hyperion.UserService;

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
    private readonly string _serverUrl;          // 由 Program.cs 从 appsettings.json + --server 参数解析
    private readonly string _driverPath;
    private readonly string _gameExePath;
    private readonly TrayIcon _trayIcon;
    private bool _driverLoaded;
    private volatile bool _running;              // M1: 跨线程访问需 volatile, OnGameExited 在线程池回调里写, 主线程读
    private uint _protectedPid;        // 当前已保护的游戏 PID,0 表示无游戏运行
    private string _protectedExe = ""; // 当前已保护的游戏可执行路径
    private IntPtr _gameProcessHandle; // 游戏进程句柄(带 SYNCHRONIZE,用于等待)
    private IntPtr _waitHandle;        // RegisterWaitForSingleObject 返回的等待句柄
    private volatile bool _gameExited;          // 由线程池回调写, 主线程读
    private bool _cleanupDone;         // 清理是否已完成(防重入)

    // 驱动加载监控(反向调用)
    private Thread? _loadImageThread;
    private IntPtr _loadImageCancelEvent;  // 手动复位事件,信号后通知监控线程退出
    private IntPtr _loadImageDeviceHandle; // 长生命周期设备句柄
    private volatile bool _loadImageMonitorStarted;

    // Tracker 事件订阅 (ETW + Windows Event)
    // events (winevent+etw) 走 ServerDataClient.PostEvent → /api/tracker/events
    private TrackerIntegration? _tracker;

    // SuperUserService 集成组件
    // _localSink 仅本地 Console 日志;数据上报走 _server (4 种独立 API)
    private LocalLogTrackerSink? _localSink;
    private ServerDataClient? _server;
    private NativeHost? _nativeHost;
    private ProcessSnapshotIntegration? _processSnapshot;
    private DriverAttachOrchestrator? _attachOrchestrator;
    private CommsMonitorIntegration? _commsMonitor;
    private EtwLiveIntegration? _etwLive;

    // H3: Tracker 配置缓存, 启动时拉取一次, 避免三次独立 HTTP GET 导致配置不一致
    private ServerDataClient.TrackerConfig? _trackerConfig;

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
        // H2: serverUrl 由 Program.cs 解析 (appsettings.json + --server 命令行参数),
        //     构造函数保留它, Run() 不再重新读 appsettings.json (之前 --server 参数失效)
        _serverUrl = serverUrl ?? string.Empty;

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

        // 初始化数据上报客户端 + 本地日志 sink
        // 4 种独立 API: events(winevent+etw) / snapshots / kernel-comms / dumps
        // H2: Server URL 由 Program.cs 解析 (appsettings.json + --server 参数),
        //     构造函数已保留到 _serverUrl, 不再重新读 appsettings.json
        _localSink = new LocalLogTrackerSink();
        if (!string.IsNullOrEmpty(_serverUrl))
        {
            Console.Error.WriteLine($"[Service] 初始化数据上报 (本地 + 服务端 {_serverUrl})...");
            _server = new ServerDataClient(_serverUrl);
            // 异步建立会话
            _ = _server.StartSessionAsync(Environment.MachineName, Environment.ProcessId);
        }
        else
        {
            Console.Error.WriteLine("[Service] 初始化数据上报 (仅本地, 未配置服务端 URL)...");
        }

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

        // ═══════════════════════════════════════════════════════════════
        // 启动前防御 3: 进程全量快照 (Security 模式)
        // 初始化 CombinationNative + 拍一次全系统 Security 快照 (含句柄/内存/Token/Protection)
        // 建立 baseline, 后续 Tree 轮询对比检测新增进程
        // ═══════════════════════════════════════════════════════════════
        _trayIcon.UpdateStatus("采集进程快照...");
        Console.Error.WriteLine("[Service] Pre-flight: process security snapshot");
        if (!InitializeNativeAndSnapshot())
        {
            // 快照失败不致命,游戏仍可运行,只是缺少 baseline
            Console.Error.WriteLine("[Service] WARNING: Process snapshot failed, continuing without baseline");
        }

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

            // ═══════════════════════════════════════════════════════════════
            // 驱动扫描 + IAT 危险函数检查 + 设备附着
            // 扫描所有 THIRD_PARTY_WHQL 驱动, 对 IAT 含危险函数的驱动附着其暴露设备
            // 跳过 KernelService.sys (自家驱动, 不能附着自己)
            // ═══════════════════════════════════════════════════════════════
            _trayIcon.UpdateStatus("扫描驱动并附着...");
            Console.Error.WriteLine("[Service] Scanning drivers and attaching devices...");
            ScanAndAttachDrivers();
            Console.Error.WriteLine("[Service] [STEP] ScanAndAttachDrivers done");

            // ═══════════════════════════════════════════════════════════════
            // 启动通信监控 (HeuristicDumper CommsMonitor)
            // 监控被附着驱动设备的 IOCTL 通信, dump 业务文件到 dumpfile\ + filecopy\
            // 使用 MiniDump 模式
            // ═══════════════════════════════════════════════════════════════
            _trayIcon.UpdateStatus("启动通信监控...");
            Console.Error.WriteLine("[Service] [STEP] calling StartCommsMonitor...");
            StartCommsMonitor();
            Console.Error.WriteLine("[Service] [STEP] StartCommsMonitor returned");

            // ═══════════════════════════════════════════════════════════════
            // 启动 ETW 实时订阅 (HeuristicDumper EtwLive)
            // 订阅 KernelService 驱动的 ETW Provider, 实时投递 IOCTL 拦截事件到 sink
            // ═══════════════════════════════════════════════════════════════
            _trayIcon.UpdateStatus("启动 ETW 监控...");
            Console.Error.WriteLine("[Service] [STEP] calling StartEtwLive...");
            StartEtwLive();
            Console.Error.WriteLine("[Service] [STEP] StartEtwLive returned");

            // 延迟 2 秒,给驱动初始化缓冲
            _trayIcon.UpdateStatus("准备启动游戏...");
            Console.Error.WriteLine("[Service] [STEP] Waiting 2s before launching game...");
            Thread.Sleep(2000);

            // 启动游戏并设置 PPL
            Console.Error.WriteLine("[Service] [STEP] calling StartGameAndProtect...");
            StartGameAndProtect();
            Console.Error.WriteLine("[Service] [STEP] StartGameAndProtect returned");
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
            _trayIcon.ShowBalloon("Hyperion", $"无法启动游戏: {_gameExePath}", System.Windows.Forms.ToolTipIcon.Error);
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
                _trayIcon.ShowBalloon("Hyperion", "游戏 PPL 设置失败,游戏将被终止",
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

            // 启动驱动加载监控(反向调用)
            // 任何新 .sys 加载 → 内核完成 IRP → 监控线程唤醒 → 仅记录,游戏继续运行
            StartLoadImageMonitor();

            // 启动 Tracker 事件订阅 (ETW + Windows Event)
            // 监控驱动加载/安装、CodeIntegrity、Defender 等高危事件,本地日志
            // 未来接 Server 上报时只需把 sink 换成 ServerTrackerSink
            StartTracker();

            // 启动进程 Tree 轮询 (每 10 秒一次, 检测新增进程)
            // Security 全量快照已在驱动加载前完成, 这里只启动轻量轮询
            StartTreePolling();

            _trayIcon.UpdateStatus("运行中 (测试模式)", true);
            _trayIcon.ShowBalloon("Hyperion", $"游戏已启动并保护 (PID {pid})",
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

    // ═══════════════════════════════════════════════════════════════
    //  Tracker 事件订阅 (ETW + Windows Event)
    //  在游戏启动后启动,监控驱动加载/安装、CodeIntegrity、Defender 等高危事件。
    //  事件经分级后投递到 ITrackerSink:
    //    - 当前: LocalLogTrackerSink (仅 Console.Error 日志)
    //    - 未来: ServerTrackerSink   (走 HTTP 上报到 Hyperion.Server)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 启动 Tracker 事件订阅。
    /// 幂等:重复调用不会重复订阅。
    /// </summary>
    private void StartTracker()
    {
        if (_tracker != null)
        {
            Console.Error.WriteLine("[Service] Tracker already started");
            return;
        }

        try
        {
            // Tracker 走独立 events API(winevent+etw) + 本地日志
            _tracker = new TrackerIntegration(_server, _localSink!);
            _tracker.Start();
            Console.Error.WriteLine("[Service] Tracker started");
        }
        catch (Exception ex)
        {
            // Tracker 启动失败不致命,游戏仍可运行,只是失去事件监控能力
            Console.Error.WriteLine($"[Service] Tracker start failed: {ex.Message}");
            _tracker = null;
        }
    }

    /// <summary>
    /// 停止 Tracker 事件订阅 (由 Cleanup 调用)。
    /// 顺序:先停 ETW/WinEvent 订阅,再 Flush sink 缓冲。
    /// </summary>
    private void StopTracker()
    {
        if (_tracker == null) return;
        try
        {
            _tracker.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Tracker stop failed: {ex.Message}");
        }
        _tracker = null;
        Console.Error.WriteLine("[Service] Tracker stopped");
    }

    // ═══════════════════════════════════════════════════════════════
    //  SuperUserService 集成组件的 Start/Stop
    //  所有组件共享同一个 ITrackerSink (LocalLogTrackerSink),
    //  未来换 ServerTrackerSink 时所有组件一起切换。
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 初始化 NativeHost 并执行 Security 全量快照。
    /// 在签名检查之后、驱动加载之前调用。
    /// 返回 false 表示快照失败 (不致命,游戏仍可运行)。
    /// </summary>
    private bool InitializeNativeAndSnapshot()
    {
        try
        {
            _nativeHost = new NativeHost();
            if (!_nativeHost.Initialize())
            {
                Console.Error.WriteLine("[Service] NativeHost initialize failed");
                return false;
            }

            _processSnapshot = new ProcessSnapshotIntegration(_nativeHost, _server);
            _processSnapshot.CaptureInitialSecuritySnapshot();
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Native snapshot failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 执行驱动扫描 + IAT 危险函数检查 + 设备附着。
    /// 在 PPL 设置之后调用 (此时驱动已加载,可被扫描)。
    /// </summary>
    private void ScanAndAttachDrivers()
    {
        if (_nativeHost == null)
        {
            Console.Error.WriteLine("[Service] NativeHost not initialized, skipping driver attach");
            return;
        }

        try
        {
            _attachOrchestrator = new DriverAttachOrchestrator(_nativeHost, _server);
            _attachOrchestrator.ScanAndAttach();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Driver attach failed: {ex.Message}");
        }
    }

    /// <summary>
    /// 启动通信监控 (HeuristicDumper CommsMonitor)。
    /// 后台线程运行 FetchComms, dump 业务文件到 dumpfile\ + filecopy\ (MiniDump 模式)。
    /// </summary>
    private void StartCommsMonitor()
    {
        if (_nativeHost == null) { Console.Error.WriteLine("[Service] [STEP] StartCommsMonitor: nativeHost null, skip"); return; }

        try
        {
            Console.Error.WriteLine("[Service] [STEP] StartCommsMonitor: 拉取配置...");
            // 拉取配置: dumpMode + fileCopyEnabled
            var cfg = FetchTrackerConfig();
            Console.Error.WriteLine("[Service] [STEP] StartCommsMonitor: 创建 CommsMonitorIntegration...");
            _commsMonitor = new CommsMonitorIntegration(
                _nativeHost, _server,
                dumpMode: cfg.DumpModeEnum,
                fileCopyEnabled: cfg.FileCopyEnabled);
            Console.Error.WriteLine("[Service] [STEP] StartCommsMonitor: 调用 Start()...");
            _commsMonitor.Start();
            Console.Error.WriteLine($"[Service] [STEP] CommsMonitor started (dump={cfg.DumpMode}, fileCopy={cfg.FileCopyEnabled})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] CommsMonitor start failed: {ex.Message}");
            _commsMonitor = null;
        }
    }

    /// <summary>停止通信监控 (调用 StopComms 设置停止标志, 等待后台线程退出)。</summary>
    private void StopCommsMonitor()
    {
        if (_commsMonitor == null) return;
        try
        {
            _commsMonitor.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] CommsMonitor stop failed: {ex.Message}");
        }
        _commsMonitor = null;
        Console.Error.WriteLine("[Service] CommsMonitor stopped");
    }

    /// <summary>
    /// 启动 ETW 实时订阅 (HeuristicDumper EtwLive)。
    /// 后台线程订阅 KernelService ETW Provider, 实时投递 IOCTL 拦截事件到 sink。
    /// </summary>
    private void StartEtwLive()
    {
        if (_nativeHost == null) { Console.Error.WriteLine("[Service] [STEP] StartEtwLive: nativeHost null, skip"); return; }

        Console.Error.WriteLine("[Service] [STEP] StartEtwLive: 拉取配置...");
        // IOCTL 监听开关:由服务端配置决定,默认关闭
        var cfg = FetchTrackerConfig();
        if (!cfg.IoctlEnabled)
        {
            Console.Error.WriteLine("[Service] [STEP] EtwLive 跳过: IOCTL 监听已关闭 (服务端配置)");
            return;
        }

        try
        {
            Console.Error.WriteLine("[Service] [STEP] StartEtwLive: 创建 EtwLiveIntegration...");
            _etwLive = new EtwLiveIntegration(_nativeHost, _server);
            Console.Error.WriteLine("[Service] [STEP] StartEtwLive: 调用 Start()...");
            _etwLive.Start();
            Console.Error.WriteLine("[Service] [STEP] EtwLive started (IOCTL 监听已开启)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] EtwLive start failed: {ex.Message}");
            _etwLive = null;
        }
    }

    /// <summary>停止 ETW 实时订阅 (调用 StopEtwLive 设置停止标志, 等待后台线程退出)。</summary>
    private void StopEtwLive()
    {
        if (_etwLive == null) return;
        try
        {
            _etwLive.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] EtwLive stop failed: {ex.Message}");
        }
        _etwLive = null;
        Console.Error.WriteLine("[Service] EtwLive stopped");
    }

    /// <summary>
    /// 启动进程 Tree 轮询。
    /// 频率由服务端 /api/tracker/config 配置(默认 10 秒),在启动前拉取。
    /// </summary>
    private void StartTreePolling()
    {
        if (_processSnapshot == null)
        {
            Console.Error.WriteLine("[Service] ProcessSnapshot not initialized, skipping tree polling");
            return;
        }

        try
        {
            var cfg = FetchTrackerConfig();
            _processSnapshot.StartTreePolling(cfg.TreePollIntervalSec);
            Console.Error.WriteLine($"[Service] Tree polling started ({cfg.TreePollIntervalSec}s)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Tree polling start failed: {ex.Message}");
        }
    }

    /// <summary>
    /// 从服务端 /api/tracker/config 拉取 Tracker 配置。
    /// 失败则返回默认值(treePoll=10, ioctl=false, dump=mini, fileCopy=true)。
    /// H3: 第一次调用时拉取并缓存到 _trackerConfig, 后续调用直接返回缓存,
    ///     避免三个 Start* 方法各自独立 HTTP GET 导致:
    ///       1. 浪费 3 次 HTTP 请求
    ///       2. 三次请求之间配置可能变化 (CommsMonitor/EtwLive/TreePolling 拿到不同配置)
    /// </summary>
    private ServerDataClient.TrackerConfig FetchTrackerConfig()
    {
        // 已缓存则直接返回
        if (_trackerConfig != null)
        {
            Console.Error.WriteLine($"[Service] [CFG] 使用缓存配置: treePoll={_trackerConfig.TreePollIntervalSec}s " +
                                    $"ioctl={_trackerConfig.IoctlEnabled} dump={_trackerConfig.DumpMode} " +
                                    $"fileCopy={_trackerConfig.FileCopyEnabled}");
            return _trackerConfig;
        }

        if (_server == null)
        {
            Console.Error.WriteLine("[Service] [CFG] _server null, 用默认配置");
            _trackerConfig = new ServerDataClient.TrackerConfig();
            return _trackerConfig;
        }
        Console.Error.WriteLine("[Service] [CFG] 开始拉取配置...");
        try
        {
            // 用 Task.Run 包一层,避免在 WinForms 主线程上 sync-over-async 死锁
            // (主线程有 SynchronizationContext, 直接 GetAwaiter().GetResult() 会死锁)
            Console.Error.WriteLine("[Service] [CFG] 等待异步完成...");
            var cfg = Task.Run(() => _server.FetchConfigAsync()).GetAwaiter().GetResult()
                ?? new ServerDataClient.TrackerConfig();
            Console.Error.WriteLine($"[Service] [CFG] 拉取成功: treePoll={cfg.TreePollIntervalSec}s ioctl={cfg.IoctlEnabled} dump={cfg.DumpMode} fileCopy={cfg.FileCopyEnabled}");
            _trackerConfig = cfg;
            return _trackerConfig;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] [CFG] 拉取失败,用默认值: {ex.Message}");
            return new ServerDataClient.TrackerConfig();
        }
    }

    /// <summary>停止进程 Tree 轮询。</summary>
    private void StopTreePolling()
    {
        if (_processSnapshot == null) return;
        try
        {
            _processSnapshot.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Service] Tree polling stop failed: {ex.Message}");
        }
        _processSnapshot = null;
        Console.Error.WriteLine("[Service] Tree polling stopped");
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

        // 0. 停止驱动加载监控(必须最先,因为关闭设备句柄会触发内核取消 pending IRP)
        StopLoadImageMonitor();

        // 0.1 停止 Tracker 事件订阅 (ETW + Windows Event)
        // 放在 LoadImage 之后、kill 游戏之前:此时游戏可能还活着,
        // 能继续捕获退出过程的最后一批事件,kill 后再停订阅
        StopTracker();

        // 0.2 停止进程 Tree 轮询 (停止定时器, 不再产生新快照)
        StopTreePolling();

        // 0.3 停止 ETW 实时订阅 (IOCL 拦截事件)
        // 放在 kill 游戏前:捕获退出过程的最后一批 IOCTL 事件
        StopEtwLive();

        // 0.4 停止通信监控 (dump-to-file)
        // 放在 ETW 之后:确保 dump 数据完整 (FetchComms 在 Stop 后返回汇总)
        StopCommsMonitor();

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

        // 5. 释放 NativeHost (CombinationNative 资源)
        _nativeHost?.Dispose();
        _nativeHost = null;

        // 6. 结束服务端会话 (等 Channel 排空 + SendLoop 发完最后一批)
        // M2: 加 5 秒超时, 避免 EndSessionAsync 内部 await _sendLoop (排空 + 最后一次 POST 15s timeout)
        //     阻塞 Cleanup 最坏 16+ 秒
        try
        {
            var endTask = _server?.EndSessionAsync();
            if (endTask != null)
            {
                if (!endTask.Wait(TimeSpan.FromSeconds(5)))
                {
                    Console.Error.WriteLine("[Service] Server end session 超时 5s, 放弃等待");
                }
            }
        }
        catch (Exception ex) { Console.Error.WriteLine($"[Service] Server end session 异常: {ex.Message}"); }

        _trayIcon.UpdateStatus("已退出");
        Console.Error.WriteLine("[Service] Cleanup done");
    }

    public void Dispose()
    {
        // H1: 兜底 — 若异常路径没走 Cleanup (例如 Run() 中途异常), 这里调 Cleanup
        //     确保以下 native handle 被释放:
        //       - _gameProcessHandle / _waitHandle (进程句柄)
        //       - _loadImageDeviceHandle / _loadImageCancelEvent (设备/事件句柄)
        //       - DriverLoader.UnloadDriver() (停止驱动服务)
        //     Cleanup 自身有 _cleanupDone 防重入, 已执行过则只做 trayIcon 兜底释放。
        if (!_cleanupDone)
        {
            try { Cleanup(); }
            catch (Exception ex) { Console.Error.WriteLine($"[Service] Dispose 路径 Cleanup 异常: {ex.Message}"); }
        }

        // 即使 Cleanup 已执行, 各 Integration 的 Dispose 仍兜底调用 (它们内部对重复 dispose 安全)
        _etwLive?.Dispose();
        _etwLive = null;
        _commsMonitor?.Dispose();
        _commsMonitor = null;
        _processSnapshot?.Dispose();
        _processSnapshot = null;
        _tracker?.Dispose();
        _tracker = null;
        _nativeHost?.Dispose();
        _nativeHost = null;
        _server?.Dispose();
        _server = null;
        _trayIcon.Dispose();
    }
}
