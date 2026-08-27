using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 模拟键鼠检测器(全局低级钩子)。
///
/// 参考 MKMonitorTest.cpp 原型:安装 WH_MOUSE_LL / WH_KEYBOARD_LL 全局低级钩子,
/// 通过 LLMHF_INJECTED / LLKHF_INJECTED(含 Lower_IL 变体)标志识别 SendInput 等
/// 软件注入的模拟键盘鼠标事件(模拟点击 / 宏 / 自动化挂机)。
///
/// 按服务端策略工作:
///   Report — 检测到模拟事件时回调 onEvent(引擎侧走会话事件通道上报 Server);
///            同一钩子 500ms 内只上报一次,防止高频注入(如每帧模拟移动)刷爆事件队列
///   Block  — 返回 1 吞掉事件,模拟操作不生效
///
/// 两个开关均关闭时由调用方决定不安装钩子(零开销)。
/// 钩子安装与消息泵运行在专用后台线程;Dispose 通过 WM_QUIT 优雅退出。
/// </summary>
public sealed class MockInputMonitor : IDisposable
{
    /// <summary>同一线程钩子两次上报之间的最小间隔。</summary>
    private static readonly TimeSpan ReportInterval = TimeSpan.FromMilliseconds(500);

    /// <summary>检测到的模拟输入事件(供上报)。</summary>
    public sealed record MockInputEventInfo(string Source, string Action, string Detail);

    private readonly object _gate = new();
    private Thread? _hookThread;
    private uint _hookThreadId;

    // 钩子句柄与回调委托(委托必须保活,防止 GC 回收后钩子崩溃)
    private IntPtr _mouseHook;
    private IntPtr _keyboardHook;
    private readonly LowLevelMouseProc _mouseProc;
    private readonly LowLevelKeyboardProc _keyboardProc;

    private volatile bool _block;
    private volatile bool _report;
    private Action<MockInputEventInfo>? _onEvent;
    private long _lastMouseReportTicks;
    private long _lastKeyboardReportTicks;

    public MockInputMonitor()
    {
        _mouseProc = MouseProc;
        _keyboardProc = KeyboardProc;
    }

    // ═══════════════════════════════════════════════════════════════
    //  生命周期
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// 启动钩子线程并安装全局低级钩子。
    /// </summary>
    /// <param name="block">拦截(吞掉)模拟事件</param>
    /// <param name="report">检测到模拟事件时回调 onEvent</param>
    /// <param name="onEvent">事件回调(钩子线程调用,须快速返回;引擎侧仅做非阻塞入队)</param>
    public void Start(bool block, bool report, Action<MockInputEventInfo> onEvent)
    {
        lock (_gate)
        {
            if (_hookThread != null) return;
            _block = block;
            _report = report;
            _onEvent = onEvent;

            _hookThread = new Thread(HookLoop)
            {
                IsBackground = true,
                Name = "MockInputMonitor",
            };
            _hookThread.Start();
        }
        Console.WriteLine($"[MockInput] 全局低级钩子已启动 (report={report}, block={block})");
    }

    private void HookLoop()
    {
        _hookThreadId = GetCurrentThreadId();

        _mouseHook = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc, GetModuleHandle(null), 0);
        if (_mouseHook == IntPtr.Zero)
            Console.Error.WriteLine($"[MockInput] 安装鼠标钩子失败,错误码 {Marshal.GetLastWin32Error()}");

        _keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc, GetModuleHandle(null), 0);
        if (_keyboardHook == IntPtr.Zero)
            Console.Error.WriteLine($"[MockInput] 安装键盘钩子失败,错误码 {Marshal.GetLastWin32Error()}");

        // 消息泵保持钩子存活;Dispose 投递 WM_QUIT 退出(GetMessage 返回 0)
        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(in msg);
            DispatchMessage(in msg);
        }

        if (_mouseHook != IntPtr.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = IntPtr.Zero; }
        if (_keyboardHook != IntPtr.Zero) { UnhookWindowsHookEx(_keyboardHook); _keyboardHook = IntPtr.Zero; }
        Console.WriteLine("[MockInput] 钩子已卸载,线程退出");
    }

    public void Dispose()
    {
        Thread? t;
        uint tid;
        lock (_gate)
        {
            t = _hookThread;
            tid = _hookThreadId;
            _hookThread = null;
            _onEvent = null;
        }
        if (t == null) return;

        // 投递 WM_QUIT 结束消息泵,钩子在线程退出前自行卸载
        PostThreadMessage(tid, WM_QUIT, IntPtr.Zero, IntPtr.Zero);
        try { t.Join(3000); } catch { }
    }

    // ═══════════════════════════════════════════════════════════════
    //  鼠标钩子回调
    // ═══════════════════════════════════════════════════════════════

    private IntPtr MouseProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            var p = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
            // 0x01 = LLMHF_INJECTED, 0x02 = LLMHF_LOWER_IL_INJECTED
            bool injected = (p.flags & 0x01) != 0 || (p.flags & 0x02) != 0;
            if (injected)
            {
                uint msg = (uint)wParam.ToInt64();
                if (msg == WM_MOUSEMOVE)
                {
                    ReportOnce(ref _lastMouseReportTicks, "Mouse", "模拟鼠标移动",
                        $"坐标 ({p.pt.x}, {p.pt.y})");
                }
                else if (msg is WM_LBUTTONDOWN or WM_LBUTTONUP or WM_RBUTTONDOWN
                              or WM_RBUTTONUP or WM_MBUTTONDOWN or WM_MBUTTONUP)
                {
                    string action = msg switch
                    {
                        WM_LBUTTONDOWN => "左键按下",
                        WM_LBUTTONUP => "左键抬起",
                        WM_RBUTTONDOWN => "右键按下",
                        WM_RBUTTONUP => "右键抬起",
                        WM_MBUTTONDOWN => "中键按下",
                        _ => "中键抬起",
                    };
                    Report("Mouse", $"模拟鼠标点击 {action}", $"坐标 ({p.pt.x}, {p.pt.y})");
                }

                if (_block) return new IntPtr(1); // 吞掉模拟事件
            }
        }
        return CallNextHookEx(_mouseHook, nCode, wParam, lParam);
    }

    // ═══════════════════════════════════════════════════════════════
    //  键盘钩子回调
    // ═══════════════════════════════════════════════════════════════

    private IntPtr KeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0)
        {
            uint msg = (uint)wParam.ToInt64();
            if (msg is WM_KEYDOWN or WM_SYSKEYDOWN or WM_KEYUP or WM_SYSKEYUP)
            {
                var p = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                // 0x10 = LLKHF_INJECTED, 0x02 = LLKHF_LOWER_IL_INJECTED
                bool injected = (p.flags & 0x10) != 0 || (p.flags & 0x02) != 0;
                if (injected)
                {
                    string action = msg is WM_KEYDOWN or WM_SYSKEYDOWN ? "按下" : "抬起";
                    ReportOnce(ref _lastKeyboardReportTicks, "Keyboard", $"模拟键盘{action}",
                        $"VK=0x{p.vkCode:X} ScanCode={p.scanCode}");

                    if (_block) return new IntPtr(1); // 吞掉模拟事件
                }
            }
        }
        return CallNextHookEx(_keyboardHook, nCode, wParam, lParam);
    }

    // ═══════════════════════════════════════════════════════════════
    //  上报(点击类事件逐条上报;移动/按键类按 500ms 节流,防高频注入刷爆队列)
    // ═══════════════════════════════════════════════════════════════

    private void Report(string source, string action, string detail)
    {
        try { _onEvent?.Invoke(new MockInputEventInfo(source, action, detail)); }
        catch { /* 回调异常不影响钩子 */ }
    }

    private void ReportOnce(ref long lastTicks, string source, string action, string detail)
    {
        var now = Stopwatch.GetTimestamp();
        var last = Interlocked.Read(ref lastTicks);
        if ((now - last) * 1000.0 / Stopwatch.Frequency < ReportInterval.TotalMilliseconds)
            return;
        Interlocked.Exchange(ref lastTicks, now);
        Report(source, action, detail);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Win32
    // ═══════════════════════════════════════════════════════════════

    private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    private const int WH_MOUSE_LL = 14;
    private const int WH_KEYBOARD_LL = 13;
    private const uint WM_MOUSEMOVE = 0x0200;
    private const uint WM_LBUTTONDOWN = 0x0201, WM_LBUTTONUP = 0x0202;
    private const uint WM_RBUTTONDOWN = 0x0204, WM_RBUTTONUP = 0x0205;
    private const uint WM_MBUTTONDOWN = 0x0207, WM_MBUTTONUP = 0x0208;
    private const uint WM_KEYDOWN = 0x0100, WM_KEYUP = 0x0101;
    private const uint WM_SYSKEYDOWN = 0x0104, WM_SYSKEYUP = 0x0105;
    private const uint WM_QUIT = 0x0012;

    [StructLayout(LayoutKind.Sequential)]
    private struct MSLLHOOKSTRUCT
    {
        public POINT pt;
        public uint mouseData;
        public uint flags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x, y; }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll")]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(in MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(in MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern bool PostThreadMessage(uint idThread, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public nint wParam;
        public nint lParam;
        public uint time;
        public POINT pt;
    }
}
