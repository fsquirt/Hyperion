using System.Drawing;

namespace SEWindows.UserService;

/// <summary>
/// 系统托盘图标
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private NotifyIcon? _notifyIcon;
    private readonly Action _onExit;
    private const string StatusItemName = "status";

    public TrayIcon(Action onExit)
    {
        _onExit = onExit;
    }

    public void Show()
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "ico.jpg");
        Icon icon;
        if (File.Exists(iconPath))
        {
            using var img = Image.FromFile(iconPath);
            using var bmp = new Bitmap(img, 16, 16);
            icon = Icon.FromHandle(bmp.GetHicon());
        }
        else
        {
            icon = SystemIcons.Shield;
        }

        var contextMenu = new ContextMenuStrip();

        // 标题项(不可点击)
        var titleItem = contextMenu.Items.Add("SEWindows 反作弊");
        titleItem.ForeColor = Color.DarkBlue;
        contextMenu.Items.Add("-");

        // 状态项(用 Name 标记,便于 UpdateStatus 查找)
        var statusItem = contextMenu.Items.Add("状态: 等待中");
        statusItem.Name = StatusItemName;
        statusItem.ForeColor = Color.Green;
        contextMenu.Items.Add("-");

        // 退出 — 服务和游戏同生共死,一个项同时结束两者
        var exitItem = contextMenu.Items.Add("退出", null, (_, _) => _onExit());
        exitItem.ForeColor = Color.Red;

        _notifyIcon = new NotifyIcon
        {
            Icon = icon,
            Text = "SEWindows 反作弊",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        _notifyIcon.ShowBalloonTip(3000, "SEWindows", "反作弊服务已启动", ToolTipIcon.Info);
    }

    public void UpdateStatus(string text, bool isTestMode = false)
    {
        if (_notifyIcon?.ContextMenuStrip != null)
        {
            var statusItem = _notifyIcon.ContextMenuStrip.Items.Find(StatusItemName, false).FirstOrDefault();
            if (statusItem != null)
            {
                statusItem.Text = $"状态: {text}";
                statusItem.ForeColor = isTestMode ? Color.Orange : Color.Green;
            }
        }
        if (_notifyIcon != null)
        {
            // NotifyIcon.Text 最长 63 字符
            var full = $"SEWindows: {text}";
            _notifyIcon.Text = full.Length > 63 ? full[..63] : full;
        }
    }

    public void ShowBalloon(string title, string text, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _notifyIcon?.ShowBalloonTip(3000, title, text, icon);
    }

    public void Dispose()
    {
        _notifyIcon!.Visible = false;
        _notifyIcon.Dispose();
    }
}
