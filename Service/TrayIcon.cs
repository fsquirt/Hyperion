using System.Drawing;

namespace SEWindows.Service;

/// <summary>
/// 系统托盘图标
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private NotifyIcon? _notifyIcon;
    private readonly Action _onExit;

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
        contextMenu.Items.Add("SEWindows Anti-Cheat", null, (_, _) => { });
        contextMenu.Items.Add("-");
        contextMenu.Items.Add("Status: Waiting", null, (_, _) => { });
        contextMenu.Items.Add("-");
        var exitItem = contextMenu.Items.Add("Exit", null, (_, _) => _onExit());
        exitItem.ForeColor = Color.Red;

        _notifyIcon = new NotifyIcon
        {
            Icon = icon,
            Text = "SEWindows Anti-Cheat",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        _notifyIcon.ShowBalloonTip(3000, "SEWindows", "Anti-cheat service started", ToolTipIcon.Info);
    }

    public void UpdateStatus(string text, bool isTestMode = false)
    {
        if (_notifyIcon?.ContextMenuStrip?.Items.Count >= 4)
        {
            _notifyIcon.ContextMenuStrip.Items[2].Text = $"Status: {text}";
            _notifyIcon.ContextMenuStrip.Items[2].ForeColor = isTestMode ? Color.Orange : Color.Green;
        }
        _notifyIcon!.Text = $"SEWindows: {text}";
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
