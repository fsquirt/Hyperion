using System.Drawing.Drawing2D;
using Hyperion.UserService.Comm;

namespace Hyperion.UserService;

/// <summary>
/// UserService 启动加载窗体，
/// 位于屏幕右下角，展示自 Server 拉取的背景图，
/// 底部展示进度条，并在右下角进度条上方以小字展示当前执行步骤。
/// </summary>
public sealed class SplashForm : Form
{
    private readonly string _serverUrl;
    private Image? _bgImage;
    private int _progressPercent = 0;
    private string _statusText = "初始化中...";
    private bool _isError = false;

    private readonly Panel _bottomBar;
    private readonly Label _statusLabel;
    private readonly Panel _progressTrack;
    private readonly Panel _progressBar;

    public SplashForm(string serverUrl)
    {
        _serverUrl = serverUrl;

        // 窗体基础属性：无边框、无任务栏图标且保持置顶
        this.FormBorderStyle = FormBorderStyle.None;
        this.ShowInTaskbar = false;
        this.TopMost = true;
        this.StartPosition = FormStartPosition.Manual;
        this.Size = new Size(480, 270);
        this.DoubleBuffered = true;
        this.BackColor = Color.FromArgb(20, 22, 28);

        // 设置在屏幕右下角，预留 16px 外边距
        var workArea = Screen.PrimaryScreen?.WorkingArea ?? Screen.GetWorkingArea(this);
        this.Location = new Point(workArea.Right - this.Width - 16, workArea.Bottom - this.Height - 16);

        // 状态文字容器，位于右下角进度条上方
        _statusLabel = new Label
        {
            AutoSize = false,
            Height = 22,
            Width = 360,
            TextAlign = ContentAlignment.MiddleRight,
            Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point),
            ForeColor = Color.FromArgb(235, 240, 250),
            BackColor = Color.FromArgb(170, 10, 12, 18),
            Text = _statusText,
            Padding = new Padding(0, 0, 8, 0)
        };

        // 底部进度条轨道，高度设为 6px
        _progressTrack = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 6,
            BackColor = Color.FromArgb(40, 45, 55)
        };

        // 实际进度指示条
        _progressBar = new Panel
        {
            Height = 6,
            Width = 0,
            BackColor = Color.FromArgb(0, 168, 255),
            Location = new Point(0, 0)
        };
        _progressTrack.Controls.Add(_progressBar);

        // 底部组合容器
        _bottomBar = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 32,
            BackColor = Color.Transparent
        };
        _bottomBar.Controls.Add(_progressTrack);

        _statusLabel.Location = new Point(_bottomBar.Width - _statusLabel.Width - 8, 4);
        _statusLabel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _bottomBar.Controls.Add(_statusLabel);

        this.Controls.Add(_bottomBar);

        // 异步拉取服务端背景图
        _ = LoadBackgroundImageAsync();
    }

    private async Task LoadBackgroundImageAsync()
    {
        try
        {
            string splashUrl = $"{_serverUrl.TrimEnd('/')}/api/client/splash-image";
            using var client = CertPinning.CreatePinnedClient(timeout: TimeSpan.FromSeconds(4));
            var resp = await client.GetAsync(splashUrl);
            if (resp.IsSuccessStatusCode)
            {
                var bytes = await resp.Content.ReadAsByteArrayAsync();
                using var ms = new MemoryStream(bytes);
                var img = Image.FromStream(ms);
                _bgImage = new Bitmap(img);
                if (!IsDisposed)
                {
                    this.BeginInvoke(new Action(() => this.Invalidate()));
                }
                return;
            }
        }
        catch
        {
            // 网络异常或未配置时回退至本地默认图片
        }

        // 回退至本地 ico.jpg
        try
        {
            var localIco = Path.Combine(AppContext.BaseDirectory, "ico.jpg");
            if (File.Exists(localIco))
            {
                using var img = Image.FromFile(localIco);
                _bgImage = new Bitmap(img);
                if (!IsDisposed)
                {
                    this.BeginInvoke(new Action(() => this.Invalidate()));
                }
            }
        }
        catch { }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;

        // 绘制背景图，按 Cover 模式居中裁剪并填充
        if (_bgImage != null)
        {
            DrawImageCover(g, _bgImage, this.ClientRectangle);
        }
        else
        {
            using var brush = new LinearGradientBrush(
                this.ClientRectangle,
                Color.FromArgb(15, 23, 42),
                Color.FromArgb(2, 6, 23),
                LinearGradientMode.Vertical);
            g.FillRectangle(brush, this.ClientRectangle);
        }

        // 绘制半透明底层渐变遮罩，使底部小字更清晰
        using (var overlayBrush = new LinearGradientBrush(
            new Rectangle(0, this.Height - 80, this.Width, 80),
            Color.Transparent,
            Color.FromArgb(190, 0, 0, 0),
            LinearGradientMode.Vertical))
        {
            g.FillRectangle(overlayBrush, 0, this.Height - 80, this.Width, 80);
        }

        // 左上角精巧品牌标示
        using (var brandBg = new SolidBrush(Color.FromArgb(140, 10, 15, 25)))
        {
            g.FillRectangle(brandBg, 12, 12, 150, 24);
        }
        using (var brandText = new SolidBrush(Color.FromArgb(220, 230, 245)))
        using (var font = new Font("Segoe UI", 8.5F, FontStyle.Bold))
        {
            g.DrawString("HYPERION ACTIVE DEFENSE", font, brandText, 16, 16);
        }

        // 外层细边框
        using var pen = new Pen(Color.FromArgb(60, 70, 85), 1);
        g.DrawRectangle(pen, 0, 0, this.Width - 1, this.Height - 1);
    }

    private static void DrawImageCover(Graphics g, Image img, Rectangle dest)
    {
        float imgRatio = (float)img.Width / img.Height;
        float destRatio = (float)dest.Width / dest.Height;

        Rectangle src;
        if (imgRatio > destRatio)
        {
            int srcWidth = (int)(img.Height * destRatio);
            int srcX = (img.Width - srcWidth) / 2;
            src = new Rectangle(srcX, 0, srcWidth, img.Height);
        }
        else
        {
            int srcHeight = (int)(img.Width / destRatio);
            int srcY = (img.Height - srcHeight) / 2;
            src = new Rectangle(0, srcY, img.Width, srcHeight);
        }

        g.DrawImage(img, dest, src, GraphicsUnit.Pixel);
    }

    public void UpdateProgress(int percent, string statusText, bool isError = false)
    {
        if (this.IsDisposed) return;

        if (this.InvokeRequired)
        {
            try
            {
                this.BeginInvoke(new Action(() => UpdateProgress(percent, statusText, isError)));
            }
            catch { }
            return;
        }

        _progressPercent = Math.Clamp(percent, 0, 100);
        _statusText = statusText;
        _isError = isError;

        _statusLabel.Text = _statusText;
        if (_isError)
        {
            _statusLabel.ForeColor = Color.FromArgb(255, 100, 100);
            _progressBar.BackColor = Color.FromArgb(235, 60, 60);
        }
        else
        {
            _statusLabel.ForeColor = Color.FromArgb(235, 240, 250);
            _progressBar.BackColor = Color.FromArgb(0, 168, 255);
        }

        int targetWidth = (int)((_progressTrack.Width * _progressPercent) / 100.0);
        _progressBar.Width = targetWidth;
    }

    public void CloseSafely()
    {
        if (this.IsDisposed) return;
        if (this.InvokeRequired)
        {
            try
            {
                this.BeginInvoke(new Action(CloseSafely));
            }
            catch { }
            return;
        }

        this.Close();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _bgImage?.Dispose();
        }
        base.Dispose(disposing);
    }
}

/// <summary>
/// 负责在独立的 STA 线程中运行 SplashForm，避免主线程加载驱动和网络通信阻塞界面渲染。
/// </summary>
public sealed class SplashWindowController : IDisposable
{
    private Thread? _uiThread;
    private SplashForm? _form;
    private readonly ManualResetEventSlim _readyEvent = new();

    public void Show(string serverUrl)
    {
        _uiThread = new Thread(() =>
        {
            try
            {
                Application.SetHighDpiMode(HighDpiMode.SystemAware);
                _form = new SplashForm(serverUrl);
                _form.Load += (_, _) => _readyEvent.Set();
                Application.Run(_form);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Splash] UI 线程异常: {ex.Message}");
                _readyEvent.Set();
            }
        })
        {
            IsBackground = true,
            Name = "SplashUIThread"
        };
        _uiThread.SetApartmentState(ApartmentState.STA);
        _uiThread.Start();
        _readyEvent.Wait(2000);
    }

    public void UpdateProgress(int percent, string text, bool isError = false)
    {
        _form?.UpdateProgress(percent, text, isError);
    }

    public void Close()
    {
        _form?.CloseSafely();
    }

    public void Dispose()
    {
        Close();
        _readyEvent.Dispose();
    }
}
