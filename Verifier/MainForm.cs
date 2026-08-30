using MeasuredBootParser;
using Hyperion.Verifier.RemoteVerify;
using System.Runtime.InteropServices;

namespace Hyperion.Verifier
{
    public partial class MainForm : Form
    {
        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;
        [DllImport("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam); [DllImport("user32.dll")]
        public static extern bool ReleaseCapture();

        private readonly Label[] _statusLabels = new Label[6];

        public MainForm()
        {
            InitializeComponent();

            _statusLabels[0] = StatusLabel_0;
            _statusLabels[1] = StatusLabel_1;
            _statusLabels[2] = StatusLabel_2;
            _statusLabels[3] = StatusLabel_3;
            _statusLabels[4] = StatusLabel_4;
            _statusLabels[5] = StatusLabel_5;

            this.FormBorderStyle = FormBorderStyle.None;
            this.BackColor = Color.White;
            this.Opacity = 0;
        }

        private async void MainForm_Load(object sender, EventArgs e)
        {
            //TermOfUse termOfUse = new TermOfUse();
            //termOfUse.ShowDialog();

            this.StartPosition = FormStartPosition.Manual;
            Rectangle workingArea = Screen.PrimaryScreen.WorkingArea;
            int x = workingArea.Width - this.Width;
            int y = workingArea.Height - this.Height;
            this.Location = new Point(x, y);

            for (double i = 0; i <= 1.0; i += 0.05)
            {
                this.Opacity = i;
                await Task.Delay(10);
            }
            this.Opacity = 1.0;

            await Task.Run(async () =>
            {
                // 本地验证部分
                await NtpTimeSync.NTPMain(ok => UpdateCheckpoint(0, ok));
                await MeasuredBootCore.Run(ok => UpdateCheckpoint(1, ok));
                // 远程验证部分
                await RemoteAttestation.RunAsync(onCheckpoint: (step, ok) => UpdateCheckpoint(step, ok));
            });


            Console.WriteLine("验证完成 5秒后退出");
            await Task.Delay(5000);
            Application.Exit();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            uint blurColor = 0x01010101;
            EnableAcrylic(this.Handle, blurColor);
        }

        // 清空底层背景，让系统亚克力透上来
        protected override void OnPaintBackground(PaintEventArgs e)
        {
            e.Graphics.Clear(Color.Transparent);
        }

        // 在亚克力之上，绘制从左到右渐变透明的图片
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (this.BackgroundImage != null)
            {
                // 绘制图片。图片左边是透明渐变，透明的地方就会漏出底层的亚克力效果
                e.Graphics.DrawImage(this.BackgroundImage, this.ClientRectangle);
            }
        }

        // 实现无边框窗体的拖拽（充当自定义标题栏）
        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }

        private void EnableAcrylic(IntPtr handle, uint color)
        {
            var accent = new AccentPolicy();
            accent.AccentState = AccentState.ACCENT_ENABLE_ACRYLICBLURBEHIND;
            accent.GradientColor = (int)color;

            var accentStructSize = Marshal.SizeOf(accent);
            var accentPtr = Marshal.AllocHGlobal(accentStructSize);
            Marshal.StructureToPtr(accent, accentPtr, false);

            var data = new WindowCompositionAttributeData();
            data.Attribute = WindowCompositionAttribute.WCA_ACCENT_POLICY;
            data.SizeOfData = accentStructSize;
            data.Data = accentPtr;

            NativeMethods.SetWindowCompositionAttribute(handle, ref data);

            Marshal.FreeHGlobal(accentPtr);
        }

        private void UpdateCheckpoint(int index, bool success)
        {
            if (index < 0 || index >= _statusLabels.Length) return;

            if (_statusLabels[index].InvokeRequired)
            {
                _statusLabels[index].Invoke(new Action(() => UpdateCheckpoint(index, success)));
                return;
            }

            _statusLabels[index].Text = success ? "✔" : "✘";
            _statusLabels[index].ForeColor = success ? Color.LimeGreen : Color.Red;
        }

    }

    // --- 底层结构体定义保持不变 ---
    public enum AccentState
    {
        ACCENT_DISABLED = 0,
        ACCENT_ENABLE_GRADIENT = 1,
        ACCENT_ENABLE_TRANSPARENTGRADIENT = 2,
        ACCENT_ENABLE_BLURBEHIND = 3,
        ACCENT_ENABLE_ACRYLICBLURBEHIND = 4,
        ACCENT_INVALID_STATE = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct AccentPolicy
    {
        public AccentState AccentState;
        public int AccentFlags;
        public int GradientColor;
        public int AnimationId;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct WindowCompositionAttributeData
    {
        public WindowCompositionAttribute Attribute;
        public IntPtr Data;
        public int SizeOfData;
    }

    public enum WindowCompositionAttribute
    {
        WCA_ACCENT_POLICY = 19
    }

    internal static class NativeMethods
    {
        [DllImport("user32.dll")]
        internal static extern int SetWindowCompositionAttribute(IntPtr hwnd, ref WindowCompositionAttributeData data);
    }
}
