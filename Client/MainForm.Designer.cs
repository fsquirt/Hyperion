namespace SEWindows
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            StatusLabel_0 = new Label();
            CheckLabel_0 = new Label();
            StatusLabel_1 = new Label();
            CheckLabel_1 = new Label();
            StatusLabel_2 = new Label();
            CheckLabel_2 = new Label();
            StatusLabel_3 = new Label();
            CheckLabel_3 = new Label();
            StatusLabel_4 = new Label();
            CheckLabel_4 = new Label();
            SuspendLayout();
            // 
            // StatusLabel_0
            // 
            StatusLabel_0.AutoSize = true;
            StatusLabel_0.BackColor = Color.Transparent;
            StatusLabel_0.Font = new Font("Segoe UI Emoji", 11F, FontStyle.Regular, GraphicsUnit.Point, 0);
            StatusLabel_0.ForeColor = Color.Gray;
            StatusLabel_0.Location = new Point(18, 18);
            StatusLabel_0.Name = "StatusLabel_0";
            StatusLabel_0.Size = new Size(22, 20);
            StatusLabel_0.TabIndex = 10;
            StatusLabel_0.Text = "○";
            // 
            // CheckLabel_0
            // 
            CheckLabel_0.AutoSize = true;
            CheckLabel_0.BackColor = Color.Transparent;
            CheckLabel_0.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point, 134);
            CheckLabel_0.ForeColor = Color.White;
            CheckLabel_0.Location = new Point(42, 18);
            CheckLabel_0.Name = "CheckLabel_0";
            CheckLabel_0.Size = new Size(93, 20);
            CheckLabel_0.TabIndex = 11;
            CheckLabel_0.Text = "NTP时间同步";
            // 
            // StatusLabel_1
            // 
            StatusLabel_1.AutoSize = true;
            StatusLabel_1.BackColor = Color.Transparent;
            StatusLabel_1.Font = new Font("Segoe UI Emoji", 11F, FontStyle.Regular, GraphicsUnit.Point, 0);
            StatusLabel_1.ForeColor = Color.Gray;
            StatusLabel_1.Location = new Point(18, 50);
            StatusLabel_1.Name = "StatusLabel_1";
            StatusLabel_1.Size = new Size(22, 20);
            StatusLabel_1.TabIndex = 12;
            StatusLabel_1.Text = "○";
            // 
            // CheckLabel_1
            // 
            CheckLabel_1.AutoSize = true;
            CheckLabel_1.BackColor = Color.Transparent;
            CheckLabel_1.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point, 134);
            CheckLabel_1.ForeColor = Color.White;
            CheckLabel_1.Location = new Point(42, 50);
            CheckLabel_1.Name = "CheckLabel_1";
            CheckLabel_1.Size = new Size(93, 20);
            CheckLabel_1.TabIndex = 13;
            CheckLabel_1.Text = "本地度量验证";
            // 
            // StatusLabel_2
            // 
            StatusLabel_2.AutoSize = true;
            StatusLabel_2.BackColor = Color.Transparent;
            StatusLabel_2.Font = new Font("Segoe UI Emoji", 11F, FontStyle.Regular, GraphicsUnit.Point, 0);
            StatusLabel_2.ForeColor = Color.Gray;
            StatusLabel_2.Location = new Point(18, 82);
            StatusLabel_2.Name = "StatusLabel_2";
            StatusLabel_2.Size = new Size(22, 20);
            StatusLabel_2.TabIndex = 14;
            StatusLabel_2.Text = "○";
            // 
            // CheckLabel_2
            // 
            CheckLabel_2.AutoSize = true;
            CheckLabel_2.BackColor = Color.Transparent;
            CheckLabel_2.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point, 134);
            CheckLabel_2.ForeColor = Color.White;
            CheckLabel_2.Location = new Point(42, 82);
            CheckLabel_2.Name = "CheckLabel_2";
            CheckLabel_2.Size = new Size(96, 20);
            CheckLabel_2.TabIndex = 15;
            CheckLabel_2.Text = "EK证书链验证";
            // 
            // StatusLabel_3
            // 
            StatusLabel_3.AutoSize = true;
            StatusLabel_3.BackColor = Color.Transparent;
            StatusLabel_3.Font = new Font("Segoe UI Emoji", 11F, FontStyle.Regular, GraphicsUnit.Point, 0);
            StatusLabel_3.ForeColor = Color.Gray;
            StatusLabel_3.Location = new Point(18, 114);
            StatusLabel_3.Name = "StatusLabel_3";
            StatusLabel_3.Size = new Size(22, 20);
            StatusLabel_3.TabIndex = 16;
            StatusLabel_3.Text = "○";
            // 
            // CheckLabel_3
            // 
            CheckLabel_3.AutoSize = true;
            CheckLabel_3.BackColor = Color.Transparent;
            CheckLabel_3.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point, 134);
            CheckLabel_3.ForeColor = Color.White;
            CheckLabel_3.Location = new Point(42, 114);
            CheckLabel_3.Name = "CheckLabel_3";
            CheckLabel_3.Size = new Size(84, 20);
            CheckLabel_3.TabIndex = 17;
            CheckLabel_3.Text = "AK凭证验证";
            // 
            // StatusLabel_4
            // 
            StatusLabel_4.AutoSize = true;
            StatusLabel_4.BackColor = Color.Transparent;
            StatusLabel_4.Font = new Font("Segoe UI Emoji", 11F, FontStyle.Regular, GraphicsUnit.Point, 0);
            StatusLabel_4.ForeColor = Color.Gray;
            StatusLabel_4.Location = new Point(18, 146);
            StatusLabel_4.Name = "StatusLabel_4";
            StatusLabel_4.Size = new Size(22, 20);
            StatusLabel_4.TabIndex = 18;
            StatusLabel_4.Text = "○";
            // 
            // CheckLabel_4
            // 
            CheckLabel_4.AutoSize = true;
            CheckLabel_4.BackColor = Color.Transparent;
            CheckLabel_4.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Regular, GraphicsUnit.Point, 134);
            CheckLabel_4.ForeColor = Color.White;
            CheckLabel_4.Location = new Point(42, 146);
            CheckLabel_4.Name = "CheckLabel_4";
            CheckLabel_4.Size = new Size(92, 20);
            CheckLabel_4.TabIndex = 19;
            CheckLabel_4.Text = "PCR引述验证";
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            BackgroundImage = (Image)resources.GetObject("$this.BackgroundImage");
            BackgroundImageLayout = ImageLayout.Zoom;
            ClientSize = new Size(345, 194);
            Controls.Add(StatusLabel_0);
            Controls.Add(CheckLabel_0);
            Controls.Add(StatusLabel_1);
            Controls.Add(CheckLabel_1);
            Controls.Add(StatusLabel_2);
            Controls.Add(CheckLabel_2);
            Controls.Add(StatusLabel_3);
            Controls.Add(CheckLabel_3);
            Controls.Add(StatusLabel_4);
            Controls.Add(CheckLabel_4);
            DoubleBuffered = true;
            Name = "MainForm";
            Text = "SEWindows";
            Load += MainForm_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private Label CheckLabel_0, StatusLabel_0;
        private Label CheckLabel_1, StatusLabel_1;
        private Label CheckLabel_2, StatusLabel_2;
        private Label CheckLabel_3, StatusLabel_3;
        private Label CheckLabel_4, StatusLabel_4;
    }
}