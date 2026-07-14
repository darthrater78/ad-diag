using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

#nullable enable
namespace AdDiag;

static class Program
{
    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, "Global\\AdDiag_SingleInstance", out bool isNew);
        if (!isNew)
        {
            MessageBox.Show("AD Diagnostics is already running.", "AD Diag",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}

class MainForm : Form
{
    static readonly Color BgColor = Color.FromArgb(0x0f, 0x11, 0x17);
    static readonly Color SurfaceColor = Color.FromArgb(0x1a, 0x1d, 0x27);
    static readonly Color BorderColor = Color.FromArgb(0x2a, 0x2d, 0x3a);
    static readonly Color TextColor = Color.FromArgb(0xe2, 0xe4, 0xea);
    static readonly Color DimColor = Color.FromArgb(0x8b, 0x8f, 0xa3);
    static readonly Color PassColor = Color.FromArgb(0x34, 0xd3, 0x99);
    static readonly Color FailColor = Color.FromArgb(0xf8, 0x71, 0x71);
    static readonly Color WarnColor = Color.FromArgb(0xfb, 0xbf, 0x24);
    static readonly Color SkipColor = Color.FromArgb(0x6b, 0x72, 0x80);
    static readonly Color AccentColor = Color.FromArgb(0x60, 0xa5, 0xfa);
    static readonly Color AccentDimColor = Color.FromArgb(0x25, 0x63, 0xeb);
    static readonly Regex HostnamePattern = new(@"^[a-zA-Z0-9.\-]+$");
    static readonly Pen BorderPen = new(BorderColor);

    static readonly Font GroupHeaderFont = new("Segoe UI", 8f, FontStyle.Bold);
    static readonly Font TestNameFont = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font TestDetailFont = new("Cascadia Code", 8f);
    static readonly Font PlaceholderFont = new("Segoe UI", 10f);
    static readonly SolidBrush PassBrush = new(PassColor);
    static readonly SolidBrush FailBrush = new(FailColor);
    static readonly SolidBrush WarnBrush = new(WarnColor);
    static readonly SolidBrush SkipBrush = new(SkipColor);
    static readonly SolidBrush AccentBrush = new(AccentColor);
    static readonly Font TabFontActive = new("Segoe UI", 8.5f, FontStyle.Bold);
    static readonly Font TabFontInactive = new("Segoe UI", 8.5f);

    readonly TextBox _txtDomain, _txtDc;
    readonly CheckBox _chkDcSuffix;
    readonly Button _btnRun, _btnExport, _btnClear, _btnTabResults, _btnTabGuide, _btnTabGp, _btnTabTickets;
    readonly Button _btnGpRefresh, _btnGpUpdate, _btnPurgeTickets;
    readonly CheckBox _chkGpForce;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly Panel _summaryPanel, _resultsCanvas, _resultsScrollPanel, _historyPanel, _gpPanel, _ticketsPanel;
    readonly RichTextBox _guideBox, _gpBox, _ticketsBox;
    bool _gpRunning;
    bool _showingExplainer;
    List<TestGroup>? _lastResults;
    List<TestGroup>? _renderedGroups;
    bool _renderRunning;
    string? _placeholderText;
    readonly List<DiagRun> _runHistory = [];
    int _selectedRunIndex = -1;
    CancellationTokenSource? _runCts;


    public MainForm()
    {
        Text = "AD Diagnostics";
        Size = new Size(820, 900);
        MinimumSize = new Size(600, 500);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = BgColor;
        ForeColor = TextColor;
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;
        var exePath = Environment.ProcessPath ?? Application.ExecutablePath;
        var extracted = Icon.ExtractAssociatedIcon(exePath);
        if (extracted != null) Icon = extracted;

        var mainPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = Padding.Empty };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            AutoSize = false,
            Padding = Padding.Empty,
            Margin = Padding.Empty,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // header
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // config
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // actions
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // summary
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // content
        layout.RowCount = 5;

        // Header
        var header = new Panel { Height = 34, Dock = DockStyle.Fill };
        header.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, header.Height - 1, header.Width, header.Height - 1);
        var lblTitle = new Label { Text = "AD Diagnostics", ForeColor = TextColor, Font = new Font("Segoe UI", 11f, FontStyle.Bold), AutoSize = true, Location = new Point(10, 6) };
        var lblTag = new Label { Text = " v1.0.0 ", ForeColor = AccentColor, BackColor = AccentDimColor, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, Location = new Point(148, 10) };
        var lnkGithub = new LinkLabel { Text = "GitHub", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkGithub.LinkClicked += (s, e) => Process.Start(new ProcessStartInfo { FileName = "https://github.com/darthrater78/ad-diag", UseShellExecute = true });
        var lnkRelease = new LinkLabel { Text = "Release Notes", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkRelease.LinkClicked += (s, e) => Process.Start(new ProcessStartInfo { FileName = "https://github.com/darthrater78/ad-diag/releases/latest", UseShellExecute = true });
        header.Controls.AddRange([lblTitle, lblTag, lnkGithub, lnkRelease]);
        header.Resize += (s, e) =>
        {
            lnkRelease.Location = new Point(header.ClientSize.Width - lnkRelease.Width - 10, 10);
            lnkGithub.Location = new Point(lnkRelease.Left - lnkGithub.Width - 12, 10);
        };
        layout.Controls.Add(header, 0, 0);

        // Config
        var configPanel = new Panel { Height = 60, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        _txtDomain = MakeInput(configPanel, "DOMAIN", 0, 0);
        _txtDc = MakeInput(configPanel, "DC HOSTNAME (optional)", 1, 0);

        _chkDcSuffix = new CheckBox { Text = "+ domain suffix", ForeColor = Color.White, Font = new Font("Segoe UI", 7.5f, FontStyle.Bold), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(0, 2) };
        configPanel.Controls.Add(_chkDcSuffix);
        configPanel.Resize += (s, e) =>
        {
            _chkDcSuffix.Location = new Point(configPanel.ClientSize.Width / 2 + 4 + 130, 2);
        };

        layout.Controls.Add(configPanel, 0, 1);

        // Actions
        var actionsPanel = new Panel { Height = 36, Dock = DockStyle.Fill };
        actionsPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, actionsPanel.Height - 1, actionsPanel.Width, actionsPanel.Height - 1);
        _btnRun = new Button { Text = "Run Diagnostics", BackColor = AccentColor, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(130, 26), Location = new Point(10, 4), Cursor = Cursors.Hand };
        _btnRun.FlatAppearance.BorderSize = 0;
        _btnRun.Click += BtnRun_Click;
        _btnExport = new Button { Text = "Export Results", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(110, 26), Location = new Point(148, 4), Enabled = false, Cursor = Cursors.Hand };
        _btnExport.FlatAppearance.BorderColor = BorderColor;
        _btnExport.Click += BtnExport_Click;
        _btnClear = new Button { Text = "Clear Results", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(266, 4), Cursor = Cursors.Hand };
        _btnClear.FlatAppearance.BorderColor = BorderColor;
        _btnClear.Click += BtnClear_Click;
        var btnReset = new Button { Text = "Reset All", BackColor = SurfaceColor, ForeColor = FailColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(75, 26), Location = new Point(374, 4), Cursor = Cursors.Hand };
        btnReset.FlatAppearance.BorderColor = BorderColor;
        btnReset.Click += BtnReset_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = false, Location = new Point(460, 4), Size = new Size(340, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
        actionsPanel.Controls.AddRange([_btnRun, _btnExport, _btnClear, btnReset, _lblStatus]);
        layout.Controls.Add(actionsPanel, 0, 2);

        // Summary bar
        _summaryPanel = new Panel { Height = 26, Dock = DockStyle.Fill, Visible = false };
        _summaryPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _summaryPanel.Height - 1, _summaryPanel.Width, _summaryPanel.Height - 1);
        var monoFont = new Font("Cascadia Code", 9f, FontStyle.Bold);
        _lblPassCount = new Label { Text = "0", ForeColor = PassColor, Font = monoFont, AutoSize = true, Location = new Point(10, 4) };
        var lblPassText = new Label { Text = "passed", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(24, 5) };
        _lblFailCount = new Label { Text = "0", ForeColor = FailColor, Font = monoFont, AutoSize = true, Location = new Point(80, 4) };
        var lblFailText = new Label { Text = "failed", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(94, 5) };
        _lblWarnCount = new Label { Text = "0", ForeColor = WarnColor, Font = monoFont, AutoSize = true, Location = new Point(140, 4) };
        var lblWarnText = new Label { Text = "warnings", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(154, 5) };
        _summaryPanel.Controls.AddRange([_lblPassCount, lblPassText, _lblFailCount, lblFailText, _lblWarnCount, lblWarnText]);
        layout.Controls.Add(_summaryPanel, 0, 3);

        // Content area with tab bar
        var contentWrapper = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };

        var tabBar = new Panel { Height = 30, Dock = DockStyle.Top, BackColor = BgColor };
        tabBar.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, tabBar.Height - 1, tabBar.Width, tabBar.Height - 1);
        _btnTabResults = new Button { Text = "Results", FlatStyle = FlatStyle.Flat, BackColor = SurfaceColor, ForeColor = AccentColor, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), Size = new Size(80, 26), Location = new Point(10, 2), Cursor = Cursors.Hand };
        _btnTabResults.FlatAppearance.BorderColor = BorderColor;
        _btnTabResults.FlatAppearance.BorderSize = 1;
        _btnTabResults.Click += (s, e) => SwitchTab("results");
        _btnTabGuide = new Button { Text = "Guide", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(80, 26), Location = new Point(94, 2), Cursor = Cursors.Hand };
        _btnTabGuide.FlatAppearance.BorderColor = BorderColor;
        _btnTabGuide.FlatAppearance.BorderSize = 1;
        _btnTabGuide.Click += (s, e) => SwitchTab("guide");
        _btnTabGp = new Button { Text = "Group Policy", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(110, 26), Location = new Point(178, 2), Cursor = Cursors.Hand };
        _btnTabGp.FlatAppearance.BorderColor = BorderColor;
        _btnTabGp.FlatAppearance.BorderSize = 1;
        _btnTabGp.Click += (s, e) => { SwitchTab("gp"); RefreshGpTab(); };
        _btnTabTickets = new Button { Text = "Kerberos Tickets", FlatStyle = FlatStyle.Flat, BackColor = BgColor, ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Size = new Size(130, 26), Location = new Point(292, 2), Cursor = Cursors.Hand };
        _btnTabTickets.FlatAppearance.BorderColor = BorderColor;
        _btnTabTickets.FlatAppearance.BorderSize = 1;
        _btnTabTickets.Click += (s, e) => { SwitchTab("tickets"); RefreshTickets(); };
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide, _btnTabGp, _btnTabTickets]);

        // Results canvas (owner-drawn)
        _resultsScrollPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = BgColor };
        _resultsCanvas = new Panel { Location = Point.Empty, BackColor = BgColor, Height = 100 };
        _resultsCanvas.GetType().GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(_resultsCanvas, true);
        _resultsCanvas.Paint += PaintResults;
        _resultsScrollPanel.Controls.Add(_resultsCanvas);

        _resultsScrollPanel.Resize += (s, e) =>
        {
            int w = _resultsScrollPanel.ClientSize.Width;
            if (w > 0 && _resultsCanvas.Width != w)
            {
                _resultsCanvas.Width = w;
                _resultsCanvas.Height = MeasureResultsHeight(w);
                _resultsCanvas.Invalidate();
            }
        };

        // Guide (RichTextBox)
        _guideBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = BgColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            Visible = false,
        };
        PopulateGuide();

        // Group Policy tab
        _gpBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = BgColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _btnGpRefresh = new Button { Text = "Refresh", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Cursor = Cursors.Hand };
        _btnGpRefresh.FlatAppearance.BorderColor = BorderColor;
        _btnGpRefresh.Click += (s, e) => RefreshGpTab();
        _btnGpUpdate = new Button { Text = "Run gpupdate", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(110, 28), Cursor = Cursors.Hand };
        _btnGpUpdate.FlatAppearance.BorderColor = BorderColor;
        _btnGpUpdate.Click += BtnGpUpdate_Click;
        _chkGpForce = new CheckBox { Text = "Force", ForeColor = WarnColor, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), AutoSize = true, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand };
        var gpBtnPanel = new Panel { Height = 34, Dock = DockStyle.Bottom, BackColor = BgColor };
        _btnGpRefresh.Location = new Point(10, 3);
        _btnGpUpdate.Location = new Point(100, 3);
        _chkGpForce.Location = new Point(216, 8);
        gpBtnPanel.Controls.AddRange([_btnGpRefresh, _btnGpUpdate, _chkGpForce]);
        _gpPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _gpPanel.Controls.Add(_gpBox);
        _gpPanel.Controls.Add(gpBtnPanel);
        AppendGpLine("Switch to this tab to load Group Policy details, or click Refresh.\n", DimColor);

        // Kerberos Tickets tab
        _ticketsBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = BgColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Cascadia Code", 9f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _btnPurgeTickets = new Button { Text = "Purge All Tickets", BackColor = SurfaceColor, ForeColor = WarnColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(140, 28), Cursor = Cursors.Hand };
        _btnPurgeTickets.FlatAppearance.BorderColor = BorderColor;
        _btnPurgeTickets.Click += BtnPurgeTickets_Click;
        var ticketsRefreshBtn = new Button { Text = "Refresh", BackColor = SurfaceColor, ForeColor = DimColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Cursor = Cursors.Hand };
        ticketsRefreshBtn.FlatAppearance.BorderColor = BorderColor;
        ticketsRefreshBtn.Click += (s, e) => RefreshTickets();
        var ticketsInfoBtn = new Button { Text = "What is this?", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28), Cursor = Cursors.Hand };
        ticketsInfoBtn.FlatAppearance.BorderColor = BorderColor;
        ticketsInfoBtn.Click += (s, e) => { if (_showingExplainer) { _showingExplainer = false; RefreshTickets(); } else ShowTicketsExplainer(); };
        var ticketsBtnPanel = new Panel { Height = 34, Dock = DockStyle.Bottom, BackColor = BgColor };
        _btnPurgeTickets.Location = new Point(10, 3);
        ticketsRefreshBtn.Location = new Point(158, 3);
        ticketsInfoBtn.Location = new Point(246, 3);
        ticketsBtnPanel.Controls.AddRange([_btnPurgeTickets, ticketsRefreshBtn, ticketsInfoBtn]);
        _ticketsPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _ticketsPanel.Controls.Add(_ticketsBox);
        _ticketsPanel.Controls.Add(ticketsBtnPanel);

        _historyPanel = new Panel { Height = 28, Dock = DockStyle.Top, BackColor = BgColor, Visible = false };
        _historyPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _historyPanel.Height - 1, _historyPanel.Width, _historyPanel.Height - 1);

        contentWrapper.Controls.Add(_resultsScrollPanel);
        contentWrapper.Controls.Add(_guideBox);
        contentWrapper.Controls.Add(_gpPanel);
        contentWrapper.Controls.Add(_ticketsPanel);
        contentWrapper.Controls.Add(_historyPanel);
        contentWrapper.Controls.Add(tabBar);
        layout.Controls.Add(contentWrapper, 0, 4);

        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);

        _placeholderText = "Enter target domain and run diagnostics";

        Load += (s, e) =>
        {
            _resultsCanvas.Width = _resultsScrollPanel.ClientSize.Width;
            _resultsCanvas.Height = MeasureResultsHeight(_resultsCanvas.Width);
            _resultsCanvas.Invalidate();
        };

        FormClosing += (s, e) =>
        {
            _runCts?.Cancel();
        };
        FormClosed += (s, e) => Environment.Exit(0);
        _ = DetectDomainAsync();
    }

    async Task DetectDomainAsync()
    {
        if (!string.IsNullOrWhiteSpace(_txtDomain.Text)) return; // don't override a saved value

        try
        {
            string? domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");

            if (string.IsNullOrWhiteSpace(domain))
            {
                domain = await Task.Run(() =>
                {
                    try
                    {
                        string dsreg = RunProcess("dsregcmd", "/status", timeoutMs: 5000);
                        var m = Regex.Match(dsreg, @"Device Domain\s*:\s*(\S+)", RegexOptions.IgnoreCase);
                        return m.Success ? m.Groups[1].Value.Trim() : null;
                    }
                    catch { return null; }
                });
            }

            if (string.IsNullOrWhiteSpace(domain))
            {
                domain = await Task.Run(() =>
                {
                    try { return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName; }
                    catch { return null; }
                });
            }

            if (IsDisposed || string.IsNullOrWhiteSpace(domain)) return;
            if (!string.IsNullOrWhiteSpace(_txtDomain.Text)) return; // user may have started typing

            _txtDomain.Text = domain.Trim().ToLowerInvariant();
            _lblStatus.Text = $"Auto-detected domain: {_txtDomain.Text}";
        }
        catch { }
    }

    TextBox MakeInput(Panel parent, string label, int col, int row)
    {
        int x = col == 0 ? 14 : parent.Width / 2 + 4;
        int y = row == 0 ? 2 : 42;
        int w = parent.Width / 2 - 24;

        var lbl = new Label
        {
            Text = label, ForeColor = DimColor,
            Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
            Location = new Point(x, y), AutoSize = true,
        };

        var txt = new TextBox
        {
            Text = "",
            BackColor = SurfaceColor, ForeColor = TextColor,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Cascadia Code", 9f),
            Location = new Point(x, y + 13), Width = w,
        };

        parent.Controls.AddRange([lbl, txt]);

        parent.Resize += (s, e) =>
        {
            int newX = col == 0 ? 14 : parent.ClientSize.Width / 2 + 4;
            int newW = parent.ClientSize.Width / 2 - 24;
            lbl.Location = new Point(newX, lbl.Location.Y);
            txt.Location = new Point(newX, txt.Location.Y);
            txt.Width = newW;
        };

        return txt;
    }

    // ── Settings ────────────────────────────────────────────

    void BtnClear_Click(object? sender, EventArgs e)
    {
        _runHistory.Clear();
        _selectedRunIndex = -1;
        _lastResults = null;
        _renderedGroups = null;
        _placeholderText = "Enter target domain and run diagnostics";
        _resultsCanvas.Height = 200;
        _resultsCanvas.Invalidate();
        _summaryPanel.Visible = false;
        _btnExport.Enabled = false;
        RebuildHistoryBar();
        _lblStatus.Text = "Results cleared";
    }

    void BtnReset_Click(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "This will clear all input fields and results.\n\nContinue?",
            "Reset All", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (result != DialogResult.Yes) return;

        _txtDomain.Text = "";
        _txtDc.Text = "";
        BtnClear_Click(sender, e);
        _lblStatus.Text = "All fields reset";
    }

    // ── Tab switching ───────────────────────────────────────

    void SwitchTab(string tab)
    {
        _resultsScrollPanel.Visible = tab == "results";
        _guideBox.Visible = tab == "guide";
        _gpPanel.Visible = tab == "gp";
        _ticketsPanel.Visible = tab == "tickets";

        foreach (var (btn, key) in new[] { (_btnTabResults, "results"), (_btnTabGuide, "guide"), (_btnTabGp, "gp"), (_btnTabTickets, "tickets") })
        {
            btn.BackColor = tab == key ? SurfaceColor : BgColor;
            btn.ForeColor = tab == key ? AccentColor : DimColor;
            btn.Font = tab == key ? TabFontActive : TabFontInactive;
        }
    }

    // ── Guide content ───────────────────────────────────────

    static readonly Font GuideTestNameFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font GuideBodyFont = new("Segoe UI", 9f);
    static readonly Font GuideFixFont = new("Segoe UI", 8.5f);
    static readonly Font GuideFixLabelFont = new("Segoe UI", 8.5f, FontStyle.Bold);
    static readonly Color FixLabelColor = Color.FromArgb(0xfb, 0xbf, 0x24);

    void PopulateGuide()
    {
        _guideBox.Clear();
        AppendGuide("AD Diagnostics — Test Guide\n\n", new Font("Segoe UI", 12f, FontStyle.Bold), AccentColor);

        foreach (var (title, body) in GetGuideSections())
        {
            AppendGuide($"\n{title}\n", new Font("Segoe UI", 10.5f, FontStyle.Bold), TextColor);
            AppendGuide("─────────────────────────────────────────\n\n", GuideBodyFont, BorderColor);

            var lines = body.Split('\n');
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                if (line.StartsWith("• "))
                {
                    int dash = line.IndexOf(" — ", StringComparison.Ordinal);
                    if (dash > 0)
                    {
                        AppendGuide(line[..(dash + 3)], GuideTestNameFont, AccentColor);
                        AppendGuide(line[(dash + 3)..] + "\n", GuideBodyFont, TextColor);
                    }
                    else
                    {
                        AppendGuide(line + "\n", GuideTestNameFont, AccentColor);
                    }
                }
                else if (line.TrimStart().StartsWith("Fix:"))
                {
                    string trimmed = line.TrimStart();
                    AppendGuide("  Fix: ", GuideFixLabelFont, FixLabelColor);
                    AppendGuide(trimmed[5..].TrimStart() + "\n\n", GuideFixFont, DimColor);
                }
                else if (line.TrimStart().StartsWith("- "))
                {
                    AppendGuide("    " + line.TrimStart() + "\n", GuideBodyFont, DimColor);
                }
                else
                {
                    AppendGuide(line + "\n", GuideBodyFont, DimColor);
                }
            }
            AppendGuide("\n", GuideBodyFont, DimColor);
        }

        _guideBox.SelectionStart = 0;
        _guideBox.ScrollToCaret();
    }

    void AppendGuide(string text, Font font, Color color)
    {
        _guideBox.SelectionStart = _guideBox.TextLength;
        _guideBox.SelectionLength = 0;
        _guideBox.SelectionFont = font;
        _guideBox.SelectionColor = color;
        _guideBox.AppendText(text);
    }

    static List<(string Title, string Body)> GetGuideSections()
    {
        var s = new List<(string, string)>
        {
            ("Domain Membership & Identity",
                "Uses dsregcmd /status, nltest, and WindowsIdentity to verify this device's relationship to the domain.\n\n" +
                "• Domain Joined — must be YES for this machine to authenticate against AD\n" +
                "  Fix: Join the domain via Settings > Accounts > Access work or school > Connect > Join this device to a local Active Directory domain\n\n" +
                "• Logged-on User — shows the Windows identity (DOMAIN\\user)\n" +
                "  Fix: If showing a local account, sign out and sign in with domain credentials\n\n" +
                "• Secure Channel — verifies the computer account's trust relationship with the domain via nltest /sc_verify\n" +
                "  Fix: If broken, reset the computer's secure channel: 'Test-ComputerSecureChannel -Repair' (requires domain admin credentials) or rejoin the domain\n\n" +
                "• Site Assignment — the AD site this client is assigned to, from nltest /dsgetsite\n" +
                "  Fix: If no site or wrong site, verify the client's subnet is registered in AD Sites and Services under the correct site\n\n" +
                "• Computer Password Age — the machine account password auto-rotates every 30 days by default; a stale password can cause trust failures\n" +
                "  Fix: If over 45 days old, the machine may have lost its trust relationship. Reset with 'Test-ComputerSecureChannel -Repair' or rejoin the domain. Check that the DisablePasswordChange registry value is not set"),

            ("DC Discovery & Connectivity",
                "Locates a domain controller and tests connectivity to the ports required for AD operations.\n\n" +
                "• Locate DC — nltest /dsgetdc finds the nearest available domain controller\n" +
                "  Fix: If this fails, check DNS SRV records and network connectivity to any DC. Run 'nltest /dsgetdc:<domain> /force' for a fresh lookup\n\n" +
                "• Port 389 (LDAP) — required for directory queries, group policy, and logon\n" +
                "  Fix: Check firewall rules between client and DC. Verify the DC's LDAP service is running\n\n" +
                "• Port 636 (LDAPS) — encrypted LDAP; optional but recommended for sensitive queries\n" +
                "  Fix: If required by policy, ensure the DC has a valid certificate bound to LDAPS\n\n" +
                "• Port 88 (Kerberos) — KDC port; required for domain authentication\n" +
                "  Fix: Verify firewall allows TCP/UDP 88 to the DC\n\n" +
                "• Port 445 (SMB) — required for SYSVOL and NETLOGON share access; Group Policy downloads GPOs over SMB\n" +
                "  Fix: Check firewall rules for TCP 445. Verify the Server service is running on the DC\n\n" +
                "• Port 135 (RPC) — RPC endpoint mapper; used for domain join, replication, and some management tools\n" +
                "  Fix: Check firewall rules for TCP 135 and the dynamic RPC port range (49152-65535)\n\n" +
                "• Port 464 (Kpasswd) — Kerberos password change protocol; used when changing domain passwords\n" +
                "  Fix: Check firewall rules for TCP/UDP 464. Only required if password changes fail\n\n" +
                "• Port 53 (DNS) — the DC is typically also a DNS server for AD-integrated zones\n" +
                "  Fix: Confirm the client's configured DNS servers point to AD-integrated DNS\n\n" +
                "• Port 3268 (Global Catalog) — used for forest-wide searches in multi-domain environments\n" +
                "  Fix: Only relevant in multi-domain forests; verify the target DC is a Global Catalog server if this is expected"),

            ("DNS for Active Directory",
                "AD relies entirely on DNS for service discovery. Missing or stale records break authentication silently.\n\n" +
                "• _ldap._tcp SRV — clients use this record to locate any domain controller\n" +
                "  Fix: Check DNS zone replication and confirm the DC registered its records: run 'nltest /dsregdns' on the DC, or 'ipconfig /registerdns'\n\n" +
                "• _kerberos._tcp SRV — required for Kerberos KDC discovery\n" +
                "  Fix: Same as LDAP SRV — verify DNS zone health and DC registration\n\n" +
                "• _gc._tcp SRV — locates Global Catalog servers (multi-domain forests only)\n" +
                "  Fix: Only required in multi-domain forests; verify the DC is configured as a Global Catalog in AD Sites and Services\n\n" +
                "• DC A Record — the located DC's hostname must resolve to an IP address\n" +
                "  Fix: Check that the DC's computer account registered its A record, or add it manually if using non-dynamic DNS\n\n" +
                "• DNS Suffix Search List — verifies the target domain appears in the machine's DNS suffix search order\n" +
                "  Fix: If the domain is missing from the suffix list, short-name DNS lookups will fail. Set via Group Policy (Computer Configuration > Administrative Templates > Network > DNS Client > DNS Suffix Search List) or manually in network adapter IPv4/IPv6 properties > Advanced > DNS tab"),

            ("SYSVOL & NETLOGON",
                "These domain shares are critical infrastructure for Group Policy and logon scripts.\n\n" +
                "• SYSVOL Access — tests read access to \\\\domain\\SYSVOL, where Group Policy templates and scripts are stored\n" +
                "  Fix: If inaccessible, check Port 445 (SMB) connectivity, DNS resolution of the domain name, DFS service on the DC (the SYSVOL share uses DFS-R or NTFRS), and NTFS/share permissions\n\n" +
                "• NETLOGON Access — tests read access to \\\\domain\\NETLOGON, used for logon scripts and domain-wide script distribution\n" +
                "  Fix: Same troubleshooting as SYSVOL — these shares are typically co-located on the same DC. If SYSVOL works but NETLOGON doesn't, check the share configuration on the DC with 'net share' or Server Manager"),

            ("Group Policy",
                "Parses gpresult to check whether Group Policy is applying correctly to this computer. For the full breakdown — every applied and filtered GPO for both Computer and User scope — switch to the Group Policy tab.\n\n" +
                "• GP Last Refresh — how long since policy was last applied\n" +
                "  Fix: If stale, run 'gpupdate /force' (available directly from the Group Policy tab) and check the Event Viewer (Applications and Services Logs > Microsoft > Windows > GroupPolicy) for errors\n\n" +
                "• Applied GPOs — count of policies successfully applied to this computer\n" +
                "  Fix: If zero, verify the computer object is in an OU with linked GPOs, and that security filtering allows this computer\n\n" +
                "• Denied GPOs — policies that exist but were filtered out (security filtering, WMI filters, disabled links)\n" +
                "  Fix: This is often expected behavior — review each denied GPO's link status and security filtering if unexpected\n\n" +
                "The Group Policy tab shows Computer and User scope side by side: last applied time (with age and staleness warning), site name, and every applied and denied GPO with its filtering reason. Use 'Run gpupdate' to force a refresh without leaving the app — check 'Force' to reapply all policies rather than just changed ones."),

            ("Trust Relationships",
                "Uses nltest /domain_trusts to enumerate trust relationships visible to this domain.\n\n" +
                "• Domain Trusts — lists trusted domains, trust type (Parent/Child, External, Forest), and direction\n" +
                "  Fix: If an expected trust is missing or shows as broken, verify it with 'nltest /trusted_domains' from a DC, or re-establish it via Active Directory Domains and Trusts"),

            ("Kerberos & Time Sync",
                "Kerberos requires tight time synchronization and functioning ticket acquisition.\n\n" +
                "• TGT Present — a krbtgt ticket in klist proves this session has contacted the KDC\n" +
                "  Fix: If missing, run 'klist get krbtgt' to attempt acquisition and check the DC connectivity and account status\n\n" +
                "• Clock Skew — Kerberos has a strict 5-minute tolerance between client and DC\n" +
                "  Fix: Run 'w32tm /resync'. Verify the Windows Time service (W32Time) is running and syncing from the domain hierarchy: 'w32tm /query /status'\n\n" +
                "• Time Source — confirms this client is syncing from the domain hierarchy, not an external NTP server\n" +
                "  Fix: Domain members should sync from the domain hierarchy automatically. If not, run 'w32tm /config /syncfromflags:domhier /update'"),
        };

        return s;
    }

    // ── Group Policy tab ────────────────────────────────────

    void AppendGpLine(string text, Color color, bool bold = false, Color? backColor = null)
    {
        _gpBox.SelectionStart = _gpBox.TextLength;
        _gpBox.SelectionLength = 0;
        _gpBox.SelectionColor = color;
        _gpBox.SelectionBackColor = backColor ?? _gpBox.BackColor;
        _gpBox.SelectionFont = bold ? new Font(_gpBox.Font, FontStyle.Bold) : _gpBox.Font;
        _gpBox.AppendText(text);
    }

    async void RefreshGpTab()
    {
        if (_gpRunning) return;
        _gpRunning = true;
        _gpBox.Clear();
        AppendGpLine("Loading Group Policy details...\n", DimColor);

        string raw;
        try
        {
            raw = await Task.Run(() => RunProcess("gpresult", "/r", timeoutMs: 25000));
        }
        catch (Exception ex)
        {
            _gpBox.Clear();
            AppendGpLine($"Error running gpresult: {ex.Message}\n", FailColor);
            _gpRunning = false;
            return;
        }

        _gpBox.Clear();
        var scopes = ParseGpResult(raw);
        if (scopes.Count == 0)
        {
            AppendGpLine("Could not parse gpresult output. Raw output:\n\n", WarnColor);
            AppendGpLine(raw, DimColor);
            _gpRunning = false;
            return;
        }

        AppendGpLine("\n", BgColor);
        foreach (var scope in scopes)
            RenderGpScope(scope);

        _gpBox.SelectionStart = 0;
        _gpBox.ScrollToCaret();
        _gpRunning = false;
    }

    void RenderGpScope(GpScope scope)
    {
        AppendGpLine($"  ══════════════════════════════════════\n", BorderColor);
        AppendGpLine($"   {scope.Name.ToUpperInvariant()} SCOPE\n", AccentColor, bold: true);
        AppendGpLine($"  ══════════════════════════════════════\n\n", BorderColor);

        if (!string.IsNullOrEmpty(scope.LastApplied))
        {
            AppendGpLine("  Last Applied: ", DimColor);
            bool parsed = DateTime.TryParse(Regex.Replace(scope.LastApplied, @"\s+at\s+", " "), out var lastTime);
            string ageText = parsed ? $"  ({FormatTimeSpan(DateTime.Now - lastTime)} ago)" : "";
            Color ageColor = parsed && (DateTime.Now - lastTime).TotalDays >= 7 ? WarnColor : TextColor;
            AppendGpLine(scope.LastApplied + ageText + "\n", ageColor, bold: true);
        }

        if (!string.IsNullOrEmpty(scope.Site))
        {
            AppendGpLine("  Site: ", DimColor);
            AppendGpLine(scope.Site + "\n", TextColor);
        }

        AppendGpLine("\n", BorderColor);
        AppendGpLine("  Applied GPOs", TextColor, bold: true);
        AppendGpLine($"  ({scope.Applied.Count})\n", DimColor);
        if (scope.Applied.Count == 0)
        {
            AppendGpLine("    None\n", DimColor);
        }
        foreach (var gpo in scope.Applied)
        {
            AppendGpLine("    ● ", PassColor);
            AppendGpLine(gpo + "\n", TextColor);
        }

        AppendGpLine("\n", BorderColor);
        AppendGpLine("  Denied / Filtered GPOs", TextColor, bold: true);
        AppendGpLine($"  ({scope.Denied.Count})\n", DimColor);
        if (scope.Denied.Count == 0)
        {
            AppendGpLine("    None\n", DimColor);
        }
        foreach (var (name, reason) in scope.Denied)
        {
            AppendGpLine("    ● ", WarnColor);
            AppendGpLine(name, TextColor);
            if (!string.IsNullOrEmpty(reason))
                AppendGpLine($"  — {reason}", DimColor);
            AppendGpLine("\n", TextColor);
        }

        AppendGpLine("\n\n", BorderColor);
    }

    static List<GpScope> ParseGpResult(string raw)
    {
        var scopes = new List<GpScope>();
        var sectionPattern = new Regex(@"(COMPUTER SETTINGS|USER SETTINGS)\s*\r?\n-+\s*\r?\n([\s\S]*?)(?=\r?\nCOMPUTER SETTINGS|\r?\nUSER SETTINGS|\z)", RegexOptions.IgnoreCase);

        foreach (Match sm in sectionPattern.Matches(raw))
        {
            string name = sm.Groups[1].Value.Equals("COMPUTER SETTINGS", StringComparison.OrdinalIgnoreCase) ? "Computer" : "User";
            string body = sm.Groups[2].Value;

            var lastAppliedMatch = Regex.Match(body, @"Last time Group Policy was applied:\s*(.+)", RegexOptions.IgnoreCase);
            var siteMatch = Regex.Match(body, @"^\s*Site Name:\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);

            var applied = new List<string>();
            var appliedSection = Regex.Match(body, @"Applied Group Policy Objects\s*\r?\n\s*-+\s*\r?\n([\s\S]*?)(?=\r?\n\s*\r?\n|\r?\n\s*The following GPOs|\z)", RegexOptions.IgnoreCase);
            if (appliedSection.Success)
            {
                foreach (var line in appliedSection.Groups[1].Value.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.Length > 0) applied.Add(t);
                }
            }

            var denied = new List<(string, string)>();
            var deniedSection = Regex.Match(body, @"The following GPOs were not applied because they were filtered out\s*\r?\n\s*-+\s*\r?\n([\s\S]*?)(?=\r?\n\s*The \w+ is a part of the following security groups|\r?\n\s*\r?\n\s*\r?\n|\z)", RegexOptions.IgnoreCase);
            if (deniedSection.Success)
            {
                string? currentName = null;
                foreach (var rawLine in deniedSection.Groups[1].Value.Split('\n'))
                {
                    string line = rawLine.TrimEnd('\r');
                    string trimmed = line.Trim();
                    if (trimmed.Length == 0) continue;

                    // Indented "Filtering: <reason>" lines describe the GPO just above them
                    if (trimmed.StartsWith("Filtering:", StringComparison.OrdinalIgnoreCase))
                    {
                        string reason = trimmed["Filtering:".Length..].Trim();
                        if (currentName != null)
                            denied.Add((currentName, reason));
                        currentName = null;
                    }
                    else
                    {
                        if (currentName != null) denied.Add((currentName, ""));
                        currentName = trimmed;
                    }
                }
                if (currentName != null) denied.Add((currentName, ""));
            }

            scopes.Add(new GpScope(name,
                lastAppliedMatch.Success ? lastAppliedMatch.Groups[1].Value.Trim() : "",
                siteMatch.Success ? siteMatch.Groups[1].Value.Trim() : "",
                applied, denied));
        }

        return scopes;
    }

    async void BtnGpUpdate_Click(object? sender, EventArgs e)
    {
        bool force = _chkGpForce.Checked;
        string message = force
            ? "This will run 'gpupdate /force', which re-applies ALL group policies (not just changed ones). This can briefly disrupt mapped drives, printers, and other policy-managed settings, and may require a restart for some extensions.\n\nContinue?"
            : "This will run 'gpupdate', which applies any changed group policies.\n\nContinue?";
        var confirm = MessageBox.Show(message, "Run gpupdate",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        _btnGpUpdate.Enabled = false;
        _gpBox.Clear();
        AppendGpLine(force ? "Running gpupdate /force...\n" : "Running gpupdate...\n", AccentColor, bold: true);

        try
        {
            string output = await Task.Run(() => RunProcess("gpupdate", force ? "/force" : "", timeoutMs: 90000));
            AppendGpLine("\n" + output.Trim() + "\n\n", DimColor);
            AppendGpLine("Refreshing details...\n", DimColor);
        }
        catch (Exception ex)
        {
            AppendGpLine($"\ngpupdate failed: {ex.Message}\n\n", FailColor);
        }
        finally
        {
            _btnGpUpdate.Enabled = true;
        }

        RefreshGpTab();
    }

    // ── Kerberos Tickets tab ──────────────────────────────────

    void AppendTicketsLine(string text, Color color, bool bold = false, Color? backColor = null)
    {
        _ticketsBox.SelectionStart = _ticketsBox.TextLength;
        _ticketsBox.SelectionLength = 0;
        _ticketsBox.SelectionColor = color;
        _ticketsBox.SelectionBackColor = backColor ?? _ticketsBox.BackColor;
        _ticketsBox.SelectionFont = bold ? new Font(_ticketsBox.Font, FontStyle.Bold) : _ticketsBox.Font;
        _ticketsBox.AppendText(text);
    }

    void RefreshTickets()
    {
        _ticketsBox.Clear();
        string raw;
        try { raw = RunProcess("klist", "", timeoutMs: 5000); }
        catch (Exception ex) { AppendTicketsLine($"Error running klist: {ex.Message}\n", DimColor); return; }

        if (string.IsNullOrWhiteSpace(raw) || raw.Contains("no credentials", StringComparison.OrdinalIgnoreCase))
        {
            AppendTicketsLine("No Kerberos tickets cached.\n", DimColor);
            return;
        }

        var lines = raw.Split('\n');
        var headers = new List<string>();
        var tickets = new List<(string Server, Dictionary<string, string> Fields)>();
        string? currentServer = null;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (string rawLine in lines)
        {
            string line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line)) continue;

            if (line.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Cached Tickets", StringComparison.OrdinalIgnoreCase))
            {
                headers.Add(line);
                continue;
            }

            if (line.TrimStart().StartsWith("#"))
            {
                if (currentServer != null)
                    tickets.Add((currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));
                currentServer = null;
                fields.Clear();
                continue;
            }

            var kv = line.Split(':', 2);
            if (kv.Length == 2)
            {
                string key = kv[0].Trim();
                string val = kv[1].Trim();
                if (key.Equals("Server", StringComparison.OrdinalIgnoreCase))
                    currentServer = val;
                else
                    fields[key] = val;
            }
        }
        if (currentServer != null)
            tickets.Add((currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));

        foreach (var h in headers)
        {
            if (h.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase))
                AppendTicketsLine(h + "\n\n", DimColor);
            else
                AppendTicketsLine(h + "\n", AccentColor, bold: true);
        }

        for (int i = 0; i < tickets.Count; i++)
            RenderTicket(tickets[i].Server, tickets[i].Fields, i);

        if (tickets.Count == 0)
            AppendTicketsLine("No Kerberos tickets cached.\n", DimColor);
    }

    void RenderTicket(string server, Dictionary<string, string> fields, int index)
    {
        string svc = server.Split('/')[0].ToUpperInvariant();
        string cacheFlag = fields.TryGetValue("Cache Flags", out var cf) ? cf : "";
        bool isDelegation = cacheFlag.Contains("DELEGATION", StringComparison.OrdinalIgnoreCase);
        bool isPrimary = cacheFlag.Contains("PRIMARY", StringComparison.OrdinalIgnoreCase);

        string tgtDesc = isDelegation ? "Delegation TGT — forwarded for Kerberos delegation"
            : isPrimary ? "Primary TGT — your main logon credential from the KDC"
            : "Ticket Granting Ticket — master key from KDC";

        var (label, desc) = svc switch
        {
            "KRBTGT" => ("TGT", tgtDesc),
            "CIFS" => ("CIFS", "SMB file share service ticket"),
            "HTTP" => ("HTTP", "Web service ticket (ADFS, Exchange, etc.)"),
            "LDAP" => ("LDAP", "Directory service ticket"),
            "HOST" => ("HOST", "Host service ticket (remote admin, WinRM)"),
            "RPCSS" => ("RPCSS", "RPC service ticket"),
            "DNS" => ("DNS", "DNS service ticket"),
            "TERMSRV" => ("RDP", "Remote Desktop service ticket"),
            "MSSQLSVC" => ("SQL", "SQL Server service ticket"),
            "EXCHANGEMDB" => ("EXCH", "Exchange mailbox service ticket"),
            _ => ("SVC", $"{svc} service ticket"),
        };

        Color badgeBg = svc == "KRBTGT" ? AccentColor : PassColor;

        AppendTicketsLine($"\n ┌─ ", BorderColor);
        AppendTicketsLine($" {label} ", Color.Black, bold: true, backColor: badgeBg);
        AppendTicketsLine($"  {desc}\n", DimColor);
        AppendTicketsLine($" │\n", BorderColor);

        AppendTicketsLine($" │  ", BorderColor);
        AppendTicketsLine("Server: ", DimColor);
        AppendTicketsLine(server + "\n", TextColor, bold: true);

        if (fields.TryGetValue("Client", out var client))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Client: ", DimColor);
            AppendTicketsLine(client + "\n", TextColor, bold: true);
        }

        if (fields.TryGetValue("KerbTicket Encryption Type", out var enc))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Encryption: ", DimColor);
            Color encColor = enc.Contains("AES", StringComparison.OrdinalIgnoreCase) ? PassColor
                : enc.Contains("RC4", StringComparison.OrdinalIgnoreCase) ? WarnColor : TextColor;
            AppendTicketsLine(enc + "\n", encColor);
        }

        if (fields.TryGetValue("Ticket Flags", out var flags))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Flags: ", DimColor);
            AppendTicketsLine(flags + "\n", DimColor);
        }

        if (!string.IsNullOrEmpty(cacheFlag))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("Cache: ", DimColor);
            AppendTicketsLine(cacheFlag + "\n", isDelegation ? WarnColor : isPrimary ? PassColor : TextColor);
        }

        if (fields.TryGetValue("Kdc Called", out var kdc))
        {
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine("KDC: ", DimColor);
            AppendTicketsLine(kdc + "\n", TextColor);
        }

        foreach (var timeKey in new[] { "Start Time", "End Time", "Renew Time" })
        {
            if (!fields.TryGetValue(timeKey, out var timeVal)) continue;
            AppendTicketsLine($" │  ", BorderColor);
            AppendTicketsLine($"{timeKey}: ", DimColor);

            bool expired = false;
            if (timeKey == "End Time")
            {
                string cleaned = Regex.Replace(timeVal, @"\s*\(.*?\)\s*$", "");
                expired = DateTime.TryParse(cleaned, out var endTime) && endTime < DateTime.Now;
            }
            AppendTicketsLine(timeVal + (expired ? "  EXPIRED" : "") + "\n", expired ? FailColor : TextColor);
        }

        AppendTicketsLine($" └──\n", BorderColor);
    }

    void ShowTicketsExplainer()
    {
        _showingExplainer = true;
        _ticketsBox.Clear();

        AppendTicketsLine("KERBEROS TICKETS EXPLAINED\n\n", AccentColor, bold: true);

        AppendTicketsLine("What are Kerberos tickets?\n", TextColor, bold: true);
        AppendTicketsLine("When you log in to a Windows domain, the Key Distribution Center (KDC)\n", DimColor);
        AppendTicketsLine("issues you a Ticket Granting Ticket (TGT). This TGT is your master\n", DimColor);
        AppendTicketsLine("credential — it proves your identity without sending your password again.\n\n", DimColor);

        AppendTicketsLine("Each time you access a network resource (file share, web app, database),\n", DimColor);
        AppendTicketsLine("your TGT is used to request a service ticket for that specific resource.\n", DimColor);
        AppendTicketsLine("These service tickets are cached so you don't re-authenticate every time.\n\n", DimColor);

        AppendTicketsLine("TICKET TYPES\n\n", AccentColor, bold: true);

        AppendTicketsLine(" TGT  ", Color.Black, bold: true, backColor: AccentColor);
        AppendTicketsLine("  Ticket Granting Ticket\n", TextColor, bold: true);
        AppendTicketsLine("       Your master Kerberos credential from the domain controller.\n", DimColor);
        AppendTicketsLine("       Server field shows: krbtgt/REALM @ REALM\n", DimColor);
        AppendTicketsLine("       If this is missing or expired, nothing else works.\n\n", DimColor);
        AppendTicketsLine("       You may see two TGTs — check the Cache Flags to tell them apart:\n", DimColor);
        AppendTicketsLine("       • PRIMARY", PassColor, bold: true);
        AppendTicketsLine(" — your main logon TGT, issued during interactive login\n", DimColor);
        AppendTicketsLine("       • DELEGATION", WarnColor, bold: true);
        AppendTicketsLine(" — a forwarded TGT for Kerberos delegation. Issued when a\n", DimColor);
        AppendTicketsLine("         service is trusted for delegation and needs to act on your behalf.\n\n", DimColor);

        AppendTicketsLine(" CIFS ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  SMB/File Share\n", TextColor, bold: true);
        AppendTicketsLine("       Grants access to Windows file shares (\\\\server\\share).\n\n", DimColor);

        AppendTicketsLine(" LDAP ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Directory Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Active Directory lookups and queries.\n\n", DimColor);

        AppendTicketsLine(" HOST ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Host/Remote Admin\n", TextColor, bold: true);
        AppendTicketsLine("       Used for WinRM, remote management, and scheduled tasks.\n\n", DimColor);

        AppendTicketsLine(" HTTP ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Web Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Kerberos-authenticated web apps, ADFS, Exchange OWA.\n\n", DimColor);

        AppendTicketsLine(" RDP  ", Color.Black, bold: true, backColor: PassColor);
        AppendTicketsLine("  Remote Desktop\n", TextColor, bold: true);
        AppendTicketsLine("       Authenticates Remote Desktop (TERMSRV) connections.\n\n", DimColor);

        AppendTicketsLine("ENCRYPTION\n\n", AccentColor, bold: true);
        AppendTicketsLine("  AES-256  ", PassColor);
        AppendTicketsLine("— Strong. Expected on modern domains.\n", DimColor);
        AppendTicketsLine("  RC4      ", WarnColor);
        AppendTicketsLine("— Weak. May indicate legacy systems or misconfigured SPNs.\n\n", DimColor);

        AppendTicketsLine("WHAT DOES PURGE DO?\n\n", AccentColor, bold: true);
        AppendTicketsLine("Purging destroys all cached Kerberos tickets. Your TGT is re-acquired\n", DimColor);
        AppendTicketsLine("on next authentication, and service tickets are re-requested on next\n", DimColor);
        AppendTicketsLine("access. Useful when troubleshooting stale credentials or delegation issues.\n\n", DimColor);

        AppendTicketsLine("Click ", DimColor);
        AppendTicketsLine("What is this?", AccentColor, bold: true);
        AppendTicketsLine(" again to return to the ticket list.\n", DimColor);
    }

    void BtnPurgeTickets_Click(object? sender, EventArgs e)
    {
        var confirm = MessageBox.Show(
            "This will destroy all cached Kerberos tickets.\n\n"
            + "Your TGT will be re-acquired on next authentication, but you may need to "
            + "re-authenticate to access network resources (file shares, web apps, etc.).\n\n"
            + "Continue?",
            "Purge Kerberos Tickets", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        try
        {
            RunProcess("klist", "purge", timeoutMs: 5000);
            _lblStatus.Text = "Tickets purged — run diagnostics twice (first run reacquires tickets, second shows true results)";
            _lblStatus.ForeColor = WarnColor;
            RefreshTickets();
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Purge failed: {ex.Message}";
        }
    }

    // ── Owner-drawn results ─────────────────────────────────

    int MeasureResultsHeight(int width)
    {
        if (_renderedGroups == null)
            return 200;

        int y = 8;
        int detailW = Math.Max(width - 204, 80);

        foreach (var group in _renderedGroups)
        {
            y += 28;
            foreach (var test in group.Tests)
            {
                string detail = _renderRunning ? "running..." : test.Detail;
                var sz = TextRenderer.MeasureText(detail, TestDetailFont,
                    new Size(detailW, 0), TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
                y += Math.Max(20, sz.Height + 4) + 2;
            }
        }
        return y + 14;
    }

    void PaintResults(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        int w = _resultsCanvas.Width;

        if (_renderedGroups == null)
        {
            string msg = _placeholderText ?? "Enter target domain and run diagnostics";
            TextRenderer.DrawText(g, msg, PlaceholderFont, new Point(16, 40), DimColor);
            return;
        }

        int y = 8;
        int nameX = 16;
        int detailX = 190;
        int detailW = Math.Max(w - 204, 80);

        foreach (var group in _renderedGroups)
        {
            y += 10;
            TextRenderer.DrawText(g, group.Name.ToUpperInvariant(), GroupHeaderFont,
                new Point(nameX, y), DimColor);
            y += 18;

            foreach (var test in group.Tests)
            {
                Color detailColor;
                string detail;
                SolidBrush dotBrush;
                if (_renderRunning)
                {
                    dotBrush = AccentBrush;
                    detailColor = DimColor;
                    detail = "running...";
                }
                else
                {
                    dotBrush = test.Status switch { Status.Pass => PassBrush, Status.Fail => FailBrush, Status.Warn => WarnBrush, _ => SkipBrush };
                    detailColor = test.Status switch { Status.Pass => PassColor, Status.Fail => FailColor, Status.Warn => WarnColor, _ => DimColor };
                    detail = test.Detail;
                }

                g.FillEllipse(dotBrush, 2, y + 4, 8, 8);

                TextRenderer.DrawText(g, test.Name, TestNameFont,
                    new Rectangle(nameX, y, 170, 18), TextColor,
                    TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);

                var detailSize = TextRenderer.MeasureText(g, detail, TestDetailFont,
                    new Size(detailW, 0), TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
                TextRenderer.DrawText(g, detail, TestDetailFont,
                    new Rectangle(detailX, y + 1, detailW, detailSize.Height),
                    detailColor, TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);

                int rowH = Math.Max(20, detailSize.Height + 4);
                y += rowH + 2;
            }
        }
    }

    void RenderResults(List<TestGroup> groups, bool running = false)
    {
        _renderedGroups = groups;
        _renderRunning = running;
        _placeholderText = null;
        int h = MeasureResultsHeight(_resultsCanvas.Width);
        _resultsCanvas.Height = h;
        _resultsCanvas.Invalidate();
    }

    // ── Events ──────────────────────────────────────────────

    async void BtnRun_Click(object? sender, EventArgs e)
    {
        string domain = _txtDomain.Text.Trim();
        string dc = _txtDc.Text.Trim();
        if (_chkDcSuffix.Checked && !string.IsNullOrEmpty(domain) && !dc.Contains('.'))
            dc = string.IsNullOrEmpty(dc) ? "" : $"{dc}.{domain}";

        if (string.IsNullOrEmpty(domain))
        {
            _lblStatus.Text = "Domain is required";
            return;
        }
        if (!HostnamePattern.IsMatch(domain))
        {
            _lblStatus.Text = "Invalid domain characters";
            return;
        }
        if (!string.IsNullOrEmpty(dc) && !HostnamePattern.IsMatch(dc))
        {
            _lblStatus.Text = "Invalid DC hostname";
            return;
        }

        _runCts?.Cancel();
        _runCts = new CancellationTokenSource();
        var cts = _runCts;

        _btnRun.Enabled = false;
        _btnExport.Enabled = false;
        _summaryPanel.Visible = false;
        _lblStatus.ForeColor = DimColor;
        _lblStatus.Text = "Running diagnostics...";
        SwitchTab("results");

        var results = BuildSkeleton();
        RenderResults(results, running: true);

        _runHistory.Insert(0, new DiagRun(DateTime.MinValue, domain, results));
        _selectedRunIndex = 0;
        RebuildHistoryBar();

        var config = new DiagConfig(domain, dc);
        int completed = 0;
        int totalGroups = results.Count;

        void ReplaceGroup(string name, TestGroup result)
        {
            if (cts.IsCancellationRequested || IsDisposed) return;
            int idx = results.FindIndex(g => g.Name == name);
            if (idx >= 0) results[idx] = result;
            completed++;
            _lblStatus.Text = $"Running diagnostics... ({completed}/{totalGroups})";
            ShowResults(results);
        }

        var identityTask = Task.Run(() => TestDomainMembership(config));
        var dcTask = Task.Run(() => TestDcConnectivity(config));
        var dnsTask = Task.Run(() => TestDnsForAd(config));
        var sysvolTask = Task.Run(() => TestSysvolNetlogon(config));
        var gpTask = Task.Run(() => TestGroupPolicy(config));
        var trustTask = Task.Run(() => TestTrusts(config));
        var kerbTask = Task.Run(() => TestKerberosAndTime(config));

        var pending = new List<(Task task, string name, Func<TestGroup> getResult)>
        {
            (identityTask, "Domain Membership & Identity", () => identityTask.Result),
            (dcTask, "DC Discovery & Connectivity", () => dcTask.Result),
            (dnsTask, "DNS for Active Directory", () => dnsTask.Result),
            (sysvolTask, "SYSVOL & NETLOGON", () => sysvolTask.Result),
            (gpTask, "Group Policy", () => gpTask.Result),
            (trustTask, "Trust Relationships", () => trustTask.Result),
            (kerbTask, "Kerberos & Time Sync", () => kerbTask.Result),
        };

        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(p => p.task));
            if (cts.IsCancellationRequested || IsDisposed) return;
            var match = pending.First(p => p.task == done);
            pending.Remove(match);
            ReplaceGroup(match.name, match.getResult());
        }

        _lastResults = results;
        _runHistory[0] = new DiagRun(DateTime.Now, domain, results);
        if (_runHistory.Count > 5) _runHistory.RemoveAt(5);
        _selectedRunIndex = 0;
        ShowResults(results);
        RebuildHistoryBar();

        _lblStatus.Text = "Complete";
        _btnRun.Enabled = true;
        _btnExport.Enabled = true;
    }

    void RebuildHistoryBar()
    {
        _historyPanel.Controls.Clear();
        if (_runHistory.Count == 0)
        {
            _historyPanel.Visible = false;
            return;
        }

        int x = 10;
        var lblRuns = new Label { Text = "Runs:", ForeColor = DimColor, Font = new Font("Segoe UI", 8f), AutoSize = true, Location = new Point(x, 6) };
        _historyPanel.Controls.Add(lblRuns);
        x += lblRuns.PreferredWidth + 4;

        for (int ri = _runHistory.Count - 1; ri >= 0; ri--)
        {
            int idx = ri;
            var run = _runHistory[ri];
            bool selected = ri == _selectedRunIndex;
            bool isPending = run.Timestamp == DateTime.MinValue;
            string label = isPending ? "Pending..." : run.Timestamp.ToString("HH:mm:ss");

            var btn = new Button
            {
                Text = label, FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 7.5f, selected ? FontStyle.Bold : FontStyle.Regular),
                BackColor = selected ? (isPending ? WarnColor : AccentColor) : SurfaceColor,
                ForeColor = selected ? Color.Black : (isPending ? WarnColor : DimColor),
                Size = new Size(isPending ? 72 : 62, 20), Location = new Point(x, 4), Cursor = Cursors.Hand,
            };
            btn.FlatAppearance.BorderSize = 0;
            if (!isPending) btn.Click += (s, e) => SelectRun(idx);
            _historyPanel.Controls.Add(btn);
            x += (isPending ? 76 : 66);
        }

        var del = new Button
        {
            Text = "Delete Run", FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 7.5f),
            BackColor = SurfaceColor, ForeColor = FailColor,
            Size = new Size(70, 20), Cursor = Cursors.Hand,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        del.FlatAppearance.BorderSize = 0;
        del.Location = new Point(_historyPanel.ClientSize.Width - del.Width - 10, 4);
        del.Click += (s, e) => DeleteRun(_selectedRunIndex);
        _historyPanel.Controls.Add(del);

        _historyPanel.Visible = true;
    }

    void SelectRun(int index)
    {
        if (index < 0 || index >= _runHistory.Count) return;
        _selectedRunIndex = index;
        _lastResults = _runHistory[index].Results;
        ShowResults(_runHistory[index].Results);
        _lblStatus.Text = $"Run from {_runHistory[index].Timestamp:HH:mm:ss}";
        _btnExport.Enabled = true;
        RebuildHistoryBar();
    }

    void DeleteRun(int index)
    {
        if (index < 0 || index >= _runHistory.Count) return;
        _runHistory.RemoveAt(index);

        if (_runHistory.Count == 0)
        {
            _selectedRunIndex = -1;
            _lastResults = null;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this domain";
            _resultsCanvas.Height = 200;
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = false;
        }
        else
        {
            if (_selectedRunIndex >= _runHistory.Count)
                _selectedRunIndex = _runHistory.Count - 1;
            _lastResults = _runHistory[_selectedRunIndex].Results;
            ShowResults(_runHistory[_selectedRunIndex].Results);
            _lblStatus.Text = $"Run from {_runHistory[_selectedRunIndex].Timestamp:HH:mm:ss}";
        }
        RebuildHistoryBar();
    }

    void ShowResults(List<TestGroup> results)
    {
        RenderResults(results);
        int pass = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Pass);
        int fail = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Fail);
        int warn = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Warn);
        _lblPassCount.Text = pass.ToString();
        _lblFailCount.Text = fail.ToString();
        _lblWarnCount.Text = warn.ToString();
        _summaryPanel.Visible = true;
    }

    void BtnExport_Click(object? sender, EventArgs e)
    {
        if (_lastResults == null) return;

        using var dlg = new SaveFileDialog
        {
            FileName = $"ad-diag-{Regex.Replace(_txtDomain.Text.Trim(), @"[^a-zA-Z0-9.\-]", "_")}-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt",
            DefaultExt = ".txt"
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine("===================================================");
        sb.AppendLine("  AD Diagnostics Report");
        sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("===================================================");
        sb.AppendLine();
        sb.AppendLine("Configuration:");
        sb.AppendLine($"  Domain:  {_txtDomain.Text.Trim()}");
        sb.AppendLine($"  DC Host: {_txtDc.Text.Trim()}");
        sb.AppendLine();

        foreach (var group in _lastResults)
        {
            sb.AppendLine("---------------------------------------------------");
            sb.AppendLine($"  {group.Name.ToUpperInvariant()}");
            sb.AppendLine("---------------------------------------------------");
            foreach (var test in group.Tests)
            {
                char icon = test.Status switch { Status.Pass => '+', Status.Fail => 'X', Status.Warn => '!', _ => 'o' };
                sb.AppendLine($"  {icon} {test.Name,-26} {test.Detail}");
            }
            sb.AppendLine();
        }

        File.WriteAllText(dlg.FileName, sb.ToString(), Encoding.UTF8);
        _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
    }

    // ── Test skeleton ───────────────────────────────────────

    static List<TestGroup> BuildSkeleton()
    {
        var groups = new List<TestGroup>
        {
            new("Domain Membership & Identity", [
                new("Domain Joined"), new("Logged-on User"),
                new("Secure Channel"), new("Site Assignment"),
                new("Computer Password Age"),
            ]),
            new("DC Discovery & Connectivity", [
                new("Locate DC"), new("Port 389 (LDAP)"), new("Port 636 (LDAPS)"),
                new("Port 88 (Kerberos)"), new("Port 445 (SMB)"), new("Port 135 (RPC)"),
                new("Port 464 (Kpasswd)"), new("Port 53 (DNS)"), new("Port 3268 (Global Catalog)"),
            ]),
            new("DNS for Active Directory", [
                new("_ldap._tcp SRV"), new("_kerberos._tcp SRV"),
                new("_gc._tcp SRV"), new("DC A Record"),
                new("DNS Suffix Search List"),
            ]),
            new("SYSVOL & NETLOGON", [
                new("SYSVOL Access"), new("NETLOGON Access"),
            ]),
            new("Group Policy", [
                new("GP Last Refresh"), new("Applied GPOs"), new("Denied GPOs"),
            ]),
            new("Trust Relationships", [
                new("Domain Trusts"),
            ]),
            new("Kerberos & Time Sync", [
                new("TGT Present"), new("Clock Skew"), new("Time Source"),
            ]),
        };
        return groups;
    }

    // ── Diagnostics engine ──────────────────────────────────

    static TestGroup TestDomainMembership(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string? dsreg = null;

        try
        {
            dsreg = RunProcess("dsregcmd", "/status");
            var m = Regex.Match(dsreg, @"DomainJoined\s*:\s*(\S+)");
            bool domJoined = m.Success && m.Groups[1].Value == "YES";
            tests.Add(new("Domain Joined",
                domJoined ? Status.Pass : Status.Fail,
                m.Success ? $"DomainJoined: {m.Groups[1].Value}" : "Could not determine"));
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Joined", Status.Fail, $"dsregcmd error: {ex.Message}"));
        }

        try
        {
            var id = WindowsIdentity.GetCurrent();
            tests.Add(new("Logged-on User", Status.Pass, id.Name));
        }
        catch (Exception ex)
        {
            tests.Add(new("Logged-on User", Status.Fail, $"Cannot get identity: {ex.Message}"));
        }

        try
        {
            string scVerify = RunProcess("nltest", $"/sc_verify:{cfg.Domain}", timeoutMs: 10000);
            bool ok = scVerify.Contains("ERROR_SUCCESS", StringComparison.OrdinalIgnoreCase)
                   || scVerify.Contains("The command completed successfully", StringComparison.OrdinalIgnoreCase);
            bool accessDenied = scVerify.Contains("ACCESS_DENIED", StringComparison.OrdinalIgnoreCase)
                             || scVerify.Contains("Access is denied", StringComparison.OrdinalIgnoreCase);
            var trustMatch = Regex.Match(scVerify, @"Trust Verification Status\s*=\s*(.+)", RegexOptions.IgnoreCase);
            if (accessDenied)
                tests.Add(new("Secure Channel", Status.Warn, "Requires elevation (Run as Administrator)"));
            else
                tests.Add(new("Secure Channel",
                    ok ? Status.Pass : Status.Fail,
                    trustMatch.Success ? trustMatch.Groups[1].Value.Trim() : (ok ? "Verified" : scVerify.Trim())));
        }
        catch (Exception ex)
        {
            tests.Add(new("Secure Channel", Status.Warn, $"nltest not available: {ex.Message}"));
        }

        try
        {
            string dsGetSite = RunProcess("nltest", "/dsgetsite", timeoutMs: 5000);
            string site = dsGetSite.Trim().Split('\n').FirstOrDefault(l => !l.Contains("command completed", StringComparison.OrdinalIgnoreCase))?.Trim() ?? "";
            tests.Add(new("Site Assignment",
                !string.IsNullOrEmpty(site) ? Status.Pass : Status.Warn,
                !string.IsNullOrEmpty(site) ? $"Site: {site}" : "No site returned - subnet may not be registered in AD Sites and Services"));
        }
        catch (Exception ex)
        {
            tests.Add(new("Site Assignment", Status.Warn, $"nltest not available: {ex.Message}"));
        }

        try
        {
            string ps = RunProcess("powershell", "-NoProfile -Command \"$s=[adsisearcher]\\\"(&(objectCategory=computer)(name=$env:COMPUTERNAME))\\\";$s.PropertiesToLoad.Add('pwdLastSet')|Out-Null;$r=$s.FindOne();if($r){[datetime]::FromFileTime($r.Properties['pwdlastset'][0]).ToString('o')}else{'NOTFOUND'}\"", timeoutMs: 10000);
            string dateStr = ps.Trim();
            if (dateStr == "NOTFOUND")
            {
                tests.Add(new("Computer Password Age", Status.Skip, "Computer object not found in AD"));
            }
            else if (DateTime.TryParse(dateStr, out var lastChanged))
            {
                var age = DateTime.Now - lastChanged;
                tests.Add(new("Computer Password Age",
                    age.TotalDays < 45 ? Status.Pass : age.TotalDays < 90 ? Status.Warn : Status.Fail,
                    $"Last changed: {lastChanged:g} ({(int)age.TotalDays}d ago)" + (age.TotalDays >= 45 ? " — may indicate broken auto-rotation" : "")));
            }
            else
            {
                tests.Add(new("Computer Password Age", Status.Warn, "Could not query AD — check domain connectivity"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("Computer Password Age", Status.Warn, $"AD query failed: {ex.Message}"));
        }

        return new("Domain Membership & Identity", tests);
    }

    static TestGroup TestDcConnectivity(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string? dcHost = null;

        try
        {
            string dsGetDc = RunProcess("nltest", $"/dsgetdc:{cfg.Domain}", timeoutMs: 8000);
            var m = Regex.Match(dsGetDc, @"DC:\s*\\\\(\S+)", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                dcHost = m.Groups[1].Value;
                tests.Add(new("Locate DC", Status.Pass, $"Found {dcHost}"));
            }
            else
            {
                tests.Add(new("Locate DC", Status.Fail, "Could not locate a domain controller"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("Locate DC", Status.Fail, $"nltest error: {ex.Message}"));
        }

        string kdc = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : (dcHost ?? cfg.Domain);
        IPAddress? kdcIp = null;
        try { kdcIp = Dns.GetHostAddresses(kdc).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork); }
        catch { }

        var portTasks = new List<(string Name, int Port, Task<bool> Task)>
        {
            ("Port 389 (LDAP)", 389, Task.Run(() => TryTcpConnect(kdcIp, kdc, 389))),
            ("Port 636 (LDAPS)", 636, Task.Run(() => TryTcpConnect(kdcIp, kdc, 636))),
            ("Port 88 (Kerberos)", 88, Task.Run(() => TryTcpConnect(kdcIp, kdc, 88))),
            ("Port 445 (SMB)", 445, Task.Run(() => TryTcpConnect(kdcIp, kdc, 445))),
            ("Port 135 (RPC)", 135, Task.Run(() => TryTcpConnect(kdcIp, kdc, 135))),
            ("Port 464 (Kpasswd)", 464, Task.Run(() => TryTcpConnect(kdcIp, kdc, 464))),
            ("Port 53 (DNS)", 53, Task.Run(() => TryTcpConnect(kdcIp, kdc, 53))),
            ("Port 3268 (Global Catalog)", 3268, Task.Run(() => TryTcpConnect(kdcIp, kdc, 3268))),
        };

        Task.WaitAll(portTasks.Select(p => p.Task).ToArray());

        foreach (var (name, port, task) in portTasks)
        {
            bool open = task.Result;
            bool required = port is 389 or 88 or 445;
            if (kdcIp == null)
                tests.Add(new(name, Status.Skip, $"Cannot resolve {kdc}"));
            else
                tests.Add(new(name,
                    open ? Status.Pass : (required ? Status.Fail : Status.Warn),
                    open ? $"Reachable at {kdc}" : $"Unreachable at {kdc}"));
        }

        return new("DC Discovery & Connectivity", tests);
    }

    static TestGroup TestDnsForAd(DiagConfig cfg)
    {
        var tests = new List<TestEntry>
        {
            LookupSrv($"_ldap._tcp.{cfg.Domain}", "_ldap._tcp SRV", required: true),
            LookupSrv($"_kerberos._tcp.{cfg.Domain}", "_kerberos._tcp SRV", required: true),
            LookupSrv($"_gc._tcp.{cfg.Domain}", "_gc._tcp SRV", required: false),
        };

        try
        {
            string host = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : cfg.Domain;
            var addrs = Dns.GetHostAddresses(host).Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            tests.Add(new("DC A Record",
                addrs.Length > 0 ? Status.Pass : Status.Fail,
                addrs.Length > 0 ? $"{host} -> {string.Join(", ", addrs.Select(a => a.ToString()))}" : $"Cannot resolve {host}"));
        }
        catch (Exception ex)
        {
            tests.Add(new("DC A Record", Status.Fail, $"Resolution failed: {ex.Message}"));
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            var searchList = key?.GetValue("SearchList") as string ?? "";
            var domain = key?.GetValue("Domain") as string ?? "";
            var suffixes = new List<string>();
            if (!string.IsNullOrWhiteSpace(searchList))
                suffixes.AddRange(searchList.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0));
            else if (!string.IsNullOrWhiteSpace(domain))
                suffixes.Add(domain);

            if (suffixes.Count > 0)
            {
                bool hasDomain = suffixes.Any(s => s.Contains(cfg.Domain, StringComparison.OrdinalIgnoreCase));
                tests.Add(new("DNS Suffix Search List",
                    hasDomain ? Status.Pass : Status.Warn,
                    string.Join(", ", suffixes) + (hasDomain ? "" : $" — target domain {cfg.Domain} not in suffix list")));
            }
            else
            {
                tests.Add(new("DNS Suffix Search List", Status.Warn, "No DNS suffix configured"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("DNS Suffix Search List", Status.Warn, $"Registry read failed: {ex.Message}"));
        }

        return new("DNS for Active Directory", tests);
    }

    static TestEntry LookupSrv(string record, string testName, bool required)
    {
        try
        {
            string output = RunProcess("nslookup", $"-type=SRV {record}", timeoutMs: 5000);
            bool found = output.Contains("service", StringComparison.OrdinalIgnoreCase)
                      && output.Contains(record.Split('.', 3)[2], StringComparison.OrdinalIgnoreCase);
            if (found)
            {
                var m = Regex.Match(output, @"svr hostname\s*=\s*(.+)", RegexOptions.IgnoreCase);
                string host = m.Success ? m.Groups[1].Value.Trim() : "found";
                return new(testName, Status.Pass, $"{record} -> {host}" + (required ? "" : " (optional)"));
            }
            return new(testName, required ? Status.Fail : Status.Warn,
                $"No {record} record" + (required ? "" : " (optional)"));
        }
        catch
        {
            return new(testName, Status.Warn, "nslookup not available");
        }
    }

    static TestGroup TestSysvolNetlogon(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        void TestShare(string shareName, string testName)
        {
            string path = $@"\\{cfg.Domain}\{shareName}";
            try
            {
                bool exists = Directory.Exists(path);
                if (exists)
                {
                    var entries = Directory.GetFileSystemEntries(path);
                    tests.Add(new(testName, Status.Pass, $"{path} accessible ({entries.Length} entries)"));
                }
                else
                {
                    tests.Add(new(testName, Status.Fail, $"{path} not accessible"));
                }
            }
            catch (UnauthorizedAccessException)
            {
                tests.Add(new(testName, Status.Warn, $"{path} exists but access denied — check permissions"));
            }
            catch (Exception ex)
            {
                tests.Add(new(testName, Status.Fail, $"{path} — {ex.Message}"));
            }
        }

        TestShare("SYSVOL", "SYSVOL Access");
        TestShare("NETLOGON", "NETLOGON Access");

        return new("SYSVOL & NETLOGON", tests);
    }

    static TestGroup TestGroupPolicy(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        try
        {
            string gpresult = RunProcess("gpresult", "/r", timeoutMs: 20000);
            bool hasComputer = gpresult.Contains("COMPUTER SETTINGS", StringComparison.OrdinalIgnoreCase);
            bool hasUser = gpresult.Contains("USER SETTINGS", StringComparison.OrdinalIgnoreCase);

            if (!hasComputer && !hasUser)
            {
                tests.Add(new("GP Last Refresh", Status.Warn, "gpresult returned no data — run as Administrator for full results"));
                tests.Add(new("Applied GPOs", Status.Skip, "No scope data available"));
                tests.Add(new("Denied GPOs", Status.Skip, "No scope data available"));
                return new("Group Policy", tests);
            }

            var scopes = ParseGpResult(gpresult);
            var computer = scopes.FirstOrDefault(s => s.Name == "Computer");
            var user = scopes.FirstOrDefault(s => s.Name == "User");
            var primary = computer ?? user;
            string scopeLabel = computer != null ? "Computer" : "User";
            string elevationNote = !hasComputer ? " (run as Administrator for Computer scope)" : "";

            if (primary != null && !string.IsNullOrEmpty(primary.LastApplied)
                && DateTime.TryParse(Regex.Replace(primary.LastApplied, @"\s+at\s+", " "), out var lastTime))
            {
                var age = DateTime.Now - lastTime;
                tests.Add(new("GP Last Refresh",
                    age.TotalHours < 24 ? Status.Pass : age.TotalDays < 7 ? Status.Warn : Status.Fail,
                    $"{scopeLabel}: {lastTime:g} ({FormatTimeSpan(age)} ago){elevationNote}"));
            }
            else
            {
                tests.Add(new("GP Last Refresh", Status.Warn,
                    $"Could not determine last refresh time{elevationNote}"));
            }

            int appliedCount = primary?.Applied.Count(a => !a.Equals("N/A", StringComparison.OrdinalIgnoreCase)) ?? 0;
            tests.Add(new("Applied GPOs",
                appliedCount > 0 ? Status.Pass : Status.Warn,
                appliedCount > 0
                    ? $"{scopeLabel}: {appliedCount} GPO(s) applied{elevationNote}"
                    : $"{scopeLabel}: No applied GPOs found{elevationNote}"));

            int deniedCount = primary?.Denied.Count ?? 0;
            tests.Add(new("Denied GPOs", Status.Pass,
                $"{scopeLabel}: {deniedCount} GPO(s) filtered out (informational){elevationNote}"));
        }
        catch (Exception ex)
        {
            tests.Add(new("GP Last Refresh", Status.Fail, $"gpresult error: {ex.Message}"));
            tests.Add(new("Applied GPOs", Status.Skip, "gpresult unavailable"));
            tests.Add(new("Denied GPOs", Status.Skip, "gpresult unavailable"));
        }

        return new("Group Policy", tests);
    }

    static TestGroup TestTrusts(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        try
        {
            string trusts = RunProcess("nltest", "/domain_trusts", timeoutMs: 8000);
            var lines = trusts.Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && Regex.IsMatch(l, @"^\S+\s+\S+\s+\("))
                .ToList();

            if (lines.Count > 0)
                tests.Add(new("Domain Trusts", Status.Pass, $"{lines.Count} trust(s): {string.Join(" | ", lines.Take(5))}"));
            else
                tests.Add(new("Domain Trusts", Status.Pass, "No additional trusts found (single-domain environment)"));
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Trusts", Status.Warn, $"nltest not available: {ex.Message}"));
        }

        return new("Trust Relationships", tests);
    }

    static TestGroup TestKerberosAndTime(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();
        string realm = cfg.Domain.ToUpperInvariant();

        try
        {
            string klist = RunProcess("klist", "");
            var tgtPattern = new Regex($@"krbtgt/{Regex.Escape(realm)}\s*@\s*{Regex.Escape(realm)}", RegexOptions.IgnoreCase);
            tests.Add(new("TGT Present",
                tgtPattern.IsMatch(klist) ? Status.Pass : Status.Fail,
                tgtPattern.IsMatch(klist) ? $"krbtgt/{realm} present" : "No TGT found - no KDC contact"));
        }
        catch (Exception ex)
        {
            tests.Add(new("TGT Present", Status.Fail, $"klist error: {ex.Message}"));
        }

        string kdc = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : cfg.Domain;
        try
        {
            string w32 = RunProcess("w32tm", $"/stripchart /computer:{kdc} /samples:1 /dataonly", timeoutMs: 5000);
            var m = Regex.Match(w32, @"([+-]?\d+\.\d+)s");
            if (m.Success)
            {
                double skew = Math.Abs(double.Parse(m.Groups[1].Value));
                tests.Add(new("Clock Skew",
                    skew < 60 ? Status.Pass : skew < 300 ? Status.Warn : Status.Fail,
                    $"{skew:F2}s drift from {kdc}" + (skew >= 300 ? " - exceeds Kerberos 5min tolerance" : "")));
            }
            else
                tests.Add(new("Clock Skew", Status.Warn, "Cannot measure (DC unreachable?)"));
        }
        catch { tests.Add(new("Clock Skew", Status.Warn, "w32tm not available")); }

        try
        {
            string w32status = RunProcess("w32tm", "/query /status", timeoutMs: 5000);
            var srcMatch = Regex.Match(w32status, @"Source:\s*(.+)", RegexOptions.IgnoreCase);
            string source = srcMatch.Success ? srcMatch.Groups[1].Value.Trim() : "unknown";
            bool isLocalCmos = source.Contains("Local CMOS", StringComparison.OrdinalIgnoreCase);
            tests.Add(new("Time Source",
                isLocalCmos ? Status.Warn : Status.Pass,
                source + (isLocalCmos ? " - not syncing from domain hierarchy" : "")));
        }
        catch (Exception ex)
        {
            tests.Add(new("Time Source", Status.Warn, $"w32tm not available: {ex.Message}"));
        }

        return new("Kerberos & Time Sync", tests);
    }

    // ── Helpers ─────────────────────────────────────────────

    static string RunProcess(string fileName, string arguments, int timeoutMs = 15000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName, Arguments = arguments,
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(true); } catch { }
        }
        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        if (string.IsNullOrWhiteSpace(stdout) && !string.IsNullOrWhiteSpace(stderr))
            return stderr;
        return stdout;
    }

    static bool TryTcpConnect(IPAddress? ip, string host, int port, int timeoutMs = 3000)
    {
        try
        {
            using var client = new TcpClient();
            var task = ip != null ? client.ConnectAsync(ip, port) : client.ConnectAsync(host, port);
            return task.Wait(timeoutMs) && client.Connected;
        }
        catch { return false; }
    }

    static string FormatTimeSpan(TimeSpan ts)
    {
        if (ts.TotalDays >= 1) return $"{(int)ts.TotalDays}d {ts.Hours}h";
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        return $"{(int)ts.TotalMinutes}m";
    }
}

// ── Data types ──────────────────────────────────────────

record DiagConfig(string Domain, string Dc);
enum Status { Pass, Fail, Warn, Skip }
record TestEntry(string Name, Status Status = Status.Skip, string Detail = "");
record TestGroup(string Name, List<TestEntry> Tests);
record DiagRun(DateTime Timestamp, string Domain, List<TestGroup> Results);
record GpScope(string Name, string LastApplied, string Site, List<string> Applied, List<(string Name, string Reason)> Denied);
