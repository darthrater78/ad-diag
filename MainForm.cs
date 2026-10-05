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
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

// P/Invoke targets are all system DLLs; never resolve them from the exe's own folder, where a planted copy could sit
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

#nullable enable
namespace AdDiag;

static class Program
{
    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, "Local\\AdDiag_SingleInstance", out bool isNew);
        if (!isNew)
        {
            MessageBox.Show("AD Diagnostics is already running.", "AD Diag",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}

class MainForm : Form
{
    // Tokens: see DESIGN.md. The theme starts from the Windows light/dark app setting and the header button
    // switches it (SetTheme); nothing is saved, so the next launch follows Windows again.
    static bool Dark = DetectDarkMode();
    static Color Themed(int light, int dark) => Color.FromArgb(unchecked((int)0xFF000000) | (Dark ? dark : light));
    static Color BgColor => Themed(0xf3f3f3, 0x202020);       // window
    static Color PanelColor => Themed(0xffffff, 0x1c1c1c);    // results and text panes
    static Color SurfaceColor => Themed(0xfbfbfb, 0x2d2d2d);  // buttons and inputs
    static Color BorderColor => Themed(0xd1d1d1, 0x3d3d3d);
    static Color RowLineColor => Themed(0xededed, 0x2a2a2a);
    static Color TextColor => Themed(0x1b1b1b, 0xf2f2f2);
    static Color DimColor => Themed(0x5f5f5f, 0xa3a3a3);
    static Color PassColor => Themed(0x0f7b0f, 0x6ccb5f);
    static Color FailColor => Themed(0xc42b1c, 0xff99a4);
    static Color WarnColor => Themed(0x9d5d00, 0xfce100);
    static Color SkipColor => Themed(0x767676, 0x8a8a8a);
    static Color AccentColor => Themed(0x005fb8, 0x4cc2ff);
    static Color OnAccentColor => Themed(0xffffff, 0x000000); // text on Accent, Pass and Warn fills
    // Cascadia Code ships with Windows 11 but not Windows 10 or Server; without a fallback GDI substitutes a
    // proportional font and the ticket boxes stop lining up
    static readonly string MonoFamily = FontInstalled("Cascadia Code") ? "Cascadia Code" : "Consolas";
    static readonly Regex HostnamePattern = new(@"^[a-zA-Z0-9.\-]+$");
    static Pen BorderPen = new(BorderColor);
    static Pen RowLinePen = new(RowLineColor);

    static bool DetectDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch { return false; }
    }

    static readonly Font GroupHeaderFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font GroupCountFont = new("Segoe UI", 8.5f);
    static readonly Font StatusFont = new("Segoe UI", 8.5f);
    static readonly Font TestNameFont = new("Segoe UI", 9f);
    static readonly Font TestDetailFont = new(MonoFamily, 8.5f);
    static readonly Font PlaceholderFont = new("Segoe UI", 10f);
    static SolidBrush PassBrush = new(PassColor);
    static SolidBrush FailBrush = new(FailColor);
    static SolidBrush WarnBrush = new(WarnColor);
    static SolidBrush SkipBrush = new(SkipColor);
    static readonly Font TabFontInactive = new("Segoe UI", 9f);
    static readonly Font TabFontActive = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font GpBoldFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font TicketsBoldFont = new(MonoFamily, 9f, FontStyle.Bold);
    static readonly Font HistoryLabelFont = new("Segoe UI", 8f);
    static readonly Font HistoryFont = new("Segoe UI", 7.5f);
    static readonly Font HistoryFontBold = new("Segoe UI", 7.5f, FontStyle.Bold);

    readonly TextBox _txtDomain, _txtDc;
    readonly CheckBox _chkDcSuffix;
    readonly Button _btnRun, _btnExport, _btnCopy, _btnClear, _btnTheme;
    readonly ThemedButton _btnTabResults, _btnTabGuide, _btnTabGp, _btnTabTickets;
    readonly Button _btnGpRefresh, _btnGpUpdate, _btnPurgeTickets;
    readonly CheckBox _chkGpForce;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly ResultsCanvas _resultsCanvas;
    readonly Panel _summaryPanel, _resultsScrollPanel, _historyPanel, _gpPanel, _ticketsPanel;
    readonly RichTextBox _guideBox, _gpBox, _ticketsBox;
    bool _gpRunning, _gpLoaded, _ticketsLoaded;
    bool _showingExplainer;
    bool _ticketsRunning;
    List<TestGroup>? _renderedGroups;
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
        var appVersion = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        var lblTag = new Label { Text = appVersion, ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Location = new Point(148, 9) };
        var lnkGithub = new LinkLabel { Text = "GitHub", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkGithub.LinkClicked += (s, e) => OpenUrl("https://github.com/darthrater78/ad-diag");
        var lnkRelease = new LinkLabel { Text = "Release Notes", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkRelease.LinkClicked += (s, e) => OpenUrl($"https://github.com/darthrater78/ad-diag/releases/tag/v{appVersion}");
        // Names the theme it switches to; the light theme is called Flashbang
        _btnTheme = new ThemedButton { Text = ThemeButtonText, BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 8f), Size = new Size(84, 22), Location = new Point(0, 6) };
        _btnTheme.Click += (s, e) => SetTheme(!Dark);
        header.Controls.AddRange([lblTitle, lblTag, _btnTheme, lnkGithub, lnkRelease]);
        header.Resize += (s, e) =>
        {
            lblTag.Left = lblTitle.Right + S(8);
            lnkRelease.Location = new Point(header.ClientSize.Width - lnkRelease.Width - S(10), S(10));
            lnkGithub.Location = new Point(lnkRelease.Left - lnkGithub.Width - S(12), S(10));
            _btnTheme.Left = lnkGithub.Left - _btnTheme.Width - S(14);
        };
        layout.Controls.Add(header, 0, 0);

        // Config
        var configPanel = new Panel { Height = 50, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        _txtDomain = MakeInput(configPanel, "Domain", 0, 0);
        _txtDc = MakeInput(configPanel, "Domain controller (optional)", 1, 0);

        _chkDcSuffix = new CheckBox { Text = "Add domain suffix", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(0, 0) };
        configPanel.Controls.Add(_chkDcSuffix);
        configPanel.Resize += (s, e) =>
        {
            // Right-aligned over the DC field, clear of its label whatever the font or DPI
            _chkDcSuffix.Location = new Point(_txtDc.Right - _chkDcSuffix.Width, _txtDc.Top - _chkDcSuffix.Height - S(1));
        };

        layout.Controls.Add(configPanel, 0, 1);

        // Actions
        var actionsPanel = new Panel { Height = 36, Dock = DockStyle.Fill };
        actionsPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, actionsPanel.Height - 1, actionsPanel.Width, actionsPanel.Height - 1);
        _btnRun = new ThemedButton { Text = "Run diagnostics", BackColor = AccentColor, ForeColor = OnAccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(130, 26), Location = new Point(10, 4) };
        _btnRun.Click += BtnRun_Click;
        _btnExport = new ThemedButton { Text = "Export results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(110, 26), Location = new Point(148, 4), Enabled = false };
        _btnExport.Click += BtnExport_Click;
        _btnCopy = new ThemedButton { Text = "Copy results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(266, 4), Enabled = false };
        _btnCopy.Click += BtnCopy_Click;
        _btnClear = new ThemedButton { Text = "Clear results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(374, 4) };
        _btnClear.Click += BtnClear_Click;
        var btnReset = new ThemedButton { Text = "Reset all", BackColor = SurfaceColor, ForeColor = FailColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(75, 26), Location = new Point(482, 4) };
        btnReset.Click += BtnReset_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = false, Location = new Point(566, 4), Size = new Size(234, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
        actionsPanel.Controls.AddRange([_btnRun, _btnExport, _btnCopy, _btnClear, btnReset, _lblStatus]);
        layout.Controls.Add(actionsPanel, 0, 2);

        // Summary bar
        _summaryPanel = new Panel { Height = 26, Dock = DockStyle.Fill, Visible = false };
        _summaryPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _summaryPanel.Height - 1, _summaryPanel.Width, _summaryPanel.Height - 1);
        var countFont = new Font("Segoe UI", 9f, FontStyle.Bold);
        var summaryFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(8, 4, 0, 0), Margin = Padding.Empty };
        Label Count(Color color) => new() { Text = "0", ForeColor = color, Font = countFont, AutoSize = true, Margin = new Padding(0, 0, 0, 0) };
        Label Caption(string text) => new() { Text = text, ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Margin = new Padding(0, 0, 14, 0) };
        _lblPassCount = Count(PassColor);
        _lblFailCount = Count(FailColor);
        _lblWarnCount = Count(WarnColor);
        summaryFlow.Controls.AddRange([_lblPassCount, Caption("passed"), _lblFailCount, Caption("failed"), _lblWarnCount, Caption("warnings")]);
        _summaryPanel.Controls.Add(summaryFlow);
        layout.Controls.Add(_summaryPanel, 0, 3);

        // Content area with tab bar
        var contentWrapper = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };

        var tabBar = new Panel { Height = 30, Dock = DockStyle.Top, BackColor = BgColor };
        tabBar.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, tabBar.Height - 1, tabBar.Width, tabBar.Height - 1);
        _btnTabResults = new ThemedButton { Text = "Results", IsTab = true, Selected = true, BackColor = BgColor, Font = TabFontInactive, Size = new Size(80, 26), Location = new Point(10, 2) };
        _btnTabResults.Click += (s, e) => SwitchTab("results");
        _btnTabGuide = new ThemedButton { Text = "Guide", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(80, 26), Location = new Point(94, 2) };
        _btnTabGuide.Click += (s, e) => SwitchTab("guide");
        _btnTabGp = new ThemedButton { Text = "Group Policy", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(110, 26), Location = new Point(178, 2) };
        _btnTabGp.Click += (s, e) => { SwitchTab("gp"); RefreshGpTab(); };
        _btnTabTickets = new ThemedButton { Text = "Kerberos tickets", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(130, 26), Location = new Point(292, 2) };
        _btnTabTickets.Click += (s, e) => { SwitchTab("tickets"); RefreshTickets(); };
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide, _btnTabGp, _btnTabTickets]);

        // Results canvas (owner-drawn)
        _resultsScrollPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = PanelColor };
        _resultsCanvas = new ResultsCanvas { Location = Point.Empty, BackColor = PanelColor, Height = 100, AccessibleName = "Diagnostic results" };
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
            BackColor = PanelColor,
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
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _btnGpRefresh = new ThemedButton { Text = "Refresh", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28) };
        _btnGpRefresh.Click += (s, e) => RefreshGpTab();
        _btnGpUpdate = new ThemedButton { Text = "Run gpupdate", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(110, 28) };
        _btnGpUpdate.Click += BtnGpUpdate_Click;
        _chkGpForce = new CheckBox { Text = "Force", ForeColor = WarnColor, Font = new Font("Segoe UI", 8.5f, FontStyle.Bold), AutoSize = true, FlatStyle = FlatStyle.Flat };
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
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font(MonoFamily, 9f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        _btnPurgeTickets = new ThemedButton { Text = "Purge all tickets", BackColor = SurfaceColor, ForeColor = WarnColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(140, 28) };
        _btnPurgeTickets.Click += BtnPurgeTickets_Click;
        var ticketsRefreshBtn = new ThemedButton { Text = "Refresh", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28) };
        ticketsRefreshBtn.Click += (s, e) => RefreshTickets();
        var ticketsInfoBtn = new ThemedButton { Text = "What is this?", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28) };
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

        foreach (var scrolling in new Control[] { _resultsScrollPanel, _guideBox, _gpBox, _ticketsBox })
            ThemeScrollbars(scrolling);

        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);
        AcceptButton = _btnRun; // Enter in the domain or DC field starts a run

        // Everything above is laid out for 96 DPI; this scales it once to the display's DPI. Code that
        // positions or draws afterwards scales its own pixel values with S().
        AutoScaleDimensions = new SizeF(96f, 96f);
        AutoScaleMode = AutoScaleMode.Dpi;

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
        FormClosed += (s, e) =>
        {
            KillChildProcesses();
            // Not Environment.Exit: that runs the runtime's orderly shutdown, which can wait on worker threads
            // still inside a Windows call and leave ad-diag.exe running with no window. There is nothing to
            // flush (the app writes no files), so end the process outright.
            TerminateProcess(GetCurrentProcess(), 0);
        };
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

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyTitleBarTheme();
    }

    void ApplyTitleBarTheme()
    {
        int dark = Dark ? 1 : 0;
        try { DwmSetWindowAttribute(Handle, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int)); } catch { }
    }

    static string ThemeButtonText => Dark ? "Flashbang" : "Dark mode";

    // Colours a control can hold as its background or text; SetTheme maps each to the same token in the other theme
    static Color[] BackTokens() => [BgColor, PanelColor, SurfaceColor, AccentColor, WarnColor];
    static Color[] ForeTokens() => [TextColor, DimColor, PassColor, FailColor, WarnColor, AccentColor, OnAccentColor];

    /// <summary>Switches between the dark theme and the light one ("Flashbang") while the app is running.</summary>
    void SetTheme(bool dark)
    {
        if (dark == Dark) return;
        Color[] oldBack = BackTokens(), oldFore = ForeTokens();
        Dark = dark;
        Color[] newBack = BackTokens(), newFore = ForeTokens();

        foreach (IDisposable old in new IDisposable[] { BorderPen, RowLinePen, PassBrush, FailBrush, WarnBrush, SkipBrush })
            old.Dispose();
        BorderPen = new(BorderColor);
        RowLinePen = new(RowLineColor);
        PassBrush = new(PassColor);
        FailBrush = new(FailColor);
        WarnBrush = new(WarnColor);
        SkipBrush = new(SkipColor);

        static Color Map(Color c, Color[] from, Color[] to)
        {
            int i = Array.FindIndex(from, f => f.ToArgb() == c.ToArgb());
            return i >= 0 ? to[i] : c;
        }
        void Retheme(Control control)
        {
            control.BackColor = Map(control.BackColor, oldBack, newBack);
            control.ForeColor = Map(control.ForeColor, oldFore, newFore);
            if (control is LinkLabel link)
                link.LinkColor = link.ActiveLinkColor = link.VisitedLinkColor = AccentColor;
            foreach (Control child in control.Controls) Retheme(child);
        }
        Retheme(this);
        _btnTheme.Text = ThemeButtonText;
        ApplyTitleBarTheme();
        foreach (var scrolling in new Control[] { _resultsScrollPanel, _guideBox, _gpBox, _ticketsBox })
            if (scrolling.IsHandleCreated) ApplyScrollbarTheme(scrolling);

        // The text panes hold coloured runs, so they are written again in the new colours
        PopulateGuide();
        if (_gpLoaded) RefreshGpTab();
        else { _gpBox.Clear(); AppendGpLine("Switch to this tab to load Group Policy details, or click Refresh.\n", DimColor); }
        if (_showingExplainer) ShowTicketsExplainer();
        else if (_ticketsLoaded) RefreshTickets();
        RebuildHistoryBar();
        Invalidate(true);
    }

    /// <summary>Asks Windows to draw this control's scrollbars to match the theme, now and whenever its handle is created.</summary>
    static void ThemeScrollbars(Control control) => control.HandleCreated += (s, e) => ApplyScrollbarTheme(control);

    static void ApplyScrollbarTheme(Control control)
    {
        try { SetWindowTheme(control.Handle, Dark ? "DarkMode_Explorer" : "Explorer", null); } catch { }
    }

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    static extern int SetWindowTheme(IntPtr hwnd, string? appName, string? idList);

    const int DwmwaUseImmersiveDarkMode = 20; // dark title bar, Windows 10 2004 and later

    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    static Color Blend(Color a, Color b, double amount) => Color.FromArgb(
        (int)(a.R + (b.R - a.R) * amount), (int)(a.G + (b.G - a.G) * amount), (int)(a.B + (b.B - a.B) * amount));

    /// <summary>
    /// The app's button: a 4px-radius fill in its BackColor with a border when that is the plain surface, or, as
    /// a tab (<see cref="IsTab"/>), bare text with an accent underline when selected. Drawn here because a
    /// standard WinForms button can't follow the dark theme.
    /// </summary>
    sealed class ThemedButton : Button
    {
        bool _hover, _pressed, _selected;

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool IsTab { get; init; }

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool Selected
        {
            get => _selected;
            set { _selected = value; Invalidate(); }
        }

        public ThemedButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = _pressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _pressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _pressed = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        int Px(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Parent?.BackColor ?? BgColor);
            var box = new Rectangle(0, 0, Width - 1, Height - 1);
            const TextFormatFlags centered = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine;

            if (IsTab)
            {
                TextRenderer.DrawText(g, Text, _selected ? TabFontActive : Font, box, _selected || _hover ? TextColor : DimColor, centered);
                if (_selected)
                {
                    using var underline = new SolidBrush(AccentColor);
                    g.FillRectangle(underline, Px(8), Height - Px(3), Width - Px(16), Px(3));
                }
                if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(g, Rectangle.Inflate(box, -Px(3), -Px(3)));
                return;
            }

            bool plain = BackColor.ToArgb() == SurfaceColor.ToArgb();
            Color fill = !Enabled ? Blend(BackColor, BgColor, 0.6)
                : _pressed ? Blend(BackColor, TextColor, 0.14)
                : _hover ? Blend(BackColor, TextColor, 0.07)
                : BackColor;
            using (var path = RoundedRect(box, Px(4)))
            {
                using var brush = new SolidBrush(fill);
                g.FillPath(brush, path);
                if (plain || (Focused && ShowFocusCues))
                {
                    using var pen = new Pen(Focused && ShowFocusCues ? AccentColor : BorderColor);
                    g.DrawPath(pen, path);
                }
            }
            TextRenderer.DrawText(g, Text, Font, box, Enabled ? ForeColor : Blend(DimColor, fill, 0.45), centered);
        }

        static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            int d = radius * 2;
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }
    }

    /// <summary>A 96-DPI pixel value scaled to the display's DPI.</summary>
    int S(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

    TextBox MakeInput(Panel parent, string label, int col, int row)
    {
        int x = col == 0 ? 14 : parent.Width / 2 + 4;
        int y = row == 0 ? 2 : 42;
        int w = parent.Width / 2 - 24;

        var lbl = new Label
        {
            Text = label, ForeColor = DimColor,
            Font = new Font("Segoe UI", 8.5f),
            Location = new Point(x, y), AutoSize = true,
        };

        var txt = new TextBox
        {
            Text = "",
            BackColor = SurfaceColor, ForeColor = TextColor,
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font(MonoFamily, 9f),
            Location = new Point(x, y + 18), Width = w,
        };

        parent.Controls.AddRange([lbl, txt]);

        parent.Resize += (s, e) =>
        {
            int newX = col == 0 ? S(14) : parent.ClientSize.Width / 2 + S(4);
            int newW = parent.ClientSize.Width / 2 - S(24);
            lbl.Location = new Point(newX, lbl.Location.Y);
            txt.Location = new Point(newX, txt.Location.Y);
            txt.Width = newW;
        };

        return txt;
    }

    // ── Settings ────────────────────────────────────────────

    void BtnClear_Click(object? sender, EventArgs e)
    {
        _runCts?.Cancel();
        _btnRun.Enabled = true; // a cancelled run returns early and never re-enables it
        _runHistory.Clear();
        _selectedRunIndex = -1;
        _renderedGroups = null;
        _placeholderText = "Enter target domain and run diagnostics";
        _resultsCanvas.Height = S(200);
        _resultsCanvas.Invalidate();
        _summaryPanel.Visible = false;
        _btnExport.Enabled = _btnCopy.Enabled = false;
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
            btn.Selected = tab == key;
        }
    }

    // ── Guide content ───────────────────────────────────────

    static readonly Font GuideTestNameFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font GuideBodyFont = new("Segoe UI", 9f);
    static readonly Font GuideFixFont = new("Segoe UI", 8.5f);
    static readonly Font GuideFixLabelFont = new("Segoe UI", 8.5f, FontStyle.Bold);
    static Color FixLabelColor => WarnColor;

    void PopulateGuide()
    {
        _guideBox.Clear();
        AppendGuide("Test guide\n", new Font("Segoe UI", 13f, FontStyle.Bold), TextColor);

        foreach (var (title, body) in GetGuideSections())
        {
            AppendGuide($"\n{title}\n\n", new Font("Segoe UI", 10.5f, FontStyle.Bold), TextColor);

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
                        AppendGuide(line[..(dash + 3)], GuideTestNameFont, TextColor);
                        AppendGuide(line[(dash + 3)..] + "\n", GuideBodyFont, TextColor);
                    }
                    else
                    {
                        AppendGuide(line + "\n", GuideTestNameFont, TextColor);
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
                "Reads the Resultant Set of Policy (the data gpresult reports) to check whether Group Policy is applying correctly to this computer. For the full breakdown — every applied and filtered GPO for both Computer and User scope — switch to the Group Policy tab.\n\n" +
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
                "• TGT Present — checks for a krbtgt ticket in klist; if none is cached, requests one from the KDC ('klist get krbtgt/<REALM>'), proving the KDC can be reached\n" +
                "  Fix: If a TGT can't be obtained, check DC connectivity (port 88), clock skew, and the account's status (locked, disabled, expired password)\n\n" +
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
        _gpBox.SelectionFont = bold ? GpBoldFont : _gpBox.Font;
        _gpBox.AppendText(text);
    }

    // keepExisting preserves text already in the box (e.g. gpupdate output) and renders below it
    async void RefreshGpTab(bool keepExisting = false)
    {
        if (_gpRunning) return;
        _gpRunning = _gpLoaded = true;
        int keep = keepExisting ? _gpBox.TextLength : 0;
        try
        {
            ResetGpBox(keep);
            AppendGpLine("Loading Group Policy details...\n", DimColor);

            string raw = "";
            List<GpScope> scopes;
            try
            {
                scopes = await Task.Run(() => Diagnostics.QueryRsop(Probe, out raw));
            }
            catch (Exception ex)
            {
                ResetGpBox(keep);
                AppendGpLine($"Error querying Group Policy results: {ex.Message}\n", FailColor);
                return;
            }

            ResetGpBox(keep);
            if (scopes.Count == 0)
            {
                AppendGpLine("Could not read Group Policy results. Raw output:\n\n", WarnColor);
                AppendGpLine(raw, DimColor);
                return;
            }

            AppendGpLine("\n", BgColor);
            foreach (var scope in scopes)
                RenderGpScope(scope);

            _gpBox.SelectionStart = 0;
            _gpBox.ScrollToCaret();
        }
        finally
        {
            _gpRunning = false;
        }
    }

    void ResetGpBox(int keepLength)
    {
        if (keepLength == 0) { _gpBox.Clear(); return; }
        _gpBox.Select(keepLength, _gpBox.TextLength - keepLength);
        _gpBox.SelectedText = "";
    }

    void RenderGpScope(GpScope scope)
    {
        AppendGpLine($"  {scope.Name} scope\n", TextColor, bold: true);
        AppendGpLine("  ────────────────────────────────────────\n\n", BorderColor);

        if (scope.State != GpScopeState.Ok)
        {
            AppendGpLine("  " + Diagnostics.GpScopeUnavailable(scope) + "\n\n\n", scope.State == GpScopeState.Error ? FailColor : WarnColor);
            return;
        }

        if (scope.LastAppliedUtc is { } lastUtc)
        {
            var lastTime = lastUtc.ToLocalTime();
            AppendGpLine("  Last Applied: ", DimColor);
            Color ageColor = (DateTime.Now - lastTime).TotalDays >= 7 ? WarnColor : TextColor;
            AppendGpLine($"{lastTime:g}  ({Diagnostics.FormatTimeSpan(DateTime.Now - lastTime)} ago)\n", ageColor, bold: true);
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


    async void BtnGpUpdate_Click(object? sender, EventArgs e)
    {
        if (_gpRunning) return;

        bool force = _chkGpForce.Checked;
        string message = force
            ? "This will run 'gpupdate /force', which re-applies ALL group policies (not just changed ones). This can briefly disrupt mapped drives, printers, and other policy-managed settings, and may require a restart for some extensions.\n\nContinue?"
            : "This will run 'gpupdate', which applies any changed group policies.\n\nContinue?";
        var confirm = MessageBox.Show(message, "Run gpupdate",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        _gpRunning = true;
        _btnGpUpdate.Enabled = false;
        _gpBox.Clear();
        AppendGpLine(force ? "Running gpupdate /force...\n" : "Running gpupdate...\n", AccentColor, bold: true);

        try
        {
            string output = await Task.Run(() => RunProcess("gpupdate", force ? "/force" : "", timeoutMs: 90000));
            AppendGpLine("\n" + output.Trim() + "\n\n", DimColor);
        }
        catch (Exception ex)
        {
            AppendGpLine($"\ngpupdate failed: {ex.Message}\n\n", FailColor);
        }
        finally
        {
            _btnGpUpdate.Enabled = true;
            _gpRunning = false;
        }

        RefreshGpTab(keepExisting: true);
    }

    // ── Kerberos Tickets tab ──────────────────────────────────

    void AppendTicketsLine(string text, Color color, bool bold = false, Color? backColor = null)
    {
        _ticketsBox.SelectionStart = _ticketsBox.TextLength;
        _ticketsBox.SelectionLength = 0;
        _ticketsBox.SelectionColor = color;
        _ticketsBox.SelectionBackColor = backColor ?? _ticketsBox.BackColor;
        _ticketsBox.SelectionFont = bold ? TicketsBoldFont : _ticketsBox.Font;
        _ticketsBox.AppendText(text);
    }

    async void RefreshTickets()
    {
        if (_ticketsRunning) return;
        _ticketsRunning = _ticketsLoaded = true;
        _showingExplainer = false;
        _ticketsBox.Clear();
        AppendTicketsLine("Loading tickets...\n", DimColor);
        string raw;
        try { raw = await Task.Run(() => RunProcess("klist", "", timeoutMs: 5000)); }
        catch (Exception ex)
        {
            if (!_showingExplainer)
            {
                _ticketsBox.Clear();
                AppendTicketsLine($"Error running klist: {ex.Message}\n", DimColor);
            }
            return;
        }
        finally { _ticketsRunning = false; }

        if (_showingExplainer || IsDisposed) return; // user opened the explainer while klist ran
        _ticketsBox.Clear();

        var (headers, tickets) = Parsers.ParseKlist(raw);
        if (headers.Count == 0 && tickets.Count == 0)
        {
            AppendTicketsLine("No Kerberos tickets cached.\n", DimColor);
            return;
        }

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
        AppendTicketsLine($" {label} ", OnAccentColor, bold: true, backColor: badgeBg);
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

        AppendTicketsLine(" TGT  ", OnAccentColor, bold: true, backColor: AccentColor);
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

        AppendTicketsLine(" CIFS ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  SMB/File Share\n", TextColor, bold: true);
        AppendTicketsLine("       Grants access to Windows file shares (\\\\server\\share).\n\n", DimColor);

        AppendTicketsLine(" LDAP ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Directory Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Active Directory lookups and queries.\n\n", DimColor);

        AppendTicketsLine(" HOST ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Host/Remote Admin\n", TextColor, bold: true);
        AppendTicketsLine("       Used for WinRM, remote management, and scheduled tasks.\n\n", DimColor);

        AppendTicketsLine(" HTTP ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Web Service\n", TextColor, bold: true);
        AppendTicketsLine("       Used for Kerberos-authenticated web apps, ADFS, Exchange OWA.\n\n", DimColor);

        AppendTicketsLine(" RDP  ", OnAccentColor, bold: true, backColor: PassColor);
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

    async void BtnPurgeTickets_Click(object? sender, EventArgs e)
    {
        var confirm = MessageBox.Show(
            "This will destroy all cached Kerberos tickets.\n\n"
            + "Your TGT will be re-acquired on next authentication, but you may need to "
            + "re-authenticate to access network resources (file shares, web apps, etc.).\n\n"
            + "Continue?",
            "Purge Kerberos Tickets", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        _btnPurgeTickets.Enabled = false;
        try
        {
            await Task.Run(() => RunProcess("klist", "purge", timeoutMs: 5000));
            _lblStatus.Text = "Tickets purged — run diagnostics twice (first run reacquires tickets, second shows true results)";
            _lblStatus.ForeColor = WarnColor;
            RefreshTickets();
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Purge failed: {ex.Message}";
        }
        finally
        {
            _btnPurgeTickets.Enabled = true;
        }
    }

    // ── Owner-drawn results ─────────────────────────────────

    // NoPrefix: without it "&" is read as a mnemonic marker, so "SYSVOL & NETLOGON" drew as "SYSVOL _NETLOGON"
    const TextFormatFlags DetailTextFlags = TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.NoPrefix;

    // Results grid columns at 96 DPI: status mark and word, test name, then the detail to the right edge
    const int GridLeft = 14, NameX = 100, DetailX = 280;

    int DetailWidth(int width) => Math.Max(width - S(DetailX) - S(GridLeft), S(80));

    static bool IsPending(TestEntry test) => test.Status == Status.Skip && test.Detail.Length == 0;

    int MeasureResultsHeight(int width)
    {
        if (_renderedGroups == null)
            return S(200);

        int y = S(4);
        int detailW = DetailWidth(width);
        foreach (var group in _renderedGroups)
        {
            y += S(34);
            foreach (var test in group.Tests)
            {
                var sz = TextRenderer.MeasureText(test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
                y += S(4) + Math.Max(S(20), sz.Height + S(4));
            }
        }
        return y + S(14);
    }

    /// <summary>"9 checks · 1 failed · 1 warning", so a group's state reads without scanning its rows.</summary>
    static string GroupCounts(TestGroup group)
    {
        int fail = group.Tests.Count(t => t.Status == Status.Fail);
        int warn = group.Tests.Count(t => t.Status == Status.Warn);
        int running = group.Tests.Count(IsPending);
        string text = $"{group.Tests.Count} check{(group.Tests.Count == 1 ? "" : "s")}";
        if (fail > 0) text += $" · {fail} failed";
        if (warn > 0) text += $" · {warn} warning{(warn == 1 ? "" : "s")}";
        if (running > 0) text += $" · {running} running";
        return text;
    }

    // Each state has its own shape as well as its own colour, so it reads without colour vision
    void DrawStatusMark(Graphics g, TestEntry test, int x, int y)
    {
        int d = S(10);
        if (IsPending(test))
        {
            using var ring = new Pen(AccentColor, S(2));
            g.DrawEllipse(ring, x + 1, y + 1, d - 2, d - 2);
            return;
        }
        switch (test.Status)
        {
            case Status.Pass:
                g.FillEllipse(PassBrush, x, y, d, d);
                break;
            case Status.Warn:
                g.FillPolygon(WarnBrush, new Point[] { new(x + d / 2, y), new(x + d, y + d), new(x, y + d) });
                break;
            case Status.Fail:
                using (var cross = new Pen(FailColor, S(2)))
                {
                    g.DrawLine(cross, x + 1, y + 1, x + d - 1, y + d - 1);
                    g.DrawLine(cross, x + d - 1, y + 1, x + 1, y + d - 1);
                }
                break;
            default:
                g.FillRectangle(SkipBrush, x, y + d / 2 - S(1), d, S(2));
                break;
        }
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
            TextRenderer.DrawText(g, msg, PlaceholderFont, new Point(S(GridLeft), S(40)), DimColor, TextFormatFlags.NoPrefix);
            return;
        }

        int y = S(4);
        int left = S(GridLeft), right = w - S(GridLeft);
        int detailW = DetailWidth(w);
        _resultsCanvas.Rows.Clear();

        foreach (var group in _renderedGroups)
        {
            y += S(12);
            TextRenderer.DrawText(g, group.Name, GroupHeaderFont, new Point(left - S(3), y), TextColor, TextFormatFlags.NoPrefix);
            string counts = GroupCounts(group);
            int countsW = TextRenderer.MeasureText(g, counts, GroupCountFont, Size.Empty, TextFormatFlags.NoPrefix).Width;
            TextRenderer.DrawText(g, counts, GroupCountFont, new Point(right - countsW, y + S(2)), DimColor, TextFormatFlags.NoPrefix);
            y += S(22);

            foreach (var test in group.Tests)
            {
                bool pending = IsPending(test);
                var (word, color) = pending ? ("Running", DimColor) : test.Status switch
                {
                    Status.Pass => ("Passed", PassColor),
                    Status.Fail => ("Failed", FailColor),
                    Status.Warn => ("Warning", WarnColor),
                    _ => ("Skipped", DimColor),
                };

                g.DrawLine(RowLinePen, left, y, right, y);
                y += S(4);
                DrawStatusMark(g, test, left, y + S(4));
                TextRenderer.DrawText(g, word, StatusFont, new Point(left + S(15), y + S(1)), color, TextFormatFlags.NoPrefix);
                TextRenderer.DrawText(g, test.Name, TestNameFont,
                    new Rectangle(S(NameX), y, S(DetailX - NameX - 6), S(18)), TextColor,
                    TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

                // The detail is plain text: the mark and word carry the status, so a long line stays readable
                var detailSize = TextRenderer.MeasureText(g, test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
                TextRenderer.DrawText(g, test.Detail, TestDetailFont,
                    new Rectangle(S(DetailX), y + S(1), detailW, detailSize.Height),
                    test.Status == Status.Skip ? DimColor : TextColor, DetailTextFlags);

                int rowHeight = Math.Max(S(20), detailSize.Height + S(4));
                _resultsCanvas.Rows.Add(new(group.Name, test.Name, word, test.Detail, new Rectangle(left, y, right - left, rowHeight)));
                y += rowHeight;
            }
        }
    }

    /// <summary>
    /// The painted results list. It has no child controls, so it describes its rows to assistive technology
    /// itself: a list whose items are the rows as last painted (name and status, the detail as the value).
    /// </summary>
    sealed class ResultsCanvas : Panel
    {
        public record struct Row(string Group, string Name, string Status, string Detail, Rectangle Bounds);

        public readonly List<Row> Rows = [];

        public ResultsCanvas() { DoubleBuffered = true; }

        protected override AccessibleObject CreateAccessibilityInstance() => new ListAccessible(this);

        sealed class ListAccessible(ResultsCanvas owner) : ControlAccessibleObject(owner)
        {
            public override AccessibleRole Role => AccessibleRole.List;
            public override int GetChildCount() => owner.Rows.Count;
            public override AccessibleObject? GetChild(int index) =>
                index >= 0 && index < owner.Rows.Count ? new RowAccessible(owner, this, owner.Rows[index]) : null;
        }

        sealed class RowAccessible(ResultsCanvas owner, AccessibleObject list, Row row) : AccessibleObject
        {
            public override string? Name => $"{row.Name}, {row.Status}";
            public override string? Value => row.Detail;
            public override string? Description => row.Group;
            public override AccessibleRole Role => AccessibleRole.ListItem;
            public override AccessibleStates State => AccessibleStates.ReadOnly;
            public override AccessibleObject? Parent => list;
            public override Rectangle Bounds => owner.RectangleToScreen(row.Bounds);
        }
    }

    void RenderResults(List<TestGroup> groups)
    {
        _renderedGroups = groups;
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
        _btnExport.Enabled = _btnCopy.Enabled = false;
        _summaryPanel.Visible = false;
        _lblStatus.ForeColor = DimColor;
        _lblStatus.Text = "Running diagnostics...";
        SwitchTab("results");

        var results = BuildSkeleton();
        RenderResults(results);

        var pendingRun = new DiagRun(DateTime.MinValue, domain, dc, results);
        _runHistory.Insert(0, pendingRun);
        _selectedRunIndex = 0;
        RebuildHistoryBar();

        var config = new DiagConfig(domain, dc, cts.Token);
        int completed = 0;
        int totalGroups = results.Count;

        void ReplaceGroup(string name, TestGroup result)
        {
            if (cts.IsCancellationRequested || IsDisposed) return;
            int idx = results.FindIndex(g => g.Name == name);
            if (idx >= 0) results[idx] = result;
            completed++;
            _lblStatus.Text = $"Running diagnostics... ({completed}/{totalGroups})";
            if (ReferenceEquals(SelectedRun, pendingRun)) ShowResults(results);
        }

        // Each group blocks on external tools and the network for seconds at a time, so it gets its own
        // thread: on the shared pool they starve the continuations that read the tools' output
        Task<TestGroup> StartGroup(Func<DiagConfig, TestGroup> test) =>
            Task.Factory.StartNew(() => test(config), cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        var identityTask = StartGroup(cfg => Diagnostics.TestDomainMembership(cfg, Probe));
        var dcTask = StartGroup(cfg => Diagnostics.TestDcConnectivity(cfg, Probe));
        var dnsTask = StartGroup(cfg => Diagnostics.TestDnsForAd(cfg, Probe));
        var sysvolTask = StartGroup(cfg => Diagnostics.TestSysvolNetlogon(cfg, Probe));
        var gpTask = StartGroup(cfg => Diagnostics.TestGroupPolicy(cfg, Probe));
        var trustTask = StartGroup(cfg => Diagnostics.TestTrusts(cfg, Probe));
        var kerbTask = StartGroup(cfg => Diagnostics.TestKerberosAndTime(cfg, Probe));

        var pending = new List<(Task task, string name, Func<TestGroup> getResult)>
        {
            (identityTask, "Domain Membership & Identity", () => identityTask.GetAwaiter().GetResult()),
            (dcTask, "DC Discovery & Connectivity", () => dcTask.GetAwaiter().GetResult()),
            (dnsTask, "DNS for Active Directory", () => dnsTask.GetAwaiter().GetResult()),
            (sysvolTask, "SYSVOL & NETLOGON", () => sysvolTask.GetAwaiter().GetResult()),
            (gpTask, "Group Policy", () => gpTask.GetAwaiter().GetResult()),
            (trustTask, "Trust Relationships", () => trustTask.GetAwaiter().GetResult()),
            (kerbTask, "Kerberos & Time Sync", () => kerbTask.GetAwaiter().GetResult()),
        };

        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(p => p.task));
            if (cts.IsCancellationRequested || IsDisposed) return;
            var match = pending.First(p => p.task == done);
            pending.Remove(match);
            try
            {
                ReplaceGroup(match.name, match.getResult());
            }
            catch (Exception ex)
            {
                ReplaceGroup(match.name, new TestGroup(match.name, [new TestEntry("Error", Status.Fail, ex.Message)]));
            }
        }

        // The pending run may have been deleted, or another run selected, while it was running
        int pendingIndex = _runHistory.FindIndex(r => ReferenceEquals(r, pendingRun));
        if (pendingIndex >= 0)
        {
            bool wasSelected = _selectedRunIndex == pendingIndex;
            _runHistory[pendingIndex] = new DiagRun(DateTime.Now, domain, dc, results);
            if (_runHistory.Count > 5) _runHistory.RemoveAt(_runHistory.Count - 1);
            if (wasSelected || _selectedRunIndex >= _runHistory.Count)
                _selectedRunIndex = pendingIndex;
        }
        if (SelectedRun is { } selected)
            ShowResults(selected.Results);
        RebuildHistoryBar();

        _lblStatus.Text = "Complete";
        _btnRun.Enabled = true;
        _btnExport.Enabled = _btnCopy.Enabled = SelectedRun is { IsPending: false };
    }

    void RebuildHistoryBar()
    {
        // Deferred: this can run from one of these buttons' own Click handler
        var old = _historyPanel.Controls.Cast<Control>().ToArray();
        _historyPanel.Controls.Clear();
        if (old.Length > 0 && IsHandleCreated)
            BeginInvoke(() => { foreach (var c in old) c.Dispose(); });
        if (_runHistory.Count == 0)
        {
            _historyPanel.Visible = false;
            return;
        }

        int x = S(10);
        var lblRuns = new Label { Text = "Runs:", ForeColor = DimColor, Font = HistoryLabelFont, AutoSize = true, Location = new Point(x, S(6)) };
        _historyPanel.Controls.Add(lblRuns);
        x += lblRuns.PreferredWidth + S(4);

        for (int ri = _runHistory.Count - 1; ri >= 0; ri--)
        {
            int idx = ri;
            var run = _runHistory[ri];
            bool selected = ri == _selectedRunIndex;
            bool isPending = run.IsPending;
            string label = isPending ? "Pending..." : run.Timestamp.ToString("HH:mm:ss");

            var btn = new ThemedButton
            {
                Text = label, FlatStyle = FlatStyle.Flat,
                Font = selected ? HistoryFontBold : HistoryFont,
                BackColor = selected ? (isPending ? WarnColor : AccentColor) : SurfaceColor,
                ForeColor = selected ? OnAccentColor : (isPending ? WarnColor : DimColor),
                Size = new Size(S(isPending ? 72 : 62), S(20)), Location = new Point(x, S(4)),
            };
            if (!isPending) btn.Click += (s, e) => SelectRun(idx);
            _historyPanel.Controls.Add(btn);
            x += S(isPending ? 76 : 66);
        }

        var del = new ThemedButton
        {
            Text = "Delete run", FlatStyle = FlatStyle.Flat,
            Font = HistoryFont,
            BackColor = SurfaceColor, ForeColor = FailColor,
            Size = new Size(S(70), S(20)),
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
        };
        del.Location = new Point(_historyPanel.ClientSize.Width - del.Width - S(10), S(4));
        del.Click += (s, e) => DeleteRun(_selectedRunIndex);
        _historyPanel.Controls.Add(del);

        _historyPanel.Visible = true;
    }

    void SelectRun(int index)
    {
        if (index < 0 || index >= _runHistory.Count) return;
        _selectedRunIndex = index;
        ShowSelectedRun();
        RebuildHistoryBar();
    }

    void DeleteRun(int index)
    {
        if (index < 0 || index >= _runHistory.Count) return;
        _runHistory.RemoveAt(index);

        if (_runHistory.Count == 0)
        {
            _selectedRunIndex = -1;
            _renderedGroups = null;
            _placeholderText = "Run diagnostics for this domain";
            _resultsCanvas.Height = S(200);
            _resultsCanvas.Invalidate();
            _summaryPanel.Visible = false;
            _lblStatus.Text = "";
            _btnExport.Enabled = _btnCopy.Enabled = false;
        }
        else
        {
            if (_selectedRunIndex >= _runHistory.Count)
                _selectedRunIndex = _runHistory.Count - 1;
            ShowSelectedRun();
        }
        RebuildHistoryBar();
    }

    DiagRun? SelectedRun => _selectedRunIndex >= 0 && _selectedRunIndex < _runHistory.Count ? _runHistory[_selectedRunIndex] : null;

    void ShowSelectedRun()
    {
        if (SelectedRun is not { } run) return;
        ShowResults(run.Results);
        _lblStatus.Text = run.IsPending ? "Running diagnostics..." : $"Run from {run.Timestamp:HH:mm:ss}";
        _btnExport.Enabled = _btnCopy.Enabled = !run.IsPending;
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

    /// <summary>The selected run as plain text: what Export saves and Copy puts on the clipboard.</summary>
    static string BuildReport(DiagRun run)
    {
        var sb = new StringBuilder();
        sb.AppendLine("===================================================");
        sb.AppendLine("  AD Diagnostics Report");
        sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"  Run at:    {run.Timestamp:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("===================================================");
        sb.AppendLine();
        sb.AppendLine("Configuration:");
        sb.AppendLine($"  Domain:  {run.Domain}");
        sb.AppendLine($"  DC Host: {run.Dc}");
        sb.AppendLine();

        foreach (var group in run.Results)
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
        return sb.ToString();
    }

    void BtnCopy_Click(object? sender, EventArgs e)
    {
        if (SelectedRun is not { IsPending: false } run) return;
        try
        {
            Clipboard.SetText(BuildReport(run));
            _lblStatus.Text = "Results copied to the clipboard";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Copy failed: {ex.Message}";
        }
    }

    void BtnExport_Click(object? sender, EventArgs e)
    {
        if (SelectedRun is not { IsPending: false } run) return;

        using var dlg = new SaveFileDialog
        {
            FileName = $"ad-diag-{Regex.Replace(run.Domain, @"[^a-zA-Z0-9.\-]", "_")}-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt",
            DefaultExt = ".txt"
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        string report = BuildReport(run);

        try
        {
            File.WriteAllText(dlg.FileName, report, Encoding.UTF8);
            _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Export failed: {ex.Message}";
        }
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

    // ── What the diagnostics (Diagnostics.cs) ask of this machine ──

    static readonly IProbe Probe = new WindowsProbe();

    sealed class WindowsProbe : IProbe
    {
        public string RunTool(string tool, string arguments, int timeoutMs, CancellationToken ct) => RunProcess(tool, arguments, timeoutMs, ct);
        public string RunPowerShell(string script, int timeoutMs, CancellationToken ct) => MainForm.RunPowerShell(script, timeoutMs, ct);
        public IPAddress[] Resolve(string host, CancellationToken ct) => Runner.ResolveHost(host, ct);
        public Task<bool> TcpConnect(IPAddress ip, int port, CancellationToken ct) => Runner.TryTcpConnectAsync(ip, port, ct);

        public List<string>? QuerySrv(string record, CancellationToken ct) =>
            Runner.RunWithTimeout(() => MainForm.QuerySrv(record), Runner.DnsTimeoutMs, $"{record} query", ct);

        public int? ShareEntries(string path, CancellationToken ct) => Runner.RunWithTimeout<int?>(
            () => Directory.Exists(path) ? Directory.GetFileSystemEntries(path).Length : null,
            ShareTimeoutMs, $"Opening {path}", ct);

        public string CurrentUser()
        {
            using var id = WindowsIdentity.GetCurrent();
            return id.Name;
        }

        public (string SearchList, string Domain) DnsSuffixConfig()
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            return (key?.GetValue("SearchList") as string ?? "", key?.GetValue("Domain") as string ?? "");
        }

        public string?[] OwnDomainNames() => GetOwnDomainNames();
    }

    const ushort DnsTypeSrv = 33;
    const uint DnsQueryBypassCache = 0x8;       // ask the DNS server, like nslookup, not the local resolver cache
    const int DnsErrorNameError = 9003;         // DNS_ERROR_RCODE_NAME_ERROR (NXDOMAIN)
    const int DnsInfoNoRecords = 9501;          // DNS_INFO_NO_RECORDS

    /// <summary>
    /// SRV targets for <paramref name="record"/> ("host:port"), best first (lowest priority, then highest weight);
    /// null if the name or record doesn't exist. Uses the DNS API directly, so nothing depends on nslookup's
    /// (translated) output.
    /// </summary>
    static List<string>? QuerySrv(string record)
    {
        int status = DnsQuery_W(record, DnsTypeSrv, DnsQueryBypassCache, IntPtr.Zero, out IntPtr results, IntPtr.Zero);
        try
        {
            if (status is DnsErrorNameError or DnsInfoNoRecords) return null;
            if (status != 0) throw new System.ComponentModel.Win32Exception(status);

            var srv = new List<(string Target, ushort Priority, ushort Weight, ushort Port)>();
            for (IntPtr p = results; p != IntPtr.Zero;)
            {
                var r = Marshal.PtrToStructure<DnsSrvRecord>(p);
                // Only answers: the additional section carries the targets' A/AAAA records
                if (r.wType == DnsTypeSrv && (r.Flags & 0x3) == 1)
                    srv.Add((Marshal.PtrToStringUni(r.pNameTarget) ?? "", r.wPriority, r.wWeight, r.wPort));
                p = r.pNext;
            }
            return srv.Count == 0 ? null
                : srv.OrderBy(s => s.Priority).ThenByDescending(s => s.Weight).Select(s => $"{s.Target}:{s.Port}").ToList();
        }
        finally
        {
            if (results != IntPtr.Zero) DnsRecordListFree(results, 1); // DnsFreeRecordList
        }
    }

    // DNS_RECORDW's header followed by the DNS_SRV_DATAW member of its data union
    [StructLayout(LayoutKind.Sequential)]
    struct DnsSrvRecord
    {
        public IntPtr pNext;
        public IntPtr pName;
        public ushort wType;
        public ushort wDataLength;
        public uint Flags;        // bits 0-1: section (1 = answer)
        public uint dwTtl;
        public uint dwReserved;
        public IntPtr pNameTarget;
        public ushort wPriority;
        public ushort wWeight;
        public ushort wPort;
        public ushort Pad;
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    static extern int DnsQuery_W(string name, ushort type, uint options, IntPtr extra, out IntPtr results, IntPtr reserved);

    [DllImport("dnsapi.dll")]
    static extern void DnsRecordListFree(IntPtr recordList, int freeType);

    // ── Helpers ─────────────────────────────────────────────

    /// <summary>Runs a PowerShell script passed via -EncodedCommand, avoiding command-line quoting entirely.</summary>
    static string RunPowerShell(string script, int timeoutMs, CancellationToken ct = default)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return RunProcess("powershell", $"-NoProfile -NonInteractive -EncodedCommand {encoded}", timeoutMs, ct);
    }

    // Console tools write redirected output in the OEM code page (e.g. 437, 850), not UTF-8;
    // decoding it as UTF-8 garbles any non-ASCII GPO, site or user name.
    static readonly Encoding ConsoleEncoding = GetConsoleEncoding();

    static Encoding GetConsoleEncoding()
    {
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            return Encoding.GetEncoding((int)GetOEMCP());
        }
        catch { return Encoding.UTF8; }
    }

    [DllImport("kernel32.dll")]
    static extern uint GetOEMCP();

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    static extern int NetGetJoinInformation(string? server, out IntPtr nameBuffer, out int joinStatus);

    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buffer);

    /// <summary>This machine's own domain: its NetBIOS name (from the join state) and its primary DNS suffix.</summary>
    static string?[] GetOwnDomainNames()
    {
        string? netbios = null;
        try
        {
            const int NetSetupDomainName = 3;
            if (NetGetJoinInformation(null, out var buffer, out int status) == 0)
            {
                try { if (status == NetSetupDomainName) netbios = Marshal.PtrToStringUni(buffer); }
                finally { NetApiBufferFree(buffer); }
            }
        }
        catch { }

        string? dns = null;
        try { dns = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName; }
        catch { }

        return [netbios, dns];
    }

    // Every tool the app starts is put in this job, which Windows empties when the app's handle to it closes.
    // So no tool outlives the app, whether it exits normally, crashes or is ended from Task Manager.
    static readonly IntPtr ChildJob = CreateChildJob();

    const int JobObjectExtendedLimitInformationClass = 9;
    const uint JobObjectLimitKillOnJobClose = 0x2000;

    static IntPtr CreateChildJob()
    {
        try
        {
            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return IntPtr.Zero;
            var info = new JobObjectExtendedLimitInformation();
            info.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
            SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref info, Marshal.SizeOf<JobObjectExtendedLimitInformation>());
            return job;
        }
        catch { return IntPtr.Zero; }
    }

    static void KillChildProcesses()
    {
        if (ChildJob != IntPtr.Zero) TerminateJobObject(ChildJob, 1);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount; // IO_COUNTERS
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll")]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation info, int length);

    [DllImport("kernel32.dll")]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll")]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);

    /// <summary>
    /// Full path of a Windows tool in System32. A bare name would make CreateProcess search the exe's own folder
    /// and the current directory first, so a planted klist.exe next to a downloaded ad-diag.exe would run instead,
    /// elevated whenever the app is.
    /// </summary>
    static string SystemTool(string name) => Path.Combine(Environment.SystemDirectory,
        name == "powershell" ? @"WindowsPowerShell\v1.0\powershell.exe" : name + ".exe");

    /// <summary>
    /// Opens an http(s) URL in the default browser at the shell's integrity level: explorer.exe hands it to the
    /// already-running (unelevated) shell, where ShellExecute from an elevated app would open an elevated browser.
    /// </summary>
    static void OpenUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps) return;
        string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        try { Process.Start(new ProcessStartInfo(explorer, $"\"{uri.AbsoluteUri}\"") { UseShellExecute = false })?.Dispose(); }
        catch { }
    }

    const int ShareTimeoutMs = 20000;

    /// <summary>Runs a System32 tool inside the kill-on-close job; see <see cref="Runner.RunProcess"/>.</summary>
    static string RunProcess(string fileName, string arguments, int timeoutMs = 15000, CancellationToken ct = default) =>
        Runner.RunProcess(SystemTool(fileName), arguments, timeoutMs, ct, ConsoleEncoding,
            proc => { if (ChildJob != IntPtr.Zero) AssignProcessToJobObject(ChildJob, proc.Handle); });

    static bool FontInstalled(string family)
    {
        using var probe = new Font(family, 9f);
        return probe.Name.Equals(family, StringComparison.OrdinalIgnoreCase);
    }

}

// ── Data types ──────────────────────────────────────────

record DiagRun(DateTime Timestamp, string Domain, string Dc, List<TestGroup> Results)
{
    public bool IsPending => Timestamp == DateTime.MinValue;
}
