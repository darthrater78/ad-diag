using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
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
    static readonly Font ReadinessNameFont = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font ResultsLinkFont = new("Segoe UI", 9f, FontStyle.Underline);
    static SolidBrush PassBrush = new(PassColor);
    static SolidBrush FailBrush = new(FailColor);
    static SolidBrush WarnBrush = new(WarnColor);
    static SolidBrush InfoBrush = new(AccentColor);
    static SolidBrush SkipBrush = new(SkipColor);
    static readonly Font TabFontInactive = new("Segoe UI", 9f);
    static readonly Font TabFontActive = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font GpBoldFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font TicketsBoldFont = new(MonoFamily, 9f, FontStyle.Bold);
    static readonly Font HistoryLabelFont = new("Segoe UI", 8f);
    static readonly Font HistoryFont = new("Segoe UI", 7.5f);
    static readonly Font HistoryFontBold = new("Segoe UI", 7.5f, FontStyle.Bold);

    TextBox _txtDomain = null!, _txtDc = null!;
    CheckBox _chkDcSuffix = null!;
    Button _btnRun = null!, _btnRunMenu = null!, _btnExport = null!, _btnCopy = null!, _btnClear = null!, _btnTheme = null!;
    ThemedButton _btnTabResults = null!, _btnTabGuide = null!, _btnTabGp = null!, _btnTabTickets = null!, _btnTabDns = null!, _btnTabIntune = null!, _btnTabLog = null!;
    ThemedButton[] _tabs = null!;
    // Intune policies tab
    Panel _intunePanel = null!;
    RichTextBox _intuneBox = null!;
    ThemedButton _btnIntuneSync = null!;
    Label _lblIntuneNote = null!;
    bool _intuneRunning, _intuneLoaded;
    MdmEnrollment? _intuneEnrollment;
    Button _btnGpRefresh = null!, _btnGpUpdate = null!, _btnPurgeTickets = null!, _btnRegister = null!, _btnDnsCheck = null!;
    CheckBox _chkGpForce = null!, _chkDebug = null!;
    ComboBox _cmbZtna = null!;
    // How the PC is joined decides which sections run and show; detected at start-up, the user can pick another
    ComboBox _cmbProfile = null!;
    Label _lblProfileHint = null!;
    readonly List<Control> _domainControls = [];
    JoinProfile _profile = JoinProfile.Domain;
    JoinProfile? _detectedProfile;
    const int ProfileWidth = 255;
    Label _lblStatus = null!, _lblPassCount = null!, _lblFailCount = null!, _lblWarnCount = null!, _lblWarnCaption = null!, _lblInfoCount = null!, _lblInfoCaption = null!;
    ResultsCanvas _resultsCanvas = null!;
    CheckBox _chkExpandAll = null!;
    bool _expandAll; // "Expand all groups after a run"; never saved
    readonly Dictionary<string, int> _guideAnchors = []; // Guide section title -> its position in the Guide
    readonly List<(int Start, int End, string Title)> _guideHeadings = []; // where each section title sits, to fold it
    HashSet<string>? _guideOpen;                         // the Guide sections the reader opened; all start folded
    Panel _summaryPanel = null!, _resultsArea = null!, _resultsBar = null!, _resultsScrollPanel = null!, _historyPanel = null!, _gpPanel = null!, _ticketsPanel = null!, _dnsPanel = null!, _logPanel = null!;
    RichTextBox _guideBox = null!, _gpBox = null!, _ticketsBox = null!, _dnsBox = null!, _logBox = null!;
    bool _gpRunning, _gpLoaded, _ticketsLoaded;
    bool _showingExplainer;
    bool _ticketsRunning;
    List<TestGroup>? _renderedGroups;
    string? _placeholderText;
    readonly List<DiagRun> _runHistory = [];
    int _selectedRunIndex = -1;
    CancellationTokenSource? _runCts;
    bool _running; // a full run or a single section is running; only one runs at a time
    // DNS registration tab: the trace on show, kept so a theme switch can write it again
    bool _dnsRunning, _fillingZtna;
    string? _ztnaAdapter; // the picker's choice (DiagConfig.ZtnaAdapter); never saved
    string? _dnsHeading;
    readonly List<TestEntry> _dnsSteps = [];
    CancellationTokenSource? _dnsCts;
    long _logSeq; // the last log line written to the Log tab
    enum LogView { Sections, ByTime, Raw }
    LogView _logView = LogView.Sections; // the Log tab's view: by run and section, one timeline, or the plain log
    bool _logBySection => _logView == LogView.Sections;
    bool _logStale;            // a heading's totals changed since the Log tab was written
    DateTime _logRenderedAt;
    LogBlock? _logLastBlock;   // By time: the block whose heading was written last
    // Sections: the runs and sections the reader folded (a block, or a block and section name), and where each
    // heading sits in the pane, so a click or Enter on one folds or opens it
    readonly HashSet<object> _logOpen = []; // everything starts folded
    readonly List<(int Start, int End, object Key)> _logHeadings = [];
    ThemedButton _btnLogSections = null!, _btnLogByTime = null!, _btnLogRaw = null!;
    readonly System.Windows.Forms.Timer _logTimer = new() { Interval = 300 };


    public MainForm()
    {
        ConfigureWindow();
        string appVersion = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "?";
        bool elevated = false;
        try { elevated = Probe.IsElevated(); } catch (Exception) { } // unknown: shown as not elevated
        // Windows marks an elevated window this way (as Command Prompt does), and the header says it too
        if (elevated) Text = "Administrator: " + Text;
        var layout = BuildLayout();
        layout.Controls.Add(BuildHeader(appVersion, elevated), 0, 0);
        layout.Controls.Add(BuildConfigPanel(), 0, 1);
        layout.Controls.Add(BuildActionsPanel(), 0, 2);
        layout.Controls.Add(BuildSummaryPanel(), 0, 3);
        layout.Controls.Add(BuildContent(), 0, 4);

        var mainPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = Padding.Empty };
        mainPanel.Controls.Add(layout);
        Controls.Add(mainPanel);
        AcceptButton = _btnRun; // Enter in the domain or DC field starts a run

        // Everything above is laid out for 96 DPI; this scales it once to the display's DPI. Code that
        // positions or draws afterwards scales its own pixel values with S().
        AutoScaleDimensions = new SizeF(96f, 96f);
        AutoScaleMode = AutoScaleMode.Dpi;

        ShowPreview();
        WireLifecycle();
        AppLog.Info("app", $"AD Diagnostics {appVersion} on {Environment.OSVersion.VersionString}, {(elevated ? "running as Administrator" : "not elevated")}");
        _ = DetectStartupAsync();
    }

    void ConfigureWindow()
    {
        Text = "AD Diagnostics";
        Size = new Size(820, 900);
        MinimumSize = new Size(660, 500);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = BgColor;
        ForeColor = TextColor;
        Font = new Font("Segoe UI", 9f);
        DoubleBuffered = true;
        var exePath = Environment.ProcessPath ?? Application.ExecutablePath;
        var extracted = Icon.ExtractAssociatedIcon(exePath);
        if (extracted != null) Icon = extracted;
    }

    // Header, inputs, actions and counts take their own height; the tabs take the rest
    static TableLayoutPanel BuildLayout()
    {
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
        return layout;
    }

    Panel BuildHeader(string appVersion, bool elevated)
    {
        // Header
        var header = new Panel { Height = 34, Dock = DockStyle.Fill };
        header.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, header.Height - 1, header.Width, header.Height - 1);
        var lblTitle = new Label { Text = "AD Diagnostics", ForeColor = TextColor, Font = new Font("Segoe UI", 11f, FontStyle.Bold), AutoSize = true, Location = new Point(10, 6) };
        var lblTag = new Label { Text = appVersion, ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Location = new Point(148, 9) };
        var lnkGithub = new LinkLabel { Text = "GitHub", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkGithub.LinkClicked += (s, e) => OpenUrl("https://github.com/darthrater78/ad-diag");
        var lnkRelease = new LinkLabel { Text = "Release Notes", Font = new Font("Segoe UI", 8f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
        lnkRelease.LinkClicked += (s, e) => OpenUrl($"https://github.com/darthrater78/ad-diag/releases/tag/v{appVersion}");
        // Names the theme it switches to; the light theme is called Flashbang
        _btnTheme = new ThemedButton { Text = ThemeButtonText, BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 8f), Size = new Size(84, 22), Location = new Point(0, 6) };
        _btnTheme.Click += (s, e) => SetTheme(!Dark);
        header.Controls.AddRange([lblTitle, lblTag, _btnTheme, lnkGithub, lnkRelease]);
        var admin = elevated ? AdminIndicator() : null;
        if (admin != null) header.Controls.Add(admin);
        header.Resize += (s, e) =>
        {
            lblTag.Left = lblTitle.Right + S(8);
            if (admin != null) admin.Location = new Point(lblTag.Right + S(12), S(7));
            lnkRelease.Location = new Point(header.ClientSize.Width - lnkRelease.Width - S(10), S(10));
            lnkGithub.Location = new Point(lnkRelease.Left - lnkGithub.Width - S(12), S(10));
            _btnTheme.Left = lnkGithub.Left - _btnTheme.Width - S(14);
        };
        return header;
    }

    // A shield and "Running as administrator" beside the version, when the app is elevated
    Control AdminIndicator()
    {
        const string text = "Running as administrator";
        var font = new Font("Segoe UI", 8.5f);
        var box = new Panel { Size = new Size(TextRenderer.MeasureText(text, font).Width + 22, 20), AccessibleName = text, AccessibleRole = AccessibleRole.StaticText };
        box.Paint += (s, e) =>
        {
            DrawShield(e.Graphics, AccentColor, S(7), box.Height / 2f, 12);
            TextRenderer.DrawText(e.Graphics, text, font, new Rectangle(S(16), 0, box.Width - S(16), box.Height), TextColor,
                TextFormatFlags.NoPrefix | TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        };
        return box;
    }

    Panel BuildConfigPanel()
    {
        // Config
        var configPanel = new Panel { Height = 50, Dock = DockStyle.Fill };
        configPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, configPanel.Height - 1, configPanel.Width, configPanel.Height - 1);
        var lblProfile = new Label { Text = "Profile", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), Location = new Point(14, 2), AutoSize = true };
        _cmbProfile = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Location = new Point(14, 20), Width = ProfileWidth, AccessibleName = "Profile: how this PC is joined" };
        _cmbProfile.SelectionChangeCommitted += (s, e) => { _profilePicked = true; SetProfile((JoinProfile)_cmbProfile.SelectedIndex); };
        _lblProfileHint = new Label { Text = "Domain checks are hidden on an Entra joined PC. Pick Hybrid joined or Domain joined to run them.", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(ProfileWidth + 28, 24), Visible = false };
        configPanel.Controls.AddRange([lblProfile, _cmbProfile, _lblProfileHint]);
        FillProfileChoices();

        _txtDomain = MakeInput(configPanel, "Domain", 0, 0);
        _txtDc = MakeInput(configPanel, "Domain controller (optional)", 1, 0);

        _chkDcSuffix = new CheckBox { Text = "Add domain suffix", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Checked = true, Location = new Point(0, 0) };
        configPanel.Controls.Add(_chkDcSuffix);
        _domainControls.Add(_chkDcSuffix);
        configPanel.Resize += (s, e) =>
        {
            // Right-aligned over the DC field, clear of its label whatever the font or DPI
            _chkDcSuffix.Location = new Point(_txtDc.Right - _chkDcSuffix.Width, _txtDc.Top - _chkDcSuffix.Height - S(1));
        };

        return configPanel;
    }

    Panel BuildActionsPanel()
    {
        // Actions
        var actionsPanel = new Panel { Height = 36, Dock = DockStyle.Fill };
        actionsPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, actionsPanel.Height - 1, actionsPanel.Width, actionsPanel.Height - 1);
        _btnRun = new ThemedButton { Text = "Run diagnostics", BackColor = AccentColor, ForeColor = OnAccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(130, 26), Location = new Point(10, 4), Split = SplitPart.Left };
        _btnRun.Click += BtnRun_Click;
        // The Run button's drop-down: run all sections, or one
        _btnRunMenu = new ThemedButton { DropArrow = true, Split = SplitPart.Right, BackColor = AccentColor, ForeColor = OnAccentColor, FlatStyle = FlatStyle.Flat, Size = new Size(26, 26), Location = new Point(140, 4), AccessibleName = "Run one section", AccessibleRole = AccessibleRole.ButtonDropDown };
        _btnRunMenu.Click += (s, e) => ShowRunMenu();
        _btnExport = new ThemedButton { Text = "Export results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(110, 26), Location = new Point(174, 4), Enabled = false };
        _btnExport.Click += BtnExport_Click;
        _btnCopy = new ThemedButton { Text = "Copy results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(292, 4), Enabled = false };
        _btnCopy.Click += BtnCopy_Click;
        _btnClear = new ThemedButton { Text = "Clear results", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 26), Location = new Point(400, 4) };
        _btnClear.Click += BtnClear_Click;
        var btnReset = new ThemedButton { Text = "Reset all", BackColor = SurfaceColor, ForeColor = FailColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(75, 26), Location = new Point(508, 4) };
        btnReset.Click += BtnReset_Click;
        _lblStatus = new Label { ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = false, Location = new Point(591, 4), Size = new Size(209, 28), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right };
        actionsPanel.Controls.AddRange([_btnRun, _btnRunMenu, _btnExport, _btnCopy, _btnClear, btnReset, _lblStatus]);
        return actionsPanel;
    }

    Panel BuildSummaryPanel()
    {
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
        _lblInfoCount = Count(AccentColor);
        _lblWarnCaption = Caption("warnings");
        _lblInfoCaption = Caption("notes");
        summaryFlow.Controls.AddRange([_lblPassCount, Caption("passed"), _lblFailCount, Caption("failed"), _lblWarnCount, _lblWarnCaption, _lblInfoCount, _lblInfoCaption]);
        _summaryPanel.Controls.Add(summaryFlow);
        return _summaryPanel;
    }

    Panel BuildTabBar()
    {
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
        _btnTabDns = new ThemedButton { Text = "DNS registration", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(130, 26), Location = new Point(426, 2) };
        _btnTabDns.Click += (s, e) => SwitchTab("dns");
        _btnTabIntune = new ThemedButton { Text = "Intune policies", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(120, 26), Location = new Point(560, 2) };
        _btnTabIntune.Click += (s, e) => { SwitchTab("intune"); RefreshIntuneTab(); };
        _btnTabLog = new ThemedButton { Text = "Log", IsTab = true, Selected = false, BackColor = BgColor, Font = TabFontInactive, Size = new Size(60, 26), Location = new Point(684, 2) };
        _btnTabLog.Click += (s, e) => SwitchTab("log");
        _tabs = [_btnTabResults, _btnTabGuide, _btnTabGp, _btnTabTickets, _btnTabDns, _btnTabIntune, _btnTabLog];
        tabBar.Controls.AddRange(_tabs);
        return tabBar;
    }

    Panel BuildContent()
    {
        // Content area with tab bar
        var contentWrapper = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };
        var tabBar = BuildTabBar();
        BuildResultsArea();
        BuildGuideBox();
        BuildGpTab();
        BuildIntuneTab();
        BuildTicketsTab();
        (_dnsPanel, _dnsBox, _btnRegister, _btnDnsCheck, _cmbZtna) = BuildDnsTab();
        FillZtnaChoices([]);
        RenderDnsBox();

        (_logPanel, _logBox, _chkDebug) = BuildLogTab();
        // The log is written from worker threads; the pane catches up on a timer, and only while it is on show
        _logTimer.Tick += (s, e) => RefreshLog();
        _logTimer.Start();

        _historyPanel = new Panel { Height = 28, Dock = DockStyle.Top, BackColor = BgColor, Visible = false };
        _historyPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _historyPanel.Height - 1, _historyPanel.Width, _historyPanel.Height - 1);

        // The tabs share one host under the Runs strip. Docked straight into the wrapper, a tab's place depended on
        // the wrapper's child order, which WinForms can change once the strip appears, leaving tabs under it
        var tabHost = new Panel { Dock = DockStyle.Fill, BackColor = BgColor };
        tabHost.Controls.AddRange([_resultsArea, _guideBox, _gpPanel, _ticketsPanel, _dnsPanel, _intunePanel, _logPanel]);
        contentWrapper.Controls.Add(tabHost);
        contentWrapper.Controls.Add(_historyPanel);
        contentWrapper.Controls.Add(tabBar);

        foreach (var scrolling in new Control[] { _resultsScrollPanel, _guideBox, _gpBox, _ticketsBox, _dnsBox, _intuneBox, _logBox })
            ThemeScrollbars(scrolling);
        return contentWrapper;
    }

    void BuildResultsArea()
    {
        // Results canvas (owner-drawn)
        _resultsScrollPanel = new KeepScrollPanel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = PanelColor };
        _resultsCanvas = new ResultsCanvas { Location = Point.Empty, BackColor = PanelColor, Height = 100, AccessibleName = "Diagnostic results" };
        _resultsCanvas.Paint += PaintResults;
        _resultsCanvas.Activated += ActivateResultsItem;
        _resultsScrollPanel.Controls.Add(_resultsCanvas);

        BuildResultsBar();
        _resultsArea = new Panel { Dock = DockStyle.Fill, BackColor = PanelColor };
        _resultsArea.Controls.Add(_resultsScrollPanel);
        _resultsArea.Controls.Add(_resultsBar);

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
    }

    void BuildResultsBar()
    {
        // Above the results: whether groups open after a run, and opening or closing them all
        _chkExpandAll = new CheckBox { Text = "Expand all groups after a run", ForeColor = DimColor, BackColor = PanelColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Location = new Point(14, 4) };
        _chkExpandAll.CheckedChanged += (s, e) =>
        {
            _expandAll = _chkExpandAll.Checked;
            SelectedRun?.Open.Clear(); // the new default applies to the run on show too
            RerenderResults();
        };
        LinkLabel BarLink(string text, bool open)
        {
            var link = new LinkLabel { Text = text, Font = new Font("Segoe UI", 8.5f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, BackColor = PanelColor, Anchor = AnchorStyles.Top | AnchorStyles.Right };
            link.LinkClicked += (s, e) => SetAllGroupsOpen(open);
            return link;
        }
        var lnkExpandAll = BarLink("Expand all", true);
        var lnkCollapseAll = BarLink("Collapse all", false);
        _resultsBar = new Panel { Height = 26, Dock = DockStyle.Top, BackColor = PanelColor, Visible = false };
        _resultsBar.Controls.AddRange([_chkExpandAll, lnkExpandAll, lnkCollapseAll]);
        _resultsBar.Resize += (s, e) =>
        {
            lnkCollapseAll.Location = new Point(_resultsBar.ClientSize.Width - lnkCollapseAll.Width - S(14), S(6));
            lnkExpandAll.Location = new Point(lnkCollapseAll.Left - lnkExpandAll.Width - S(14), S(6));
        };
    }

    void BuildGuideBox()
    {
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
        _guideBox.MouseClick += (s, e) =>
        {
            if (e.Button == MouseButtons.Left && GuideHeadingAt(_guideBox.GetCharIndexFromPosition(e.Location)) is { } title) ToggleGuideSection(title);
        };
        _guideBox.MouseMove += (s, e) =>
            _guideBox.Cursor = GuideHeadingAt(_guideBox.GetCharIndexFromPosition(e.Location)) != null ? Cursors.Hand : Cursors.IBeam;
        _guideBox.KeyDown += (s, e) =>
        {
            if (e.KeyCode is Keys.Enter or Keys.Space && GuideHeadingAt(_guideBox.SelectionStart) is { } title)
            {
                ToggleGuideSection(title);
                e.Handled = e.SuppressKeyPress = true;
            }
        };
        PopulateGuide();
    }

    void BuildGpTab()
    {
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
        var gpBtnPanel = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        _btnGpRefresh.Location = new Point(10, 3);
        _btnGpUpdate.Location = new Point(100, 3);
        _chkGpForce.Location = new Point(216, 8);
        gpBtnPanel.Controls.AddRange([_btnGpRefresh, _btnGpUpdate, _chkGpForce]);
        _gpPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _gpPanel.Controls.Add(_gpBox);
        _gpPanel.Controls.Add(gpBtnPanel);
        AppendGpLine("Switch to this tab to load Group Policy details, or click Refresh.\n", DimColor);
    }

    void BuildIntuneTab()
    {
        // Intune policies tab
        _intuneBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
            DetectUrls = false, // policy values are text to read, not links
        };
        var btnIntuneRefresh = new ThemedButton { Text = "Refresh", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(10, 3) };
        btnIntuneRefresh.Click += (s, e) => RefreshIntuneTab();
        _btnIntuneSync = new ThemedButton { Text = "Sync now", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(90, 28), Location = new Point(100, 3), Enabled = false };
        _btnIntuneSync.Click += BtnIntuneSync_Click;
        _lblIntuneNote = new Label { Text = SyncNote, ForeColor = DimColor, BackColor = BgColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(200, 9) };
        var intuneBtnPanel = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        intuneBtnPanel.Controls.AddRange([btnIntuneRefresh, _btnIntuneSync, _lblIntuneNote]);
        _intunePanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _intunePanel.Controls.Add(_intuneBox);
        _intunePanel.Controls.Add(intuneBtnPanel);
        AppendIntuneLine("Switch to this tab to load Intune details, or click Refresh.\n", DimColor);
    }

    void BuildTicketsTab()
    {
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
            DetectUrls = false, // the PRT authority is a value to read, not a link
        };
        _btnPurgeTickets = new ThemedButton { Text = "Purge all tickets", BackColor = SurfaceColor, ForeColor = WarnColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(140, 28) };
        _btnPurgeTickets.Click += BtnPurgeTickets_Click;
        var ticketsRefreshBtn = new ThemedButton { Text = "Refresh", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28) };
        ticketsRefreshBtn.Click += (s, e) => RefreshTickets();
        var ticketsInfoBtn = new ThemedButton { Text = "What is this?", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28) };
        ticketsInfoBtn.Click += (s, e) => { if (_showingExplainer) { _showingExplainer = false; RefreshTickets(); } else ShowTicketsExplainer(); };
        var ticketsBtnPanel = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        _btnPurgeTickets.Location = new Point(10, 3);
        ticketsRefreshBtn.Location = new Point(158, 3);
        ticketsInfoBtn.Location = new Point(246, 3);
        ticketsBtnPanel.Controls.AddRange([_btnPurgeTickets, ticketsRefreshBtn, ticketsInfoBtn]);
        _ticketsPanel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        _ticketsPanel.Controls.Add(_ticketsBox);
        _ticketsPanel.Controls.Add(ticketsBtnPanel);
    }

    void WireLifecycle()
    {
        Load += (s, e) =>
        {
            LayoutTabs();
            _resultsCanvas.Width = _resultsScrollPanel.ClientSize.Width;
            _resultsCanvas.Height = MeasureResultsHeight(_resultsCanvas.Width);
            _resultsCanvas.Invalidate();
        };

        FormClosing += (s, e) =>
        {
            _runCts?.Cancel();
            _dnsCts?.Cancel();
        };
        FormClosed += (s, e) =>
        {
            KillChildProcesses();
            // Not Environment.Exit: that runs the runtime's orderly shutdown, which can wait on worker threads
            // still inside a Windows call and leave ad-diag.exe running with no window. There is nothing to
            // flush (the app writes no files), so end the process outright.
            TerminateProcess(GetCurrentProcess(), 0);
        };
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
                        string dsreg = Probe.RunTool("dsregcmd", "/status", 5000, default);
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
        RecreateThemeBrushes();

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
        foreach (var scrolling in new Control[] { _resultsScrollPanel, _guideBox, _gpBox, _ticketsBox, _dnsBox, _intuneBox, _logBox })
            if (scrolling.IsHandleCreated) ApplyScrollbarTheme(scrolling);
        RerenderTextPanes();
        Invalidate(true);
    }

    static void RecreateThemeBrushes()
    {
        foreach (IDisposable old in new IDisposable[] { BorderPen, RowLinePen, PassBrush, FailBrush, WarnBrush, InfoBrush, SkipBrush })
            old.Dispose();
        BorderPen = new(BorderColor);
        RowLinePen = new(RowLineColor);
        PassBrush = new(PassColor);
        FailBrush = new(FailColor);
        WarnBrush = new(WarnColor);
        InfoBrush = new(AccentColor);
        SkipBrush = new(SkipColor);
    }

    // The text panes hold coloured runs, so they are written again in the new colours
    void RerenderTextPanes()
    {
        PopulateGuide();
        if (_gpLoaded) RefreshGpTab();
        else { _gpBox.Clear(); AppendGpLine("Switch to this tab to load Group Policy details, or click Refresh.\n", DimColor); }
        if (_showingExplainer) ShowTicketsExplainer();
        else if (_ticketsLoaded) RefreshTickets();
        if (_intuneLoaded) RefreshIntuneTab();
        else { _intuneBox.Clear(); AppendIntuneLine("Switch to this tab to load Intune details, or click Refresh.\n", DimColor); }
        RenderDnsBox();
        RenderLog();
        RebuildHistoryBar();
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
    /// <summary>Which half of a two-part button a <see cref="ThemedButton"/> is: only its outer corners are rounded.</summary>
    enum SplitPart { None, Left, Middle, Right }

    sealed class ThemedButton : Button
    {
        bool _hover, _pressed, _selected;

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool IsTab { get; init; }

        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public SplitPart Split { get; init; }

        /// <summary>Shows a down arrow instead of text: the button opens a drop-down.</summary>
        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool DropArrow { get; init; }

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
            using (var path = RoundedRect(box, Px(4), Split))
            {
                using var brush = new SolidBrush(fill);
                g.FillPath(brush, path);
                // A filled part after the first is set off from the one before by a thin line in its text colour
                if (Split is SplitPart.Middle or SplitPart.Right && !plain)
                {
                    using var divider = new Pen(Blend(fill, ForeColor, 0.45));
                    g.DrawLine(divider, 0, Px(5), 0, Height - Px(6));
                }
                if (plain || (Focused && ShowFocusCues))
                {
                    using var pen = new Pen(Focused && ShowFocusCues ? AccentColor : BorderColor);
                    g.DrawPath(pen, path);
                }
            }
            Color ink = Enabled ? ForeColor : Blend(DimColor, fill, 0.45);
            if (DropArrow)
            {
                int d = Px(8), x = (Width - d) / 2, y = (Height - d / 2) / 2;
                using var pen = new Pen(ink, Math.Max(1f, Px(3) / 2f));
                g.DrawLines(pen, new Point[] { new(x, y), new(x + d / 2, y + d / 2), new(x + d, y) });
            }
            else
                TextRenderer.DrawText(g, Text, Font, box, ink, centered);
        }

        public static GraphicsPath RoundedRect(Rectangle r, int radius, SplitPart split = SplitPart.None)
        {
            int d = radius * 2;
            bool roundLeft = split is SplitPart.None or SplitPart.Left, roundRight = split is SplitPart.None or SplitPart.Right;
            var path = new GraphicsPath();
            if (roundLeft) path.AddArc(r.X, r.Y, d, d, 180, 90);
            else path.AddLine(r.X, r.Y, r.X, r.Y);
            if (roundRight)
            {
                path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
                path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            }
            else path.AddLine(r.Right, r.Y, r.Right, r.Bottom);
            if (roundLeft) path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            else path.AddLine(r.X, r.Bottom, r.X, r.Bottom);
            path.CloseFigure();
            return path;
        }
    }

    /// <summary>A 96-DPI pixel value scaled to the display's DPI.</summary>
    int S(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

    // An input column's left edge and width, for a panel this wide; scale turns 96-DPI pixels into the display's
    static (int X, int W) InputColumn(int panelWidth, int col, Func<int, int> scale)
    {
        int left = scale(14 + ProfileWidth + 14), gap = scale(16);
        int room = panelWidth - left - scale(14) - gap;
        int domainWidth = room * 2 / 5;
        return col == 0 ? (left, domainWidth) : (left + domainWidth + gap, room - domainWidth);
    }

    TextBox MakeInput(Panel parent, string label, int col, int row)
    {
        // Two columns to the right of the profile picker; the DC's is wider, since its label shares the row with the suffix box
        var (x, w) = InputColumn(parent.Width, col, px => px);
        int y = row == 0 ? 2 : 42;

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
        _domainControls.AddRange([lbl, txt]);

        parent.Resize += (s, e) =>
        {
            var (newX, newW) = InputColumn(parent.ClientSize.Width, col, S);
            lbl.Location = new Point(newX, lbl.Location.Y);
            txt.Location = new Point(newX, txt.Location.Y);
            txt.Width = newW;
        };

        return txt;
    }

    // ── Settings ────────────────────────────────────────────

    void BtnClear_Click(object? sender, EventArgs e)
    {
        AppLog.Info("run", "Results cleared" + (_running ? "; run cancelled" : ""));
        _runCts?.Cancel();
        _runHistory.Clear();
        SetRunning(false); // a cancelled run returns early and never ends itself
        _selectedRunIndex = -1;
        ShowPreview();
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
        _profilePicked = false;
        SetProfile(_detectedProfile ?? JoinProfile.Domain);
        BtnClear_Click(sender, e);
        _lblStatus.Text = "All fields reset";
    }

    // ── Tab switching ───────────────────────────────────────

    void SwitchTab(string tab)
    {
        _resultsArea.Visible = tab == "results";
        _guideBox.Visible = tab == "guide";
        _gpPanel.Visible = tab == "gp";
        _ticketsPanel.Visible = tab == "tickets";
        _dnsPanel.Visible = tab == "dns";
        _intunePanel.Visible = tab == "intune";
        _logPanel.Visible = tab == "log";
        if (tab == "log") RefreshLog(force: true);

        foreach (var (btn, key) in new[] { (_btnTabResults, "results"), (_btnTabGuide, "guide"), (_btnTabGp, "gp"), (_btnTabTickets, "tickets"), (_btnTabDns, "dns"), (_btnTabIntune, "intune"), (_btnTabLog, "log") })
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

    static readonly Font GuideSectionFont = new("Segoe UI", 10.5f, FontStyle.Bold);
    static readonly Font GuideChevronFont = new(MonoFamily, 9f); // ► and ▼ are in the monospace font everywhere

    // Each section folds to its title, with a chevron down when open and right when folded; all start folded, so
    // the Guide opens as a list of its sections
    void PopulateGuide()
    {
        _guideBox.Clear();
        _guideAnchors.Clear();
        _guideHeadings.Clear();
        AppendGuide("Test guide\n", new Font("Segoe UI", 13f, FontStyle.Bold), TextColor);
        AppendGuide("Click a section to open or fold it.\n", GuideBodyFont, DimColor);

        bool previousOpen = true;
        foreach (var (title, body) in GetGuideSections().Where(g => InProfile(g.Title, _profile)))
        {
            bool open = _guideOpen?.Contains(title) == true;
            if (open || previousOpen) AppendGuide("\n", GuideBodyFont, TextColor);
            previousOpen = open;
            _guideAnchors[title] = _guideBox.TextLength;
            AppendGuide(open ? "\u25BC " : "\u25BA ", GuideChevronFont, DimColor);
            AppendGuide(title, GuideSectionFont, TextColor);
            _guideHeadings.Add((_guideAnchors[title], _guideBox.TextLength, title));
            AppendGuide(open ? "\n\n" : "\n", GuideSectionFont, TextColor);
            if (!open) continue;

            foreach (var line in body.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
                AppendGuideLine(line);
            AppendGuide("\n", GuideBodyFont, DimColor);
        }

        _guideBox.SelectionStart = 0;
        _guideBox.ScrollToCaret();
    }

    // A section body line: "• Check — what it is" with the check in bold, "Fix:" and "Recommended:" labelled,
    // "- " items indented, anything else as dim text
    void AppendGuideLine(string line)
    {
        string trimmed = line.TrimStart();
        if (line.StartsWith("• "))
        {
            int dash = line.IndexOf(" — ", StringComparison.Ordinal);
            if (dash <= 0)
            {
                AppendGuide(line + "\n", GuideTestNameFont, TextColor);
                return;
            }
            AppendGuide(line[..(dash + 3)], GuideTestNameFont, TextColor);
            AppendGuide(line[(dash + 3)..] + "\n", GuideBodyFont, TextColor);
        }
        else if (trimmed.StartsWith("Fix:"))
        {
            AppendGuide("  Fix: ", GuideFixLabelFont, FixLabelColor);
            AppendGuide(trimmed[4..].TrimStart() + "\n\n", GuideFixFont, DimColor);
        }
        else if (trimmed.StartsWith("Recommended:"))
        {
            AppendGuide("  Recommended: ", GuideFixLabelFont, FixLabelColor);
            AppendGuide(trimmed[12..].TrimStart() + "\n\n", GuideFixFont, DimColor);
        }
        else if (trimmed.StartsWith("- "))
            AppendGuide("    " + trimmed + "\n", GuideBodyFont, DimColor);
        else
            AppendGuide(line + "\n", GuideBodyFont, DimColor);
    }

    string? GuideHeadingAt(int charIndex) =>
        _guideHeadings.FirstOrDefault(h => charIndex >= h.Start && charIndex <= h.End).Title;

    // Folds or opens a section and keeps its title where it was on screen
    void ToggleGuideSection(string title)
    {
        _guideOpen ??= [];
        if (!_guideOpen.Remove(title)) _guideOpen.Add(title);
        int top = _guideBox.GetLineFromCharIndex(_guideBox.GetCharIndexFromPosition(new Point(1, 1)));
        PopulateGuide();
        _guideBox.SelectionStart = _guideAnchors[title];
        _guideBox.SelectionLength = 0;
        int now = _guideBox.GetLineFromCharIndex(_guideBox.GetCharIndexFromPosition(new Point(1, 1)));
        if (top != now) SendMessage(_guideBox.Handle, EmLineScroll, IntPtr.Zero, top - now);
    }

    /// <summary>Opens the Guide tab with the section <paramref name="title"/> open and at the top.</summary>
    void ShowGuideSection(string title)
    {
        SwitchTab("guide");
        _guideOpen ??= [];
        if (_guideOpen.Add(title)) PopulateGuide();
        if (!_guideAnchors.TryGetValue(title, out int at)) return;
        // A hidden control is left out of docking, so the Guide only gets its size now; its lines wrap at that
        // width, so it is sized before the scroll or the scroll lands on the wrong line
        _guideBox.Parent?.PerformLayout();
        _guideBox.SelectionStart = at;
        _guideBox.SelectionLength = 0;
        // Scrolled by lines so the section's title is the first line shown, not just somewhere on screen. The line
        // on top is read back after each scroll and corrected, since not every rich edit scrolls exactly as asked
        int target = _guideBox.GetLineFromCharIndex(at);
        for (int attempt = 0; attempt < 4; attempt++)
        {
            int top = _guideBox.GetLineFromCharIndex(_guideBox.GetCharIndexFromPosition(new Point(1, 1)));
            if (top == target) break;
            SendMessage(_guideBox.Handle, EmLineScroll, IntPtr.Zero, target - top);
        }
    }

    const int EmLineScroll = 0x00B6;

    [DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam);

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

            ("Dynamic DNS Registration",
                "A domain member registers its own host record with the DNS server that owns its zone. These checks only read; the DNS registration tab can send a registration and trace it. A ZTNA or VPN client changes what each step means, so it is detected first.\n\n" +
                "• Registration Name — the name Windows registers: the host name plus the primary DNS suffix\n" +
                "  Fix: A machine with no primary DNS suffix registers nothing. The suffix is set by the domain join (System Properties > Computer Name > Change > More)\n\n" +
                "• ZTNA / VPN Client — an adapter from a known client (Zscaler, Cloudflare WARP, Netskope, GlobalProtect, Twingate, Island and others), any other tunnel or virtual adapter that holds an address, an adapter with a /32 address and no gateway, 100.64.0.0/10 addresses, or DNS answered by the client's local proxy (informational)\n" +
                "  Fix: Nothing to fix. It explains the results below: the client decides which DNS queries and which traffic reach the corporate network. If a client is missed or wrongly found, pick its adapter (or None) under 'ZTNA adapter' on the DNS registration tab; the choice lasts until the app closes\n\n" +
                "• Registering Adapters — the connected adapters with 'Register this connection's addresses in DNS' turned on, and the addresses they would register\n" +
                "  Fix: Turn registration off on a tunnel adapter that holds a 100.64.0.0/10 address, since no other host can route to it. Set it per adapter (IPv4 properties > Advanced > DNS) or with 'Set-DnsClient -RegisterThisConnectionsAddress'\n\n" +
                "• Zone Primary Server — the zone holding this machine's name and its primary server, from the SOA record, asked of the DNS servers of the adapters that register, as Windows does; the detail names the server that answered. Windows sends updates to the primary server\n" +
                "  Fix: If no SOA is found behind a ZTNA client, its DNS proxy is answering address lookups only; updates then need DNS for the AD zone to reach a real DNS server. A primary server shown with a 100.64.0.0/10 address is a synthetic address from the client. One with a public address is usually the zone's internet-facing copy, which takes no updates from this machine: the DNS server that answered does not know the internal zone\n\n" +
                "• Update Path (Port 53) — TCP 53 to the primary server. Secure updates negotiate over TCP and also need Kerberos (port 88) to a domain controller\n" +
                "  Fix: Allow TCP and UDP 53 to the primary server through the firewall or the ZTNA access policy\n\n" +
                "• Registered Record — the A/AAAA records the primary server holds for this machine, compared with the addresses it has now\n" +
                "  Fix: A stale or missing record means registration isn't arriving. Use Register now on the DNS registration tab (as Administrator) and read the trace. 'Refused' usually means the record is owned by another account or the zone doesn't allow updates\n\n" +
                "• Registration Errors — DNS Client warnings (event IDs in the 8000s) in the System log in the last 24 hours; Windows logs one for each failed registration and nothing on success\n" +
                "  Fix: The event text gives the server that was sent the update and the reason (refused, timed out, not authoritative)"),

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
                "  Fix: Domain members should sync from the domain hierarchy automatically. If not, run 'w32tm /config /syncfromflags:domhier /update'\n\n" +
                "• krbtgt Key — when the domain's krbtgt key was last set (its pwdLastSet), read from AD. Older than 180 days warns: a stolen key keeps forging tickets until it is rolled over\n" +
                "  Fix: A domain admin resets the krbtgt password twice, a day or more apart so replication and existing tickets catch up, for example with Microsoft's New-KrbtgtKeys.ps1. Never twice in quick succession: that invalidates every ticket at once"),

            (Diagnostics.EntraSsoGroup,
                "Checks whether this PC signs in to Microsoft 365 and other cloud apps that use Microsoft Entra ID without asking for a password, however it is joined: domain joined, hybrid joined or Entra joined. Only this PC is checked: how it is joined, its tokens, the browser settings Seamless SSO needs, and a direct connection to the sign-in endpoints. It can't see whether Seamless SSO is turned on in your tenant, or whether your domain is federated, where Seamless SSO doesn't apply.\n" +
                "Microsoft Entra joined and hybrid joined PCs sign in with their Primary Refresh Token, which Edge, Chrome and Office use on Windows. Domain-joined PCs use Seamless SSO. On a hybrid joined PC Seamless SSO is the fallback, for browsers and apps that can't use the token or for when it is missing, so while the token is in place a Seamless SSO problem shows as Info, not a warning. Entra joined PCs reach AD resources with cloud Kerberos trust instead.\n\n" +
                "• Join Type — how this PC is joined, from dsregcmd /status: hybrid joined (AzureAdJoined and DomainJoined both YES), Entra joined (AzureAdJoined only) or domain joined only\n" +
                "  Fix: A domain-joined PC that should be hybrid joined: check that Microsoft Entra Connect > Configure device options has set up the service connection point for this forest, and that the PC's OU is synchronized. Then restart the PC, or run 'dsregcmd /join' as SYSTEM\n\n" +
                "• Device Auth — DeviceAuthStatus must be SUCCESS, meaning the device is enabled in Entra ID and its certificate is valid\n" +
                "  Fix: If FAILED, an Entra admin checks the device in the Microsoft Entra admin center > Devices. Disabled: enable it. Deleted: run 'dsregcmd /leave' as Administrator and restart to join again\n\n" +
                "• Primary Refresh Token — AzureAdPrt must be YES. A token is valid for 14 days and Windows renews it at sign-in, at unlock and when apps ask for one, so a day or two old is normal; older than 14 days means renewal is failing\n" +
                "  Fix: Lock and unlock, or sign out and in. If it stays NO, read the Diagnostic Data section of 'dsregcmd /status' for the error, and check that login.microsoftonline.com and device.login.microsoftonline.com are reachable without TLS inspection\n\n" +
                "• Seamless SSO Ticket — a Kerberos ticket for HTTP/autologon.microsoftazuread-sso.com from a domain controller ('klist get'). Without it the AZUREADSSOACC computer account is missing from the user's domain, which means Seamless SSO was never turned on for this forest\n" +
                "  Fix: On the Microsoft Entra Connect server: Change user sign-in > Enable single sign-on, and enter Domain Admin credentials for this forest. To confirm, run 'Get-ADComputer AZUREADSSOACC -Properties servicePrincipalName'\n" +
                "  Recommended: allow only AES256 on AZUREADSSOACC ('Set-ADComputer AZUREADSSOACC -KerberosEncryptionType AES256') and roll its key at least every 30 days with 'Update-AzureADSSOForest' on the Entra Connect server\n\n" +
                "• Intranet Zone — https://autologon.microsoftazuread-sso.com must be in the Local intranet zone; browsers send a Kerberos ticket only to intranet sites\n" +
                "  Fix: In a GPO for the users: User Configuration > Policies > Administrative Templates > Windows Components > Internet Explorer > Internet Control Panel > Security Page > Site to Zone Assignment List. Enable it and add https://autologon.microsoftazuread-sso.com with the value 1. Then run gpupdate (Group Policy tab) and sign out and in. Edge and Chrome follow this setting; Firefox needs network.negotiate-auth.trusted-uris set to the same address\n\n" +
                "• Automatic Logon — the Local intranet zone must log on automatically with the current user name and password\n" +
                "  Fix: In the same GPO: ... Security Page > Intranet Zone > Logon options: Automatic logon only in Intranet zone\n\n" +
                "• Status Bar Scripts — 'Allow updates to status bar via script' in the Local intranet zone; only older clients need it, so off shows as Info\n" +
                "  Fix: In the same GPO: ... Security Page > Intranet Zone > Allow updates to status bar via script: Enabled\n\n" +
                "• Cloud Kerberos — Entra joined PCs: CloudTgt YES, a Microsoft Entra Kerberos ticket for Azure Files and other cloud resources\n" +
                "  Fix: Needs Windows 10 21H2 or later with current updates. Sign out and in\n\n" +
                "• On-premises Kerberos — Entra joined PCs: OnPremTgt YES, a ticket for AD issued through cloud Kerberos trust. Without it, file shares and printers ask for a password\n" +
                "  Fix: The user must be synchronized from AD: in the Microsoft Entra admin center, Users > the user > On-premises sync enabled must be Yes. Once per domain, a Domain Admin who is also a Hybrid Identity Administrator creates the Microsoft Entra Kerberos server object: 'Install-Module AzureADHybridAuthenticationManagement', then 'Set-AzureADKerberosServer -Domain <domain> -UserPrincipalName <admin UPN>'. Then sign out and in on this PC\n\n" +
                "• Cloud Trust Groups — Entra joined PCs: whether the signed-in user is in a group the Microsoft Entra Kerberos server object's password replication policy denies (by default Domain Admins, Enterprise Admins, Schema Admins, Administrators and the other privileged groups), or in none it allows. Such an account gets no on-premises tickets through cloud Kerberos trust. Read from AD: the user's own groups and the AzureADKerberos object's policy\n" +
                "  Fix: Use a separate, non-privileged account for everyday sign-in, and a privileged one only where it is needed. Don't take privileged groups off the denied list: that lets a compromised Entra ID hand out tickets for them\n\n" +
                "• Seamless SSO Key — when the AZUREADSSOACC account's Kerberos decryption key was last set, read from AD (domain and hybrid joined PCs). Microsoft says to roll it over at least every 30 days; older warns\n" +
                "  Fix: On the Microsoft Entra Connect server, as a Hybrid Identity Administrator and a domain admin: Import-Module .\\AzureADSSO.psd1, New-AzureADSSOAuthenticationContext, then Update-AzureADSSOForest -OnPremCredentials (Get-Credential)\n\n" +
                "• Cloud Kerberos Key — when the krbtgt_AzureAD key of the Microsoft Entra Kerberos server object was last set (PCs that get on-premises tickets through cloud Kerberos trust). Older than 180 days warns\n" +
                "  Fix: With the AzureADHybridAuthenticationManagement module, as a domain admin and Hybrid Identity Administrator: Set-AzureADKerberosServer -Domain <domain> -UserPrincipalName <admin> -RotateServerKey\n\n" +
                "• Entra Endpoints — a direct TCP connection on port 443 to login.microsoftonline.com and, for Seamless SSO, autologon.microsoftazuread-sso.com; nothing is sent\n" +
                "  Fix: Allow both through the firewall and proxy, and exclude them from TLS inspection. Behind a ZTNA client, check that its policy carries them. Through a proxy a warning here can be expected\n\n" +
                "Microsoft's guides: 'Microsoft Entra seamless single sign-on: quickstart' and 'How SSO to on-premises resources works on Microsoft Entra joined devices' on learn.microsoft.com"),

            (Diagnostics.CredentialsGroup,
                "How this user's sign-in credentials are held: Windows Hello for Business, the TPM that protects its keys, the encryption of cached Kerberos tickets, and Windows credentials saved in Credential Manager. Runs on every profile. Credential Manager is read for the names of saved credentials only, never their passwords.\n\n" +
                "• Windows Hello — whether Hello for Business is set up for this user (dsregcmd NgcSet). Not set up is Info: a password or smart card still signs in\n" +
                "  Fix: To set it up, enable Windows Hello for Business by Group Policy (Computer Configuration > Administrative Templates > Windows Components > Windows Hello for Business) or Intune (Devices > Enrollment > Windows Hello for Business), then sign out and in\n\n" +
                "• Hello Trust — how Hello signs in to on-premises resources: cloud Kerberos trust, certificate trust, or key trust when neither is set. On an Entra joined PC with none set, Hello reaches cloud apps only (Info)\n" +
                "  Fix: For Entra joined PCs that need file shares and other AD resources, deploy cloud Kerberos trust: create the Microsoft Entra Kerberos server object in AD, then set Use cloud trust for on-premises authentication by Group Policy or the PassportForWork policy in Intune\n\n" +
                "• Sign-in Methods — PIN, plus the fingerprint, face or iris enrolled for this user\n\n" +
                "• TPM — the TPM's version, and on a PC joined to Entra ID whether the device key is protected by it (TpmProtected). No TPM, TPM 1.2, or a device key outside the TPM warns: the keys are then kept in software\n" +
                "  Fix: Turn on the TPM (Security Device / PTT / fTPM) in the firmware settings. A device key outside the TPM is fixed by joining again: 'dsregcmd /leave' as Administrator, restart, and join\n\n" +
                "• Ticket Encryption — cached Kerberos tickets that use RC4 instead of AES. Domain controllers hardened to AES refuse RC4, and Microsoft is retiring it\n" +
                "  Fix: Set the service account's msDS-SupportedEncryptionTypes to AES (0x18), reset its password so AES keys exist, then purge tickets on the Kerberos tickets tab\n\n" +
                "• Saved Credentials — Windows credentials saved in Credential Manager for servers. A saved password is used instead of the signed-in user's own sign-in, and locks the account out once the password changes\n" +
                "  Fix: Remove them in Control Panel > Credential Manager > Windows Credentials, or 'cmdkey /delete:<target>'"),

            (Diagnostics.IntuneGroup,
                "Whether this PC is managed by Microsoft Intune (or another MDM), read from the registry keys the Windows MDM client keeps. It runs on every profile, since Intune works the same however the PC is joined. Whether Intune counts the PC as compliant is decided in the service and isn't stored on the PC, so it isn't checked. The Intune policies tab lists every setting Intune pushed.\n\n" +
                "• MDM Enrollment — enrolled, and the account that enrolled the PC. Not enrolled is Info, and the other checks don't apply\n" +
                "  Fix: Enroll from Settings > Accounts > Access work or school > Connect, or through automatic enrollment (Microsoft Entra ID > Mobility (MDM and WIP) > Microsoft Intune, MDM user scope). For an enrollment that isn't complete, read Event Viewer > Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin\n\n" +
                "• Last Sync — when the PC last synced with Intune. A PC that is on syncs about every 8 hours, so over a week, or a failed attempt since the last success, warns\n" +
                "  Fix: Click Sync now on the Intune policies tab, or Sync in Settings > Accounts > Access work or school > Info. If it fails, read the DeviceManagement-Enterprise-Diagnostics-Provider log, and check that the PC reaches *.manage.microsoft.com without TLS inspection\n\n" +
                "• Management Extension — the Intune Management Extension service, which installs Win32 apps and runs scripts and remediations. Not installed is Info: Intune adds it with the first such assignment\n" +
                "  Fix: If it is stopped, start the 'Microsoft Intune Management Extension' service. If it won't stay running, read its logs in C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\n\n" +
                "• Device Policies — how many settings Intune pushed to the device are in force; a setting another provider (another MDM, a provisioning package) sets instead is counted separately\n" +
                "  Fix: None arriving: check the device's and user's group assignments in the Intune admin center, then sync"),
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
        DiagLog.Block = new LogBlock($"Group Policy {Clock(DateTime.Now)}", "Resultant Set of Policy query");
        _gpRunning = _gpLoaded = true;
        int keep = keepExisting ? _gpBox.TextLength : 0;
        try
        {
            ResetGpBox(keep);
            AppendGpLine("Loading Group Policy details...\n", DimColor);
            string raw = "";
            List<GpScope> scopes;
            try { scopes = await Task.Run(() => Diagnostics.QueryRsop(Probe, out raw)); }
            catch (Exception ex)
            {
                ResetGpBox(keep);
                AppendGpLine($"Error querying Group Policy results: {ex.Message}\n", FailColor);
                return;
            }
            ResetGpBox(keep);
            RenderGpResults(scopes, raw);
        }
        finally
        {
            _gpRunning = false;
        }
    }

    void RenderGpResults(List<GpScope> scopes, string raw)
    {
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

        RenderGpoList("Applied GPOs", scope.Applied.Select(gpo => (gpo, "")).ToList(), PassColor);
        RenderGpoList("Denied / Filtered GPOs", scope.Denied, WarnColor);
        AppendGpLine("\n\n", BorderColor);
    }

    void RenderGpoList(string title, List<(string Name, string Reason)> gpos, Color mark)
    {
        AppendGpLine("\n", BorderColor);
        AppendGpLine($"  {title}", TextColor, bold: true);
        AppendGpLine($"  ({gpos.Count})\n", DimColor);
        if (gpos.Count == 0)
            AppendGpLine("    None\n", DimColor);
        foreach (var (name, reason) in gpos)
        {
            AppendGpLine("    ● ", mark);
            AppendGpLine(name, TextColor);
            if (!string.IsNullOrEmpty(reason))
                AppendGpLine($"  — {reason}", DimColor);
            AppendGpLine("\n", TextColor);
        }
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

        DiagLog.Block = new LogBlock($"Group Policy {Clock(DateTime.Now)}", force ? "gpupdate /force" : "gpupdate");
        _gpRunning = true;
        _btnGpUpdate.Enabled = false;
        _gpBox.Clear();
        AppendGpLine(force ? "Running gpupdate /force...\n" : "Running gpupdate...\n", AccentColor, bold: true);

        try
        {
            string output = await Task.Run(() => Probe.RunTool("gpupdate", force ? "/force" : "", 90000, default));
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

    // ── Profile ─────────────────────────────────────────────

    bool _profilePicked; // the user chose a profile, so a late detection only marks its choice "(detected)"

    static string ProfileName(JoinProfile profile) => profile switch
    {
        JoinProfile.Domain => "Domain joined",
        JoinProfile.Hybrid => "Microsoft Entra hybrid joined",
        _ => "Microsoft Entra joined",
    };


    void FillProfileChoices()
    {
        _cmbProfile.Items.Clear();
        foreach (var profile in Enum.GetValues<JoinProfile>())
            _cmbProfile.Items.Add(ProfileName(profile) + (profile == _detectedProfile ? " (detected)" : ""));
        _cmbProfile.SelectedIndex = (int)_profile;
    }

    /// <summary>
    /// Shows what the profile covers: an Entra joined PC has no domain, so the Domain and DC fields, the Group Policy
    /// tab and the domain-only sections and Guide sections go. Runs already made keep their own sections.
    /// </summary>
    void SetProfile(JoinProfile profile, bool detected = false)
    {
        bool changed = profile != _profile;
        _profile = profile;
        if (detected) _detectedProfile = profile;
        FillProfileChoices();

        bool entra = profile == JoinProfile.Entra;
        foreach (var control in _domainControls) control.Visible = !entra;
        _lblProfileHint.Visible = entra;
        _btnTabGp.Visible = !entra;
        LayoutTabs();
        if (entra && _gpPanel.Visible) SwitchTab("results");
        PopulateGuide();
        if (_runHistory.Count == 0) ShowPreview();
        if (changed || detected)
            AppLog.Info("app", $"Profile: {ProfileName(profile)}{(detected ? " (detected)" : " (picked)")}");
        if (!entra && string.IsNullOrWhiteSpace(_txtDomain.Text)) _ = DetectDomainAsync();
    }

    // How the PC is joined decides the profile; the domain is filled in afterwards where the profile has one
    async Task DetectStartupAsync()
    {
        try
        {
            var ds = await Task.Run(() => Parsers.ParseDsreg(Probe.RunTool("dsregcmd", "/status", 5000, default)));
            if (IsDisposed) return;
            var detected = Diagnostics.DetectProfile(ds);
            if (_profilePicked)
            {
                _detectedProfile = detected;
                FillProfileChoices();
            }
            else SetProfile(detected, detected: true);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AppLog.Info("app", $"Profile not detected: {ex.Message}; using {ProfileName(_profile)}");
            if (!IsDisposed) await DetectDomainAsync();
        }
    }

    // Tabs sit left to right in a fixed order, closing up around a hidden one
    void LayoutTabs()
    {
        int x = S(10);
        foreach (var tab in _tabs.Where(t => t.Visible))
        {
            tab.Left = x;
            x += tab.Width + S(4);
        }
    }

    // ── Intune policies tab ─────────────────────────────────

    const string SyncNote = "Sync now asks first, then starts the same sync as Settings > Accounts > Access work or school > Sync";
    static readonly Font IntuneBoldFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font IntuneValueFont = new(MonoFamily, 8.5f);

    void AppendIntuneLine(string text, Color color, bool bold = false, bool mono = false)
    {
        _intuneBox.SelectionStart = _intuneBox.TextLength;
        _intuneBox.SelectionLength = 0;
        _intuneBox.SelectionColor = color;
        _intuneBox.SelectionBackColor = _intuneBox.BackColor;
        _intuneBox.SelectionFont = bold ? IntuneBoldFont : mono ? IntuneValueFont : _intuneBox.Font;
        _intuneBox.AppendText(text);
    }

    async void RefreshIntuneTab()
    {
        if (_intuneRunning) return;
        _intuneRunning = _intuneLoaded = true;
        DiagLog.Block = new LogBlock($"Intune policies {Clock(DateTime.Now)}", "MDM enrollment and policy settings from the registry");
        _intuneBox.Clear();
        AppendIntuneLine("Loading Intune details...\n", DimColor);

        (MdmEnrollment? Enrollment, IntuneState? State, string? Error) read;
        try { read = await Task.Run(ReadIntuneDetails); }
        finally { _intuneRunning = false; }
        if (IsDisposed) return;

        _intuneEnrollment = read.Enrollment;
        _btnIntuneSync.Enabled = read.Enrollment != null && Diagnostics.SyncTaskPath(read.Enrollment) != null;
        _intuneBox.Clear();
        if (read.Error != null)
            AppendIntuneLine($"  Intune details not read: {read.Error}\n", FailColor);
        else if (read.State == null)
        {
            AppendIntuneLine("  Not enrolled in Intune or another MDM\n\n", TextColor, bold: true);
            AppendIntuneLine("  This PC gets no Intune policies. To enroll it: Settings > Accounts > Access work or school > Connect,\n  or automatic enrollment through Microsoft Entra ID.\n", DimColor);
        }
        else RenderIntune(read.State);
        _intuneBox.SelectionStart = 0;
        _intuneBox.ScrollToCaret();
    }

    // The enrollment and what it pushed; never throws, so a failure becomes the reason shown in the tab
    static (MdmEnrollment? Enrollment, IntuneState? State, string? Error) ReadIntuneDetails()
    {
        try
        {
            var enrollment = Diagnostics.ReadEnrollment(Probe);
            return (enrollment, enrollment == null ? null : Diagnostics.ReadIntuneState(Probe, enrollment), null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return (null, null, "needs Run as Administrator to read the enrollment");
        }
        catch (Exception ex)
        {
            return (null, null, ex.Message);
        }
    }

    void IntuneSection(string title)
    {
        AppendIntuneLine($"  {title}\n", TextColor, bold: true);
        AppendIntuneLine("  ────────────────────────────────────────\n\n", BorderColor);
    }

    void RenderIntune(IntuneState s)
    {
        RenderIntuneEnrollment(s);
        if (s.PolicyError != null)
        {
            IntuneSection("Policy settings");
            AppendIntuneLine($"  Not read: {s.PolicyError}\n", WarnColor);
            return;
        }
        var e = s.Enrollment;
        RenderIntuneScope("Device scope", s.Device, e.ProviderName);
        RenderIntuneScope(e.Upn is { Length: > 0 } user ? $"User scope ({user})" : "User scope", s.User, e.ProviderName);
    }

    void RenderIntuneEnrollment(IntuneState s)
    {
        var e = s.Enrollment;
        IntuneSection("Enrollment");
        AppendIntuneLine("  MDM: ", DimColor);
        AppendIntuneLine(e.ProviderName, TextColor, bold: true);
        if (e.Upn is { Length: > 0 } upn)
        {
            AppendIntuneLine("  enrolled as ", DimColor);
            AppendIntuneLine(upn, TextColor, mono: true);
        }
        AppendIntuneLine("\n", TextColor);
        if (e.State != 1)
            AppendIntuneLine($"  Enrollment not complete (EnrollmentState {e.State?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "not set"})\n", WarnColor);

        RenderIntuneSync(s);
        AppendIntuneLine("  Management Extension: ", DimColor);
        var (text, color) = ExtensionLook(s);
        AppendIntuneLine(text + "\n\n\n", color);
    }

    void RenderIntuneSync(IntuneState s)
    {
        AppendIntuneLine("  Last sync: ", DimColor);
        if (s.SyncError != null)
        {
            AppendIntuneLine($"not read: {s.SyncError}\n", DimColor);
            return;
        }
        if (s.LastSuccess is not { } success)
        {
            AppendIntuneLine("none recorded\n", DimColor);
            return;
        }
        var age = Diagnostics.Age(success, DateTime.UtcNow);
        AppendIntuneLine($"{success.ToLocalTime():g}", age.TotalDays > 7 ? WarnColor : TextColor, bold: true);
        AppendIntuneLine($"  ({Diagnostics.FormatTimeSpan(age)} ago)", DimColor);
        if (s.LastFailure is { } failure && failure > success)
            AppendIntuneLine($"   Last attempt failed {failure.ToLocalTime():g}", WarnColor);
        AppendIntuneLine("\n", TextColor);
    }

    static (string Text, Color Color) ExtensionLook(IntuneState s) => s.ExtensionError != null
        ? ($"not read: {s.ExtensionError}", DimColor)
        : s.ExtensionState switch
        {
            null => ("not installed", DimColor),
            4 => ("running", PassColor),
            1 => ("stopped", WarnColor),
            var other => ($"state {other}", TextColor),
        };

    void RenderIntuneScope(string title, List<MdmSetting> settings, string provider)
    {
        IntuneSection(title);
        if (settings.Count == 0)
        {
            AppendIntuneLine($"    None from {provider}\n\n\n", DimColor);
            return;
        }
        var areas = settings.GroupBy(x => x.Area).ToList();
        AppendIntuneLine($"  {settings.Count} setting{(settings.Count == 1 ? "" : "s")} in {areas.Count} area{(areas.Count == 1 ? "" : "s")} from {provider}\n", DimColor);
        foreach (var area in areas)
        {
            AppendIntuneLine($"\n  {area.Key}", TextColor, bold: true);
            AppendIntuneLine($"  ({area.Count()})\n", DimColor);
            foreach (var setting in area)
            {
                AppendIntuneLine("    ● ", setting.ProviderWins ? PassColor : WarnColor);
                AppendIntuneLine(setting.Name + "  ", TextColor);
                AppendIntuneLine(setting.Value, TextColor, mono: true);
                if (!setting.ProviderWins)
                    AppendIntuneLine($"  — another provider's value is in force ({setting.Winner})", DimColor);
                AppendIntuneLine("\n", TextColor);
            }
        }
        AppendIntuneLine("\n\n", TextColor);
    }

    // Starts the MDM client's own sync task, the one behind Sync in Settings (script and its result: Intune.cs)
    async void BtnIntuneSync_Click(object? sender, EventArgs e)
    {
        if (_intuneRunning || _intuneEnrollment is not { } enrollment || Diagnostics.SyncTaskPath(enrollment) is not { } task) return;
        var confirm = MessageBox.Show(
            $"This asks {enrollment.ProviderName} for new policies and apps now, the same as Sync in Settings > Accounts > Access work or school. "
            + "Anything it receives applies as it arrives.\n\nContinue?",
            "Sync with Intune", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        DiagLog.Block = new LogBlock($"Intune sync {Clock(DateTime.Now)}", "Start-ScheduledTask PushLaunch");
        _btnIntuneSync.Enabled = false;
        (bool Started, string Reason) result;
        try { result = Diagnostics.ParseSyncOutput(await Task.Run(() => Probe.RunPowerShell(Diagnostics.SyncScript(task), 30000, default))); }
        catch (Exception ex) { result = (false, ex.Message); }
        finally { if (!IsDisposed) _btnIntuneSync.Enabled = true; }
        if (IsDisposed) return;
        ShowSyncResult(result.Started, result.Reason);
    }

    void ShowSyncResult(bool started, string reason)
    {
        AppLog.Info("intune", started ? "Sync started" : $"Sync not started: {reason}");
        _lblIntuneNote.ForeColor = started ? TextColor : FailColor;
        if (started)
        {
            _lblIntuneNote.Text = $"Sync started at {Clock(DateTime.Now)}. It takes a minute or two; click Refresh to see the new sync time.";
            return;
        }
        bool elevated = false;
        try { elevated = Probe.IsElevated(); } catch (Exception) { } // unknown: suggest elevating anyway
        _lblIntuneNote.Text = $"Sync not started: {reason}{(elevated ? "" : " Run as Administrator, or use Sync in Settings.")}";
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
        DiagLog.Block = new LogBlock($"Kerberos tickets {Clock(DateTime.Now)}", "dsregcmd /status, klist");
        _ticketsRunning = _ticketsLoaded = true;
        _showingExplainer = false;
        _ticketsBox.Clear();
        AppendTicketsLine("Loading tickets...\n", DimColor);
        // The PRT card comes from dsregcmd; it runs beside klist, and a failure only leaves a note in its place
        var prtTask = Task.Run(ReadPrtCard);
        string raw;
        try { raw = await Task.Run(() => Probe.RunTool("klist", "", 5000, default)); }
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

        var prt = await prtTask;
        if (_showingExplainer || IsDisposed) return; // user opened the explainer while klist ran
        _ticketsBox.Clear();

        if (prt.Card is { } card) RenderPrtCard(card);
        else if (prt.Error is { } error) AppendTicketsLine($"Primary Refresh Token not checked: dsregcmd failed: {error}\n\n", DimColor);

        RenderTicketList(raw);
    }

    static (PrtCard? Card, string? Error) ReadPrtCard()
    {
        try { return (Diagnostics.PrtCardFor(Parsers.ParseDsreg(Probe.RunTool("dsregcmd", "/status", 5000, default)), DateTime.UtcNow), null); }
        catch (Exception ex) { return (null, ex.Message); }
    }

    void RenderTicketList(string raw)
    {
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

    // Same frame as a ticket; the badge and any coloured value take the Results row's status colour
    void RenderPrtCard(PrtCard card)
    {
        Color Tone(Status s) => StatusLook(new TestEntry("", s)).Color;
        int width = card.Rows.Max(r => r.Label.Length) + 2;

        AppendTicketsLine(" ┌─ ", BorderColor);
        AppendTicketsLine($" {card.Badge} ", OnAccentColor, bold: true, backColor: Tone(card.BadgeStatus));
        AppendTicketsLine($"  {card.Caption}\n", DimColor);
        AppendTicketsLine(" │\n", BorderColor);
        foreach (var row in card.Rows)
        {
            AppendTicketsLine(" │  ", BorderColor);
            AppendTicketsLine($"{row.Label}:".PadRight(width), DimColor);
            AppendTicketsLine(row.Value + "\n", row.Tone is { } t ? Tone(t) : TextColor, bold: row.Label == "Status");
        }
        AppendTicketsLine(" └──\n\n", BorderColor);
    }

    void RenderTicket(string server, Dictionary<string, string> fields, int index)
    {
        string svc = server.Split('/')[0].ToUpperInvariant();
        string cacheFlag = fields.TryGetValue("Cache Flags", out var cf) ? cf : "";
        bool isDelegation = cacheFlag.Contains("DELEGATION", StringComparison.OrdinalIgnoreCase);
        bool isPrimary = cacheFlag.Contains("PRIMARY", StringComparison.OrdinalIgnoreCase);
        var (label, desc) = TicketKind(svc, isDelegation, isPrimary);

        AppendTicketsLine($"\n ┌─ ", BorderColor);
        AppendTicketsLine($" {label} ", OnAccentColor, bold: true, backColor: svc == "KRBTGT" ? AccentColor : PassColor);
        AppendTicketsLine($"  {desc}\n", DimColor);
        AppendTicketsLine($" │\n", BorderColor);

        TicketField("Server", server, TextColor, bold: true);
        if (fields.TryGetValue("Client", out var client))
            TicketField("Client", client, TextColor, bold: true);
        if (fields.TryGetValue("KerbTicket Encryption Type", out var enc))
            TicketField("Encryption", enc, enc.Contains("AES", StringComparison.OrdinalIgnoreCase) ? PassColor
                : enc.Contains("RC4", StringComparison.OrdinalIgnoreCase) ? WarnColor : TextColor);
        if (fields.TryGetValue("Ticket Flags", out var flags))
            TicketField("Flags", flags, DimColor);
        if (!string.IsNullOrEmpty(cacheFlag))
            TicketField("Cache", cacheFlag, isDelegation ? WarnColor : isPrimary ? PassColor : TextColor);
        if (fields.TryGetValue("Kdc Called", out var kdc))
            TicketField("KDC", kdc, TextColor);

        foreach (var timeKey in new[] { "Start Time", "End Time", "Renew Time" })
        {
            if (!fields.TryGetValue(timeKey, out var timeVal)) continue;
            bool expired = timeKey == "End Time" && TicketExpired(timeVal);
            TicketField(timeKey, timeVal + (expired ? "  EXPIRED" : ""), expired ? FailColor : TextColor);
        }

        AppendTicketsLine($" └──\n", BorderColor);
    }

    // One " │  Label: value" line of a ticket card
    void TicketField(string label, string value, Color color, bool bold = false)
    {
        AppendTicketsLine(" │  ", BorderColor);
        AppendTicketsLine($"{label}: ", DimColor);
        AppendTicketsLine(value + "\n", color, bold: bold);
    }

    static bool TicketExpired(string endTime) =>
        DateTime.TryParse(Regex.Replace(endTime, @"\s*\(.*?\)\s*$", ""), out var end) && end < DateTime.Now;

    static (string Label, string Desc) TicketKind(string svc, bool isDelegation, bool isPrimary) => svc switch
    {
        "KRBTGT" => ("TGT", isDelegation ? "Delegation TGT — forwarded for Kerberos delegation"
            : isPrimary ? "Primary TGT — your main logon credential from the KDC"
            : "Ticket Granting Ticket — master key from KDC"),
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

        AppendTicketsLine("PRIMARY REFRESH TOKEN\n\n", AccentColor, bold: true);
        AppendTicketsLine(" PRT  ", OnAccentColor, bold: true, backColor: PassColor);
        AppendTicketsLine("  Primary Refresh Token\n", TextColor, bold: true);
        AppendTicketsLine("       Shown above the tickets on Entra and hybrid joined PCs. It is not a\n", DimColor);
        AppendTicketsLine("       Kerberos ticket, so klist never lists it: it comes from dsregcmd /status.\n", DimColor);
        AppendTicketsLine("       Edge, Chrome and Office use it to sign in to Microsoft Entra ID.\n", DimColor);
        AppendTicketsLine("       It lasts 14 days, and Windows renews it at sign-in and unlock.\n", DimColor);
        AppendTicketsLine("       Missing or expired on a hybrid joined PC, browsers fall back to\n", DimColor);
        AppendTicketsLine("       Seamless SSO (amber); on an Entra joined PC it is red.\n\n", DimColor);

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
        DiagLog.Block = new LogBlock($"Kerberos tickets {Clock(DateTime.Now)}", "klist purge");

        _btnPurgeTickets.Enabled = false;
        try
        {
            await Task.Run(() => Probe.RunTool("klist", "purge", 5000, default));
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

    // ── DNS registration tab ──────────────────────────────────

    // The tab's controls, for the constructor to keep
    (Panel Panel, RichTextBox Box, Button Register, Button Check, ComboBox Ztna) BuildDnsTab()
    {
        var box = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        var register = new ThemedButton { Text = "Register now", BackColor = SurfaceColor, ForeColor = AccentColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Size = new Size(110, 28), Location = new Point(10, 3) };
        register.Click += BtnRegister_Click;
        var check = new ThemedButton { Text = "Check again", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28), Location = new Point(128, 3) };
        check.Click += BtnDnsCheck_Click;
        var lblZtna = new Label { Text = "ZTNA adapter:", ForeColor = DimColor, Font = new Font("Segoe UI", 9f), AutoSize = true, Location = new Point(244, 9) };
        var ztna = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, FlatStyle = FlatStyle.Flat, BackColor = SurfaceColor, ForeColor = TextColor, Font = new Font("Segoe UI", 9f), Location = new Point(334, 5), Size = new Size(290, 24), AccessibleName = "ZTNA adapter" };
        ztna.DropDown += (s, e) => RefreshZtnaChoices();
        ztna.SelectedIndexChanged += CmbZtna_SelectedIndexChanged;
        var buttons = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        buttons.Controls.AddRange([register, check, lblZtna, ztna]);
        // The picker takes the room the window gives it, up to where a longer line stops being easier to read
        buttons.Resize += (s, e) =>
            ztna.Width = Math.Clamp(buttons.Width - ztna.Left - register.Left, register.Width, ztna.Left * 3 / 2);
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        panel.Controls.Add(box);
        panel.Controls.Add(buttons);
        return (panel, box, register, check, ztna);
    }

    static string StatusWord(Status status) => status switch
    {
        Status.Pass => "Passed", Status.Fail => "Failed", Status.Warn => "Warning", Status.Info => "Info", _ => "Skipped",
    };

    // The wait is a step in progress, not a verdict, in the pane and in the log alike
    static string StepWord(TestEntry step) => step.Name == Diagnostics.RegWait ? "Waiting" : StatusWord(step.Status);

    static void AppendRun(RichTextBox box, string text, Color color, Font? font = null)
    {
        box.SelectionStart = box.TextLength;
        box.SelectionLength = 0;
        box.SelectionColor = color;
        box.SelectionFont = font ?? box.Font;
        box.AppendText(text);
    }

    // Starts a paragraph in the DNS pane: a result row has the grid's three columns (status, name, detail) and
    // wraps its detail under the detail column; anything else is plain text
    void DnsParagraph(bool row)
    {
        _dnsBox.SelectionStart = _dnsBox.TextLength;
        _dnsBox.SelectionLength = 0;
        _dnsBox.SelectionTabs = row ? [S(96), S(270)] : [];
        _dnsBox.SelectionHangingIndent = row ? S(270) : 0;
    }

    void AppendDnsStep(TestEntry step)
    {
        // Shapes as in the results grid, so the status reads without colour
        var (mark, color) = step.Status switch
        {
            Status.Pass => ("●", PassColor), Status.Warn => ("▲", WarnColor), Status.Fail => ("✕", FailColor), Status.Info => ("i", AccentColor), _ => ("–", DimColor),
        };
        DnsParagraph(row: true);
        AppendRun(_dnsBox, $"  {mark} {StepWord(step)}", color);
        AppendRun(_dnsBox, $"\t{step.Name}", TextColor, GpBoldFont);
        AppendRun(_dnsBox, $"\t{step.Detail}\n", step.Status == Status.Skip ? DimColor : TextColor);
        _dnsBox.ScrollToCaret();
    }

    void RenderDnsBox()
    {
        _dnsBox.Clear();
        DnsParagraph(row: false);
        if (_dnsHeading == null)
        {
            AppendRun(_dnsBox, "\n  Register now asks Windows to register this computer's host (A/AAAA) and pointer (PTR) records in DNS\n"
                + "  ('ipconfig /registerdns'), then traces what happens: the record on the zone's primary server before and\n"
                + "  after, and any failure the DNS Client logs. It changes records in DNS and requires Run as Administrator.\n\n"
                + "  Check again repeats the read-only Dynamic DNS registration checks from the Results tab. It sends nothing.\n", DimColor);
        }
        else
        {
            AppendRun(_dnsBox, $"\n  {_dnsHeading}\n\n", TextColor, GpBoldFont);
            foreach (var step in _dnsSteps)
                AppendDnsStep(step);
        }
        // Filled while the tab is hidden the box is a few pixels tall, so Windows scrolls it to the end and keeps
        // it there once the tab opens; start from the top
        _dnsBox.SelectionStart = 0;
        _dnsBox.ScrollToCaret();
    }

    /// <summary>An entry in the ZTNA adapter picker; <see cref="Tag"/> is what <see cref="DiagConfig.ZtnaAdapter"/> takes.</summary>
    sealed record ZtnaChoice(string? Tag, string Text)
    {
        public override string ToString() => Text;
    }

    /// <summary>Writes the picker's entries again, keeping the user's choice selected even if its adapter has gone.</summary>
    void FillZtnaChoices(List<(string Name, string Text)> adapters)
    {
        _fillingZtna = true;
        _cmbZtna.BeginUpdate();
        _cmbZtna.Items.Clear();
        _cmbZtna.Items.Add(new ZtnaChoice(null, "Detect automatically"));
        _cmbZtna.Items.Add(new ZtnaChoice("", "None — no ZTNA or VPN client on this machine"));
        foreach (var (name, text) in adapters)
            _cmbZtna.Items.Add(new ZtnaChoice(name, text));
        if (!string.IsNullOrEmpty(_ztnaAdapter) && adapters.All(a => a.Name != _ztnaAdapter))
            _cmbZtna.Items.Add(new ZtnaChoice(_ztnaAdapter, $"{_ztnaAdapter} — not connected"));
        _cmbZtna.SelectedItem = _cmbZtna.Items.Cast<ZtnaChoice>().First(c => c.Tag == _ztnaAdapter);
        _cmbZtna.DropDownWidth = Math.Max(_cmbZtna.Width,
            _cmbZtna.Items.Cast<ZtnaChoice>().Max(c => TextRenderer.MeasureText(c.Text, _cmbZtna.Font).Width) + SystemInformation.VerticalScrollBarWidth);
        _cmbZtna.EndUpdate();
        _fillingZtna = false;
    }

    // Read each time the list opens, so an adapter that has connected since is there to pick
    void RefreshZtnaChoices()
    {
        try { FillZtnaChoices(Diagnostics.AdapterChoices(Probe.Adapters())); }
        catch (Exception ex) { AppLog.Info("ddns", $"Could not list the network adapters: {ex.Message}"); }
    }

    void CmbZtna_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_fillingZtna || _cmbZtna.SelectedItem is not ZtnaChoice choice || choice.Tag == _ztnaAdapter) return;
        _ztnaAdapter = choice.Tag;
        AppLog.Info("ddns", _ztnaAdapter switch
        {
            null => "ZTNA adapter: detect automatically",
            "" => "ZTNA adapter: set to none by the user",
            _ => $"ZTNA adapter: \"{_ztnaAdapter}\" tagged by the user",
        });
    }

    // Logs a step and shows it, unless its job has been cancelled since; called from the job's thread
    void ReportDnsStep(TestEntry step, CancellationTokenSource cts)
    {
        AppLog.Info("ddns", $"{StepWord(step),-8} {step.Name}: {step.Detail}");
        try
        {
            BeginInvoke(() =>
            {
                if (cts.IsCancellationRequested || IsDisposed) return;
                _dnsSteps.Add(step);
                AppendDnsStep(step);
            });
        }
        catch (InvalidOperationException) { } // the window closed while the job was running
    }

    /// <summary>Runs a DNS registration job off the UI thread, showing and logging each step as it reports it.</summary>
    async Task RunDnsTrace(string heading, Action<DiagConfig, Action<TestEntry>> work)
    {
        if (_dnsRunning) return;
        _dnsRunning = true;
        _btnRegister.Enabled = _btnDnsCheck.Enabled = false;
        _dnsCts = new CancellationTokenSource();
        var cts = _dnsCts;
        _dnsSteps.Clear();
        _dnsHeading = $"{heading}, {Clock(DateTime.Now)}";
        RenderDnsBox();
        var block = DiagLog.Block = new LogBlock($"DNS registration {Clock(DateTime.Now)}", heading);
        AppLog.Info("ddns", heading);

        void Report(TestEntry step) => ReportDnsStep(step, cts);

        try
        {
            await Task.Factory.StartNew(() => work(new DiagConfig("", "", cts.Token, _ztnaAdapter), Report),
                cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Report(new("Error", Status.Fail, ex.Message));
        }
        finally
        {
            _dnsRunning = false;
            _btnRegister.Enabled = _btnDnsCheck.Enabled = true;
            block.Totals = Totals(_dnsSteps);
            _logStale = true;
        }
    }

    async void BtnRegister_Click(object? sender, EventArgs e)
    {
        if (_dnsRunning) return;
        var confirm = MessageBox.Show(
            "This will run 'ipconfig /registerdns', which asks Windows to register this computer's host (A/AAAA) and "
            + "pointer (PTR) records with its DNS server, for every adapter that has DNS registration turned on.\n\n"
            + "It changes records in DNS.\n\nContinue?",
            "Register in DNS", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (confirm != DialogResult.Yes) return;

        Status verdict = Status.Skip;
        await RunDnsTrace("Registering this computer in DNS", (cfg, report) => verdict = Diagnostics.RegisterDns(cfg, Probe, report));
        _lblStatus.ForeColor = DimColor;
        _lblStatus.Text = verdict switch
        {
            Status.Pass => "DNS registration confirmed",
            Status.Fail => "DNS registration failed",
            Status.Warn => "DNS registration not confirmed",
            _ => _lblStatus.Text,
        };
    }

    async void BtnDnsCheck_Click(object? sender, EventArgs e) =>
        await RunDnsTrace("Dynamic DNS registration checks", (cfg, report) =>
        {
            foreach (var test in Diagnostics.TestDnsRegistration(cfg, Probe).Tests)
                report(test);
        });

    // ── Log tab ───────────────────────────────────────────────

    (Panel Panel, RichTextBox Box, CheckBox Debug) BuildLogTab()
    {
        var box = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font(MonoFamily, 8.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
        };
        box.MouseClick += (s, e) =>
        {
            if (e.Button == MouseButtons.Left && LogHeadingAt(box.GetCharIndexFromPosition(e.Location)) is { } key) ToggleLogFold(key);
        };
        box.MouseMove += (s, e) =>
            box.Cursor = LogHeadingAt(box.GetCharIndexFromPosition(e.Location)) != null ? Cursors.Hand : Cursors.IBeam;
        box.KeyDown += (s, e) =>
        {
            if (e.KeyCode is Keys.Enter or Keys.Space && LogHeadingAt(box.SelectionStart) is { } key)
            {
                ToggleLogFold(key);
                e.Handled = e.SuppressKeyPress = true;
            }
        };
        var debug = new CheckBox { Text = "Debug", ForeColor = TextColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, FlatStyle = FlatStyle.Flat, Location = new Point(12, 8) };
        debug.CheckedChanged += (s, e) =>
        {
            AppLog.DebugEnabled = debug.Checked;
            AppLog.Info("log", debug.Checked ? "Debug logging on: commands, timings and raw tool output are recorded" : "Debug logging off");
        };
        var btnCopyLog = new ThemedButton { Text = "Copy log", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(84, 3) };
        btnCopyLog.Click += BtnCopyLog_Click;
        var btnSaveLog = new ThemedButton { Text = "Save log", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(172, 3) };
        btnSaveLog.Click += BtnSaveLog_Click;
        var btnClearLog = new ThemedButton { Text = "Clear log", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(80, 28), Location = new Point(260, 3) };
        btnClearLog.Click += (s, e) => { AppLog.Clear(); _logOpen.Clear(); RenderLog(); };
        // The view: Sections (by run, then results section), By time (one timeline) or Raw (the plain log, as
        // written), as one three-part control
        _btnLogSections = new ThemedButton { Text = "Sections", Split = SplitPart.Left, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(76, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right, AccessibleName = "Show the log by section" };
        _btnLogByTime = new ThemedButton { Text = "By time", Split = SplitPart.Middle, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(70, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right, AccessibleName = "Show the log by time" };
        _btnLogRaw = new ThemedButton { Text = "Raw", Split = SplitPart.Right, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(56, 28), Anchor = AnchorStyles.Top | AnchorStyles.Right, AccessibleName = "Show the raw log" };
        _btnLogSections.Click += (s, e) => SetLogView(LogView.Sections);
        _btnLogByTime.Click += (s, e) => SetLogView(LogView.ByTime);
        _btnLogRaw.Click += (s, e) => SetLogView(LogView.Raw);
        StyleLogViewButtons();
        var buttons = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        buttons.Controls.AddRange([debug, btnCopyLog, btnSaveLog, btnClearLog, _btnLogSections, _btnLogByTime, _btnLogRaw]);
        buttons.Resize += (s, e) =>
        {
            _btnLogRaw.Location = new Point(buttons.ClientSize.Width - _btnLogRaw.Width - S(12), S(3));
            _btnLogByTime.Location = new Point(_btnLogRaw.Left - _btnLogByTime.Width, S(3));
            _btnLogSections.Location = new Point(_btnLogByTime.Left - _btnLogSections.Width, S(3));
        };
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = BgColor, Visible = false };
        panel.Controls.Add(box);
        panel.Controls.Add(buttons);
        return (panel, box, debug);
    }

    static readonly Font LogBlockFont = new("Segoe UI", 9.5f, FontStyle.Bold);
    static readonly Font LogSectionFont = new("Segoe UI", 9f, FontStyle.Bold);
    static readonly Font LogNoteFont = new("Segoe UI", 8.5f);
    static readonly Font LogGapFont = new("Segoe UI", 4f);

    // The results sections in order, each with the short name the By time view shows beside a line
    static IReadOnlyList<(string Name, string Short)> LogSectionNames => Sections.Select(s => (s.Name, s.Short)).ToList();

    void SetLogView(LogView view)
    {
        if (_logView == view) return;
        _logView = view;
        StyleLogViewButtons();
        RenderLog();
    }

    void StyleLogViewButtons()
    {
        foreach (var (button, on) in new[] { (_btnLogSections, _logView == LogView.Sections), (_btnLogByTime, _logView == LogView.ByTime), (_btnLogRaw, _logView == LogView.Raw) })
        {
            button.BackColor = on ? AccentColor : SurfaceColor;
            button.ForeColor = on ? OnAccentColor : TextColor;
            button.AccessibleDescription = on ? "Selected" : null;
        }
    }

    void LogParagraph(int indent, int hanging)
    {
        _logBox.SelectionStart = _logBox.TextLength;
        _logBox.SelectionLength = 0;
        _logBox.SelectionIndent = indent;
        _logBox.SelectionHangingIndent = hanging;
    }

    // Down when open, right when folded; Sections only, where a heading folds
    // ► and ▼ are in the log's monospace font everywhere
    string Chevron(object key) => !_logBySection ? "" : _logOpen.Contains(key) ? "\u25BC " : "\u25BA ";

    // A run's or an action's heading: its name and time in primary, then what it covered and how it came out
    void AppendLogBlockHeading(LogBlock block)
    {
        LogParagraph(0, 0);
        if (_logBox.TextLength > 0) AppendRun(_logBox, "\n", TextColor, LogGapFont);
        int start = _logBox.TextLength;
        AppendRun(_logBox, Chevron(block), DimColor, _logBox.Font);
        AppendRun(_logBox, block.Title, AccentColor, LogBlockFont);
        AppendRun(_logBox, "    " + block.Detail, DimColor, LogNoteFont);
        if (block.Totals != null) AppendRun(_logBox, "    " + block.Totals, DimColor, LogNoteFont);
        if (_logBySection) _logHeadings.Add((start, _logBox.TextLength, block));
        AppendRun(_logBox, "\n", TextColor, LogNoteFont);
    }

    void AppendLogSectionHeading(LogBlock block, string section)
    {
        LogParagraph(S(8), 0);
        AppendRun(_logBox, "\n", TextColor, LogGapFont);
        int start = _logBox.TextLength;
        var key = (block, section);
        AppendRun(_logBox, Chevron(key), DimColor, _logBox.Font);
        AppendRun(_logBox, section, TextColor, LogSectionFont);
        if (block.SectionNotes.TryGetValue(section, out var note)) AppendRun(_logBox, "    " + note, DimColor, LogNoteFont);
        _logHeadings.Add((start, _logBox.TextLength, key));
        AppendRun(_logBox, "\n", TextColor, LogNoteFont);
    }

    static readonly Font LogBoldFont = new(MonoFamily, 8.5f, FontStyle.Bold);
    const int LogKindColumn = DiagLog.KindColumn; // "● Warning " or a source such as "tool"

    // A status word's mark and colour, as in the results grid; all the marks are in the monospace font
    static (string Mark, Color Color) LogStatusLook(string word) => word switch
    {
        "Passed" => ("\u25CF", PassColor),
        "Warning" => ("\u25B2", WarnColor),
        "Failed" => ("\u00D7", FailColor),
        "Info" => ("i", AccentColor),
        _ => ("\u2013", DimColor),
    };

    void AppendLogLine(LogLine line)
    {
        // Raw: each line exactly as Save log writes it, in one colour, with no headings, indents or wrapping hang
        if (_logView == LogView.Raw)
        {
            LogParagraph(0, 0);
            AppendRun(_logBox, DiagLog.Prefix(line) + DiagLog.Body(line) + "\n", TextColor);
            return;
        }

        // Formatted: the time, a kind column (a result's status, or where the line came from), By time's section
        // column, then the message. Sections drops the milliseconds and the section, which its heading names
        string lead = _logBySection ? $"{line.Time:HH:mm:ss}  " : $"{line.Time:HH:mm:ss.fff}  ";
        string column = _logBySection ? ""
            : (line.Section == null ? "" : LogSectionNames.FirstOrDefault(s => s.Name == line.Section).Short ?? line.Section)
                .PadRight(DiagLog.SectionColumn);
        // Sections: a section's lines sit under its heading, a run's own lines level with the section headings
        int indent = !_logBySection || line.Block == null ? 0 : line.Section == null ? S(8) : S(20);

        LogParagraph(indent, 0);
        int start = _logBox.TextLength;
        AppendRun(_logBox, lead, DimColor);
        var (message, more) = AppendLogMessage(line, column);
        // Wrapped text, and the raw tool output after a debug line's first line, line up under the message. Where
        // the message starts is read from the box, since measuring the text apart from it comes out a little wide
        int hang = _logBox.GetPositionFromCharIndex(message).X - _logBox.GetPositionFromCharIndex(start).X;
        _logBox.Select(start, _logBox.TextLength - start);
        _logBox.SelectionHangingIndent = hang;
        foreach (string raw in more)
        {
            LogParagraph(indent + hang, 0);
            AppendRun(_logBox, raw + "\n", DimColor);
        }
    }

    // The kind and section columns, then the message's first line; returns where the message starts and its further lines
    (int Start, IEnumerable<string> More) AppendLogMessage(LogLine line, string column)
    {
        if (DiagLog.ParseResult(line) is { } res)
        {
            var (mark, color) = LogStatusLook(res.Word);
            AppendRun(_logBox, $"{mark} {res.Word}".PadRight(LogKindColumn), color);
            AppendRun(_logBox, column, DimColor);
            int at = _logBox.TextLength;
            AppendRun(_logBox, res.Name, TextColor, LogBoldFont);
            AppendRun(_logBox, (res.Detail.Length > 0 ? "  " + res.Detail : "") + "\n", TextColor);
            return (at, []);
        }
        AppendRun(_logBox, line.Source.PadRight(LogKindColumn), DimColor);
        AppendRun(_logBox, column, DimColor);
        int start = _logBox.TextLength;
        // A debug line is dim, which already sets it apart
        var parts = line.Message.Split('\n');
        AppendRun(_logBox, parts[0] + "\n", line.Debug ? DimColor : TextColor);
        return (start, parts.Skip(1));
    }

    /// <summary>
    /// Brings the Log tab up to date while it shows. By time adds the new lines at the end; Sections regroups
    /// them, so it rewrites the pane, at most once a second.
    /// </summary>
    void RefreshLog(bool force = false)
    {
        if (!_logPanel.Visible) return;
        if (!_logBySection && !_logStale)
        {
            FlushLog();
            return;
        }
        if (AppLog.LastSeq == _logSeq && !_logStale) return;
        if (!force && DateTime.Now - _logRenderedAt < TimeSpan.FromSeconds(1)) return;
        RenderLog();
    }

    /// <summary>By time: writes the lines added since the last call at the end of the pane.</summary>
    void FlushLog()
    {
        var lines = AppLog.Since(_logSeq);
        if (lines.Count == 0) return;
        // The log drops its oldest lines; so does the pane, rather than grow without limit
        if (_logBox.TextLength > 2_000_000)
        {
            RenderLog();
            return;
        }
        _logSeq = lines[^1].Seq;
        foreach (var line in lines)
        {
            if (line.Block != null && line.Block != _logLastBlock && _logView != LogView.Raw)
            {
                AppendLogBlockHeading(line.Block);
                _logLastBlock = line.Block;
            }
            AppendLogLine(line);
        }
        _logBox.ScrollToCaret();
    }

    const int WmSetRedraw = 0x000B;

    /// <summary>Writes the whole log to the pane in the chosen view, keeping the reader's place.</summary>
    void RenderLog()
    {
        long last = AppLog.LastSeq;
        var lines = AppLog.Since(0).Where(l => l.Seq <= last).ToList();
        bool atEnd = _logBox.TextLength == 0 || _logBox.GetPositionFromCharIndex(_logBox.TextLength - 1).Y < _logBox.ClientSize.Height;
        int top = _logBox.GetLineFromCharIndex(_logBox.GetCharIndexFromPosition(new Point(1, 1)));

        SendMessage(_logBox.Handle, WmSetRedraw, IntPtr.Zero, IntPtr.Zero);
        try
        {
            _logBox.Clear();
            _logHeadings.Clear();
            _logLastBlock = null;
            WriteLogItems(lines);
            _logBox.SelectionStart = atEnd ? _logBox.TextLength : 0;
            _logBox.ScrollToCaret();
            if (!atEnd && top > 0) SendMessage(_logBox.Handle, EmLineScroll, IntPtr.Zero, top);
        }
        finally
        {
            SendMessage(_logBox.Handle, WmSetRedraw, 1, IntPtr.Zero);
            _logBox.Invalidate();
        }
        _logSeq = last;
        _logStale = false;
        _logRenderedAt = DateTime.Now;
    }

    void WriteLogItems(List<LogLine> lines)
    {
        LogItem? previous = null;
        bool blockFolded = false, sectionFolded = false;
        foreach (var item in DiagLog.Arrange(lines, _logBySection, LogSectionNames.Select(s => s.Name).ToList()))
        {
            if (_logBySection && HiddenInSections(item, ref blockFolded, ref sectionFolded)) continue;
            WriteLogItem(item, previous);
            previous = item;
        }
    }

    // Sections: a folded run keeps only its heading, a folded section its heading inside the run; a run's Started
    // and Complete lines say what its heading already does
    bool HiddenInSections(LogItem item, ref bool blockFolded, ref bool sectionFolded)
    {
        if (item is LogEntry { Line: var bookend } && DiagLog.IsRunBookend(bookend)) return true;
        if (item is LogBlockHeading b) (blockFolded, sectionFolded) = (!_logOpen.Contains(b.Block), false);
        else if (item is LogSectionHeading h) sectionFolded = !_logOpen.Contains((h.Block, h.Section));
        else if (item is LogEntry { Line.Section: null }) sectionFolded = false;
        return item is not LogBlockHeading && (blockFolded && item is not LogEntry { Line.Block: null } || sectionFolded && item is LogEntry);
    }

    void WriteLogItem(LogItem item, LogItem? previous)
    {
        switch (item)
        {
            case LogBlockHeading when _logView == LogView.Raw:
                break;
            case LogBlockHeading heading:
                AppendLogBlockHeading(heading.Block);
                _logLastBlock = heading.Block;
                break;
            case LogSectionHeading heading:
                AppendLogSectionHeading(heading.Block, heading.Section);
                break;
            case LogEntry entry:
                // A run's own lines after its sections (such as "Complete") are set apart from the last one
                if (_logBySection && entry.Line.Block != null && entry.Line.Section == null && previous is LogEntry { Line.Section: not null })
                    AppendRun(_logBox, "\n", TextColor, LogGapFont);
                AppendLogLine(entry.Line);
                break;
        }
    }

    object? LogHeadingAt(int charIndex) =>
        _logHeadings.FirstOrDefault(h => charIndex >= h.Start && charIndex <= h.End).Key;

    void ToggleLogFold(object key)
    {
        if (!_logOpen.Remove(key)) _logOpen.Add(key);
        RenderLog();
    }

    // The log as text in the view on screen: what Copy log and Save log hand over; folding only changes the pane
    string LogText() => _logView == LogView.Raw ? AppLog.Text() : AppLog.Text(_logBySection, LogSectionNames);

    void BtnCopyLog_Click(object? sender, EventArgs e)
    {
        string text = LogText();
        if (text.Length == 0) return;
        try
        {
            Clipboard.SetText(text);
            _lblStatus.Text = "Log copied to the clipboard";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Copy failed: {ex.Message}";
        }
    }

    void BtnSaveLog_Click(object? sender, EventArgs e)
    {
        using var dlg = new SaveFileDialog
        {
            FileName = $"ad-diag-log-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text files (*.txt)|*.txt",
            DefaultExt = ".txt"
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;

        try
        {
            File.WriteAllText(dlg.FileName, LogText(), Encoding.UTF8);
            _lblStatus.Text = $"Saved to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Save failed: {ex.Message}";
        }
    }

    // ── Owner-drawn results ─────────────────────────────────

    // NoPrefix: without it "&" is read as a mnemonic marker, so "SYSVOL & NETLOGON" drew as "SYSVOL _NETLOGON"
    const TextFormatFlags DetailTextFlags = TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.NoPrefix;

    // Results grid columns at 96 DPI: status mark and word, test name, then the detail to the right edge
    const int GridLeft = 14, NameX = 100, DetailX = 280;

    int DetailWidth(int width) => Math.Max(width - S(DetailX) - S(GridLeft), S(80));

    static bool IsPending(TestEntry test) => test.Status == Status.Skip && test.Detail.Length == 0;

    int MeasureResultsHeight(int width) => _renderedGroups == null ? S(200) : LayoutResults(null, width);

    /// <summary>"9 checks · 1 failed · 1 warning", so a group's state reads without scanning its rows.</summary>
    static string GroupCounts(TestGroup group)
    {
        int fail = group.Tests.Count(t => t.Status == Status.Fail);
        int warn = group.Tests.Count(t => t.Status == Status.Warn);
        int notes = group.Tests.Count(t => t.Status == Status.Info);
        int running = group.Tests.Count(IsPending);
        string text = $"{group.Tests.Count} check{(group.Tests.Count == 1 ? "" : "s")}";
        if (fail > 0) text += $" · {fail} failed";
        if (warn > 0) text += $" · {warn} warning{(warn == 1 ? "" : "s")}";
        if (notes > 0) text += $" · {notes} note{(notes == 1 ? "" : "s")}";
        if (running > 0) text += $" · {running} running";
        return text;
    }

    static (string Word, Color Color) StatusLook(TestEntry test) => IsPending(test) ? ("Running", DimColor) : test.Status switch
    {
        Status.Pass => ("Passed", PassColor),
        Status.Fail => ("Failed", FailColor),
        Status.Warn => ("Warning", WarnColor),
        Status.Info => ("Info", AccentColor),
        _ => ("Skipped", DimColor),
    };

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
            case Status.Info:
                // A disc in primary with an "i" cut out of it
                g.FillEllipse(InfoBrush, x, y, d, d);
                using (var cut = new SolidBrush(PanelColor))
                {
                    g.FillRectangle(cut, x + d / 2 - S(1), y + S(2), S(2), S(2));
                    g.FillRectangle(cut, x + d / 2 - S(1), y + S(5), S(2), d - S(7));
                }
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

    // Points right when the group is closed, down when it is open
    void DrawChevron(Graphics g, int x, int y, bool open)
    {
        int d = S(8);
        using var pen = new Pen(DimColor, Math.Max(1f, S(3) / 2f));
        Point[] points = open
            ? [new(x, y + d / 4), new(x + d / 2, y + d * 3 / 4), new(x + d, y + d / 4)]
            : [new(x + d / 4, y), new(x + d * 3 / 4, y + d / 2), new(x + d / 4, y + d)];
        g.DrawLines(pen, points);
    }

    const string GuideLinkText = "See the fixes in the Guide";

    // The heading's note: the group's counts, or that it hasn't run, and when it last ran on its own
    string HeadingNote(TestGroup group) =>
        SelectedRun is not { } run ? GroupCounts(group)
        : run.NotRun.Contains(group.Name) ? "Not run"
        : run.RanAt.TryGetValue(group.Name, out var at) ? $"{GroupCounts(group)} · run at {Clock(at)}"
        : GroupCounts(group);

    /// <summary>
    /// Lays the results out at <paramref name="width"/> and returns their height. With <paramref name="g"/> it also
    /// draws them and records each item for clicks, the keyboard and screen readers; without, it only measures.
    /// </summary>
    int LayoutResults(Graphics? g, int width)
    {
        int y = S(4);
        int left = S(GridLeft), right = width - S(GridLeft);
        if (g != null)
        {
            _resultsCanvas.Rows.Clear();
            _resultsCanvas.Headings.Clear();
            _resultsCanvas.AdminNotes.Clear();
        }

        // The counts column is as wide as the longest counts on show, at least NoteColumn, so a long one (a
        // 12-hour "run at" time) never runs into the Run button
        if (g != null)
            _noteColumn = _renderedGroups!.Select(gr => TextRenderer.MeasureText(g, HeadingNote(gr), GroupCountFont, Size.Empty,
                TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine).Width).Append(S(NoteColumn)).Max();
        foreach (var group in _renderedGroups!)
        {
            bool notRun = SelectedRun?.NotRun.Contains(group.Name) == true;
            bool open = !notRun && IsGroupOpen(group);
            y = LayoutHeading(g, group, open, notRun, y, left, right);
            if (!open)
            {
                g?.DrawLine(RowLinePen, left, y, right, y);
                continue;
            }
            foreach (var test in group.Tests)
                y = LayoutTest(g, group.Name, test, y, left, right, DetailWidth(width));
            if (group.Readiness is { } ready)
                y = LayoutReadiness(g, group.Name, ready, y, left, right);
        }
        return y + S(14);
    }

    const int NoteColumn = 200; // the counts column's least width
    int _noteColumn;            // its width in this layout, in device pixels
    const int RunSlot = 88;     // room for the widest run button, "Run again"
    static readonly Font BadgeFont = new("Segoe UI", 7.5f, FontStyle.Bold);
    static readonly Font RunTextFont = new("Segoe UI", 8.5f, FontStyle.Bold);

    // A group's heading: chevron and name, the group's verdict as a pill, its counts, and at the right edge a button
    // that runs the group on its own. The button stays in place while a run is going, faded and inactive. Left of it
    // the heading is a button that opens and closes the group; one that hasn't run has nothing to open, so there it
    // is plain text
    int LayoutHeading(Graphics? g, TestGroup group, bool open, bool notRun, int y, int left, int right)
    {
        const TextFormatFlags oneLine = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
        y += S(8);
        if (g != null)
        {
            var band = new Rectangle(left - S(4), y - S(2), right - left + S(8), S(28));
            var button = RunButtonBounds(g, right, y, notRun);
            string note = HeadingNote(group);
            // The counts start at a fixed column and the verdict sits just left of it, so both line up down the list
            int noteX = right - S(RunSlot) - S(10) - _noteColumn;
            TextRenderer.DrawText(g, note, GroupCountFont, new Point(noteX, y + S(5)), DimColor, oneLine);
            if (!notRun && GroupVerdict(group) is { } verdict) DrawGroupBadge(g, verdict, noteX - S(12), y);
            if (!notRun) DrawChevron(g, left, y + S(8), open);
            TextRenderer.DrawText(g, group.Name, GroupHeaderFont, new Point(left + S(14), y + S(3)), notRun ? DimColor : TextColor, oneLine);
            bool needsAdmin = !notRun && group.Tests.Any(t => t.NeedsAdmin);
            if (needsAdmin)
            {
                int nameRight = left + S(14) + TextRenderer.MeasureText(g, group.Name, GroupHeaderFont, Size.Empty, oneLine).Width;
                DrawAdminNote(g, nameRight + S(8), noteX - S(12) - BadgeWidth(g) - S(8), y);
                note += "; some checks need Run as Administrator";
            }

            var bounds = new Rectangle(left - S(4), y, right - S(RunSlot) - S(8) - (left - S(4)), S(24));
            _resultsCanvas.Rows.Add(notRun
                ? new(group.Name, group.Name, "Not run", "", bounds)
                : new(group.Name, group.Name, "", note, bounds, ResultsCanvas.Kind.Heading, open));
            _resultsCanvas.Headings.Add((group.Name, band));
            bool hover = !_running && _resultsCanvas.HoverGroup == group.Name && _resultsCanvas.HoverButton;
            DrawRunButton(g, button, notRun, hover);
            if (!_running)
                _resultsCanvas.Rows.Add(new(group.Name, notRun ? $"Run {group.Name}" : $"Run {group.Name} again", "", "",
                    button, ResultsCanvas.Kind.RunLink));
        }
        return y + S(26);
    }

    // The group's worst result once every check has finished, the readiness line included; null while it runs
    static Status? GroupVerdict(TestGroup group)
    {
        if (group.Tests.Count == 0 || group.Tests.Any(IsPending)) return null;
        var all = group.Tests.Select(t => t.Status).Append(group.Readiness?.Status ?? Status.Pass).ToList();
        return all.Contains(Status.Fail) ? Status.Fail : all.Contains(Status.Warn) ? Status.Warn : Status.Pass;
    }

    // The verdict as a pill ending at right: PASSED, WARNING or FAILED in the status colour on a tint of it, all the
    // same width so they line up
    int BadgeWidth(Graphics g) =>
        TextRenderer.MeasureText(g, "WARNING", BadgeFont, Size.Empty, TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding).Width + S(16);

    void DrawGroupBadge(Graphics g, Status verdict, int right, int y)
    {
        var (word, color) = StatusLook(new TestEntry("", verdict, "-"));
        const TextFormatFlags flags = TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding;
        int w = BadgeWidth(g);
        var pill = new Rectangle(right - w, y + S(4), w, S(16));
        FillRounded(g, pill, S(8), Blend(PanelColor, color, 0.16));
        TextRenderer.DrawText(g, word.ToUpperInvariant(), BadgeFont, pill, color,
            flags | TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
    }

    // "Run again", or "Run" on a group that hasn't run, after a bolt, right-aligned in the run slot
    Rectangle RunButtonBounds(Graphics g, int right, int y, bool notRun)
    {
        int textW = TextRenderer.MeasureText(g, notRun ? "Run" : "Run again", RunTextFont, Size.Empty,
            TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding).Width;
        int w = S(10) + S(16) + textW + S(10);
        return new Rectangle(right - w, y + S(3), w, S(19));
    }

    // A capsule like the verdict pills, in primary: a tint behind a bolt and the words, deeper under the mouse and
    // faded during a run
    void DrawRunButton(Graphics g, Rectangle r, bool notRun, bool hover)
    {
        double strength = _running ? 0.4 : 1.0;
        FillRounded(g, r, S(9), Blend(PanelColor, AccentColor, (hover ? 0.24 : 0.12) * strength));
        var color = Blend(PanelColor, AccentColor, strength);
        DrawBolt(g, color, r.X + S(15), r.Y + r.Height / 2f);
        int textX = r.X + S(26);
        TextRenderer.DrawText(g, notRun ? "Run" : "Run again", RunTextFont, new Rectangle(textX, r.Y, r.Right - textX, r.Height), color,
            TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
    }

    const string AdminNoteText = "Needs admin";
    const string AdminNoteTip = "Some checks here need the app run as Administrator. Close it, right-click ad-diag.exe and choose Run as administrator.";

    // A capsule like the verdict pills, in the warning colour, right-aligned to end at maxRight: a shield and "Needs
    // admin", or the shield alone when the group's name leaves no room for the words
    void DrawAdminNote(Graphics g, int minLeft, int maxRight, int y)
    {
        const TextFormatFlags flags = TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding;
        int textW = TextRenderer.MeasureText(g, AdminNoteText, BadgeFont, Size.Empty, flags).Width;
        int full = S(8) + S(10) + S(5) + textW + S(8), compact = S(24);
        int w = maxRight - full >= minLeft ? full : compact;
        if (maxRight - w < minLeft) return; // no room at all on a very narrow window; the rows still carry the shield
        var r = new Rectangle(maxRight - w, y + S(4), w, S(16));
        FillRounded(g, r, S(8), Blend(PanelColor, WarnColor, 0.16));
        DrawShield(g, WarnColor, w == compact ? r.X + r.Width / 2f : r.X + S(13), r.Y + r.Height / 2f, 10);
        if (w == full)
            TextRenderer.DrawText(g, AdminNoteText, BadgeFont, new Rectangle(r.X + S(23), r.Y, textW + S(2), r.Height), WarnColor,
                flags | TextFormatFlags.VerticalCenter);
        _resultsCanvas.AdminNotes.Add(r);
    }

    // A shield size px tall, centred on (cx, cy): flat top, straight sides, a point at the bottom
    void DrawShield(Graphics g, Color color, float cx, float cy, int size)
    {
        float u = DeviceDpi / 96f, h = size * u, w = h * 0.8f, top = cy - h / 2;
        var smooth = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var path = new System.Drawing.Drawing2D.GraphicsPath())
        using (var brush = new SolidBrush(color))
        {
            path.AddLine(cx - w / 2, top + h * 0.12f, cx, top);
            path.AddLine(cx, top, cx + w / 2, top + h * 0.12f);
            path.AddLine(cx + w / 2, top + h * 0.12f, cx + w / 2, top + h * 0.5f);
            path.AddBezier(cx + w / 2, top + h * 0.5f, cx + w / 2, top + h * 0.78f, cx + w * 0.2f, top + h * 0.92f, cx, top + h);
            path.AddBezier(cx, top + h, cx - w * 0.2f, top + h * 0.92f, cx - w / 2, top + h * 0.78f, cx - w / 2, top + h * 0.5f);
            path.CloseFigure();
            g.FillPath(brush, path);
        }
        g.SmoothingMode = smooth;
    }

    // A lightning bolt 12px tall, centred on (cx, cy)
    void DrawBolt(Graphics g, Color color, float cx, float cy)
    {
        float u = DeviceDpi / 96f;
        var smooth = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var brush = new SolidBrush(color))
            g.FillPolygon(brush, new PointF[]
            {
                new(cx + 1.5f * u, cy - 6 * u), new(cx - 3.5f * u, cy + 1 * u), new(cx - 0.2f * u, cy + 1 * u),
                new(cx - 1.5f * u, cy + 6 * u), new(cx + 3.5f * u, cy - 1 * u), new(cx + 0.2f * u, cy - 1 * u),
            });
        g.SmoothingMode = smooth;
    }

    static void FillRounded(Graphics g, Rectangle r, int radius, Color color)
    {
        var smooth = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var path = ThemedButton.RoundedRect(r, radius))
        using (var fill = new SolidBrush(color))
            g.FillPath(fill, path);
        g.SmoothingMode = smooth;
    }

    // One check: mark and word, name, and the detail wrapped in its column
    int LayoutTest(Graphics? g, string group, TestEntry test, int y, int left, int right, int detailW)
    {
        var detailSize = TextRenderer.MeasureText(test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
        int rowHeight = Math.Max(S(20), detailSize.Height + S(4));
        if (g != null)
        {
            var (word, color) = StatusLook(test);
            g.DrawLine(RowLinePen, left, y, right, y);
            DrawStatusMark(g, test, left, y + S(8));
            TextRenderer.DrawText(g, word, StatusFont, new Point(left + S(15), y + S(5)), color, TextFormatFlags.NoPrefix);
            // A check held back for want of Administrator has a shield after its name
            int nameW = S(DetailX - NameX - 6) - (test.NeedsAdmin ? S(14) : 0);
            const TextFormatFlags nameFlags = TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix;
            TextRenderer.DrawText(g, test.Name, TestNameFont, new Rectangle(S(NameX), y + S(4), nameW, S(18)), TextColor, nameFlags);
            if (test.NeedsAdmin)
            {
                int drawn = Math.Min(nameW, TextRenderer.MeasureText(g, test.Name, TestNameFont, Size.Empty,
                    TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix).Width);
                DrawShield(g, WarnColor, S(NameX) + drawn + S(8), y + S(12), 10);
            }
            // The detail is plain text: the mark and word carry the status, so a long line stays readable
            TextRenderer.DrawText(g, test.Detail, TestDetailFont,
                new Rectangle(S(DetailX), y + S(5), detailW, detailSize.Height),
                test.Status == Status.Skip ? DimColor : TextColor, DetailTextFlags);
            _resultsCanvas.Rows.Add(new(group, test.Name, word, test.Detail + (test.NeedsAdmin ? " (needs Run as Administrator)" : ""),
                new Rectangle(left, y + S(4), right - left, rowHeight)));
        }
        return y + S(4) + rowHeight;
    }

    // The group's verdict as one more row: its mark and word, "Readiness", the verdict, and a link to the Guide's fixes
    int LayoutReadiness(Graphics? g, string group, Readiness ready, int y, int left, int right)
    {
        const TextFormatFlags oneLine = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
        var entry = new TestEntry("Readiness", ready.Status, ready.Text);
        var (word, color) = StatusLook(entry);
        int textW = TextRenderer.MeasureText(ready.Text, TestNameFont, Size.Empty, oneLine).Width;
        int linkW = TextRenderer.MeasureText(GuideLinkText, ResultsLinkFont, Size.Empty, oneLine).Width;
        bool linkBelow = ready.ShowGuide && S(DetailX) + textW + S(10) + linkW > right;
        int rowHeight = linkBelow ? S(40) : S(22);
        if (g != null)
        {
            g.DrawLine(RowLinePen, left, y, right, y);
            DrawStatusMark(g, entry, left, y + S(9));
            TextRenderer.DrawText(g, word, StatusFont, new Point(left + S(15), y + S(6)), color, oneLine);
            TextRenderer.DrawText(g, "Readiness", ReadinessNameFont, new Point(S(NameX), y + S(5)), TextColor, oneLine);
            TextRenderer.DrawText(g, ready.Text, TestNameFont, new Point(S(DetailX), y + S(5)), TextColor, oneLine);
            _resultsCanvas.Rows.Add(new(group, "Readiness", word, ready.Text, new Rectangle(left, y + S(4), right - left, rowHeight)));
            if (ready.ShowGuide)
            {
                var at = linkBelow ? new Point(S(DetailX), y + S(23)) : new Point(S(DetailX) + textW + S(10), y + S(5));
                TextRenderer.DrawText(g, GuideLinkText, ResultsLinkFont, at, AccentColor, oneLine);
                _resultsCanvas.Rows.Add(new(group, GuideLinkText, "", "", new Rectangle(at.X - S(2), at.Y - S(1), linkW + S(4), S(18)),
                    ResultsCanvas.Kind.GuideLink));
            }
        }
        return y + S(4) + rowHeight;
    }

    void PaintResults(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;

        if (_renderedGroups == null)
        {
            _resultsCanvas.Rows.Clear();
            string msg = _placeholderText ?? "";
            TextRenderer.DrawText(g, msg, PlaceholderFont, new Point(S(GridLeft), S(40)), DimColor, TextFormatFlags.NoPrefix);
            return;
        }

        LayoutResults(g, _resultsCanvas.Width);
        if (_resultsCanvas.FocusedItem is { } focused && _resultsCanvas.Focused && _resultsCanvas.ShowFocus)
            ControlPaint.DrawFocusRectangle(g, focused.Bounds, TextColor, PanelColor);
    }

    // A group the user opened or closed stays that way; otherwise groups start closed, their heading carrying the
    // verdict, or all open with "Expand all groups after a run"
    bool IsGroupOpen(TestGroup group) =>
        SelectedRun is { } run && run.Open.TryGetValue(group.Name, out bool open) ? open : _expandAll;

    void RerenderResults()
    {
        if (_renderedGroups != null) RenderResults(_renderedGroups);
    }

    void SetAllGroupsOpen(bool open)
    {
        if (SelectedRun is not { } run || _renderedGroups == null) return;
        foreach (var group in _renderedGroups) run.Open[group.Name] = open;
        RerenderResults();
    }

    void ActivateResultsItem(ResultsCanvas.Row item)
    {
        switch (item.Kind)
        {
            case ResultsCanvas.Kind.Heading:
                if (SelectedRun is not { } run || _renderedGroups?.Find(g => g.Name == item.Group) is not { } group) return;
                run.Open[group.Name] = !IsGroupOpen(group);
                RerenderResults();
                break;
            case ResultsCanvas.Kind.GuideLink:
                ShowGuideSection(item.Group);
                break;
            case ResultsCanvas.Kind.RunLink:
                RunSection(item.Group);
                break;
        }
    }

    /// <summary>
    /// The results panel's scroll area. A plain panel scrolls back to the top of the results whenever they take the
    /// keyboard focus (a click on a group heading); this one stays where it is.
    /// </summary>
    sealed class KeepScrollPanel : Panel
    {
        protected override Point ScrollToControl(Control activeControl) => DisplayRectangle.Location;
    }

    /// <summary>
    /// The painted results list. It has no child controls, so it handles its own clicks and keys and describes its
    /// items to assistive technology itself: group headings (buttons that open and close the group), the rows,
    /// links to the Guide, and each heading's Run link, as last painted. Up and Down move between headings and links;
    /// Enter or Space acts.
    /// </summary>
    sealed class ResultsCanvas : Panel
    {
        public enum Kind { Row, Heading, GuideLink, RunLink }

        public record struct Row(string Group, string Name, string Status, string Detail, Rectangle Bounds,
            Kind Kind = Kind.Row, bool Expanded = false)
        {
            public readonly bool Actionable => Kind != Kind.Row;
        }

        public readonly List<Row> Rows = [];
        public readonly List<(string Group, Rectangle Band)> Headings = []; // each heading's full width, for hover
        public readonly List<Rectangle> AdminNotes = [];                     // "Needs admin" capsules, for their tooltip
        bool _onAdminNote;
        public string? HoverGroup { get; private set; }  // the group whose heading is under the mouse
        public bool HoverButton { get; private set; }    // the mouse is over that heading's Run button
        readonly ToolTip _tip = new();                   // names the Run button under the mouse
        int _focus = -1; // index into Rows of the heading or link with the keyboard focus

        public event Action<Row>? Activated;

        public ResultsCanvas()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.Selectable, true);
            TabStop = true;
        }

        public Row? FocusedItem => _focus >= 0 && _focus < Rows.Count && Rows[_focus].Actionable ? Rows[_focus] : null;
        public bool ShowFocus => ShowFocusCues;

        public void Activate(Row item) => Activated?.Invoke(item);

        int HitTest(Point p) => Rows.FindIndex(r => r.Actionable && r.Bounds.Contains(p));

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            int i = HitTest(e.Location);
            if (e.Button != MouseButtons.Left || i < 0) return;
            _focus = i;
            Activate(Rows[i]);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int i = HitTest(e.Location);
            Cursor = i >= 0 && Rows[i].Kind == Kind.GuideLink ? Cursors.Hand : Cursors.Default;
            string? group = Headings.Find(h => h.Band.Contains(e.Location)).Group;
            bool onButton = i >= 0 && Rows[i].Kind == Kind.RunLink;
            bool onAdmin = !onButton && AdminNotes.Any(r => r.Contains(e.Location));
            if (onAdmin != _onAdminNote)
            {
                _onAdminNote = onAdmin;
                _tip.SetToolTip(this, onAdmin ? AdminNoteTip : null);
            }
            if (group != HoverGroup || onButton != HoverButton)
            {
                if (onButton != HoverButton) _tip.SetToolTip(this, onButton ? Rows[i].Name : null);
                (HoverGroup, HoverButton) = (group, onButton);
                Invalidate();
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (HoverGroup == null) return;
            if (HoverButton || _onAdminNote) _tip.SetToolTip(this, null);
            _onAdminNote = false;
            (HoverGroup, HoverButton) = (null, false);
            Invalidate();
        }

        protected override bool IsInputKey(Keys keyData) =>
            keyData is Keys.Up or Keys.Down or Keys.Enter or Keys.Space || base.IsInputKey(keyData);

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            var targets = Enumerable.Range(0, Rows.Count).Where(i => Rows[i].Actionable).ToList();
            if (targets.Count == 0) return;
            int pos = targets.IndexOf(_focus);
            switch (e.KeyCode)
            {
                case Keys.Down:
                    MoveFocus(targets[pos < 0 ? 0 : Math.Min(pos + 1, targets.Count - 1)]);
                    break;
                case Keys.Up:
                    MoveFocus(targets[pos <= 0 ? 0 : pos - 1]);
                    break;
                case Keys.Enter or Keys.Space when pos >= 0:
                    Activate(Rows[_focus]);
                    break;
                default:
                    return;
            }
            e.Handled = e.SuppressKeyPress = true;
        }

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            if (FocusedItem == null) _focus = Rows.FindIndex(r => r.Actionable);
            Invalidate();
            if (_focus >= 0) AccessibilityNotifyClients(AccessibleEvents.Focus, _focus);
        }

        protected override void OnLostFocus(EventArgs e)
        {
            base.OnLostFocus(e);
            Invalidate();
        }

        void MoveFocus(int index)
        {
            _focus = index;
            ScrollIntoView(Rows[index].Bounds);
            Invalidate();
            AccessibilityNotifyClients(AccessibleEvents.Focus, index);
        }

        void ScrollIntoView(Rectangle r)
        {
            if (Parent is not ScrollableControl area) return;
            int top = -Top, height = area.ClientSize.Height, margin = r.Height;
            int y = r.Top - margin < top ? r.Top - margin
                : r.Bottom + margin > top + height ? r.Bottom + margin - height
                : top;
            if (y != top) area.AutoScrollPosition = new Point(0, Math.Max(0, y));
        }

        protected override AccessibleObject CreateAccessibilityInstance() => new ListAccessible(this);

        sealed class ListAccessible(ResultsCanvas owner) : ControlAccessibleObject(owner)
        {
            public override AccessibleRole Role => AccessibleRole.List;
            public override int GetChildCount() => owner.Rows.Count;
            public override AccessibleObject? GetChild(int index) =>
                index >= 0 && index < owner.Rows.Count ? new ItemAccessible(owner, this, owner.Rows[index], index) : null;
            public override AccessibleObject? GetFocused() =>
                owner.Focused && owner.FocusedItem != null ? GetChild(owner._focus) : base.GetFocused();
        }

        sealed class ItemAccessible(ResultsCanvas owner, AccessibleObject list, Row row, int index) : AccessibleObject
        {
            public override string? Name => row.Kind switch
            {
                Kind.Heading => $"{row.Name}, {row.Detail}",
                Kind.GuideLink or Kind.RunLink => row.Name,
                _ => $"{row.Name}, {row.Status}",
            };
            public override string? Value => row.Kind == Kind.Row ? row.Detail : null;
            public override string? Description => row.Group;
            public override AccessibleRole Role => row.Kind switch
            {
                Kind.Heading => AccessibleRole.OutlineButton,
                Kind.GuideLink => AccessibleRole.Link,
                Kind.RunLink => AccessibleRole.PushButton,
                _ => AccessibleRole.ListItem,
            };
            public override AccessibleStates State
            {
                get
                {
                    if (row.Kind == Kind.Row) return AccessibleStates.ReadOnly;
                    var state = AccessibleStates.Focusable | (owner.Focused && owner._focus == index ? AccessibleStates.Focused : 0);
                    return row.Kind switch
                    {
                        Kind.Heading => state | (row.Expanded ? AccessibleStates.Expanded : AccessibleStates.Collapsed),
                        Kind.GuideLink => state | AccessibleStates.Linked,
                        _ => state,
                    };
                }
            }
            public override string? DefaultAction => row.Kind switch
            {
                Kind.Heading => row.Expanded ? "Collapse" : "Expand",
                Kind.GuideLink => "Jump",
                Kind.RunLink => "Press",
                _ => null,
            };
            public override void DoDefaultAction()
            {
                if (row.Actionable) owner.Activate(row);
            }
            public override AccessibleObject? Parent => list;
            public override Rectangle Bounds => owner.RectangleToScreen(row.Bounds);
        }
    }

    void RenderResults(List<TestGroup> groups)
    {
        _renderedGroups = groups;
        _placeholderText = null;
        _resultsBar.Visible = true;
        int h = MeasureResultsHeight(_resultsCanvas.Width);
        _resultsCanvas.Height = h;
        _resultsCanvas.Invalidate();
    }

    // ── Events ──────────────────────────────────────────────

    // Every section of a run, in the order they show, and the check behind each. They don't depend on each other's
    // results, so any one can run on its own. DomainOnly sections need the PC in a domain, so an Entra joined profile
    // leaves them out entirely: not run, not shown, not logged
    static readonly (string Name, string Short, Func<DiagConfig, IProbe, TestGroup> Test, bool DomainOnly)[] Sections =
    [
        ("Domain Membership & Identity", "Membership", Diagnostics.TestDomainMembership, true),
        ("DC Discovery & Connectivity", "DC Discovery", Diagnostics.TestDcConnectivity, true),
        ("DNS for Active Directory", "DNS for AD", Diagnostics.TestDnsForAd, true),
        ("SYSVOL & NETLOGON", "SYSVOL", Diagnostics.TestSysvolNetlogon, true),
        ("Group Policy", "Group Policy", Diagnostics.TestGroupPolicy, true),
        ("Trust Relationships", "Trusts", Diagnostics.TestTrusts, true),
        ("Kerberos & Time Sync", "Kerberos & Time", Diagnostics.TestKerberosAndTime, true),
        ("Dynamic DNS Registration", "DNS Registration", Diagnostics.TestDnsRegistration, false),
        (Diagnostics.EntraSsoGroup, "Seamless SSO", Diagnostics.TestEntraSso, false),
        (Diagnostics.CredentialsGroup, "Credentials", Diagnostics.TestCredentials, false),
        (Diagnostics.IntuneGroup, "Intune", Diagnostics.TestIntune, false),
    ];

    /// <summary>Whether a section (or a Guide section of the same name) belongs to a profile.</summary>
    static bool InProfile(string name, JoinProfile profile) =>
        profile != JoinProfile.Entra || !Sections.Any(s => s.Name == name && s.DomainOnly);

    // A heading from a run made for another profile can name a section this profile doesn't run
    bool SectionInProfile(string name)
    {
        if (InProfile(name, _profile)) return true;
        _lblStatus.Text = $"{name} isn't part of the {ProfileName(_profile)} profile";
        return false;
    }

    /// <summary>The sections the chosen profile runs, in the order they show.</summary>
    List<string> ProfileSections => Sections.Where(s => InProfile(s.Name, _profile)).Select(s => s.Name).ToList();

    /// <summary>The domain and DC from the fields, or null (with the reason in the status line) when they're invalid.</summary>
    (string Domain, string Dc)? ReadTarget()
    {
        // An Entra joined PC has no domain field; its key checks ask the domain the user's Kerberos realm names, if any
        if (_profile == JoinProfile.Entra) return (EntraRealm(), "");
        string domain = _txtDomain.Text.Trim();
        string dc = _txtDc.Text.Trim();
        if (_chkDcSuffix.Checked && !string.IsNullOrEmpty(domain) && !dc.Contains('.'))
            dc = string.IsNullOrEmpty(dc) ? "" : $"{dc}.{domain}";

        string? error = string.IsNullOrEmpty(domain) ? "Domain is required"
            : !HostnamePattern.IsMatch(domain) ? "Invalid domain characters"
            : !string.IsNullOrEmpty(dc) && !HostnamePattern.IsMatch(dc) ? "Invalid DC hostname"
            : null;
        if (error == null) return (domain, dc);
        _lblStatus.Text = error;
        return null;
    }

    static string EntraRealm()
    {
        string realm = Environment.GetEnvironmentVariable("USERDNSDOMAIN")?.Trim().ToLowerInvariant() ?? "";
        return HostnamePattern.IsMatch(realm) ? realm : "";
    }

    /// <summary>Marks a run as started or ended: while one runs, nothing else can start and nothing is exported.</summary>
    void SetRunning(bool running)
    {
        _running = running;
        _btnRun.Enabled = _btnRunMenu.Enabled = _cmbProfile.Enabled = !running;
        _btnExport.Enabled = _btnCopy.Enabled = !running && SelectedRun is { IsPending: false };
        _resultsCanvas.Invalidate(); // the Run links grey out
    }

    static string DcText(string dc) => dc.Length > 0 ? dc : "DC found automatically";

    // What a run covered, for its log heading: an Entra joined run has no domain
    static string TargetText(JoinProfile profile, string domain, string dc) =>
        profile == JoinProfile.Entra ? ProfileName(profile) : $"{ProfileName(profile)} · {domain} · {DcText(dc)}";

    // A log heading's outcome: "32 passed · 0 failed · 3 warnings"
    static string Totals(IEnumerable<TestEntry> tests)
    {
        var list = tests.ToList();
        int warn = list.Count(t => t.Status == Status.Warn), notes = list.Count(t => t.Status == Status.Info);
        return $"{list.Count(t => t.Status == Status.Pass)} passed · {list.Count(t => t.Status == Status.Fail)} failed · {warn} warning{(warn == 1 ? "" : "s")}"
            + (notes > 0 ? $" · {notes} note{(notes == 1 ? "" : "s")}" : "");
    }

    CancellationTokenSource StartRun(string what, string domain, string dc)
    {
        _runCts?.Cancel();
        _runCts = new CancellationTokenSource();
        AppLog.Info("run", _profile == JoinProfile.Entra
            ? $"Started{what}: {ProfileName(_profile)} profile"
            : $"Started{what}: {ProfileName(_profile)} profile, domain {domain}, DC {(dc.Length > 0 ? dc : "(auto)")}");
        SetRunning(true);
        _lblStatus.ForeColor = DimColor;
        SwitchTab("results");
        return _runCts;
    }

    void BtnRun_Click(object? sender, EventArgs e) => RunAll();

    async void RunAll()
    {
        if (_running || ReadTarget() is not { } target) return;
        var (domain, dc) = target;
        var block = DiagLog.Block = new LogBlock($"Run {Clock(DateTime.Now)}", $"{TargetText(_profile, domain, dc)} · all sections");
        var cts = StartRun("", domain, dc);
        _summaryPanel.Visible = false;
        _lblStatus.Text = "Running diagnostics...";

        var pendingRun = new DiagRun(DateTime.MinValue, domain, dc, BuildSkeleton(_profile)) { Profile = _profile };
        _runHistory.Insert(0, pendingRun);
        _selectedRunIndex = 0;
        RebuildHistoryBar();

        var config = new DiagConfig(domain, dc, cts.Token, _ztnaAdapter);
        bool finished = await RunSections(pendingRun, ProfileSections, config, cts,
            (done, total) => _lblStatus.Text = $"Running diagnostics... ({done}/{total})");
        if (!finished) return;

        // The pending run may have been deleted, or another run selected, while it was running
        int pendingIndex = _runHistory.FindIndex(r => ReferenceEquals(r, pendingRun));
        if (pendingIndex >= 0)
        {
            bool wasSelected = _selectedRunIndex == pendingIndex;
            _runHistory[pendingIndex] = pendingRun with { Timestamp = DateTime.Now };
            if (_runHistory.Count > 5) _runHistory.RemoveAt(_runHistory.Count - 1);
            if (wasSelected || _selectedRunIndex >= _runHistory.Count)
                _selectedRunIndex = pendingIndex;
        }
        if (SelectedRun is { } selected)
            ShowResults(selected.Results);
        RebuildHistoryBar();

        var all = pendingRun.Results.SelectMany(g => g.Tests).ToList();
        AppLog.Info("run", $"Complete: {Totals(all).Replace(" · ", ", ")}");
        block.Totals = Totals(all);
        _logStale = true;
        _lblStatus.Text = "Complete";
        SetRunning(false);
    }

    /// <summary>
    /// Runs one section. For the domain and DC of the run on show its results replace that section there, stamped
    /// with their own time; otherwise they start a new run in which the other sections show as not run.
    /// </summary>
    async void RunSection(string name)
    {
        if (_running || !SectionInProfile(name) || ReadTarget() is not { } target) return;
        var (domain, dc) = target;
        var block = DiagLog.Block = new LogBlock($"{name} {Clock(DateTime.Now)}", $"{TargetText(_profile, domain, dc)} · run on its own");
        var cts = StartRun($" {name}", domain, dc);
        _lblStatus.Text = $"Running {name}...";

        var run = SelectedRun is { IsPending: false } shown && shown.Profile == _profile && shown.Domain == domain && shown.Dc == dc ? shown : null;
        bool newRun = run == null;
        if (run == null)
        {
            run = new DiagRun(DateTime.Now, domain, dc, BuildSkeleton(_profile)) { Profile = _profile };
            run.NotRun.UnionWith(ProfileSections.Where(n => n != name));
            _runHistory.Insert(0, run);
            if (_runHistory.Count > 5) _runHistory.RemoveAt(_runHistory.Count - 1);
            _selectedRunIndex = 0;
            RebuildHistoryBar();
        }
        run.NotRun.Remove(name);
        run.Open[name] = true; // a group run on its own opens to show its new results, or stays open

        var config = new DiagConfig(domain, dc, cts.Token, _ztnaAdapter);
        if (!await RunSections(run, [name], config, cts)) return;
        if (!newRun) run.RanAt[name] = DateTime.Now;
        if (ReferenceEquals(SelectedRun, run)) ShowResults(run.Results);

        var tests = run.Results.Find(g => g.Name == name)?.Tests ?? [];
        AppLog.Info("run", $"Complete {name}: {Totals(tests).Replace(" · ", ", ")}");
        block.Totals = Totals(tests);
        _logStale = true;
        _lblStatus.Text = $"{name}: run at {Clock(DateTime.Now)}";
        SetRunning(false);
    }

    /// <summary>
    /// Runs the named sections into <paramref name="run"/>'s results and shows each as it finishes. False when the
    /// run was cancelled (cleared, or the window closed).
    /// </summary>
    async Task<bool> RunSections(DiagRun run, List<string> names, DiagConfig config, CancellationTokenSource cts,
        Action<int, int>? progress = null)
    {
        var skeleton = BuildSkeleton(run.Profile);
        foreach (string name in names)
        {
            int i = run.Results.FindIndex(g => g.Name == name);
            if (i >= 0) run.Results[i] = skeleton.First(g => g.Name == name);
        }
        if (ReferenceEquals(SelectedRun, run)) RenderResults(run.Results);

        // Each section blocks on external tools and the network for seconds at a time, so it gets its own
        // thread: on the shared pool they starve the continuations that read the tools' output
        var pending = names.Select(name =>
        {
            var test = Sections.First(s => s.Name == name).Test;
            return (Name: name, Task: Task.Factory.StartNew(() =>
            {
                DiagLog.Section = name; // the section's tool calls and queries log under it
                return test(config, Probe);
            }, cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default));
        }).ToList();

        int completed = 0;
        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(p => p.Task));
            if (cts.IsCancellationRequested || IsDisposed) return false;
            var match = pending.First(p => p.Task == done);
            pending.Remove(match);

            TestGroup result;
            try { result = match.Task.GetAwaiter().GetResult(); }
            catch (Exception ex) { result = new(match.Name, [new TestEntry("Error", Status.Fail, ex.Message)]); }
            LogResult(result);
            if (DiagLog.Block is { } block) block.SectionNotes[match.Name] = GroupCounts(result);

            int idx = run.Results.FindIndex(g => g.Name == match.Name);
            if (idx >= 0) run.Results[idx] = result;
            progress?.Invoke(++completed, names.Count);
            if (ReferenceEquals(SelectedRun, run)) ShowResults(run.Results);
        }
        return true;
    }

    static void LogResult(TestGroup result)
    {
        string? outer = DiagLog.Section;
        DiagLog.Section = result.Name;
        try
        {
            foreach (var test in result.Tests)
                AppLog.Info("result", $"{StatusWord(test.Status),-8} {result.Name} / {test.Name}: {test.Detail}");
            if (result.Readiness is { } ready)
                AppLog.Info("result", $"{StatusWord(ready.Status),-8} {result.Name} / Readiness: {ready.Text}");
        }
        finally
        {
            DiagLog.Section = outer;
        }
    }

    // The Run button's drop-down, built when opened so it takes the current theme
    void ShowRunMenu()
    {
        if (_running) return;
        var menu = new ContextMenuStrip { Renderer = new MenuRenderer(), ShowImageMargin = false, Font = new Font("Segoe UI", 9f), BackColor = SurfaceColor };
        menu.Items.Add("Run all sections", null, (s, e) => RunAll());
        menu.Items.Add(new ToolStripSeparator());
        foreach (string name in ProfileSections)
            menu.Items.Add(name.Replace("&", "&&"), null, (s, e) => RunSection(name)); // a lone & would underline the next letter
        menu.Closed += (s, e) => BeginInvoke(menu.Dispose);
        menu.Show(_btnRun, new Point(0, _btnRun.Height));
    }

    /// <summary>Draws drop-down menus in the theme's colours; the default renderer is light only.</summary>
    sealed class MenuRenderer : ToolStripProfessionalRenderer
    {
        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            using var fill = new SolidBrush(SurfaceColor);
            e.Graphics.FillRectangle(fill, e.AffectedBounds);
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) =>
            e.Graphics.DrawRectangle(BorderPen, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1);

        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            if (!e.Item.Selected) return;
            using var fill = new SolidBrush(Blend(SurfaceColor, AccentColor, 0.2));
            int inset = e.ToolStrip?.LogicalToDeviceUnits(2) ?? 2;
            e.Graphics.FillRectangle(fill, inset, 0, e.Item.Width - 2 * inset, e.Item.Height);
        }

        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            int y = e.Item.Height / 2;
            int inset = e.ToolStrip?.LogicalToDeviceUnits(4) ?? 4;
            e.Graphics.DrawLine(BorderPen, inset, y, e.Item.Width - inset, y);
        }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = TextColor;
            base.OnRenderItemText(e);
        }
    }

    // A time of day as the Windows clock shows it (5:09:33 PM, or 17:09:33). Log line stamps keep a fixed 24-hour
    // format with milliseconds, so they line up and sort
    static string Clock(DateTime time) => time.ToString("T", System.Globalization.CultureInfo.CurrentCulture);

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
            var btn = RunButton(ri, x);
            _historyPanel.Controls.Add(btn);
            x += btn.Width + S(4);
        }
        _historyPanel.Controls.Add(DeleteRunButton());
        _historyPanel.Visible = true;
    }

    ThemedButton RunButton(int index, int x)
    {
        var run = _runHistory[index];
        bool selected = index == _selectedRunIndex;
        bool isPending = run.IsPending;
        string label = isPending ? "Pending..." : Clock(run.Timestamp);
        var btn = new ThemedButton
        {
            Text = label, FlatStyle = FlatStyle.Flat,
            Font = selected ? HistoryFontBold : HistoryFont,
            BackColor = selected ? (isPending ? WarnColor : AccentColor) : SurfaceColor,
            ForeColor = selected ? OnAccentColor : (isPending ? WarnColor : DimColor),
            Location = new Point(x, S(4)),
        };
        // Fits the label, which follows the Windows clock and is wider in 12-hour time
        btn.Size = new Size(Math.Max(S(isPending ? 72 : 62), TextRenderer.MeasureText(label, btn.Font).Width + S(14)), S(20));
        if (!isPending) btn.Click += (s, e) => SelectRun(index);
        return btn;
    }

    ThemedButton DeleteRunButton()
    {
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
        return del;
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
            ShowPreview();
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

    // The run on show; before any run, the preview of the profile's sections
    DiagRun? SelectedRun => _selectedRunIndex >= 0 && _selectedRunIndex < _runHistory.Count ? _runHistory[_selectedRunIndex] : _preview;
    DiagRun? _preview;

    /// <summary>
    /// Before any run: every section the profile runs, as a heading that hasn't run with its Run button, so what
    /// will be checked shows before anything is. It is never a run of its own: running starts a real one.
    /// </summary>
    void ShowPreview()
    {
        var preview = new DiagRun(DateTime.MinValue, "", "", BuildSkeleton(_profile)) { Profile = _profile };
        preview.NotRun.UnionWith(preview.Results.Select(g => g.Name));
        _preview = preview;
        RenderResults(preview.Results);
        _resultsBar.Visible = false; // nothing to open or close yet
    }

    void ShowSelectedRun()
    {
        if (SelectedRun is not { } run) return;
        ShowResults(run.Results);
        _lblStatus.Text = run.IsPending ? "Running diagnostics..." : $"Run from {Clock(run.Timestamp)}";
        _btnExport.Enabled = _btnCopy.Enabled = !run.IsPending && !_running;
    }

    void ShowResults(List<TestGroup> results)
    {
        RenderResults(results);
        int pass = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Pass);
        int fail = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Fail);
        int warn = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Warn);
        int notes = results.SelectMany(g => g.Tests).Count(t => t.Status == Status.Info);
        _lblPassCount.Text = pass.ToString();
        _lblFailCount.Text = fail.ToString();
        _lblWarnCount.Text = warn.ToString();
        _lblInfoCount.Text = notes.ToString();
        _lblWarnCaption.Text = warn == 1 ? "warning" : "warnings";
        _lblInfoCaption.Text = notes == 1 ? "note" : "notes";
        _summaryPanel.Visible = true;
    }

    /// <summary>The selected run as plain text: what Export saves and Copy puts on the clipboard.</summary>
    static string BuildReport(DiagRun run)
    {
        var sb = new StringBuilder();
        sb.AppendLine("===================================================");
        sb.AppendLine("  AD Diagnostics Report");
        sb.AppendLine($"  Generated: {DateTime.Now:G}");
        sb.AppendLine($"  Run at:    {run.Timestamp:G}");
        sb.AppendLine("===================================================");
        sb.AppendLine();
        sb.AppendLine("Configuration:");
        sb.AppendLine($"  Profile: {ProfileName(run.Profile)}");
        if (run.Profile != JoinProfile.Entra)
        {
            sb.AppendLine($"  Domain:  {run.Domain}");
            sb.AppendLine($"  DC Host: {run.Dc}");
        }
        sb.AppendLine();
        foreach (var group in run.Results)
            AppendReportGroup(sb, run, group);
        return sb.ToString();
    }

    static void AppendReportGroup(StringBuilder sb, DiagRun run, TestGroup group)
    {
        bool notRun = run.NotRun.Contains(group.Name);
        string stamp = notRun ? "  (not run)"
            : run.RanAt.TryGetValue(group.Name, out var at) ? $"  (run at {at:G})" : "";
        sb.AppendLine("---------------------------------------------------");
        sb.AppendLine($"  {group.Name.ToUpperInvariant()}{stamp}");
        sb.AppendLine("---------------------------------------------------");
        if (!notRun)
        {
            foreach (var test in group.Tests)
            {
                char icon = test.Status switch { Status.Pass => '+', Status.Fail => 'X', Status.Warn => '!', Status.Info => 'i', _ => 'o' };
                sb.AppendLine($"  {icon} {test.Name,-26} {test.Detail}");
            }
            if (group.Readiness is { } ready)
                sb.AppendLine($"  = {"Readiness",-26} {ready.Text}" + (ready.ShowGuide ? $" Fixes: Guide tab, {group.Name}." : ""));
        }
        sb.AppendLine();
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
            FileName = $"ad-diag-{(run.Domain.Length > 0 ? Regex.Replace(run.Domain, @"[^a-zA-Z0-9.\-]", "_") : "entra")}-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
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

    static List<TestGroup> BuildSkeleton(JoinProfile profile)
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
                new("TGT Present"), new("Clock Skew"), new("Time Source"), new(Diagnostics.KrbtgtKeyCheck),
            ]),
            new("Dynamic DNS Registration", [
                new("Registration Name"), new("ZTNA / VPN Client"), new("Registering Adapters"),
                new("Zone Primary Server"), new("Update Path (Port 53)"), new("Registered Record"),
                new("Registration Errors"),
            ]),
            new(Diagnostics.EntraSsoGroup, [new(Diagnostics.SsoJoin),
                .. profile == JoinProfile.Domain ? Array.Empty<TestEntry>() : [new(Diagnostics.SsoDeviceAuth), new(Diagnostics.SsoPrt)],
                .. profile == JoinProfile.Entra
                    ? [new(Diagnostics.SsoCloudTgt), new(Diagnostics.SsoOnPremTgt)]
                    : new TestEntry[] { new(Diagnostics.SsoTicket), new(Diagnostics.SsoZone), new(Diagnostics.SsoLogon), new(Diagnostics.SsoStatusBar) },
                new(Diagnostics.SsoEndpoints),
            ]),
            new(Diagnostics.CredentialsGroup, [
                new(Diagnostics.HelloCheck), new(Diagnostics.TpmCheck),
                new(Diagnostics.TicketEncryptionCheck), new(Diagnostics.SavedCredentialsCheck),
            ]),
            new(Diagnostics.IntuneGroup, [
                new(Diagnostics.MdmEnrollmentCheck), new(Diagnostics.MdmSyncCheck),
                new(Diagnostics.MdmExtensionCheck), new(Diagnostics.MdmPoliciesCheck),
            ]),
        };
        return groups.Where(g => InProfile(g.Name, profile)).ToList();
    }

    // ── What the diagnostics (Diagnostics.cs) ask of this machine ──

    // In memory only: nothing is written unless the user saves the log from the Log tab
    static readonly DiagLog AppLog = new();
    static readonly IProbe Probe = new LoggingProbe(new WindowsProbe(), AppLog);

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

        public (string Host, string Suffix) HostIdentity()
        {
            var global = IPGlobalProperties.GetIPGlobalProperties();
            return (global.HostName, global.DomainName);
        }

        public List<NetAdapter> Adapters() => NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n =>
            {
                var ip = n.GetIPProperties();
                return new NetAdapter(n.Name, n.Description,
                    n.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp,
                    ip.IsDynamicDnsEnabled, ip.UnicastAddresses.Select(u => u.Address).ToArray(), ip.DnsAddresses.ToArray(),
                    IsSoftwareAdapter(n.Id),
                    ip.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork && u.PrefixLength == 32)
                        && !ip.GatewayAddresses.Any(g => !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any)));
            }).ToList();

        // Windows enumerates a software adapter itself (ROOT\, SWD\); a real one is found on a bus (PCI\, USB\, VMBUS\)
        static bool IsSoftwareAdapter(string id)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{id}\Connection");
                string instance = key?.GetValue("PnPInstanceId") as string ?? "";
                return instance.StartsWith(@"ROOT\", StringComparison.OrdinalIgnoreCase)
                    || instance.StartsWith(@"SWD\", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                return false;
            }
        }

        public SoaRecord? QuerySoa(string name, IPAddress? server, CancellationToken ct) =>
            Runner.RunWithTimeout(() => MainForm.QuerySoa(name, server), Runner.DnsTimeoutMs, $"SOA query for {name}", ct);

        public IPAddress[] QueryAddresses(string name, IPAddress? server, CancellationToken ct) =>
            Runner.RunWithTimeout(() => MainForm.QueryAddresses(name, server), Runner.DnsTimeoutMs, $"A/AAAA query for {name}", ct);

        public bool IsElevated()
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public UrlSecurity UrlSecurity(string url, CancellationToken ct) =>
            Runner.RunWithTimeout(() => QueryUrlSecurity(url), UrlSecurityTimeoutMs, $"Internet settings for {url}", ct);

        // Read only, from the 64-bit view, where the MDM client keeps its keys
        static RegistryKey? OpenHklm(string path)
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            return hklm.OpenSubKey(path, writable: false);
        }

        public string[]? RegistrySubKeys(string hklmPath)
        {
            using var key = OpenHklm(hklmPath);
            return key?.GetSubKeyNames();
        }

        public Dictionary<string, object>? RegistryValues(string hklmPath)
        {
            using var key = OpenHklm(hklmPath);
            if (key == null) return null;
            var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in key.GetValueNames())
                if (key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is { } value)
                    values[name] = value;
            return values;
        }

        public int? ServiceState(string name) => QueryServiceState(name);

        public int? TpmVersion() => QueryTpmVersion();

        public string? CurrentUserUpn() => QueryUserUpn();

        public string? CurrentUserSid()
        {
            using var id = WindowsIdentity.GetCurrent();
            return id.User?.Value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TbsDeviceInfo
    {
        public uint StructVersion, TpmVersion, TpmInterfaceType, TpmImpRevision;
    }

    [DllImport("tbs.dll")]
    static extern uint Tbsi_GetDeviceInfo(uint size, out TbsDeviceInfo info);

    const uint TbsSuccess = 0, TbsTpmNotFound = 0x8028400F;

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetUserNameExW(int nameFormat, System.Text.StringBuilder? name, ref uint size);

    const int NameUserPrincipal = 8, ErrorMoreData = 234, ErrorNoneMapped = 1332;

    /// <summary>The signed-in user's UPN from the security subsystem; null when the account has none.</summary>
    static string? QueryUserUpn()
    {
        uint size = 256;
        var name = new System.Text.StringBuilder((int)size);
        if (GetUserNameExW(NameUserPrincipal, name, ref size)) return name.ToString();
        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNoneMapped) return null;
        if (error != ErrorMoreData) throw new System.ComponentModel.Win32Exception(error);
        name = new System.Text.StringBuilder((int)size);
        return GetUserNameExW(NameUserPrincipal, name, ref size) ? name.ToString() : throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }

    /// <summary>The TPM's major version from TPM Base Services, which any user may ask; null if there is none.</summary>
    static int? QueryTpmVersion()
    {
        uint result = Tbsi_GetDeviceInfo((uint)Marshal.SizeOf<TbsDeviceInfo>(), out var info);
        if (result == TbsTpmNotFound) return null;
        if (result != TbsSuccess) throw new System.ComponentModel.Win32Exception((int)result, $"TPM Base Services error 0x{result:x8}");
        return info.TpmVersion switch { 1 => 1, 2 => 2, _ => (int)info.TpmVersion };
    }

    const uint ScManagerConnect = 0x0001, ServiceQueryStatus = 0x0004;
    const int ErrorServiceDoesNotExist = 1060;

    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatus
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CloseServiceHandle(IntPtr handle);

    /// <summary>A service's state from the service manager (query rights only, which any user has); null if it isn't installed.</summary>
    static int? QueryServiceState(string name)
    {
        IntPtr manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            IntPtr service = OpenServiceW(manager, name, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                return error == ErrorServiceDoesNotExist ? null : throw new System.ComponentModel.Win32Exception(error);
            }
            try
            {
                if (!QueryServiceStatus(service, out var status)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                return (int)status.CurrentState;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    const int UrlSecurityTimeoutMs = 5000;
    const int UrlActionCredentialsUse = 0x1A00, UrlActionStatusBarScript = 0x2103, PuafNoUi = 0x1;

    /// <summary>
    /// A URL's zone and two of its zone's policies, from the URL security manager: the component Edge and Chrome ask
    /// on Windows, which applies Group Policy, the user's own zone sites and the zone settings in the same order they
    /// do. So nothing here reads the registry or second-guesses that order.
    /// </summary>
    static UrlSecurity QueryUrlSecurity(string url)
    {
        int hr = CoInternetCreateSecurityManager(IntPtr.Zero, out var manager, 0);
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
        try
        {
            Marshal.ThrowExceptionForHR(manager.MapUrlToZone(url, out int zone, 0));
            return new(zone, UrlPolicy(manager, url, UrlActionCredentialsUse), UrlPolicy(manager, url, UrlActionStatusBarScript));
        }
        finally
        {
            Marshal.ReleaseComObject(manager);
        }
    }

    static int UrlPolicy(IInternetSecurityManager manager, string url, int action)
    {
        // S_FALSE means the action isn't allowed; the policy value still says which setting applies
        int hr = manager.ProcessUrlAction(url, action, out int policy, sizeof(int), IntPtr.Zero, 0, PuafNoUi, 0);
        if (hr < 0) Marshal.ThrowExceptionForHR(hr);
        return policy;
    }

    [DllImport("urlmon.dll")]
    static extern int CoInternetCreateSecurityManager(IntPtr serviceProvider, out IInternetSecurityManager manager, int reserved);

    // urlmon.h; methods in vtable order, the ones not called declared with placeholder arguments. No arrays: a COM
    // interface passes one as a SAFEARRAY, so a BYTE* buffer is declared as the one int it holds.
    [ComImport, Guid("79eac9ee-baf9-11ce-8c82-00aa004ba90b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IInternetSecurityManager
    {
        [PreserveSig] int SetSecuritySite(IntPtr site);
        [PreserveSig] int GetSecuritySite(out IntPtr site);
        [PreserveSig] int MapUrlToZone([MarshalAs(UnmanagedType.LPWStr)] string url, out int zone, int flags);
        [PreserveSig] int GetSecurityId(IntPtr url, IntPtr securityId, IntPtr securityIdSize, IntPtr reserved);
        [PreserveSig] int ProcessUrlAction([MarshalAs(UnmanagedType.LPWStr)] string url, int action,
            out int policy, int policySize, IntPtr context, int contextSize, int flags, int reserved);
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

    const ushort DnsTypeA = 1, DnsTypeSoa = 6, DnsTypeAaaa = 28;
    // Asked of a DNS server and nothing else: no resolver cache (0x8), no answering for this machine's own name
    // locally (0x20), no hosts file (0x40), NetBIOS (0x80) or multicast (0x800), wire only (0x100)
    const uint DnsQueryServerOnly = 0x8 | 0x20 | 0x40 | 0x80 | 0x100 | 0x800;

    /// <summary>
    /// Sends one query to <paramref name="server"/> (IPv4), or to the configured DNS servers when null, and hands
    /// each record of the asked type, from any section of the reply, to <paramref name="read"/> as its owner name
    /// and a pointer to its data. Returns the DNS API status (0, or e.g. 9003 when the name doesn't exist).
    /// </summary>
    static int QueryDnsServer(string name, ushort type, IPAddress? server, Action<string, IntPtr> read)
    {
        int status;
        IntPtr results;
        if (server != null)
        {
            var servers = new Ip4Array { AddrCount = 1, Address = BitConverter.ToUInt32(server.GetAddressBytes(), 0) };
            status = DnsQuery_W(name, type, DnsQueryServerOnly, ref servers, out results, IntPtr.Zero);
        }
        else
        {
            status = DnsQuery_W(name, type, DnsQueryServerOnly, IntPtr.Zero, out results, IntPtr.Zero);
        }
        try
        {
            for (IntPtr p = results; p != IntPtr.Zero;)
            {
                var header = Marshal.PtrToStructure<DnsRecordHeader>(p);
                if (header.wType == type)
                    read(Marshal.PtrToStringUni(header.pName) ?? "", p + Marshal.SizeOf<DnsRecordHeader>());
                p = header.pNext;
            }
        }
        finally
        {
            if (results != IntPtr.Zero) DnsRecordListFree(results, 1); // DnsFreeRecordList
        }
        return status;
    }

    /// <summary>
    /// The zone and primary server from the SOA record for <paramref name="name"/>, whether it came as the answer
    /// (the name is a zone) or as the authority for a name inside one; null if the reply carried none. Asked of
    /// <paramref name="server"/> (IPv4), or of the configured DNS servers when null.
    /// </summary>
    static SoaRecord? QuerySoa(string name, IPAddress? server)
    {
        SoaRecord? soa = null;
        // DNS_SOA_DATAW starts with the primary server's name
        int status = QueryDnsServer(name, DnsTypeSoa, server,
            (zone, data) => soa ??= new(zone, Marshal.PtrToStringUni(Marshal.ReadIntPtr(data)) ?? ""));
        if (soa == null && status is not (0 or DnsErrorNameError or DnsInfoNoRecords))
            throw new System.ComponentModel.Win32Exception(status);
        return soa;
    }

    /// <summary>The A and AAAA records a DNS server holds for <paramref name="name"/>; empty if it holds none.</summary>
    static IPAddress[] QueryAddresses(string name, IPAddress? server)
    {
        var found = new List<IPAddress>();
        foreach (ushort type in new[] { DnsTypeA, DnsTypeAaaa })
        {
            int status = QueryDnsServer(name, type, server, (_, data) =>
            {
                var bytes = new byte[type == DnsTypeA ? 4 : 16];
                Marshal.Copy(data, bytes, 0, bytes.Length);
                found.Add(new IPAddress(bytes));
            });
            if (status is not (0 or DnsErrorNameError or DnsInfoNoRecords))
                throw new System.ComponentModel.Win32Exception(status);
        }
        return found.Distinct().ToArray();
    }

    // The start of every DNS_RECORDW; the record's data follows it
    [StructLayout(LayoutKind.Sequential)]
    struct DnsRecordHeader
    {
        public IntPtr pNext;
        public IntPtr pName;
        public ushort wType;
        public ushort wDataLength;
        public uint Flags;
        public uint dwTtl;
        public uint dwReserved;
    }

    // IP4_ARRAY with one server; the address is in network byte order
    [StructLayout(LayoutKind.Sequential)]
    struct Ip4Array
    {
        public uint AddrCount;
        public uint Address;
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

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    static extern int DnsQuery_W(string name, ushort type, uint options, ref Ip4Array servers, out IntPtr results, IntPtr reserved);

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
    /// <summary>Groups the user opened (true) or closed (false) in this run; the rest follow the default.</summary>
    public Dictionary<string, bool> Open { get; init; } = [];
    /// <summary>Sections not run yet: a run started from one section leaves the others to run later.</summary>
    public HashSet<string> NotRun { get; init; } = [];
    /// <summary>When a section last ran on its own, after the run it belongs to, by name.</summary>
    public Dictionary<string, DateTime> RanAt { get; init; } = [];
    /// <summary>The profile the run was made for, which decided its sections.</summary>
    public JoinProfile Profile { get; init; }
}
