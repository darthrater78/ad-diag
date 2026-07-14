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
using System.Text.Json;
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

    readonly ComboBox _txtDomain, _txtDc;
    readonly CheckBox _chkDcSuffix;
    readonly Button _btnRun, _btnExport, _btnClear, _btnTabResults, _btnTabGuide;
    readonly Label _lblStatus, _lblPassCount, _lblFailCount, _lblWarnCount;
    readonly Panel _summaryPanel, _resultsCanvas, _resultsScrollPanel, _historyPanel;
    readonly RichTextBox _guideBox;
    List<TestGroup>? _lastResults;
    List<TestGroup>? _renderedGroups;
    bool _renderRunning;
    string? _placeholderText;
    readonly List<DiagRun> _runHistory = [];
    int _selectedRunIndex = -1;
    CancellationTokenSource? _runCts;

    static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ad-diag", "settings.json");

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
        var icoPath = Path.Combine(AppContext.BaseDirectory, "app.ico");
        if (File.Exists(icoPath)) Icon = new Icon(icoPath);

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
        tabBar.Controls.AddRange([_btnTabResults, _btnTabGuide]);

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

        _historyPanel = new Panel { Height = 28, Dock = DockStyle.Top, BackColor = BgColor, Visible = false };
        _historyPanel.Paint += (s, e) => e.Graphics.DrawLine(BorderPen, 0, _historyPanel.Height - 1, _historyPanel.Width, _historyPanel.Height - 1);

        contentWrapper.Controls.Add(_resultsScrollPanel);
        contentWrapper.Controls.Add(_guideBox);
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

        LoadSettings();
        FormClosing += (s, e) =>
        {
            _runCts?.Cancel();
            SaveSettings();
        };
        FormClosed += (s, e) => Environment.Exit(0);
    }

    ComboBox MakeInput(Panel parent, string label, int col, int row)
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

        var cbo = new ComboBox
        {
            Text = "",
            DropDownStyle = ComboBoxStyle.DropDown,
            BackColor = SurfaceColor, ForeColor = TextColor,
            FlatStyle = FlatStyle.Standard,
            Font = new Font("Cascadia Code", 9f),
            Location = new Point(x, y + 13), Width = w,
        };

        parent.Controls.AddRange([lbl, cbo]);

        parent.Resize += (s, e) =>
        {
            int newX = col == 0 ? 14 : parent.ClientSize.Width / 2 + 4;
            int newW = parent.ClientSize.Width / 2 - 24;
            lbl.Location = new Point(newX, lbl.Location.Y);
            cbo.Location = new Point(newX, cbo.Location.Y);
            cbo.Width = newW;
        };

        return cbo;
    }

    // ── Settings ────────────────────────────────────────────

    void LoadSettings()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return;
            var json = File.ReadAllText(SettingsPath);
            var s = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
            if (s == null) return;

            LoadComboHistory(_txtDomain, s, "domain");
            LoadComboHistory(_txtDc, s, "dc");

            if (s.TryGetValue("dcSuffix", out var ds))
                _chkDcSuffix.Checked = ds.ValueKind == JsonValueKind.True;
        }
        catch { }
    }

    static void LoadComboHistory(ComboBox cbo, Dictionary<string, JsonElement> data, string key)
    {
        if (!data.TryGetValue(key, out var el)) return;
        if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in el.EnumerateArray())
            {
                string? val = item.GetString();
                if (!string.IsNullOrEmpty(val))
                    cbo.Items.Add(val);
            }
            if (cbo.Items.Count > 0)
                cbo.SelectedIndex = 0;
        }
        else if (el.ValueKind == JsonValueKind.String)
        {
            string? val = el.GetString();
            if (!string.IsNullOrEmpty(val))
            {
                cbo.Items.Add(val);
                cbo.SelectedIndex = 0;
            }
        }
    }

    void SaveSettings()
    {
        try
        {
            AddToHistory(_txtDomain);
            AddToHistory(_txtDc);

            var s = new Dictionary<string, object>
            {
                ["domain"] = ComboHistory(_txtDomain),
                ["dc"] = ComboHistory(_txtDc),
                ["dcSuffix"] = _chkDcSuffix.Checked,
            };
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }

    static void AddToHistory(ComboBox cbo)
    {
        string val = cbo.Text.Trim();
        if (string.IsNullOrEmpty(val)) return;
        for (int i = 0; i < cbo.Items.Count; i++)
        {
            if (string.Equals(cbo.Items[i]?.ToString(), val, StringComparison.OrdinalIgnoreCase))
            {
                cbo.Items.RemoveAt(i);
                break;
            }
        }
        cbo.Items.Insert(0, val);
        cbo.SelectedIndex = 0;
    }

    static List<string> ComboHistory(ComboBox cbo)
    {
        var list = new List<string>();
        foreach (var item in cbo.Items)
        {
            string? s = item?.ToString();
            if (!string.IsNullOrEmpty(s))
                list.Add(s);
        }
        return list;
    }

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
            "This will clear all saved domain history, input fields, results, and settings.\n\nContinue?",
            "Reset All", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
        if (result != DialogResult.Yes) return;

        _txtDomain.Items.Clear(); _txtDomain.Text = "";
        _txtDc.Items.Clear(); _txtDc.Text = "";
        BtnClear_Click(sender, e);
        try { if (File.Exists(SettingsPath)) File.Delete(SettingsPath); } catch { }
        _lblStatus.Text = "All settings reset";
    }

    // ── Tab switching ───────────────────────────────────────

    void SwitchTab(string tab)
    {
        _resultsScrollPanel.Visible = tab == "results";
        _guideBox.Visible = tab == "guide";

        foreach (var (btn, key) in new[] { (_btnTabResults, "results"), (_btnTabGuide, "guide") })
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
                "  Fix: If no site or wrong site, verify the client's subnet is registered in AD Sites and Services under the correct site"),

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
                "  Fix: Check that the DC's computer account registered its A record, or add it manually if using non-dynamic DNS"),

            ("Group Policy",
                "Parses gpresult to check whether Group Policy is applying correctly to this computer.\n\n" +
                "• GP Last Refresh — how long since policy was last applied\n" +
                "  Fix: If stale, run 'gpupdate /force' and check the Event Viewer (Applications and Services Logs > Microsoft > Windows > GroupPolicy) for errors\n\n" +
                "• Applied GPOs — count of policies successfully applied to this computer\n" +
                "  Fix: If zero, verify the computer object is in an OU with linked GPOs, and that security filtering allows this computer\n\n" +
                "• Denied GPOs — policies that exist but were filtered out (security filtering, WMI filters, disabled links)\n" +
                "  Fix: This is often expected behavior — review each denied GPO's link status and security filtering if unexpected"),

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
        var gpTask = Task.Run(() => TestGroupPolicy(config));
        var trustTask = Task.Run(() => TestTrusts(config));
        var kerbTask = Task.Run(() => TestKerberosAndTime(config));

        var pending = new List<(Task task, string name, Func<TestGroup> getResult)>
        {
            (identityTask, "Domain Membership & Identity", () => identityTask.Result),
            (dcTask, "DC Discovery & Connectivity", () => dcTask.Result),
            (dnsTask, "DNS for Active Directory", () => dnsTask.Result),
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

        SaveSettings();
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
            ]),
            new("DC Discovery & Connectivity", [
                new("Locate DC"), new("Port 389 (LDAP)"), new("Port 636 (LDAPS)"),
                new("Port 88 (Kerberos)"), new("Port 53 (DNS)"), new("Port 3268 (Global Catalog)"),
            ]),
            new("DNS for Active Directory", [
                new("_ldap._tcp SRV"), new("_kerberos._tcp SRV"),
                new("_gc._tcp SRV"), new("DC A Record"),
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
            var trustMatch = Regex.Match(scVerify, @"Trust Verification Status\s*=\s*(.+)", RegexOptions.IgnoreCase);
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
            ("Port 53 (DNS)", 53, Task.Run(() => TryTcpConnect(kdcIp, kdc, 53))),
            ("Port 3268 (Global Catalog)", 3268, Task.Run(() => TryTcpConnect(kdcIp, kdc, 3268))),
        };

        Task.WaitAll(portTasks.Select(p => p.Task).ToArray());

        foreach (var (name, port, task) in portTasks)
        {
            bool open = task.Result;
            bool required = port is 389 or 88;
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

    static TestGroup TestGroupPolicy(DiagConfig cfg)
    {
        var tests = new List<TestEntry>();

        try
        {
            string gpresult = RunProcess("gpresult", "/r /scope:computer", timeoutMs: 20000);

            var lastApplied = Regex.Match(gpresult, @"Last time Group Policy was applied\s*:\s*(.+)", RegexOptions.IgnoreCase);
            if (lastApplied.Success && DateTime.TryParse(lastApplied.Groups[1].Value.Trim(), out var lastTime))
            {
                var age = DateTime.Now - lastTime;
                tests.Add(new("GP Last Refresh",
                    age.TotalHours < 24 ? Status.Pass : age.TotalDays < 7 ? Status.Warn : Status.Fail,
                    $"{lastTime:g} ({FormatTimeSpan(age)} ago)"));
            }
            else
            {
                tests.Add(new("GP Last Refresh", Status.Warn, "Could not determine last refresh time"));
            }

            var appliedSection = Regex.Match(gpresult, @"Applied Group Policy Objects\s*\r?\n[\s\S]*?(?=\r?\n\s*\r?\n|\z)", RegexOptions.IgnoreCase);
            int appliedCount = 0;
            if (appliedSection.Success)
                appliedCount = appliedSection.Value.Split('\n').Count(l => l.Trim().Length > 0 && !l.Contains("Applied Group Policy Objects", StringComparison.OrdinalIgnoreCase) && !l.Contains("----", StringComparison.OrdinalIgnoreCase));
            tests.Add(new("Applied GPOs",
                appliedCount > 0 ? Status.Pass : Status.Warn,
                appliedCount > 0 ? $"{appliedCount} GPO(s) applied" : "No applied GPOs found"));

            var deniedSection = Regex.Match(gpresult, @"The following GPOs were not applied because they were filtered out\s*\r?\n[\s\S]*?(?=\r?\n\s*\r?\n|\z)", RegexOptions.IgnoreCase);
            int deniedCount = 0;
            if (deniedSection.Success)
                deniedCount = deniedSection.Value.Split('\n')
                    .Select(l => l.Trim())
                    .Count(l => l.Length > 0 && !l.Contains("filtered out", StringComparison.OrdinalIgnoreCase));
            tests.Add(new("Denied GPOs", Status.Pass, $"{deniedCount} GPO(s) filtered out (informational)"));
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
        };
        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        var outputTask = proc.StandardOutput.ReadToEndAsync();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(true); } catch { }
        }
        return outputTask.GetAwaiter().GetResult();
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
