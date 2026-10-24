using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

#nullable enable
namespace AdDiag;

// The Active Directory | SMB switch and everything the SMB mode shows: the strip's File server and Share fields and Test
// connection, the Results tab's path from this PC to the share, and its report. The checks are in SmbPath.cs.
partial class MainForm
{
    enum TestMode { Ad, Smb }
    TestMode _mode = TestMode.Ad;
    ThemedButton _btnModeAd = null!, _btnModeSmb = null!, _btnSmbTest = null!, _btnOpenShare = null!;
    TextBox _txtSmbServer = null!, _txtSmbShare = null!;
    CheckBox _chkSmbSuffix = null!;
    Label _lblDomain = null!, _lblSmbServer = null!, _lblSmbShare = null!;
    Panel _tabBar = null!;
    int _tabDividerX;
    string _tab = "results";
    // Each mode keeps its own status line, so switching back shows what that mode last said
    readonly Dictionary<TestMode, (string Text, Color Color)> _modeStatus = [];

    // The SMB pane, and the test on show
    Panel _smbPanel = null!, _smbPath = null!, _smbScroll = null!;
    SmbCanvas _smbCanvas = null!;
    LinkLabel _lnkSmbGuide = null!;
    SmbTarget? _smbTarget;
    JoinProfile _smbProfile;
    string _smbDomain = "";
    DateTime _smbAt;
    readonly List<TestGroup> _smbGroups = [];
    SmbVerdict? _smbVerdict;
    bool _smbRunning;
    CancellationTokenSource? _smbCts;
    string? _smbTestedSpn; // the Kerberos tickets tab puts this server's ticket first

    const string SmbGuideTitle = "SMB connection test";

    // ── The switch ──

    Panel BuildModeBar()
    {
        var bar = new Panel { Height = 36, Dock = DockStyle.Fill };
        var lbl = new Label { Text = "Test", ForeColor = DimColor, Font = new Font("Segoe UI", 8.5f), AutoSize = true, Location = new Point(14, 11) };
        _btnModeAd = new ThemedButton { Text = "Active Directory", Split = SplitPart.Left, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(124, 26), Location = new Point(50, 6), AccessibleName = "Test Active Directory" };
        _btnModeSmb = new ThemedButton { Text = "SMB", Split = SplitPart.Right, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(64, 26), Location = new Point(174, 6), AccessibleName = "Test an SMB connection to a file share" };
        _btnModeAd.Click += (s, e) => SetMode(TestMode.Ad);
        _btnModeSmb.Click += (s, e) => SetMode(TestMode.Smb);
        bar.Controls.AddRange([lbl, _btnModeAd, _btnModeSmb]);
        StyleModeButtons();
        return bar;
    }

    void StyleModeButtons()
    {
        foreach (var (button, on) in new[] { (_btnModeAd, _mode == TestMode.Ad), (_btnModeSmb, _mode == TestMode.Smb) })
        {
            button.BackColor = on ? AccentColor : SurfaceColor;
            button.ForeColor = on ? OnAccentColor : TextColor;
            button.AccessibleDescription = on ? "Selected" : null;
        }
    }

    void SetMode(TestMode mode)
    {
        if (_mode == mode) return;
        _modeStatus[_mode] = (_lblStatus.Text, _lblStatus.ForeColor);
        _mode = mode;
        AppLog.Info("app", $"Mode: {(mode == TestMode.Smb ? "SMB" : "Active Directory")}");
        ApplyMode();
        (_lblStatus.Text, _lblStatus.ForeColor) = _modeStatus.GetValueOrDefault(mode, ("", DimColor));
        if (mode == TestMode.Smb)
        {
            _txtSmbServer.Focus();
            // SMB needs the domain on every profile: for short names and the Kerberos checks
            if (string.IsNullOrWhiteSpace(_txtDomain.Text)) _ = DetectDomainAsync();
        }
    }

    /// <summary>
    /// Shows what the mode and profile call for: the strip's fields and primary button, the summary and Runs bars
    /// (Active Directory only), the tabs, and the Results tab's pane.
    /// </summary>
    void ApplyMode()
    {
        bool smb = _mode == TestMode.Smb, entra = _profile == JoinProfile.Entra;
        StyleModeButtons();
        foreach (var control in _domainControls) control.Visible = !smb && !entra;
        // SMB keeps the Domain field on every profile, for short names and the SPN search; an Entra joined PC has
        // no domain of its own, so the user gives the on-prem one
        _lblDomain.Visible = _txtDomain.Visible = !entra || smb;
        _lblDomain.Text = smb && entra ? "On-prem domain" : "Domain";
        _lblSmbServer.Visible = _txtSmbServer.Visible = _lblSmbShare.Visible = _txtSmbShare.Visible = _chkSmbSuffix.Visible = smb;
        _lblProfileHint.Visible = entra && !smb;

        _btnRun.Visible = _btnRunMenu.Visible = !smb;
        _btnSmbTest.Visible = smb;
        AcceptButton = smb ? _btnSmbTest : _btnRun;
        _summaryPanel.Visible = !smb && SelectedRun is { IsPending: false };
        _historyPanel.Visible = !smb && _runHistory.Count > 0;
        _btnExport.Enabled = _btnCopy.Enabled = smb ? _smbVerdict != null && !_smbRunning : !_running && SelectedRun is { IsPending: false };

        LayoutTabs();
        // A tab the mode or profile hides gives way to Results
        bool hidden = _tab switch
        {
            "gp" => smb || entra,
            "dns" => smb,
            "intune" => smb || _profile == JoinProfile.Domain,
            _ => false,
        };
        SwitchTab(hidden ? "results" : _tab);
    }

    // ── The pane ──

    void BuildSmbPanel()
    {
        _smbPath = new BufferedPanel { Height = 78, Dock = DockStyle.Top, BackColor = PanelColor, AccessibleRole = AccessibleRole.Graphic };
        _smbPath.Paint += PaintSmbPath;
        _smbPath.Resize += (s, e) => _smbPath.Invalidate();
        // The tab's own actions, in a bar at its top as on the other tabs: open the server or share, and the Guide
        _btnOpenShare = new ThemedButton { Text = "Open share", BackColor = SurfaceColor, ForeColor = TextColor, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 9f), Size = new Size(100, 28), Location = new Point(10, 3), AccessibleName = "Open the server or share in File Explorer" };
        _btnOpenShare.Click += (s, e) => OpenSmbInExplorer();
        _lnkSmbGuide = new LinkLabel { Text = "See SMB in the Guide", Font = new Font("Segoe UI", 8.5f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, BackColor = BgColor, Location = new Point(124, 9), Visible = false };
        _lnkSmbGuide.LinkClicked += (s, e) => ShowGuideSection(SmbGuideTitle);
        var actionBar = new Panel { Height = 34, Dock = DockStyle.Top, BackColor = BgColor };
        actionBar.Controls.AddRange([_btnOpenShare, _lnkSmbGuide]);
        // Drawn like the Results grid, not written into a rich edit box, so the columns and marks are exact
        _smbScroll = new KeepScrollPanel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = PanelColor };
        _smbCanvas = new SmbCanvas { Location = Point.Empty, BackColor = PanelColor, Height = 100, AccessibleName = "SMB test results" };
        _smbCanvas.Paint += (s, e) => LayoutSmb(e.Graphics, _smbCanvas.Width);
        _smbScroll.Controls.Add(_smbCanvas);
        _smbScroll.Resize += (s, e) => SizeSmbCanvas();
        _smbPanel = new Panel { Dock = DockStyle.Fill, BackColor = PanelColor, Visible = false };
        _smbPanel.Controls.Add(_smbScroll);
        _smbPanel.Controls.Add(_smbPath);
        _smbPanel.Controls.Add(actionBar);
        // Docking runs from the back of the z-order: the action bar, then the strip, take the top; the results what's left
        _smbScroll.BringToFront();
        RenderSmb();
    }

    // The results canvas: focusable, so the mouse wheel scrolls the panel it sits in
    sealed class SmbCanvas : Panel
    {
        public SmbCanvas()
        {
            DoubleBuffered = true;
            SetStyle(ControlStyles.Selectable, true);
            TabStop = true;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
        }
    }

    sealed class BufferedPanel : Panel
    {
        public BufferedPanel()
        {
            DoubleBuffered = true;
            ResizeRedraw = true;
        }
    }

    // A step's state on the path: its worst result, a note counting as passed; all skipped is not reached
    static Status? StepState(TestGroup? group) =>
        group == null ? null
        : group.Tests.All(t => t.Status == Status.Skip) ? Status.Skip
        : group.Tests.Any(t => t.Status == Status.Fail) ? Status.Fail
        : group.Tests.Any(t => t.Status == Status.Warn) ? Status.Warn
        : Status.Pass;

    // The five connection points, joined by a line that takes the colour of the step it leads to once that step passes
    void PaintSmbPath(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        string[] steps = Diagnostics.SmbSteps;
        int n = steps.Length, margin = S(GridLeft) + S(46);
        int slot = Math.Max((_smbPath.Width - 2 * margin) / (n - 1), S(60));
        int cy = S(22), r = S(12);
        int running = _smbRunning ? _smbGroups.Count(gr => steps.Contains(gr.Name)) : -1;
        string? stoppedAt = _smbVerdict is { Status: Status.Fail } v && v.Text.StartsWith("Stopped at ", StringComparison.Ordinal)
            ? steps.FirstOrDefault(s => v.Text.StartsWith($"Stopped at {s}:", StringComparison.Ordinal)) : null;
        var names = new List<string>();

        for (int i = 0; i < n; i++)
        {
            int cx = margin + slot * i;
            var state = StepState(_smbGroups.Find(gr => gr.Name == steps[i]));
            if (i > 0)
            {
                using var line = new Pen(state is Status.Pass or Status.Warn ? ChipTone(state) : RowLineColor, S(2));
                g.DrawLine(line, cx - slot + r + S(2), cy, cx - r - S(2), cy);
            }
            DrawChip(g, cx, cy, r, state, i == running);

            // A step that needed more than one try says so, as the Kerberos request may
            int tries = _smbGroups.Find(gr => gr.Name == steps[i])?.Tests.Max(t => t.Tries) ?? 1;
            string caption = i == running ? "Checking…"
                : tries > 1 && state is Status.Pass or Status.Warn ? $"Passed on try {tries}"
                : tries > 1 && state == Status.Fail ? $"Failed after {tries} tries"
                : state switch
                {
                    Status.Pass => "Passed", Status.Warn => "Warning", Status.Fail => steps[i] == stoppedAt ? "Failed here" : "Failed",
                    Status.Skip => "Not reached", _ => "",
                };
            var nameBox = new Rectangle(cx - slot / 2, cy + r + S(4), slot, S(18));
            TextRenderer.DrawText(g, steps[i], GpBoldFont, nameBox, state is null or Status.Skip ? DimColor : TextColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            if (caption.Length > 0)
                TextRenderer.DrawText(g, caption, LogNoteFont, new Rectangle(nameBox.X, nameBox.Bottom, slot, S(16)), DimColor,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine);
            names.Add(caption.Length > 0 ? $"{steps[i]}: {caption}" : steps[i]);
        }
        _smbPath.AccessibleName = "Connection path. " + string.Join(", ", names);
    }

    /// <summary>Draws the pane again: before a test what it does; after, the verdict and each step's rows.</summary>
    void RenderSmb()
    {
        if (_smbCanvas == null) return;
        _smbPath.Invalidate();
        _lnkSmbGuide.Visible = _smbVerdict?.Fix != null;
        _smbCanvas.AccessibleDescription = BuildSmbReport() ?? "";
        SizeSmbCanvas();
        _smbCanvas.Invalidate();
    }

    void SizeSmbCanvas()
    {
        int w = _smbScroll.ClientSize.Width;
        if (w <= 0) return;
        _smbCanvas.Width = w;
        _smbCanvas.Height = LayoutSmb(null, w);
    }

    const string SmbExplainer =
        "Type the File server, and the Share to test opening it, then click Test connection. The test follows the path an SMB "
        + "connection takes from this PC and stops where it breaks: the server's name in DNS, TCP port 445, a Kerberos ticket "
        + "for the server, how Windows signs in, and opening the share. This PC's SMB client settings are listed under it.\n\n"
        + "A short name gets the domain. On an Entra joined PC, the on-prem domain is needed for the Kerberos checks.\n\n"
        + "Everything is read only: nothing is written, and no password is asked for or saved.";


    /// <summary>
    /// Lays the SMB results out at <paramref name="width"/> and returns their height; with <paramref name="g"/> it
    /// also draws them. The rows use the Results grid's columns, marks and fonts.
    /// </summary>
    int LayoutSmb(Graphics? g, int width)
    {
        int left = S(GridLeft), right = width - S(GridLeft), y = S(10);
        int Para(string text, Font font, Color color, int x, int top)
        {
            var size = TextRenderer.MeasureText(text, font, new Size(Math.Max(right - x, S(80)), 0), DetailTextFlags);
            if (g != null) TextRenderer.DrawText(g, text, font, new Rectangle(x, top, right - x, size.Height), color, DetailTextFlags);
            return top + size.Height;
        }
        if (_smbTarget == null) return Para(SmbExplainer, GuideBodyFont, DimColor, left, y) + S(14);

        const TextFormatFlags oneLine = TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
        int targetW = TextRenderer.MeasureText(_smbTarget.Unc, GroupHeaderFont, Size.Empty, oneLine).Width;
        string meta = $"{ProfileName(_smbProfile)}{(_smbDomain.Length > 0 ? $" · {_smbDomain}" : "")} · {Clock(_smbAt)}";
        if (g != null)
        {
            TextRenderer.DrawText(g, _smbTarget.Unc, GroupHeaderFont, new Point(left, y), TextColor, oneLine);
            TextRenderer.DrawText(g, meta, GroupCountFont, new Point(left + targetW + S(10), y + S(2)), DimColor, oneLine);
        }
        y += S(26);

        int indent = left + S(16);
        if (_smbVerdict is { } v)
        {
            if (g != null) DrawStatusMark(g, new TestEntry("", v.Status, "-"), left, y + S(4));
            y = Para(v.Text, ReadinessNameFont, TextColor, indent, y);
            if (v.Fix != null)
            {
                int labelW = TextRenderer.MeasureText("Fix:", GuideFixLabelFont, Size.Empty, oneLine).Width;
                if (g != null) TextRenderer.DrawText(g, "Fix:", GuideFixLabelFont, new Point(indent, y + S(3)), FixLabelColor, oneLine);
                y = Para(v.Fix, GuideFixFont, DimColor, indent + labelW + S(4), y + S(3));
            }
        }
        else if (_smbRunning)
            y = Para("Testing…", GuideBodyFont, DimColor, left, y);

        int detailW = DetailWidth(width);
        foreach (var group in _smbGroups)
        {
            y += S(14);
            var state = StepState(group) ?? Status.Skip;
            string counts = state == Status.Skip ? "Not reached" : GroupCounts(group);
            if (g != null)
            {
                TextRenderer.DrawText(g, group.Name, GroupHeaderFont, new Rectangle(left, y + S(2), right - left - S(NoteColumn) - BadgeWidth(g) - S(16), S(20)), TextColor,
                    oneLine | TextFormatFlags.EndEllipsis);
                int noteX = right - S(NoteColumn);
                DrawGroupBadge(g, state, noteX - S(8), y);
                TextRenderer.DrawText(g, counts, GroupCountFont, new Point(noteX, y + S(5)), DimColor, oneLine);
            }
            y += S(26);
            foreach (var test in group.Tests)
            {
                var size = TextRenderer.MeasureText(test.Detail, TestDetailFont, new Size(detailW, 0), DetailTextFlags);
                int rowHeight = Math.Max(S(20), size.Height + S(4));
                if (g != null)
                {
                    var (word, color) = StatusLook(test);
                    g.DrawLine(RowLinePen, left, y, right, y);
                    DrawStatusMark(g, test, left, y + S(8));
                    TextRenderer.DrawText(g, word, StatusFont, new Point(left + S(15), y + S(5)), color, TextFormatFlags.NoPrefix);
                    TextRenderer.DrawText(g, test.Name, TestNameFont, new Rectangle(S(NameX), y + S(4), S(DetailX - NameX - 6), S(18)), TextColor,
                        TextFormatFlags.Left | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
                    TextRenderer.DrawText(g, test.Detail, TestDetailFont, new Rectangle(S(DetailX), y + S(5), detailW, size.Height),
                        test.Status == Status.Skip ? DimColor : TextColor, DetailTextFlags);
                }
                y += S(4) + rowHeight;
            }
            g?.DrawLine(RowLinePen, left, y, right, y);
        }
        return y + S(14);
    }

    /// <summary>
    /// Opens the server (its list of shares) or the share in File Explorer, through explorer.exe so it runs at the
    /// desktop's level even when this app is elevated. Only a path built from the validated fields is passed, and a
    /// validated server and share can't hold a quote.
    /// </summary>
    void OpenSmbInExplorer()
    {
        var (target, error) = Diagnostics.ParseSmbTarget(_txtSmbServer.Text, _txtSmbShare.Text, SmbSuffix());
        if (target == null)
        {
            _lblStatus.ForeColor = WarnColor;
            _lblStatus.Text = error;
            return;
        }
        string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        try
        {
            Process.Start(new ProcessStartInfo(explorer, $"\"{target.Unc}\"") { UseShellExecute = false })?.Dispose();
            AppLog.Info("smb", $"Opened {target.Unc} in File Explorer");
            _lblStatus.ForeColor = DimColor;
            _lblStatus.Text = $"Opened {target.Unc} in File Explorer";
        }
        catch (Exception ex)
        {
            AppLog.Info("smb", $"Could not open {target.Unc} in File Explorer: {ex.Message}");
            _lblStatus.ForeColor = WarnColor;
            _lblStatus.Text = $"Couldn't open {target.Unc}: {ex.Message}";
        }
    }

    // The domain a short file server name gets: none when Add domain suffix is off, to test the name as typed
    string SmbSuffix() => _chkSmbSuffix.Checked ? _txtDomain.Text.Trim() : "";

    // ── Running ──

    async void RunSmbTest()
    {
        if (_smbRunning) return;
        string domain = _txtDomain.Text.Trim();
        var (target, error) = Diagnostics.ParseSmbTarget(_txtSmbServer.Text, _txtSmbShare.Text, SmbSuffix());
        if (target == null)
        {
            _lblStatus.ForeColor = WarnColor;
            _lblStatus.Text = error;
            (error?.Contains("Share") == true ? _txtSmbShare : _txtSmbServer).Focus();
            return;
        }

        var profile = _profile;
        _smbCts = new CancellationTokenSource();
        var cts = _smbCts;
        _smbRunning = true;
        _btnSmbTest.Enabled = _btnExport.Enabled = _btnCopy.Enabled = false;
        (_smbTarget, _smbProfile, _smbDomain, _smbAt, _smbVerdict, _smbTestedSpn) = (target, profile, domain, DateTime.Now, null, target.Spn);
        _smbGroups.Clear();
        SwitchTab("results");
        RenderSmb();
        _lblStatus.ForeColor = DimColor;
        _lblStatus.Text = $"Testing {target.Unc}...";

        var block = DiagLog.Block = new LogBlock($"SMB {Clock(DateTime.Now)}", $"{target.Unc} · {ProfileName(profile)}{(domain.Length > 0 ? $" · {domain}" : "")}");
        AppLog.Info("smb", $"Started: {target.Unc}" + (target.Typed != target.Server ? $" (typed {target.Typed})" : "")
            + $", {ProfileName(profile)} profile, domain {(domain.Length > 0 ? domain : "(none)")}");

        try
        {
            var config = new DiagConfig(domain, "", cts.Token);
            await Task.Factory.StartNew(() => Diagnostics.TestSmb(target, profile, config, Probe, group => ReportSmbStep(group, cts, block)),
                cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            AppLog.Info("smb", $"Error: {ex.Message}");
            if (!cts.IsCancellationRequested) _smbGroups.Add(new("Error", [new("Error", Status.Fail, ex.Message)]));
        }
        finally
        {
            if (ReferenceEquals(_smbCts, cts)) _smbRunning = false;
            _btnSmbTest.Enabled = true;
        }
        if (cts.IsCancellationRequested || IsDisposed) return;

        var verdict = _smbVerdict = Diagnostics.SmbVerdictFor(target, profile, _smbGroups);
        AppLog.Info("smb", $"{StatusWord(verdict.Status)}: {verdict.Text}" + (verdict.Fix != null ? $" Fix: {verdict.Fix}" : ""));
        block.Totals = Totals(_smbGroups.SelectMany(g => g.Tests));
        _logStale = true;
        _lblStatus.Text = verdict.Status switch
        {
            Status.Pass => "Connected",
            Status.Fail => verdict.Text.Split(':')[0],
            _ => "Connected, with warnings",
        };
        _btnExport.Enabled = _btnCopy.Enabled = _mode == TestMode.Smb;
        RenderSmb();
    }

    // Logs a step's rows under its own section and shows it, unless the test has been cleared since; called from the test's thread
    void ReportSmbStep(TestGroup group, CancellationTokenSource cts, LogBlock block)
    {
        LogResult(group);
        try
        {
            BeginInvoke(() =>
            {
                if (cts.IsCancellationRequested || IsDisposed) return;
                block.SectionNotes[group.Name] = GroupCounts(group);
                _smbGroups.Add(group);
                RenderSmb();
            });
        }
        catch (InvalidOperationException) { } // the window closed while the test was running
    }

    void ClearSmb()
    {
        if (_smbRunning) AppLog.Info("smb", "SMB test cleared; test cancelled");
        _smbCts?.Cancel();
        _smbRunning = false;
        _btnSmbTest.Enabled = true;
        (_smbTarget, _smbVerdict, _smbTestedSpn) = (null, null, null);
        _smbGroups.Clear();
        RenderSmb();
        if (_mode == TestMode.Smb)
        {
            _btnExport.Enabled = _btnCopy.Enabled = false;
            _lblStatus.Text = "SMB test cleared";
        }
    }

    /// <summary>The SMB test on show as plain text, for Copy and Export; null before a test finishes.</summary>
    string? BuildSmbReport()
    {
        if (_smbTarget is not { } target || _smbVerdict is not { } verdict || _smbRunning) return null;
        var sb = new StringBuilder();
        sb.AppendLine("===================================================");
        sb.AppendLine("  AD Diagnostics: SMB connection test");
        sb.AppendLine($"  Generated: {DateTime.Now:G}");
        sb.AppendLine($"  Tested at: {_smbAt:G}");
        sb.AppendLine("===================================================");
        sb.AppendLine();
        sb.AppendLine($"  Target:  {target.Unc}");
        sb.AppendLine($"  Profile: {ProfileName(_smbProfile)}");
        if (_smbDomain.Length > 0) sb.AppendLine($"  Domain:  {_smbDomain}");
        sb.AppendLine();
        sb.AppendLine($"  Result:  {verdict.Text}");
        if (verdict.Fix != null) sb.AppendLine($"  Fix:     {verdict.Fix}");
        sb.AppendLine();
        foreach (var group in _smbGroups)
        {
            sb.AppendLine("---------------------------------------------------");
            sb.AppendLine($"  {group.Name.ToUpperInvariant()}");
            sb.AppendLine("---------------------------------------------------");
            foreach (var test in group.Tests)
                sb.AppendLine($"  {ReportIcon(test.Status)} {test.Name,-26} {test.Detail}");
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
