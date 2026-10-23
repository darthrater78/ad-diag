using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

#nullable enable
namespace AdDiag;

// The Active Directory | SMB switch and everything the SMB mode shows: the strip's Server or share field and Test
// connection, the Results tab's path from this PC to the share, and its report. The checks are in SmbPath.cs.
partial class MainForm
{
    enum TestMode { Ad, Smb }
    TestMode _mode = TestMode.Ad;
    ThemedButton _btnModeAd = null!, _btnModeSmb = null!, _btnSmbTest = null!;
    TextBox _txtSmbTarget = null!;
    Label _lblDomain = null!, _lblSmbTarget = null!;
    Panel _tabBar = null!;
    int _tabDividerX;
    string _tab = "results";

    // The SMB pane, and the test on show
    Panel _smbPanel = null!, _smbPath = null!;
    RichTextBox _smbBox = null!;
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
        _mode = mode;
        AppLog.Info("app", $"Mode: {(mode == TestMode.Smb ? "SMB" : "Active Directory")}");
        ApplyMode();
        if (mode == TestMode.Smb) _txtSmbTarget.Focus();
        else if (SelectedRun != null) ShowSelectedRun();
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
        _lblSmbTarget.Visible = _txtSmbTarget.Visible = smb;
        _lblProfileHint.Visible = entra && !smb;

        _btnRun.Visible = _btnRunMenu.Visible = !smb;
        _btnSmbTest.Visible = smb;
        AcceptButton = smb ? _btnSmbTest : _btnRun;
        _summaryPanel.Visible = !smb && SelectedRun is { IsPending: false };
        _historyPanel.Visible = !smb && _runHistory.Count > 0;
        _btnExport.Enabled = _btnCopy.Enabled = smb ? _smbVerdict != null && !_smbRunning : !_running && SelectedRun is { IsPending: false };

        LayoutTabs();
        // A tab the mode or profile hides gives way to Results
        SwitchTab(_tab is "gp" or "dns" or "intune" && (smb || (_tab == "gp" && entra)) ? "results" : _tab);
    }

    // ── The pane ──

    void BuildSmbPanel()
    {
        _smbPath = new BufferedPanel { Height = 78, Dock = DockStyle.Top, BackColor = PanelColor, AccessibleRole = AccessibleRole.Graphic };
        _smbPath.Paint += PaintSmbPath;
        _smbPath.Resize += (s, e) => _smbPath.Invalidate();
        _lnkSmbGuide = new LinkLabel { Text = "See SMB in the Guide", Font = new Font("Segoe UI", 8.5f), AutoSize = true, LinkColor = AccentColor, ActiveLinkColor = AccentColor, VisitedLinkColor = AccentColor, BackColor = PanelColor, Visible = false };
        _lnkSmbGuide.LinkClicked += (s, e) => ShowGuideSection(SmbGuideTitle);
        var linkBar = new Panel { Height = 22, Dock = DockStyle.Top, BackColor = PanelColor };
        linkBar.Controls.Add(_lnkSmbGuide);
        linkBar.Resize += (s, e) => _lnkSmbGuide.Location = new Point(S(GridLeft) + S(4), S(2));
        _smbBox = new RichTextBox
        {
            ReadOnly = true,
            BackColor = PanelColor,
            ForeColor = TextColor,
            BorderStyle = BorderStyle.None,
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9.5f),
            ScrollBars = RichTextBoxScrollBars.ForcedVertical,
            DetectUrls = false,
        };
        _smbPanel = new Panel { Dock = DockStyle.Fill, BackColor = PanelColor, Visible = false };
        _smbPanel.Controls.Add(_smbBox);
        _smbPanel.Controls.Add(linkBar);
        _smbPanel.Controls.Add(_smbPath);
        RenderSmb();
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
            Color tone = state switch
            {
                Status.Pass => PassColor, Status.Warn => WarnColor, Status.Fail => FailColor, Status.Skip => SkipColor, _ => BorderColor,
            };
            if (i > 0)
            {
                using var line = new Pen(state is Status.Pass or Status.Warn ? tone : RowLineColor, S(2));
                g.DrawLine(line, cx - slot + r + S(2), cy, cx - r - S(2), cy);
            }
            var circle = new Rectangle(cx - r, cy - r, 2 * r, 2 * r);
            using (var fill = new SolidBrush(state is Status.Pass or Status.Warn or Status.Fail ? Blend(PanelColor, tone, 0.14) : PanelColor))
                g.FillEllipse(fill, circle);
            if (i == running)
            {
                // The step being checked: a ring in primary, open on one side, like the running mark in Results
                using var ring = new Pen(AccentColor, S(2));
                g.DrawArc(ring, circle, -90, 280);
            }
            else
            {
                using var border = new Pen(state == null ? BorderColor : tone, S(2));
                g.DrawEllipse(border, circle);
                if (state is { } s) DrawStatusMark(g, new TestEntry("", s, "-"), cx - S(5), cy - S(5));
            }

            string caption = i == running ? "Checking…"
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

    /// <summary>Writes the pane again: before a test what it does; after, the verdict and each step's rows.</summary>
    void RenderSmb()
    {
        if (_smbBox == null) return;
        _smbPath.Invalidate();
        _lnkSmbGuide.Visible = _smbVerdict?.Fix != null;
        _smbBox.Clear();
        StepParagraph(_smbBox, row: false);
        if (_smbTarget == null)
        {
            AppendRun(_smbBox, "\n  Type a file server or share in Server or share, then click Test connection. The test follows the path an SMB\n"
                + "  connection takes from this PC and stops where it breaks: the server's name in DNS, TCP port 445, a Kerberos ticket\n"
                + "  for the server, how Windows signs in, and opening the share. This PC's SMB client settings are listed under it.\n\n"
                + "  A short name gets the Domain field's domain. On an Entra joined PC, give the on-prem domain for the Kerberos checks.\n"
                + "  Everything is read only: nothing is written, and no password is asked for or saved.\n", DimColor);
            return;
        }

        string where = _smbDomain.Length > 0 ? $" · {_smbDomain}" : "";
        AppendRun(_smbBox, $"\n  {_smbTarget.Unc}", TextColor, GpBoldFont);
        AppendRun(_smbBox, $"   {ProfileName(_smbProfile)}{where} · {Clock(_smbAt)}\n", DimColor);
        if (_smbVerdict is { } v)
        {
            var (mark, color) = StatusMark(v.Status);
            AppendRun(_smbBox, $"\n  {mark} ", color, GpBoldFont);
            AppendRun(_smbBox, v.Text + "\n", TextColor, GpBoldFont);
            if (v.Fix != null)
            {
                AppendRun(_smbBox, "     Fix: ", FixLabelColor, GuideFixLabelFont);
                AppendRun(_smbBox, v.Fix + "\n", DimColor, GuideFixFont);
            }
        }
        else if (_smbRunning)
            AppendRun(_smbBox, "\n  Testing…\n", DimColor);

        foreach (var group in _smbGroups)
        {
            StepParagraph(_smbBox, row: false);
            var state = StepState(group) ?? Status.Skip;
            var (_, tone) = StatusMark(state);
            AppendRun(_smbBox, $"\n  {group.Name}", TextColor, GuideSectionFont);
            AppendRun(_smbBox, state == Status.Skip ? "   NOT REACHED" : $"   {StatusWord(state).ToUpperInvariant()}", tone, BadgeFont);
            AppendRun(_smbBox, state == Status.Skip ? "\n" : $"   {GroupCounts(group)}\n", DimColor, LogNoteFont);
            foreach (var test in group.Tests)
                AppendStepRow(_smbBox, test, StatusWord(test.Status));
        }
        _smbBox.SelectionStart = 0;
        _smbBox.ScrollToCaret();
    }

    // ── Running ──

    async void RunSmbTest()
    {
        if (_smbRunning) return;
        string domain = _txtDomain.Text.Trim();
        var (target, error) = Diagnostics.ParseSmbTarget(_txtSmbTarget.Text, domain);
        if (target == null)
        {
            _lblStatus.ForeColor = WarnColor;
            _lblStatus.Text = error;
            _txtSmbTarget.Focus();
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
