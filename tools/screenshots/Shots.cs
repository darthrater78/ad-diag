using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace AdDiag;

// Screenshot harness: drives the real MainForm with mock data and saves PNGs of its client area.
static class Shots
{
    const BindingFlags F = BindingFlags.Instance | BindingFlags.NonPublic;
    static T Get<T>(object o, string name) => (T)o.GetType().GetField(name, F)!.GetValue(o)!;
    static void Set(object o, string name, object? v) => o.GetType().GetField(name, F)!.SetValue(o, v);
    static object? Call(object o, string name, params object?[] args) => o.GetType().GetMethod(name, F)!.Invoke(o, args);
    static Color Theme(string name) => (Color)typeof(MainForm).GetProperty(name, BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;

    [STAThread]
    static void Main(string[] args)
    {
        string outDir = args.Length > 0 ? args[0] : ".";
        // The app follows the Windows light/dark app setting; a second argument of "dark" selects it for this run
        using (var personalize = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
            personalize.SetValue("AppsUseLightTheme", args.Length > 1 && args[1] == "dark" ? 0 : 1, Microsoft.Win32.RegistryValueKind.DWord);
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.CurrentCulture = new CultureInfo("en-US");
        Environment.SetEnvironmentVariable("USERDNSDOMAIN", "CONTOSO.COM");
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        var form = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(20, 20) };
        form.Shown += (s, e) =>
        {
            try { CaptureAll(form, outDir); }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                Environment.Exit(1);
            }
            Environment.Exit(0);
        };
        Application.Run(form);
    }

    static void CaptureAll(MainForm form, string outDir)
    {
        // Wine runs everything as Administrator; the screenshots show the usual unelevated app
        form.Text = "AD Diagnostics";
        foreach (var c in AllControls(form).Where(c => c.AccessibleName == "Running as administrator")) c.Visible = false;
        Set(form, "_elevated", false);
        // Before any run: the profile's sections, not run yet, with one opened to the checks it will make
        Pump(800);
        Set(form, "_profilePicked", true);
        Call(form, "SetProfile", JoinProfile.Hybrid, true);
        var preview = (DiagRun)form.GetType().GetProperty("SelectedRun", F)!.GetValue(form)!;
        preview.Open["Domain Membership & Identity"] = true;
        Call(form, "RerenderResults");
        Pump(300);
        Capture(form, outDir, "before-run.png");
        Pump(800);
        Populate(form);
        // Tall enough for the two groups opened below
        form.Height = 1120;
        Pump(800);
        // Groups start closed; open two as a user would, to show their checks
        var shown = (DiagRun)form.GetType().GetProperty("SelectedRun", F)!.GetValue(form)!;
        shown.Open["DC Discovery & Connectivity"] = true;
        shown.Open["Group Policy"] = true;
        Call(form, "RerenderResults");
        Pump(300);
        // Put the pointer on one heading's run button to show its hover state
        var canvas = Get<Control>(form, "_resultsCanvas");
        var headings = (List<(string Group, Rectangle Band)>)canvas.GetType().GetField("Headings")!.GetValue(canvas)!;
        var band = headings.Find(h => h.Group == "DC Discovery & Connectivity").Band;
        Cursor.Position = canvas.PointToScreen(new Point(band.Right - 16, band.Top + 14));
        Pump(300);
        Capture(form, outDir, "results.png");
        form.Height = 900;
        Pump(500);

        // Where "See the fixes in the Guide" under a group that isn't ready leads
        Call(form, "SwitchTab", "guide");
        FrontFill(Get<RichTextBox>(form, "_guideBox"));
        Call(form, "ShowGuideSection", Diagnostics.EntraSsoGroup);
        Pump(500);
        Capture(form, outDir, "guide-sso.png");

        Call(form, "SwitchTab", "gp");
        // Wine re-syncs the child order from its native z-order, which leaves the Runs bar in front of
        // this Fill panel and covering its first lines; restore the order the form was built with
        FrontFill(Get<Panel>(form, "_gpPanel"));
        var gp = Get<RichTextBox>(form, "_gpBox");
        gp.Clear();
        Call(form, "AppendGpLine", "\n", Theme("BgColor"), false, null);
        foreach (var scope in Parsers.ParseRsop(MockRsop()))
            Call(form, "RenderGpScope", scope);
        gp.SelectionStart = 0; gp.ScrollToCaret();
        Pump(500);
        Capture(form, outDir, "group-policy.png");

        Call(form, "SwitchTab", "tickets");
        FrontFill(Get<Panel>(form, "_ticketsPanel"));
        var tb = Get<RichTextBox>(form, "_ticketsBox");
        tb.Clear();
        Call(form, "RenderPrtCard", Diagnostics.PrtCardFor(Parsers.ParseDsreg(MockDsreg()), DateTime.UtcNow)!);
        var (headers, tickets) = Parsers.ParseKlist(MockKlist());
        foreach (var h in headers)
        {
            if (h.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase))
                Call(form, "AppendTicketsLine", h + "\n\n", Theme("DimColor"), false, null);
            else
                Call(form, "AppendTicketsLine", h + "\n", Theme("AccentColor"), true, null);
        }
        for (int i = 0; i < tickets.Count; i++)
            Call(form, "RenderTicket", tickets[i].Server, tickets[i].Fields, i);
        tb.SelectionStart = 0; tb.ScrollToCaret();
        Pump(500);
        Capture(form, outDir, "kerberos-tickets.png");

        Call(form, "SwitchTab", "dns");
        FrontFill(Get<Panel>(form, "_dnsPanel"));
        Set(form, "_dnsHeading", "Registering this computer in DNS, " + DateTime.Now.AddSeconds(-40).ToString("T"));
        Get<List<TestEntry>>(form, "_dnsSteps").AddRange(MockDnsTrace());
        Call(form, "RenderDnsBox");
        Pump(500);
        Capture(form, outDir, "dns-registration.png");

        var log = (DiagLog)typeof(MainForm).GetField("AppLog", BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        Call(form, "SwitchTab", "log");
        FrontFill(Get<Panel>(form, "_logPanel"));
        Get<CheckBox>(form, "_chkDebug").Checked = true;
        log.Clear();
        MockLog(log);
        // Everything starts folded; open it all as a reader would, except one section, to show both
        var opened = Get<HashSet<object>>(form, "_logOpen");
        foreach (var line in log.Since(0).Where(l => l.Block != null))
        {
            opened.Add(line.Block!);
            if (line.Section is { } section && section != "Kerberos & Time Sync") opened.Add((line.Block!, section));
        }
        Call(form, "RenderLog");
        Pump(500);
        Capture(form, outDir, "log.png");

        // An Entra joined laptop: its profile hides the domain fields and sections, and the Intune policies tab
        Call(form, "SetProfile", JoinProfile.Entra, false);
        var entraHistory = Get<List<DiagRun>>(form, "_runHistory");
        var entraRun = new DiagRun(DateTime.Now, "", "", MockEntraResults(DateTime.Now)) { Profile = JoinProfile.Entra };
        entraRun.Open[Diagnostics.EntraSsoGroup] = true;
        entraRun.Open[Diagnostics.CredentialsGroup] = true;
        entraHistory.Insert(0, entraRun);
        Set(form, "_selectedRunIndex", 0);
        Call(form, "SwitchTab", "results");
        Call(form, "ShowSelectedRun");
        Call(form, "RebuildHistoryBar");
        Pump(500);
        Capture(form, outDir, "results-entra.png");

        Call(form, "SwitchTab", "intune");
        FrontFill(Get<Panel>(form, "_intunePanel"));
        var intune = Get<RichTextBox>(form, "_intuneBox");
        intune.Clear();
        Call(form, "AppendIntuneLine", "\n", Theme("TextColor"), false, false);
        Call(form, "RenderIntune", MockIntune(DateTime.UtcNow));
        Get<Control>(form, "_btnIntuneSync").Enabled = true;
        intune.SelectionStart = 0; intune.ScrollToCaret();
        Pump(500);
        Capture(form, outDir, "intune-policies.png");

        // Back to the hybrid PC for the rest
        Call(form, "SetProfile", JoinProfile.Hybrid, false);
        entraHistory.Remove(entraRun);

        // Last, since the menu stays open: a run started from one section, and the Run button's drop-down
        var history = Get<List<DiagRun>>(form, "_runHistory");
        var single = new DiagRun(DateTime.Now, "contoso.com", "DC01.contoso.com", MockResults(DateTime.Now, clockWarn: true)) { Profile = JoinProfile.Hybrid };
        single.NotRun.UnionWith(single.Results.Select(g => g.Name).Where(n => n != "Kerberos & Time Sync"));
        history.Insert(0, single);
        Set(form, "_selectedRunIndex", 0);
        Call(form, "SwitchTab", "results");
        Call(form, "ShowSelectedRun");
        Call(form, "RebuildHistoryBar");
        Pump(500);
        Call(form, "ShowRunMenu");
        Pump(500);
        Capture(form, outDir, "run-menu.png");
    }

    // A laptop at home behind a ZTNA client, whose record in DNS still holds its office address
    static List<TestEntry> MockDnsTrace() =>
    [
        new("Registration Name", Status.Pass, "PC042.contoso.com with 192.168.1.50"),
        new("ZTNA / VPN Client", Status.Pass, "Zscaler adapter (100.64.0.7); DNS answered by its local proxy (100.64.0.2) (informational)"),
        new("Zone Primary Server", Status.Pass, "contoso.com -> dc01.contoso.com (10.20.0.11), answered by 100.64.0.2 (DNS server of Wi-Fi)"),
        new("Record Before", Status.Warn, "dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale"),
        new("Send", Status.Pass, "ipconfig /registerdns ran: Windows IP Configuration Registration of the DNS resource records for all adapters of this computer has been initiated. Any errors will be reported in the Event Viewer in 15 minutes."),
        new("Wait", Status.Skip, "Watching the server and the DNS Client event log for up to 30s"),
        new("DNS Client Event", Status.Fail, $"event 8015 at {DateTime.Now.AddSeconds(-31):g} — The system failed to register host (A or AAAA) resource records (RRs) for network adapter with settings: Adapter Name : {{3F2A9B10-55C1-4E0B-9D7A-0C1E5A1B7F42}} Host Name : PC042 Primary Domain Suffix : contoso.com DNS server list : 100.64.0.2 Sent update to server : 10.20.0.11 IP Address(es) : 192.168.1.50 The reason the system could not register these RRs was because the update request it sent to the DNS server timed out."),
        new("Record After", Status.Warn, "dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale — Windows logged a registration failure (above)"),
        new("ZTNA / VPN Client", Status.Info, "Through a ZTNA or VPN client a secure update needs Kerberos (port 88 to a domain controller) and TCP and UDP 53 to dc01.contoso.com to pass the tunnel as real traffic, not through the client's DNS proxy"),
    ];

    static void MockLog(DiagLog log)
    {
        const string dcd = "DC Discovery & Connectivity", krb = "Kerberos & Time Sync", reg = "Dynamic DNS Registration";
        var now = DateTime.Now;
        log.Info("log", "Debug logging on: commands, timings and raw tool output are recorded");

        // A full run: its sections ran side by side, so their lines arrived interleaved
        var run = new LogBlock($"Run {now.AddSeconds(-40):T}", "contoso.com · DC01.contoso.com · all sections") { Totals = "32 passed · 0 failed · 1 warning · 1 note" };
        run.SectionNotes[dcd] = "9 checks · 1 note";
        run.SectionNotes[krb] = "3 checks";
        run.SectionNotes[reg] = "7 checks · 1 warning";
        DiagLog.Block = run;
        log.Info("run", "Started: domain contoso.com, DC DC01.contoso.com");
        DiagLog.Section = reg;
        log.Debug("machine", "Host name and primary DNS suffix (0 ms)\nPC042, suffix \"contoso.com\"");
        DiagLog.Section = dcd;
        log.Debug("tool", "nltest /dsgetdc:contoso.com (1270 ms)\n           DC: \\\\DC01.contoso.com\n      Address: \\\\10.20.0.11\n Dc Site Name: HQ-Seattle\nThe command completed successfully");
        DiagLog.Section = reg;
        log.Debug("dns", "SOA contoso.com from 100.64.0.2 (62 ms)\nzone contoso.com, primary server dc01.contoso.com");
        DiagLog.Section = dcd;
        log.Debug("tcp", "Connect 10.20.0.11 port 53: open (38 ms)");
        log.Debug("tcp", "Connect 10.20.0.11 port 636: no answer (3001 ms)");
        DiagLog.Section = reg;
        log.Debug("dns", "A/AAAA PC042.contoso.com from 10.20.0.11 (57 ms)\n10.20.4.18");
        log.Info("result", "Warning  Dynamic DNS Registration / Registered Record: dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale");
        DiagLog.Section = krb;
        log.Info("tool", "w32tm /stripchart /computer:DC01.contoso.com /samples:1 /dataonly failed after 5012 ms: w32tm timed out after 5s (TimeoutException)");
        log.Info("result", "Skipped  Kerberos & Time Sync / Clock Skew: Not checked: could not measure (DC unreachable?)");
        DiagLog.Section = dcd;
        log.Info("result", "Info     DC Discovery & Connectivity / Port 636 (LDAPS): Unreachable at DC01.contoso.com (10.20.0.11); optional, often closed on purpose, and not needed to sign in");
        DiagLog.Section = null;
        log.Info("run", "Complete: 32 passed, 0 failed, 1 warning, 1 note");

        // One section run again on its own
        var single = new LogBlock($"Group Policy {now.AddSeconds(-12):T}", "contoso.com · DC01.contoso.com · run on its own") { Totals = "3 passed · 0 failed · 0 warnings" };
        single.SectionNotes["Group Policy"] = "3 checks";
        DiagLog.Block = single;
        log.Info("run", "Started Group Policy: domain contoso.com, DC DC01.contoso.com");
        DiagLog.Section = "Group Policy";
        log.Debug("tool", "RSoP query (840 ms)\n2 computer GPOs, 3 user GPOs");
        log.Info("result", "Passed   Group Policy / GP Last Refresh: 1h 12m ago");
        DiagLog.Section = null;
        log.Info("run", "Complete Group Policy: 3 passed, 0 failed, 0 warnings");
        DiagLog.Block = null;
    }

    static IEnumerable<Control> AllControls(Control root) =>
        root.Controls.Cast<Control>().SelectMany(c => AllControls(c).Prepend(c));

    static void FrontFill(Control fill)
    {
        fill.BringToFront();
        fill.Parent!.PerformLayout();
    }

    static void Pump(int ms)
    {
        var end = DateTime.Now.AddMilliseconds(ms);
        while (DateTime.Now < end) { Application.DoEvents(); Thread.Sleep(20); }
    }

    static void Capture(Form form, string dir, string name)
    {
        form.Activate();
        form.Refresh();
        Pump(300);
        var rect = form.RectangleToScreen(form.ClientRectangle);
        using var bmp = new Bitmap(rect.Width, rect.Height);
        using (var g = Graphics.FromImage(bmp))
            g.CopyFromScreen(rect.Location, Point.Empty, rect.Size);
        bmp.Save(System.IO.Path.Combine(dir, name), ImageFormat.Png);
    }

    static void Populate(MainForm form)
    {
        Set(form, "_profilePicked", true);
        Call(form, "SetProfile", JoinProfile.Hybrid, true);
        Get<TextBox>(form, "_txtDomain").Text = "contoso.com";
        Get<TextBox>(form, "_txtDc").Text = "DC01";

        var history = Get<List<DiagRun>>(form, "_runHistory");
        var now = DateTime.Now;
        history.Insert(0, new DiagRun(now.AddMinutes(-42), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: true)) { Profile = JoinProfile.Hybrid });
        history.Insert(0, new DiagRun(now.AddMinutes(-17), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: true)) { Profile = JoinProfile.Hybrid });
        var latest = new DiagRun(now.AddSeconds(-20), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: false)) { Profile = JoinProfile.Hybrid };
        latest.RanAt[Diagnostics.EntraSsoGroup] = now.AddSeconds(-4); // run again on its own
        history.Insert(0, latest);
        Set(form, "_selectedRunIndex", 0);
        Call(form, "ShowSelectedRun");
        Call(form, "RebuildHistoryBar");
    }

    static List<TestGroup> MockResults(DateTime now, bool clockWarn)
    {
        string dc = "DC01.contoso.com", ip = "10.20.0.11";
        string gpTime = now.AddHours(-1).AddMinutes(-12).ToString("g");
        string pwTime = now.AddDays(-12).AddHours(-3).ToString("g");
        return
        [
            new("Domain Membership & Identity",
            [
                new("Domain Joined", Status.Pass, "DomainJoined: YES"),
                new("Logged-on User", Status.Pass, @"CONTOSO\jdoe"),
                new("Secure Channel", Status.Pass, $"Verified with \\\\{dc}"),
                new("Site Assignment", Status.Pass, "Site: HQ-Seattle"),
                new("Computer Password Age", Status.Pass, $"Last changed: {pwTime} (12d ago)"),
            ]),
            new("DC Discovery & Connectivity",
            [
                new("Locate DC", Status.Pass, $"Found {dc}"),
                new("Port 389 (LDAP)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 636 (LDAPS)", Status.Info, $"Unreachable at {dc} ({ip}); optional, often closed on purpose, and not needed to sign in"),
                new("Port 88 (Kerberos)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 445 (SMB)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 135 (RPC)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 464 (Kpasswd)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 53 (DNS)", Status.Pass, $"Reachable at {dc} ({ip})"),
                new("Port 3268 (Global Catalog)", Status.Pass, $"Reachable at {dc} ({ip})"),
            ]),
            new("DNS for Active Directory",
            [
                new("_ldap._tcp SRV", Status.Pass, "_ldap._tcp.contoso.com -> dc01.contoso.com:389, dc02.contoso.com:389"),
                new("_kerberos._tcp SRV", Status.Pass, "_kerberos._tcp.contoso.com -> dc01.contoso.com:88, dc02.contoso.com:88"),
                new("_gc._tcp SRV", Status.Pass, "_gc._tcp.contoso.com -> dc01.contoso.com:3268 (optional)"),
                new("DC A Record", Status.Pass, $"{dc} -> {ip}, fd00:20::11"),
                new("DNS Suffix Search List", Status.Pass, "contoso.com, corp.contoso.com"),
            ]),
            new("SYSVOL & NETLOGON",
            [
                new("SYSVOL Access", Status.Pass, @"\\contoso.com\SYSVOL accessible (1 entries)"),
                new("NETLOGON Access", Status.Pass, @"\\contoso.com\NETLOGON accessible (4 entries)"),
            ]),
            new("Group Policy",
            [
                // Not elevated, so only the user scope could be read
                new("GP Last Refresh", Status.Pass, $"User: {gpTime} (1h 12m ago) (run as Administrator for Computer scope)") { NeedsAdmin = true },
                new("Applied GPOs", Status.Pass, "User: 3 GPO(s) applied (run as Administrator for Computer scope)") { NeedsAdmin = true },
                new("Denied GPOs", Status.Pass, "User: 1 GPO(s) filtered out (informational) (run as Administrator for Computer scope)") { NeedsAdmin = true },
            ]),
            new("Trust Relationships",
            [
                new("Domain Trusts", Status.Pass, "1 trust(s): FABRIKAM fabrikam.com (NT 5) (Direct Outbound) (Direct Inbound) ( Attr: foresttrans )"),
            ]),
            new("Kerberos & Time Sync",
            [
                new("TGT Present", Status.Pass, "krbtgt/CONTOSO.COM cached"),
                clockWarn
                    ? new("Clock Skew", Status.Warn, $"74.31s drift from {dc}")
                    : new("Clock Skew", Status.Pass, $"0.04s drift from {dc}"),
                new("Time Source", Status.Pass, dc),
                new("krbtgt Key", Status.Pass, $"krbtgt key last set {now.AddDays(-96):d} (96d ago)"),
            ]),
            new("Dynamic DNS Registration",
            [
                new("Registration Name", Status.Pass, "PC042.contoso.com"),
                new("ZTNA / VPN Client", Status.Pass, "No ZTNA or VPN adapter detected"),
                new("Registering Adapters", Status.Pass, "Ethernet: 10.20.4.18"),
                new("Zone Primary Server", Status.Pass, $"contoso.com -> dc01.contoso.com ({ip}), answered by {ip} (DNS server of Ethernet)"),
                new("Update Path (Port 53)", Status.Pass, $"dc01.contoso.com ({ip}) reachable over TCP"),
                new("Registered Record", Status.Pass, "dc01.contoso.com holds 10.20.4.18"),
                new("Registration Errors", Status.Pass, "No DNS Client registration errors in the last 24 hours"),
            ]),
            // A hybrid joined PC without a PRT, so it signs in through Seamless SSO, whose address Group Policy never
            // put in the intranet zone
            new(Diagnostics.EntraSsoGroup,
            [
                new("Join Type", Status.Pass, "Microsoft Entra hybrid joined (DomainJoined: YES, AzureAdJoined: YES), tenant Contoso"),
                new("Device Auth", Status.Pass, "DeviceAuthStatus: SUCCESS"),
                new("Primary Refresh Token", Status.Warn, "AzureAdPrt: NO; browsers fall back to Seamless SSO"),
                new("Seamless SSO Ticket", Status.Pass, "HTTP/autologon.microsoftazuread-sso.com obtained from CONTOSO.COM"),
                new("Intranet Zone", Status.Fail, "https://autologon.microsoftazuread-sso.com is in the Internet zone, not Local intranet: browsers and apps that follow the Windows zones won't send it a Kerberos ticket, so Seamless SSO can't sign them in"),
                new("Automatic Logon", Status.Skip, "Depends on the Intranet Zone check"),
                new("Status Bar Scripts", Status.Skip, "Depends on the Intranet Zone check"),
                new("Seamless SSO Key", Status.Warn, $"AZUREADSSOACC$ key last set {now.AddDays(-212):d} (212d ago); roll it over at least every 30 days (Update-AzureADSSOForest)"),
                new("Entra Endpoints", Status.Pass, "login.microsoftonline.com and autologon.microsoftazuread-sso.com reachable on port 443"),
            ], new Readiness(Status.Fail, "Not ready for Seamless SSO.", true)),
            new(Diagnostics.CredentialsGroup,
            [
                new("Windows Hello", Status.Pass, "Set up for this user (NgcSet: YES)"),
                new("Hello Trust", Status.Pass, "Cloud Kerberos trust, set by Group Policy"),
                new("Sign-in Methods", Status.Pass, "PIN, fingerprint"),
                new("TPM", Status.Pass, "TPM 2.0; the device key is protected by it (TpmProtected: YES)"),
                new("Ticket Encryption", Status.Warn, "RC4 on MSSQLSvc/sql01.contoso.com:1433; set the accounts to AES (msDS-SupportedEncryptionTypes)"),
                new("Saved Credentials", Status.Pass, "No saved Windows credentials for servers"),
            ]),
            new(Diagnostics.IntuneGroup,
            [
                new("MDM Enrollment", Status.Pass, "Enrolled in Microsoft Intune as jdoe@contoso.com"),
                new("Last Sync", Status.Pass, $"Last successful sync {now.AddMinutes(-28):g} (28m ago)"),
                new("Management Extension", Status.Pass, "Intune Management Extension service running"),
                new("Device Policies", Status.Pass, "38 settings from Microsoft Intune in 9 areas (BitLocker, Defender, DeviceLock, ...)"),
            ]),
        ];
    }

    // An Entra joined laptop: only the sections that apply to it
    static List<TestGroup> MockEntraResults(DateTime now) =>
    [
        new("Dynamic DNS Registration",
        [
            new("Registration Name", Status.Pass, "LT-0417"),
            new("ZTNA / VPN Client", Status.Info, "Zscaler Client Connector adapter detected (Zscaler Network Adapter 1.0.2.0)"),
            new("Registering Adapters", Status.Pass, "Wi-Fi: 192.168.1.44"),
            new("Zone Primary Server", Status.Pass, "home.arpa -> router.home.arpa (192.168.1.1), answered by 192.168.1.1 (DNS server of Wi-Fi)"),
            new("Update Path (Port 53)", Status.Pass, "router.home.arpa (192.168.1.1) reachable over TCP"),
            new("Registered Record", Status.Warn, "router.home.arpa has no A or AAAA record for LT-0417.home.arpa"),
            new("Registration Errors", Status.Pass, "No DNS Client registration errors in the last 24 hours"),
        ]),
        new(Diagnostics.EntraSsoGroup,
        [
            new("Join Type", Status.Pass, "Microsoft Entra joined (AzureAdJoined: YES, DomainJoined: NO), tenant Contoso"),
            new("Device Auth", Status.Pass, "DeviceAuthStatus: SUCCESS"),
            new("Primary Refresh Token", Status.Pass, $"AzureAdPrt: YES, renewed {now.AddHours(-3):g} (3h 0m ago)"),
            new("Cloud Kerberos", Status.Pass, "CloudTgt: YES, a Microsoft Entra Kerberos ticket for Azure Files and other cloud resources"),
            new("On-premises Kerberos", Status.Pass, "OnPremTgt: YES, a ticket for AD resources through cloud Kerberos trust"),
            new("Cloud Trust Groups", Status.Pass, "No group membership blocks cloud Kerberos trust for this account"),
            new("Cloud Kerberos Key", Status.Pass, $"krbtgt_AzureAD key last set {now.AddDays(-41):d} (41d ago)"),
            new("Entra Endpoints", Status.Pass, "login.microsoftonline.com reachable on port 443"),
        ], new Readiness(Status.Pass, "Ready for single sign-on.", false)),
        new(Diagnostics.CredentialsGroup,
        [
            new("Windows Hello", Status.Pass, "Set up for this user (NgcSet: YES)"),
            new("Hello Trust", Status.Pass, "Cloud Kerberos trust, set by Intune"),
            new("Sign-in Methods", Status.Pass, "PIN, face"),
            new("TPM", Status.Pass, "TPM 2.0; the device key is protected by it (TpmProtected: YES)"),
            new("Ticket Encryption", Status.Pass, "All 3 cached tickets use AES"),
            new("Saved Credentials", Status.Warn, "1 saved Windows credential (fs01.contoso.com); a saved password replaces single sign-on there and locks the account out once it goes stale"),
        ]),
        new(Diagnostics.IntuneGroup,
        [
            new("MDM Enrollment", Status.Pass, "Enrolled in Microsoft Intune as jdoe@contoso.com"),
            new("Last Sync", Status.Pass, $"Last successful sync {now.AddMinutes(-28):g} (28m ago)"),
            new("Management Extension", Status.Info, "Not installed; Intune adds it with the first Win32 app, script or remediation"),
            new("Device Policies", Status.Pass, "6 settings from Microsoft Intune in 3 areas (BitLocker, Defender, Update); 1 set by another provider instead"),
        ]),
    ];

    // What the Intune policies tab shows for the same laptop
    static IntuneState MockIntune(DateTime nowUtc)
    {
        var enrollment = new MdmEnrollment("5A1B2C3D-0000-4000-8000-000000000042", "MS DM Server", 1, "jdoe@contoso.com");
        List<MdmSetting> device =
        [
            new("BitLocker", "RequireDeviceEncryption", "1", true, null),
            new("BitLocker", "EncryptionMethodByDriveType", "<enabled/><data id=\"EncryptionMethodWithXtsOsDropDown_Name\" value=\"7\"/>", true, null),
            new("Defender", "AllowRealtimeMonitoring", "1", true, null),
            new("Defender", "AllowCloudProtection", "1", true, null),
            new("Defender", "CloudBlockLevel", "2", false, "{0F2A9B11-0000-4000-8000-0000000000AA}"),
            new("Update", "ActiveHoursStart", "8", true, null),
            new("Update", "DeferQualityUpdatesPeriodInDays", "3", true, null),
        ];
        List<MdmSetting> user =
        [
            new("Edge", "HomepageLocation", "https://intranet.contoso.com", true, null),
            new("OneDrive", "KFMSilentOptIn", "72f988bf-0000-4000-8000-000000000001", true, null),
        ];
        var apps = new List<MdmApp>
        {
            new("DDF6D6BF-887E-4EB3-A89D-2C153BAF3256", "Microsoft Intune Management Extension", "1.105.103.0", 70, 0, false),
            new("6A7DFC50-0395-4E1E-BF84-ED1404E72051", "Contoso VPN Client", "4.2.1.0", 70, 0, false),
            new("7ECACCD0-8601-4884-8860-7A4ADF4ED814", "ContosoTimesheet.msi", "2.0.0.0", 60, unchecked((int)0x80070643), true),
        };
        return new(enrollment, nowUtc.AddMinutes(-28), null, null, null, null, device, user, null, apps, null);
    }

    static string MockRsop()
    {
        var now = DateTime.UtcNow;
        string comp = now.AddHours(-1).AddMinutes(-12).ToString("o");
        string user = now.AddMinutes(-38).ToString("o");
        const string dn = "cn={0},cn=policies,cn=system,DC=contoso,DC=com";
        string G(string scope, string id, int order, string flags, string name) =>
            $"GPO|{scope}|{string.Format(dn, id)}|{order}|{flags}|{name}";
        return string.Join("\n",
        [
            $"SCOPE|Computer|OK|{comp}|HQ-Seattle",
            G("Computer", "{31B2F340-016D-11D2-945F-00C04FB984F9}", 1, "1|1|0|1", "Default Domain Policy"),
            G("Computer", "{7F3A1C22-0001-4B7E-9C1D-2F6B8E4A1001}", 2, "1|1|0|1", "Workstation Security Baseline"),
            G("Computer", "{7F3A1C22-0002-4B7E-9C1D-2F6B8E4A1002}", 3, "1|1|0|1", "BitLocker Configuration"),
            G("Computer", "{7F3A1C22-0003-4B7E-9C1D-2F6B8E4A1003}", 4, "1|1|0|1", "Windows Update - Ring 2"),
            G("Computer", "{7F3A1C22-0004-4B7E-9C1D-2F6B8E4A1004}", 5, "1|1|0|1", "Defender Firewall Rules"),
            G("Computer", "{7F3A1C22-0005-4B7E-9C1D-2F6B8E4A1005}", 0, "1|1|1|1", "Server Hardening"),
            G("Computer", "{7F3A1C22-0006-4B7E-9C1D-2F6B8E4A1006}", 0, "1|1|0|0", "Laptop Power Settings"),
            $"SCOPE|User|OK|{user}|HQ-Seattle",
            G("User", "{8A4B2D33-0001-4C8F-8D2E-3A7C9F5B2001}", 1, "1|1|0|1", "Drive Mappings - Finance"),
            G("User", "{8A4B2D33-0002-4C8F-8D2E-3A7C9F5B2002}", 2, "1|1|0|1", "Office Settings"),
            G("User", "{8A4B2D33-0003-4C8F-8D2E-3A7C9F5B2003}", 3, "1|1|0|1", "Desktop Wallpaper"),
            G("User", "{8A4B2D33-0004-4C8F-8D2E-3A7C9F5B2004}", 0, "0|1|0|1", "Legacy Printer Deployment"),
        ]);
    }

    // A hybrid joined PC whose Primary Refresh Token was renewed an hour ago
    static string MockDsreg()
    {
        string Utc(TimeSpan offset) => (DateTime.UtcNow + offset).ToString("yyyy-MM-dd HH:mm:ss.000 'UTC'", CultureInfo.InvariantCulture);
        return $"""
                     AzureAdJoined : YES
                      DomainJoined : YES
                        TenantName : Contoso
                        AzureAdPrt : YES
              AzureAdPrtUpdateTime : {Utc(TimeSpan.FromHours(-1))}
              AzureAdPrtExpiryTime : {Utc(TimeSpan.FromDays(14) - TimeSpan.FromHours(1))}
               AzureAdPrtAuthority : https://login.microsoftonline.com/72f988bf-0000-4000-8000-000000000001
                         OnPremTgt : NO
                          CloudTgt : NO
            """;
    }

    static string MockKlist()
    {
        var logon = DateTime.Now.AddHours(-2).AddMinutes(-14);
        string T(DateTime d) => d.ToString("M/d/yyyy H:mm:ss", CultureInfo.InvariantCulture) + " (local)";
        string end = T(logon.AddHours(10)), renew = T(logon.AddDays(7));
        string Ticket(int i, string server, string enc, string flags, DateTime start, string cache) => $"""
            #{i}>	Client: jdoe @ CONTOSO.COM
            	Server: {server} @ CONTOSO.COM
            	KerbTicket Encryption Type: {enc}
            	Ticket Flags {flags}
            	Start Time: {T(start)}
            	End Time:   {end}
            	Renew Time: {renew}
            	Session Key Type: {enc}
            	Cache Flags: {cache}
            	Kdc Called: DC01.contoso.com

            """;
        const string aes = "AES-256-CTS-HMAC-SHA1-96";
        return "\nCurrent LogonId is 0:0x5a3c1e\n\nCached Tickets: (5)\n\n"
            + Ticket(0, "krbtgt/CONTOSO.COM", aes, "0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize", logon, "0x1 -> PRIMARY")
            + Ticket(1, "cifs/FS01.contoso.com", aes, "0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize", logon.AddMinutes(1), "0")
            + Ticket(2, "MSSQLSvc/SQL01.contoso.com:1433", "RSADSI RC4-HMAC(NT)", "0x40a10000 -> forwardable renewable pre_authent name_canonicalize", logon.AddMinutes(63), "0")
            + Ticket(3, "HTTP/intranet.contoso.com", aes, "0x40a10000 -> forwardable renewable pre_authent name_canonicalize", logon.AddMinutes(47), "0")
            + Ticket(4, "ldap/DC01.contoso.com/contoso.com", aes, "0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize", logon.AddMinutes(1), "0");
    }
}
