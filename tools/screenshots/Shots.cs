using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
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
        Pump(800);
        Populate(form);
        form.Height = 1420;
        Pump(800);
        Capture(form, outDir, "results.png");
        form.Height = 900;
        Pump(500);

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
        Set(form, "_dnsHeading", "Registering this computer in DNS, " + DateTime.Now.AddSeconds(-40).ToString("HH:mm:ss"));
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
        Call(form, "RenderLog");
        Pump(500);
        Capture(form, outDir, "log.png");
    }

    // A laptop at home behind a ZTNA client, whose record in DNS still holds its office address
    static List<TestEntry> MockDnsTrace() =>
    [
        new("Registration Name", Status.Pass, "PC042.contoso.com with 192.168.1.50"),
        new("ZTNA / VPN Client", Status.Pass, "Zscaler adapter (100.64.0.7); DNS answered by its local proxy (100.64.0.2) (informational)"),
        new("Zone Primary Server", Status.Pass, "contoso.com -> dc01.contoso.com (10.20.0.11)"),
        new("Record Before", Status.Warn, "dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale"),
        new("Send", Status.Pass, "ipconfig /registerdns ran: Windows IP Configuration Registration of the DNS resource records for all adapters of this computer has been initiated. Any errors will be reported in the Event Viewer in 15 minutes."),
        new("Wait", Status.Skip, "Watching the server and the DNS Client event log for up to 30s"),
        new("DNS Client Event", Status.Fail, $"event 8015 at {DateTime.Now.AddSeconds(-31):g} — The system failed to register host (A or AAAA) resource records (RRs) for network adapter with settings: Adapter Name : {{3F2A9B10-55C1-4E0B-9D7A-0C1E5A1B7F42}} Host Name : PC042 Primary Domain Suffix : contoso.com DNS server list : 100.64.0.2 Sent update to server : 10.20.0.11 IP Address(es) : 192.168.1.50 The reason the system could not register these RRs was because the update request it sent to the DNS server timed out."),
        new("Record After", Status.Warn, "dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale — Windows logged a registration failure (above)"),
        new("ZTNA / VPN Client", Status.Warn, "Through a ZTNA or VPN client a secure update needs Kerberos (port 88 to a domain controller) and TCP and UDP 53 to dc01.contoso.com to pass the tunnel as real traffic, not through the client's DNS proxy"),
    ];

    static void MockLog(DiagLog log)
    {
        log.Info("log", "Debug logging on: commands, timings and raw tool output are recorded");
        log.Info("run", "Started: domain contoso.com, DC DC01.contoso.com");
        log.Debug("machine", "Host name and primary DNS suffix (0 ms)\nPC042, suffix \"contoso.com\"");
        log.Debug("machine", "Network adapters (3 ms)\nWi-Fi [Intel(R) Wi-Fi 6 AX201 160MHz]: addresses 192.168.1.50; DNS servers 100.64.0.2; registers in DNS: yes\n"
            + "Ethernet 3 [Zscaler Network Adapter 1.0.2.0]: addresses 100.64.0.7; DNS servers 100.64.0.2; registers in DNS: no");
        log.Debug("dns", "SOA PC042.contoso.com (41 ms)\nno record");
        log.Debug("dns", "SOA contoso.com (62 ms)\nzone contoso.com, primary server dc01.contoso.com");
        log.Debug("tool", "nltest /dsgetdc:contoso.com (1270 ms)\n           DC: \\\\DC01.contoso.com\n      Address: \\\\10.20.0.11\n     Dom Guid: 6f1c2a54-9b1e-4a37-8f0d-2c5e7a903b11\n     Dom Name: contoso.com\n  Forest Name: contoso.com\n Dc Site Name: HQ-Seattle\nThe command completed successfully");
        log.Debug("tcp", "Connect 10.20.0.11 port 53: open (38 ms)");
        log.Debug("tcp", "Connect 10.20.0.11 port 636: no answer (3001 ms)");
        log.Debug("dns", "A/AAAA PC042.contoso.com from 10.20.0.11 (57 ms)\n10.20.4.18");
        log.Info("tool", "w32tm /stripchart /computer:DC01.contoso.com /samples:1 /dataonly failed after 5012 ms: w32tm timed out after 5s (TimeoutException)");
        log.Info("result", "Warning  DC Discovery & Connectivity / Port 636 (LDAPS): Unreachable at DC01.contoso.com (10.20.0.11)");
        log.Info("result", "Passed   Dynamic DNS Registration / Zone Primary Server: contoso.com -> dc01.contoso.com (10.20.0.11)");
        log.Info("result", "Warning  Dynamic DNS Registration / Registered Record: dc01.contoso.com holds 10.20.4.18; this machine has 192.168.1.50 — the record is stale");
        log.Info("run", "Complete: 32 passed, 0 failed, 3 warnings");
    }

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
        Get<TextBox>(form, "_txtDomain").Text = "contoso.com";
        Get<TextBox>(form, "_txtDc").Text = "DC01";

        var history = Get<List<DiagRun>>(form, "_runHistory");
        var now = DateTime.Now;
        history.Insert(0, new DiagRun(now.AddMinutes(-42), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: true)));
        history.Insert(0, new DiagRun(now.AddMinutes(-17), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: true)));
        history.Insert(0, new DiagRun(now.AddSeconds(-20), "contoso.com", "DC01.contoso.com", MockResults(now, clockWarn: false)));
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
                new("Port 636 (LDAPS)", Status.Warn, $"Unreachable at {dc} ({ip})"),
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
                new("GP Last Refresh", Status.Pass, $"Computer: {gpTime} (1h 12m ago)"),
                new("Applied GPOs", Status.Pass, "Computer: 5 GPO(s) applied"),
                new("Denied GPOs", Status.Pass, "Computer: 2 GPO(s) filtered out (informational)"),
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
            ]),
            new("Dynamic DNS Registration",
            [
                new("Registration Name", Status.Pass, "PC042.contoso.com"),
                new("ZTNA / VPN Client", Status.Pass, "No ZTNA or VPN tunnel adapter detected"),
                new("Registering Adapters", Status.Pass, "Ethernet: 10.20.4.18"),
                new("Zone Primary Server", Status.Pass, $"contoso.com -> dc01.contoso.com ({ip})"),
                new("Update Path (Port 53)", Status.Pass, $"dc01.contoso.com ({ip}) reachable over TCP"),
                new("Registered Record", Status.Pass, "dc01.contoso.com holds 10.20.4.18"),
                new("Registration Errors", Status.Pass, "No DNS Client registration errors in the last 24 hours"),
            ]),
        ];
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
