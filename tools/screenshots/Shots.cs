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
    static Color Theme(string name) => (Color)typeof(MainForm).GetField(name, BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;

    [STAThread]
    static void Main(string[] args)
    {
        string outDir = args.Length > 0 ? args[0] : ".";
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.CurrentCulture = new CultureInfo("en-US");
        Environment.SetEnvironmentVariable("USERDNSDOMAIN", "CONTOSO.COM");
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
        form.Height = 1275;
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
