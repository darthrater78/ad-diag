using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

#nullable enable
namespace AdDiag;

// Single sign-on readiness: whether this PC, as it is set up now, can sign its user in to Microsoft Entra ID without
// a password. It checks only this PC (how it is joined, its tokens, the browser settings Seamless SSO needs, and a
// direct connection to the sign-in endpoints); whether Seamless SSO is turned on in the tenant isn't visible from here.
//
// Entra joined and hybrid joined PCs sign in with their Primary Refresh Token (PRT), which Edge, Chrome and Office
// use on Windows. Seamless SSO, where the browser gets a Kerberos ticket for the AZUREADSSOACC account's SPN from a
// domain controller and hands it to Entra ID, is how domain-joined PCs sign in, and on a hybrid joined PC only the
// fallback for browsers and apps that can't use the PRT, or for when it is missing. Entra joined PCs reach AD
// resources with the Kerberos ticket Entra ID issues through cloud Kerberos trust (OnPremTgt). So the join type and
// the PRT decide which checks run and what they weigh. The fixes are in the Guide tab.
static partial class Diagnostics
{
    public const string EntraSsoGroup = "Entra Seamless Single Sign-On";
    public const string SsoJoin = "Join Type", SsoDeviceAuth = "Device Auth", SsoPrt = "Primary Refresh Token",
        SsoTicket = "Seamless SSO Ticket", SsoZone = "Intranet Zone", SsoLogon = "Automatic Logon",
        SsoStatusBar = "Status Bar Scripts", SsoCloudTgt = "Cloud Kerberos", SsoOnPremTgt = "On-premises Kerberos",
        SsoEndpoints = "Entra Endpoints";

    public const string SsoSpn = "HTTP/autologon.microsoftazuread-sso.com";
    public const string SsoUrl = "https://autologon.microsoftazuread-sso.com";
    const string LoginHost = "login.microsoftonline.com", AutologonHost = "autologon.microsoftazuread-sso.com";

    // A Primary Refresh Token is valid for 14 days. Windows renews it when the user signs in or unlocks, or an app asks
    // for a token, so one a day or two old on an idle PC is normal; one older than its lifetime has expired
    static readonly TimeSpan PrtLifetime = TimeSpan.FromDays(14);

    // Seamless SSO's own checks: on a hybrid joined PC with a PRT these cover only the fallback
    static readonly HashSet<string> SeamlessChecks = [SsoTicket, SsoZone, SsoLogon, SsoStatusBar];

    // URL security policy values (urlmon.h)
    const int LogonSilent = 0x00000, LogonPrompt = 0x10000, LogonIntranetOnly = 0x20000, LogonAnonymous = 0x30000;
    const int IntranetZone = 1;

    static readonly string[] ZoneNames = ["Local machine", "Local intranet", "Trusted sites", "Internet", "Restricted sites"];
    static string ZoneName(int zone) => zone >= 0 && zone < ZoneNames.Length ? ZoneNames[zone] : $"custom ({zone})";

    enum JoinKind { None, DomainOnly, Hybrid, EntraOnly }

    public static TestGroup TestEntraSso(DiagConfig cfg, IProbe probe) => TestEntraSso(cfg, probe, DateTime.UtcNow);

    internal static TestGroup TestEntraSso(DiagConfig cfg, IProbe probe, DateTime nowUtc)
    {
        var tests = new List<TestEntry>();

        Dictionary<string, string> ds;
        try
        {
            ds = Parsers.ParseDsreg(probe.RunTool("dsregcmd", "/status", 15000, cfg.Cancel));
        }
        catch (Exception ex)
        {
            tests.Add(new(SsoJoin, Status.Skip, $"Not checked: dsregcmd failed: {ex.Message}"));
            return new(EntraSsoGroup, tests, new(Status.Skip, "Readiness unknown: dsregcmd did not answer.", true));
        }

        var (kind, join) = ProfileJoin(cfg, ds);
        tests.Add(join);
        if (kind == null)
            return new(EntraSsoGroup, tests, new(Status.Skip, "Readiness unknown: dsregcmd reported no join state.", true));
        if (kind == JoinKind.None)
            return new(EntraSsoGroup, tests, new(Status.Fail, "Not ready: this PC is not joined to Microsoft Entra ID or a domain.", true));

        bool seamless = kind is JoinKind.Hybrid or JoinKind.DomainOnly;
        var prt = PrtCheck(ds, kind.Value, nowUtc);
        bool fallbackOnly = kind == JoinKind.Hybrid && prt.Status == Status.Pass;
        tests.AddRange(SignInChecks(cfg, probe, ds, kind.Value, prt, fallbackOnly, nowUtc));
        tests.Add(EndpointsCheck(cfg, probe, seamless ? [LoginHost, AutologonHost] : [LoginHost]));
        // One order for every profile, so switching profile only adds or removes rows
        tests = [.. tests.OrderBy(t => Array.IndexOf(SsoRowOrder, t.Name) is var i and >= 0 ? i : int.MaxValue)];
        return new(EntraSsoGroup, tests, SsoReadiness(tests, seamless, fallbackOnly));
    }

    /// <summary>Every row the group can show, in the one order all profiles keep; each profile leaves some out.</summary>
    internal static readonly string[] SsoRowOrder =
    [
        SsoJoin, SsoDeviceAuth, SsoPrt, SsoTicket, SsoZone, SsoLogon, SsoStatusBar, SeamlessKeyCheck,
        SsoCloudTgt, SsoOnPremTgt, CloudTrustGroupsCheck, CloudKerberosKeyCheck, SsoEndpoints,
    ];

    /// <summary>
    /// The rows a profile's run shows, in <see cref="SsoRowOrder"/>, for Results to list before a run. The Cloud Kerberos
    /// key shows on a hybrid joined PC only when it uses cloud Kerberos trust, so its list leaves it out.
    /// </summary>
    public static IEnumerable<string> SsoRows(JoinProfile profile) => SsoRowOrder.Where(row => profile switch
    {
        JoinProfile.Domain => row is not (SsoDeviceAuth or SsoPrt or SsoCloudTgt or SsoOnPremTgt or CloudTrustGroupsCheck or CloudKerberosKeyCheck),
        JoinProfile.Hybrid => row is not (SsoCloudTgt or SsoOnPremTgt or CloudTrustGroupsCheck or CloudKerberosKeyCheck),
        _ => row is not (SsoTicket or SsoZone or SsoLogon or SsoStatusBar or SeamlessKeyCheck),
    });

    /// <summary>
    /// How the PC is joined, as the Join Type row reports it, and the join type the checks follow: the picked profile's
    /// when there is one, so another profile's checks can be seen on this PC. The row says when they differ.
    /// </summary>
    static (JoinKind? Kind, TestEntry Entry) ProfileJoin(DiagConfig cfg, Dictionary<string, string> ds)
    {
        var (detected, entry) = JoinCheck(ds);
        if (cfg.Profile is not { } profile || detected is null or JoinKind.None) return (detected, entry);
        var (kind, name) = profile switch
        {
            JoinProfile.Domain => (JoinKind.DomainOnly, "Domain joined"),
            JoinProfile.Hybrid => (JoinKind.Hybrid, "Microsoft Entra hybrid joined"),
            _ => (JoinKind.EntraOnly, "Microsoft Entra joined"),
        };
        return kind == detected ? (kind, entry)
            : (kind, entry with { Status = Status.Info, Detail = $"{entry.Detail}; checked as {name}, the profile picked" });
    }

    // The checks for how this PC signs in. One that doesn't apply to how it is joined isn't shown at all: a
    // domain-joined PC has no device authentication or PRT, an Entra joined one no Seamless SSO
    static IEnumerable<TestEntry> SignInChecks(DiagConfig cfg, IProbe probe, Dictionary<string, string> ds, JoinKind kind,
        TestEntry prt, bool fallbackOnly, DateTime nowUtc)
    {
        if (kind != JoinKind.DomainOnly)
        {
            yield return DeviceAuthCheck(ds, kind);
            yield return prt;
        }
        var keys = SsoKeyChecks(cfg, probe, ds, kind, nowUtc);
        if (kind == JoinKind.EntraOnly)
        {
            foreach (var test in EntraKerberosChecks(ds)) yield return test;
            yield return CloudTrustGroupsEntry(cfg, probe);
            foreach (var test in keys) yield return test;
            yield break;
        }
        var sso = new List<TestEntry> { SeamlessTicketCheck(cfg, probe) };
        sso.AddRange(BrowserZoneChecks(cfg, probe));
        sso.AddRange(keys.Where(k => k.Name == SeamlessKeyCheck));
        foreach (var test in fallbackOnly ? sso.Select(AsFallback) : sso) yield return test;
        foreach (var test in keys.Where(k => k.Name != SeamlessKeyCheck)) yield return test;
    }

    // The keys this PC's sign-in depends on, read in one query: Seamless SSO's where it is used, and cloud Kerberos
    // trust's where the PC gets on-premises tickets through it
    static List<TestEntry> SsoKeyChecks(DiagConfig cfg, IProbe probe, Dictionary<string, string> ds, JoinKind kind, DateTime nowUtc)
    {
        var keys = new List<(string, string, TimeSpan, string)>();
        if (kind != JoinKind.EntraOnly) keys.Add(SeamlessKey);
        if (Parsers.DsregFlag(ds, "OnPremTgt") == true) keys.Add(CloudKerberosKey);
        return keys.Count == 0 ? [] : KeyAgeChecks(probe, cfg.Domain, nowUtc, keys, cfg.Cancel);
    }

    // A Seamless SSO problem on a PC that signs in with its PRT touches only the fallback, so it is a note
    static TestEntry AsFallback(TestEntry test) => test.Status is Status.Fail or Status.Warn
        ? test with { Status = Status.Info, Detail = test.Detail + "; this PC signs in with its Primary Refresh Token, so it matters only where the token can't be used" }
        : test;

    // How the PC is joined, which decides what else is checked; null when dsregcmd reported no join state
    static (JoinKind? Kind, TestEntry Entry) JoinCheck(Dictionary<string, string> ds)
    {
        bool? entra = Parsers.DsregFlag(ds, "AzureAdJoined"), domain = Parsers.DsregFlag(ds, "DomainJoined");
        if (entra == null && domain == null)
            return (null, new(SsoJoin, Status.Skip, "Not checked: dsregcmd reported no join state"));

        string tenant = ds.TryGetValue("TenantName", out var t) && t.Length > 0 ? $", tenant {t}" : "";
        return (entra == true, domain == true) switch
        {
            (true, true) => (JoinKind.Hybrid, new(SsoJoin, Status.Pass, $"Microsoft Entra hybrid joined (DomainJoined: YES, AzureAdJoined: YES){tenant}")),
            (true, false) => (JoinKind.EntraOnly, new(SsoJoin, Status.Pass, $"Microsoft Entra joined (AzureAdJoined: YES, DomainJoined: NO){tenant}")),
            (false, true) => (JoinKind.DomainOnly, new(SsoJoin, Status.Pass, "Domain joined, not Microsoft Entra hybrid joined (AzureAdJoined: NO); Seamless SSO still applies")),
            _ => (JoinKind.None, new(SsoJoin, Status.Fail, "Not joined to Microsoft Entra ID or a domain (AzureAdJoined: NO, DomainJoined: NO)")),
        };
    }

    static TestEntry DeviceAuthCheck(Dictionary<string, string> ds, JoinKind kind)
    {
        if (kind == JoinKind.DomainOnly)
            return new(SsoDeviceAuth, Status.Skip, "Not Microsoft Entra joined");
        if (!ds.TryGetValue("DeviceAuthStatus", out var auth) || auth.Length == 0)
            return new(SsoDeviceAuth, Status.Skip, "DeviceAuthStatus not reported by this version of Windows");
        return auth.StartsWith("SUCCESS", StringComparison.OrdinalIgnoreCase)
            ? new(SsoDeviceAuth, Status.Pass, "DeviceAuthStatus: SUCCESS")
            : new(SsoDeviceAuth, Status.Fail, $"DeviceAuthStatus: {auth}");
    }

    static TestEntry PrtCheck(Dictionary<string, string> ds, JoinKind kind, DateTime nowUtc)
    {
        if (kind == JoinKind.DomainOnly)
            return new(SsoPrt, Status.Skip, "Not Microsoft Entra joined; sign-in uses Seamless SSO");

        // On a hybrid joined PC Seamless SSO covers for a missing token; on an Entra joined one nothing does
        var missing = kind == JoinKind.Hybrid ? Status.Warn : Status.Fail;
        string fallback = kind == JoinKind.Hybrid ? "; browsers fall back to Seamless SSO" : "; there is no single sign-on without it";
        switch (Parsers.DsregFlag(ds, "AzureAdPrt"))
        {
            case null:
                return new(SsoPrt, missing, "dsregcmd showed no Primary Refresh Token state for this user" + fallback);
            case false:
                return new(SsoPrt, missing, "AzureAdPrt: NO" + fallback);
        }
        if (Parsers.DsregTime(ds, "AzureAdPrtUpdateTime") is not { } updated)
            return new(SsoPrt, Status.Pass, "AzureAdPrt: YES");

        var age = Age(updated, nowUtc);
        string when = $"renewed {updated.ToLocalTime():g} ({FormatTimeSpan(age)} ago)";
        return age <= PrtLifetime
            ? new(SsoPrt, Status.Pass, $"AzureAdPrt: YES, {when}")
            : new(SsoPrt, missing, $"AzureAdPrt: YES, but {when}; it has expired, since a token is valid for 14 days" + fallback);
    }

    /// <summary>
    /// The profile that fits how this PC is joined, from <c>dsregcmd /status</c>. A PC joined to neither gets the
    /// domain profile, which checks everything a domain needs and so shows what is missing.
    /// </summary>
    internal static JoinProfile DetectProfile(Dictionary<string, string> ds) => JoinCheck(ds).Kind switch
    {
        JoinKind.Hybrid => JoinProfile.Hybrid,
        JoinKind.EntraOnly => JoinProfile.Entra,
        _ => JoinProfile.Domain,
    };

    /// <summary>
    /// The Primary Refresh Token card at the top of the Kerberos tickets tab, from <c>dsregcmd /status</c>; null when
    /// the PC is not Entra or hybrid joined, so it has no PRT. The badge takes the Results row's status, so the two agree.
    /// </summary>
    internal static PrtCard? PrtCardFor(Dictionary<string, string> ds, DateTime nowUtc)
    {
        var (kind, _) = JoinCheck(ds);
        if (kind is not (JoinKind.Hybrid or JoinKind.EntraOnly)) return null;

        var prt = PrtCheck(ds, kind.Value, nowUtc);
        bool? has = Parsers.DsregFlag(ds, "AzureAdPrt");
        bool hybrid = kind == JoinKind.Hybrid;
        string badge = prt.Status == Status.Pass ? "PRT" : has == true ? "PRT EXPIRED" : "NO PRT";
        string caption = prt.Status == Status.Pass ? "Primary Refresh Token — Entra ID sign-in"
            : hybrid ? "Primary Refresh Token — browsers fall back to Seamless SSO"
            : "Primary Refresh Token — no single sign-on without it";

        var rows = new List<PrtCardRow>
        {
            new("Join", hybrid ? "Microsoft Entra hybrid joined" : "Microsoft Entra joined"),
        };
        if (ds.TryGetValue("TenantName", out var tenant) && tenant.Length > 0)
            rows.Add(new("Tenant", tenant));
        rows.Add(new("Status", has switch { true => "YES", false => "NO", null => "not reported" }, prt.Status));

        rows.AddRange(PrtTokenRows(ds, hybrid, nowUtc));
        return new(badge, prt.Status, caption, rows);
    }

    // The token's times and authority, then its Kerberos ticket flags. An Entra joined PC needs both flags for
    // Kerberos resources, so they take the Results colours; a hybrid joined PC gets its tickets from a domain
    // controller, so there they are plain facts
    static IEnumerable<PrtCardRow> PrtTokenRows(Dictionary<string, string> ds, bool hybrid, DateTime nowUtc)
    {
        if (Parsers.DsregTime(ds, "AzureAdPrtUpdateTime") is { } updated)
            yield return new("Renewed", $"{updated.ToLocalTime():g} ({FormatTimeSpan(Age(updated, nowUtc))} ago)");
        if (Parsers.DsregTime(ds, "AzureAdPrtExpiryTime") is { } expires)
            yield return expires < nowUtc
                ? new("Expires", $"{expires.ToLocalTime():g}, expired", hybrid ? Status.Warn : Status.Fail)
                : new("Expires", $"{expires.ToLocalTime():g}");
        if (ds.TryGetValue("AzureAdPrtAuthority", out var authority) && authority.Length > 0)
            yield return new("Authority", authority);

        foreach (var (field, label) in new[] { ("CloudTgt", "Cloud TGT"), ("OnPremTgt", "On-prem TGT") })
        {
            if (Parsers.DsregFlag(ds, field) is not { } flag) continue;
            yield return new(label, flag ? "YES" : "NO", hybrid ? null : flag ? Status.Pass : Status.Warn);
        }
    }

    static TestEntry SeamlessTicketCheck(DiagConfig cfg, IProbe probe)
    {
        try
        {
            string output = probe.RunTool("klist", $"get {SsoSpn}", 10000, cfg.Cancel);
            if (Parsers.TicketRealm(output, SsoSpn) is { } realm)
                return new(SsoTicket, Status.Pass, $"{SsoSpn} obtained from {realm}");
            string error = Parsers.KlistGetError(output) is { } code ? $" (error {code})" : "";
            return new(SsoTicket, Status.Fail,
                $"No ticket for {SsoSpn}{error}: the AZUREADSSOACC account is missing from the user's domain, or no domain controller answered");
        }
        catch (Exception ex)
        {
            return new(SsoTicket, Status.Fail, $"klist failed: {ex.Message}");
        }
    }

    static List<TestEntry> BrowserZoneChecks(DiagConfig cfg, IProbe probe)
    {
        UrlSecurity sec;
        try
        {
            sec = probe.UrlSecurity(SsoUrl, cfg.Cancel);
        }
        catch (Exception ex)
        {
            return [
                new(SsoZone, Status.Skip, $"Not checked: could not read the Internet settings: {ex.Message}"),
                new(SsoLogon, Status.Skip, "Not checked: the Internet settings could not be read"),
                new(SsoStatusBar, Status.Skip, "Not checked: the Internet settings could not be read"),
            ];
        }

        if (sec.Zone != IntranetZone)
            return [
                new(SsoZone, Status.Fail,
                    $"{SsoUrl} is in the {ZoneName(sec.Zone)} zone, not Local intranet: browsers and apps that follow the Windows zones won't send it a Kerberos ticket, so Seamless SSO can't sign them in"),
                new(SsoLogon, Status.Skip, "Depends on the Intranet Zone check"),
                new(SsoStatusBar, Status.Skip, "Depends on the Intranet Zone check"),
            ];

        return [
            new(SsoZone, Status.Pass, $"{SsoUrl} is in the Local intranet zone"),
            sec.Logon switch
            {
                LogonSilent or LogonIntranetOnly => new(SsoLogon, Status.Pass, "Local intranet zone logs on automatically with the current user name and password"),
                LogonPrompt => new(SsoLogon, Status.Fail, "Local intranet zone is set to prompt for a user name and password"),
                LogonAnonymous => new(SsoLogon, Status.Fail, "Local intranet zone is set to anonymous logon"),
                _ => new(SsoLogon, Status.Warn, $"Local intranet zone has an unrecognized logon setting (0x{sec.Logon:x})"),
            },
            sec.StatusBar == 0
                ? new(SsoStatusBar, Status.Pass, "\"Allow updates to status bar via script\" is enabled for the Local intranet zone")
                : new(SsoStatusBar, Status.Info, "\"Allow updates to status bar via script\" is not enabled for the Local intranet zone; only older clients need it"),
        ];
    }

    // An Entra joined PC gets Kerberos tickets from Entra ID instead, for cloud resources and through cloud Kerberos trust for AD
    static List<TestEntry> EntraKerberosChecks(Dictionary<string, string> ds) =>
    [
        TgtFlagCheck(ds, "CloudTgt", SsoCloudTgt,
            "a Microsoft Entra Kerberos ticket for Azure Files and other cloud resources",
            "no Microsoft Entra Kerberos ticket, so Azure Files and other cloud Kerberos resources ask for a password"),
        TgtFlagCheck(ds, "OnPremTgt", SsoOnPremTgt,
            "a ticket for AD resources through cloud Kerberos trust",
            "no ticket for AD resources, so file shares, printers and other AD resources ask for a password"),
    ];

    static TestEntry TgtFlagCheck(Dictionary<string, string> ds, string field, string name, string yes, string no) =>
        Parsers.DsregFlag(ds, field) switch
        {
            true => new(name, Status.Pass, $"{field}: YES, {yes}"),
            false => new(name, Status.Warn, $"{field}: NO, {no}"),
            null => new(name, Status.Skip, $"{field} not reported by this version of Windows"),
        };

    // A TCP handshake only: nothing is sent. A proxy may still reach a host this can't, so a miss warns, never fails
    static TestEntry EndpointsCheck(DiagConfig cfg, IProbe probe, string[] hosts)
    {
        var unreachable = new List<string>();
        foreach (string host in hosts)
        {
            try
            {
                var addrs = probe.Resolve(host, cfg.Cancel);
                var ip = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
                if (ip == null)
                    unreachable.Add($"{host} (no address)");
                else if (!probe.TcpConnect(ip, 443, cfg.Cancel).GetAwaiter().GetResult())
                    unreachable.Add($"{host} ({ip})");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                unreachable.Add($"{host} ({ex.Message})");
            }
        }
        return unreachable.Count == 0
            ? new(SsoEndpoints, Status.Pass, $"{string.Join(" and ", hosts)} reachable on port 443")
            : new(SsoEndpoints, Status.Warn,
                $"No direct connection on port 443 to {string.Join(", ", unreachable)}; expected only if a proxy carries this traffic");
    }

    static Readiness SsoReadiness(List<TestEntry> tests, bool seamless, bool fallbackOnly)
    {
        var counted = tests.Where(t => t.Status is not (Status.Skip or Status.Info)).ToList();
        var worst = counted.Any(t => t.Status == Status.Fail) ? Status.Fail
            : counted.Any(t => t.Status == Status.Warn) ? Status.Warn : Status.Pass;

        if (fallbackOnly)
        {
            bool fallbackNotReady = tests.Any(t => t.Status == Status.Info && SeamlessChecks.Contains(t.Name));
            return worst switch
            {
                Status.Fail => new(worst, "Not ready for single sign-on.", true),
                Status.Warn => new(worst, "Ready for single sign-on, with warnings.", true),
                _ when fallbackNotReady =>
                    new(worst, "Ready for single sign-on through the Primary Refresh Token; the Seamless SSO fallback is not set up.", true),
                _ => new(worst, "Ready for single sign-on.", false),
            };
        }

        if (seamless)
            return worst switch
            {
                Status.Fail => new(worst, "Not ready for Seamless SSO.", true),
                Status.Warn => new(worst, "Ready for Seamless SSO, with warnings.", true),
                _ => new(worst, "Ready for Seamless SSO.", false),
            };

        // Only on-premises access is missing: no on-premises ticket, or a group that keeps cloud Kerberos trust from giving one
        bool onPremOnly = counted.Where(t => t.Status == Status.Warn).All(t => t.Name is SsoOnPremTgt or CloudTrustGroupsCheck);
        return worst switch
        {
            Status.Fail => new(worst, "Not ready for single sign-on.", true),
            Status.Warn when onPremOnly => new(worst, "Ready for cloud apps, not for on-premises resources.", true),
            Status.Warn => new(worst, "Ready for single sign-on, with warnings.", true),
            _ => new(worst, "Ready for single sign-on.", false),
        };
    }
}

/// <summary>One line of the PRT card; <c>Tone</c> colours the value with a status colour, null for plain text.</summary>
record PrtCardRow(string Label, string Value, Status? Tone = null);
/// <summary>The PRT card on the Kerberos tickets tab: its badge text and colour, the caption beside it, and its lines.</summary>
record PrtCard(string Badge, Status BadgeStatus, string Caption, List<PrtCardRow> Rows);
