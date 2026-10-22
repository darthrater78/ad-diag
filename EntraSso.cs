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
    public const string EntraSsoGroup = "Entra Single Sign-On";
    public const string SsoJoin = "Join Type", SsoDeviceAuth = "Device Auth", SsoPrt = "Primary Refresh Token",
        SsoTicket = "Seamless SSO Ticket", SsoZone = "Intranet Zone", SsoLogon = "Automatic Logon",
        SsoStatusBar = "Status Bar Scripts", SsoCloudTgt = "Cloud Kerberos", SsoOnPremTgt = "On-premises Kerberos",
        SsoSeamless = "Seamless SSO", SsoEndpoints = "Entra Endpoints";

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
            tests.Add(new(SsoJoin, Status.Warn, $"dsregcmd failed: {ex.Message}"));
            return new(EntraSsoGroup, tests, new(Status.Warn, "Readiness unknown: dsregcmd did not answer.", true));
        }

        var (kind, join) = JoinCheck(ds);
        tests.Add(join);
        if (kind == null)
            return new(EntraSsoGroup, tests, new(Status.Warn, "Readiness unknown: dsregcmd reported no join state.", true));
        if (kind == JoinKind.None)
            return new(EntraSsoGroup, tests, new(Status.Fail, "Not ready: this PC is not joined to Microsoft Entra ID or a domain.", true));

        bool seamless = kind is JoinKind.Hybrid or JoinKind.DomainOnly;
        tests.Add(DeviceAuthCheck(ds, kind.Value));
        var prt = PrtCheck(ds, kind.Value, nowUtc);
        tests.Add(prt);
        bool fallbackOnly = kind == JoinKind.Hybrid && prt.Status == Status.Pass;

        if (seamless)
        {
            var sso = new List<TestEntry> { SeamlessTicketCheck(cfg, probe) };
            sso.AddRange(BrowserZoneChecks(cfg, probe));
            tests.AddRange(fallbackOnly ? sso.Select(AsFallback) : sso);
        }
        else
        {
            tests.AddRange(EntraKerberosChecks(ds));
        }

        tests.Add(EndpointsCheck(cfg, probe, seamless ? [LoginHost, AutologonHost] : [LoginHost]));
        return new(EntraSsoGroup, tests, SsoReadiness(tests, seamless, fallbackOnly));
    }

    // A Seamless SSO failure on a PC that signs in with its PRT breaks only the fallback, so it warns
    static TestEntry AsFallback(TestEntry test) => test.Status == Status.Fail
        ? test with { Status = Status.Warn, Detail = test.Detail + "; this PC signs in with its Primary Refresh Token, so it matters only where the token can't be used" }
        : test;

    // How the PC is joined, which decides what else is checked; null when dsregcmd reported no join state
    static (JoinKind? Kind, TestEntry Entry) JoinCheck(Dictionary<string, string> ds)
    {
        bool? entra = Parsers.DsregFlag(ds, "AzureAdJoined"), domain = Parsers.DsregFlag(ds, "DomainJoined");
        if (entra == null && domain == null)
            return (null, new(SsoJoin, Status.Warn, "dsregcmd reported no join state"));

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

        var age = nowUtc - updated;
        if (age < TimeSpan.Zero) age = TimeSpan.Zero;
        string when = $"renewed {updated.ToLocalTime():g} ({FormatTimeSpan(age)} ago)";
        return age <= PrtLifetime
            ? new(SsoPrt, Status.Pass, $"AzureAdPrt: YES, {when}")
            : new(SsoPrt, missing, $"AzureAdPrt: YES, but {when}; it has expired, since a token is valid for 14 days" + fallback);
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
                new(SsoZone, Status.Warn, $"Could not read the Internet settings: {ex.Message}"),
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
                : new(SsoStatusBar, Status.Warn, "\"Allow updates to status bar via script\" is not enabled for the Local intranet zone"),
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
        new(SsoSeamless, Status.Skip, "Not used on Microsoft Entra joined devices; sign-in uses the Primary Refresh Token"),
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
        var counted = tests.Where(t => t.Status != Status.Skip).ToList();
        var worst = counted.Any(t => t.Status == Status.Fail) ? Status.Fail
            : counted.Any(t => t.Status == Status.Warn) ? Status.Warn : Status.Pass;

        if (fallbackOnly)
        {
            bool onlyFallback = counted.Where(t => t.Status != Status.Pass).All(t => SeamlessChecks.Contains(t.Name));
            return worst switch
            {
                Status.Fail => new(worst, "Not ready for single sign-on.", true),
                Status.Warn when onlyFallback =>
                    new(worst, "Ready for single sign-on through the Primary Refresh Token; the Seamless SSO fallback is not ready.", true),
                Status.Warn => new(worst, "Ready for single sign-on, with warnings.", true),
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

        bool onPremOnly = counted.Where(t => t.Status == Status.Warn).All(t => t.Name == SsoOnPremTgt);
        return worst switch
        {
            Status.Fail => new(worst, "Not ready for single sign-on.", true),
            Status.Warn when onPremOnly => new(worst, "Ready for cloud apps, not for on-premises resources.", true),
            Status.Warn => new(worst, "Ready for single sign-on, with warnings.", true),
            _ => new(worst, "Ready for single sign-on.", false),
        };
    }
}
