using System.Net;
using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// Single sign-on readiness: which checks run for each join type, and the verdict they add up to.
public class EntraSsoTests
{
    static readonly DateTime Now = new(2026, 10, 22, 9, 0, 0, DateTimeKind.Utc);
    static readonly IPAddress LoginIp = IPAddress.Parse("20.190.151.68");
    static readonly IPAddress AutologonIp = IPAddress.Parse("40.126.7.33");

    static string Dsreg(string entra, string domain, string prt = "YES", string prtTime = "2026-10-22 08:14:03.000 UTC",
        string auth = "SUCCESS", string onPrem = "YES", string cloud = "YES") => $"""
        +----------------------------------------------------------------------+
        | Device State                                                         |
        +----------------------------------------------------------------------+

                     AzureAdJoined : {entra}
                  EnterpriseJoined : NO
                      DomainJoined : {domain}
                       Device Name : PC042.contoso.com

        +----------------------------------------------------------------------+
        | Device Details                                                       |
        +----------------------------------------------------------------------+

                          DeviceId : 5f4e2a1c-0000-4000-8000-000000000042
                  DeviceAuthStatus : {auth}

        +----------------------------------------------------------------------+
        | Tenant Details                                                       |
        +----------------------------------------------------------------------+

                        TenantName : Contoso
                          TenantId : 72f988bf-0000-4000-8000-000000000001

        +----------------------------------------------------------------------+
        | SSO State                                                            |
        +----------------------------------------------------------------------+

                        AzureAdPrt : {prt}
              AzureAdPrtUpdateTime : {prtTime}
               AzureAdPrtAuthority : https://login.microsoftonline.com/72f988bf-0000-4000-8000-000000000001
                     EnterprisePrt : NO
                         OnPremTgt : {onPrem}
                          CloudTgt : {cloud}
        """;

    const string KlistGetSso = """

        Current LogonId is 0:0x3e7c1
        A ticket to HTTP/autologon.microsoftazuread-sso.com has been retrieved successfully.

        Cached Tickets: (2)

        #0>	Client: jdoe @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96

        #1>	Client: jdoe @ CONTOSO.COM
        	Server: HTTP/autologon.microsoftazuread-sso.com @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        	Kdc Called: DC01.contoso.com
        """;

    const string KlistGetSsoFailed = """

        Current LogonId is 0:0x3e7c1
        Error calling API LsaCallAuthenticationPackage (GetTicket substatus): 0x6fb

        klist failed with 0xc000018b/-1073741429: The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.
        """;

    // A hybrid joined PC where everything single sign-on needs is in place
    static FakeProbe Machine(string dsreg)
    {
        var probe = Healthy();
        probe.Tools["dsregcmd /status"] = dsreg;
        probe.Tools["klist get HTTP/autologon"] = KlistGetSso;
        probe.Hosts["login.microsoftonline.com"] = [LoginIp];
        probe.Hosts["autologon.microsoftazuread-sso.com"] = [AutologonIp];
        probe.OpenPorts.Add(443);
        return probe;
    }

    static FakeProbe Hybrid() => Machine(Dsreg("YES", "YES"));

    static TestGroup Run(FakeProbe probe) =>
        Diagnostics.TestEntraSso(new DiagConfig("contoso.com", "", default), probe, Now);

    static TestEntry Entry(TestGroup group, string name) => Assert.Single(group.Tests, t => t.Name == name);

    [Fact]
    public void Hybrid_AllInPlace_IsReady()
    {
        var group = Run(Hybrid());

        Assert.Equal("Entra Seamless Single Sign-On", group.Name);
        Assert.Equal(["Join Type", "Device Auth", "Primary Refresh Token", "Seamless SSO Ticket", "Intranet Zone",
            "Automatic Logon", "Status Bar Scripts", "Entra Endpoints"], group.Tests.Select(t => t.Name));
        Assert.All(group.Tests, t => Assert.Equal(Status.Pass, t.Status));
        Assert.Contains("hybrid joined", Entry(group, "Join Type").Detail);
        Assert.Contains("tenant Contoso", Entry(group, "Join Type").Detail);
        Assert.Contains("obtained from CONTOSO.COM", Entry(group, "Seamless SSO Ticket").Detail);
        Assert.Contains("login.microsoftonline.com and autologon.microsoftazuread-sso.com", Entry(group, "Entra Endpoints").Detail);
        Assert.Equal(new Readiness(Status.Pass, "Ready for single sign-on.", false), group.Readiness);
    }

    // A hybrid joined PC that has no PRT signs in through Seamless SSO alone
    static FakeProbe HybridWithoutPrt() => Machine(Dsreg("YES", "YES", prt: "NO"));

    [Theory]
    [InlineData(3, "Internet")]
    [InlineData(2, "Trusted sites")]
    public void Hybrid_NoPrt_UrlOutsideIntranetZone_IsNotReady(int zone, string zoneName)
    {
        var probe = HybridWithoutPrt();
        probe.Url = new(zone, 0x20000, 0);

        var group = Run(probe);

        var entry = Entry(group, "Intranet Zone");
        Assert.Equal(Status.Fail, entry.Status);
        Assert.Contains($"in the {zoneName} zone", entry.Detail);
        // Both depend on the zone, so they wait for it rather than fail alongside it
        Assert.Equal(Status.Skip, Entry(group, "Automatic Logon").Status);
        Assert.Equal(Status.Skip, Entry(group, "Status Bar Scripts").Status);
        Assert.Equal(new Readiness(Status.Fail, "Not ready for Seamless SSO.", true), group.Readiness);
    }

    [Theory]
    [InlineData(0x00000, true)]
    [InlineData(0x20000, true)]
    [InlineData(0x10000, false)]
    [InlineData(0x30000, false)]
    public void Hybrid_NoPrt_IntranetLogonSetting_Decides(int logon, bool passes)
    {
        var probe = HybridWithoutPrt();
        probe.Url = new(1, logon, 0);

        Assert.Equal(passes ? Status.Pass : Status.Fail, Entry(Run(probe), "Automatic Logon").Status);
    }

    [Fact]
    public void Hybrid_NoPrt_StatusBarScriptsOff_IsANote()
    {
        var probe = HybridWithoutPrt();
        probe.Url = new(1, 0x20000, 3);

        var group = Run(probe);

        // The readiness warns for the missing PRT, not for the status bar setting
        Assert.Equal(Status.Info, Entry(group, "Status Bar Scripts").Status);
        Assert.Equal(new Readiness(Status.Warn, "Ready for Seamless SSO, with warnings.", true), group.Readiness);
    }

    // The log from a working hybrid joined PC: PRT in place, autologon URL in the Internet zone
    [Fact]
    public void Hybrid_WithPrt_SeamlessSsoNotSetUp_IsReadyThroughThePrt()
    {
        var probe = Hybrid();
        probe.Url = new(3, 0x20000, 0);
        probe.Tools["klist get HTTP/autologon"] = KlistGetSsoFailed;

        var group = Run(probe);

        var zone = Entry(group, "Intranet Zone");
        Assert.Equal(Status.Info, zone.Status);
        Assert.Contains("in the Internet zone", zone.Detail);
        Assert.Contains("it matters only where the token can't be used", zone.Detail);
        Assert.Equal(Status.Info, Entry(group, "Seamless SSO Ticket").Status);
        Assert.DoesNotContain(group.Tests, t => t.Status is Status.Fail or Status.Warn);
        Assert.Equal(new Readiness(Status.Pass,
            "Ready for single sign-on through the Primary Refresh Token; the Seamless SSO fallback is not set up.", true), group.Readiness);
    }

    [Fact]
    public void Hybrid_WithPrt_OtherWarning_IsReadyWithWarnings()
    {
        var probe = Hybrid();
        probe.OpenPorts.Remove(443);

        Assert.Equal(new Readiness(Status.Warn, "Ready for single sign-on, with warnings.", true), Run(probe).Readiness);
    }

    [Fact]
    public void Hybrid_NoPrt_NoSeamlessTicket_FailsWithTheError()
    {
        var probe = HybridWithoutPrt();
        probe.Tools["klist get HTTP/autologon"] = KlistGetSsoFailed;

        var group = Run(probe);

        var entry = Entry(group, "Seamless SSO Ticket");
        Assert.Equal(Status.Fail, entry.Status);
        Assert.Contains("0xc000018b", entry.Detail);
        Assert.Contains("AZUREADSSOACC", entry.Detail);
        Assert.False(group.Readiness!.Status == Status.Pass);
    }

    [Fact]
    public void Hybrid_InternetSettingsUnreadable_IsNotCheckedAndSkipsTheZonePolicies()
    {
        var probe = Hybrid();
        probe.UrlError = new TimeoutException("Internet settings timed out after 5s");

        var group = Run(probe);

        Assert.Equal(Status.Skip, Entry(group, "Intranet Zone").Status);
        Assert.StartsWith("Not checked:", Entry(group, "Intranet Zone").Detail);
        Assert.Contains("timed out", Entry(group, "Intranet Zone").Detail);
        Assert.Equal(Status.Skip, Entry(group, "Automatic Logon").Status);
        Assert.Equal(Status.Skip, Entry(group, "Status Bar Scripts").Status);
    }

    [Fact]
    public void Hybrid_PrtADayOld_Passes()
    {
        var group = Run(Machine(Dsreg("YES", "YES", prtTime: "2026-10-21 09:14:03.000 UTC")));

        var entry = Entry(group, "Primary Refresh Token");
        Assert.Equal(Status.Pass, entry.Status);
        Assert.Contains("23h 45m ago", entry.Detail);
    }

    [Fact]
    public void Hybrid_ExpiredPrt_WarnsAndSeamlessSsoCounts()
    {
        var probe = Machine(Dsreg("YES", "YES", prtTime: "2026-10-07 08:00:00.000 UTC"));
        probe.Url = new(3, 0x20000, 0);

        var group = Run(probe);

        var entry = Entry(group, "Primary Refresh Token");
        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("expired", entry.Detail);
        Assert.Equal(Status.Fail, Entry(group, "Intranet Zone").Status);
        Assert.Equal(new Readiness(Status.Fail, "Not ready for Seamless SSO.", true), group.Readiness);
    }

    [Fact]
    public void EntraJoined_ExpiredPrt_Fails()
    {
        var group = Run(Machine(Dsreg("YES", "NO", prtTime: "2026-10-07 08:00:00.000 UTC")));

        Assert.Equal(Status.Fail, Entry(group, "Primary Refresh Token").Status);
        Assert.Equal(new Readiness(Status.Fail, "Not ready for single sign-on.", true), group.Readiness);
    }

    [Fact]
    public void Hybrid_NoPrt_WarnsSinceSeamlessSsoCoversIt()
    {
        var entry = Entry(Run(Machine(Dsreg("YES", "YES", prt: "NO"))), "Primary Refresh Token");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("fall back to Seamless SSO", entry.Detail);
    }

    [Fact]
    public void Hybrid_DeviceAuthFailed_Fails()
    {
        var entry = Entry(Run(Machine(Dsreg("YES", "YES", auth: "FAILED. Device is either disabled or deleted"))), "Device Auth");

        Assert.Equal(Status.Fail, entry.Status);
        Assert.Contains("disabled or deleted", entry.Detail);
    }

    [Fact]
    public void EntraJoined_UsesThePrtNotSeamlessSso()
    {
        var probe = Machine(Dsreg("YES", "NO", onPrem: "NO"));

        var group = Run(probe);

        Assert.Equal(["Join Type", "Device Auth", "Primary Refresh Token", "Cloud Kerberos", "On-premises Kerberos",
            "Seamless SSO", "Entra Endpoints"], group.Tests.Select(t => t.Name));
        Assert.Equal(Status.Skip, Entry(group, "Seamless SSO").Status);
        Assert.Equal(Status.Warn, Entry(group, "On-premises Kerberos").Status);
        Assert.Equal("login.microsoftonline.com reachable on port 443", Entry(group, "Entra Endpoints").Detail);
        Assert.DoesNotContain(probe.ToolCalls, c => c.StartsWith("klist get"));
        Assert.Equal(new Readiness(Status.Warn, "Ready for cloud apps, not for on-premises resources.", true), group.Readiness);
    }

    [Fact]
    public void EntraJoined_AllInPlace_IsReady()
    {
        var group = Run(Machine(Dsreg("YES", "NO")));

        Assert.Equal(new Readiness(Status.Pass, "Ready for single sign-on.", false), group.Readiness);
    }

    [Fact]
    public void EntraJoined_NoPrt_IsNotReady()
    {
        var group = Run(Machine(Dsreg("YES", "NO", prt: "NO")));

        Assert.Equal(Status.Fail, Entry(group, "Primary Refresh Token").Status);
        Assert.Equal(new Readiness(Status.Fail, "Not ready for single sign-on.", true), group.Readiness);
    }

    [Fact]
    public void DomainJoinedOnly_ChecksSeamlessSsoAndSkipsTheEntraDevice()
    {
        var group = Run(Machine(Dsreg("NO", "YES")));

        Assert.Equal(Status.Skip, Entry(group, "Device Auth").Status);
        Assert.Equal(Status.Skip, Entry(group, "Primary Refresh Token").Status);
        Assert.Equal(Status.Pass, Entry(group, "Seamless SSO Ticket").Status);
        Assert.Equal(new Readiness(Status.Pass, "Ready for Seamless SSO.", false), group.Readiness);
    }

    [Fact]
    public void NotJoined_IsNotReadyAndChecksNothingElse()
    {
        var group = Run(Machine(Dsreg("NO", "NO")));

        var entry = Assert.Single(group.Tests);
        Assert.Equal(Status.Fail, entry.Status);
        Assert.True(group.Readiness is { Status: Status.Fail, ShowGuide: true });
    }

    [Fact]
    public void DsregcmdTimeout_LeavesReadinessUnknown()
    {
        var probe = Hybrid();
        probe.Tools.Remove("dsregcmd /status");

        var group = Run(probe);

        Assert.Equal(Status.Skip, Assert.Single(group.Tests).Status);
        Assert.Equal(Status.Skip, group.Readiness!.Status);
        Assert.StartsWith("Readiness unknown", group.Readiness.Text);
    }

    [Fact]
    public void EndpointUnreachable_WarnsRatherThanFails()
    {
        var probe = Hybrid();
        probe.OpenPorts.Remove(443);

        var entry = Entry(Run(probe), "Entra Endpoints");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("login.microsoftonline.com (20.190.151.68)", entry.Detail);
        Assert.Contains("proxy", entry.Detail);
    }

    [Fact]
    public void ParseDsreg_KeepsValuesWithColons()
    {
        var fields = Parsers.ParseDsreg(Dsreg("YES", "YES"));

        Assert.Equal("https://login.microsoftonline.com/72f988bf-0000-4000-8000-000000000001", fields["AzureAdPrtAuthority"]);
        Assert.Equal("PC042.contoso.com", fields["Device Name"]);
        Assert.True(Parsers.DsregFlag(fields, "azureadjoined"));
        Assert.False(Parsers.DsregFlag(fields, "EnterprisePrt"));
        Assert.Null(Parsers.DsregFlag(fields, "WorkplaceJoined"));
        Assert.Equal(new DateTime(2026, 10, 22, 8, 14, 3, DateTimeKind.Utc), Parsers.DsregTime(fields, "AzureAdPrtUpdateTime"));
    }

    [Fact]
    public void TicketRealm_ReadsOnlyTheCachedTicketLine()
    {
        Assert.Equal("CONTOSO.COM", Parsers.TicketRealm(KlistGetSso, "HTTP/autologon.microsoftazuread-sso.com"));
        Assert.Null(Parsers.TicketRealm(KlistGetSsoFailed, "HTTP/autologon.microsoftazuread-sso.com"));
        Assert.Equal("0xc000018b", Parsers.KlistGetError(KlistGetSsoFailed));
    }
}
