using System.Net;
using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// The SMB tab: each connection point's verdicts on each profile, where the path stops, and the fix it names.
public class SmbPathTests
{
    const string Server = "files.contoso.com";
    static readonly IPAddress FilesIp = IPAddress.Parse("10.20.5.40");

    static string Klist(string etype = "AES-256-CTS-HMAC-SHA1-96") => $"""

        Current LogonId is 0:0x3e7a1

        Cached Tickets: (2)

        #0>	Client: jdoe @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        	Start Time: 10/23/2026 8:00:00 (local)
        	End Time:   10/23/2026 18:00:00 (local)
        	Renew Time: 10/30/2026 8:00:00 (local)
        	Session Key Type: AES-256-CTS-HMAC-SHA1-96

        #1>	Client: jdoe @ CONTOSO.COM
        	Server: cifs/files.contoso.com @ CONTOSO.COM
        	KerbTicket Encryption Type: {etype}
        	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        	Start Time: 10/23/2026 9:00:00 (local)
        	End Time:   10/23/2026 18:00:00 (local)
        	Renew Time: 10/30/2026 8:00:00 (local)
        	Session Key Type: {etype}
        """;

    static string Dsreg(string ngc = "NO", string onPrem = "YES") => $"""
                         AzureAdJoined : YES
                          DomainJoined : NO
                                NgcSet : {ngc}
                             CloudTgt : YES
                            OnPremTgt : {onPrem}
        """;

    const string NoSavedCredentials = "\r\nCurrently stored credentials:\r\n\r\n* NONE *\r\n";

    const string SavedForFiles = """

        Currently stored credentials:

            Target: Domain:target=files
            Type: Domain Password
            User: CONTOSO\svc-scan

            Target: LegacyGeneric:target=git:https://github.com
            Type: Generic
            User: someone
        """;

    static FakeProbe Machine()
    {
        var probe = new FakeProbe();
        probe.Hosts[Server] = [FilesIp];
        probe.OpenPorts.Add(445);
        probe.Tools["klist"] = Klist();
        probe.Tools["cmdkey /list"] = NoSavedCredentials;
        probe.Tools["dsregcmd /status"] = Dsreg();
        probe.Srv["_kpasswd._tcp.contoso.com"] = ["dc01.contoso.com:464", "dc02.contoso.com:464"];
        return probe;
    }

    static SmbTarget Target(string input = @"\\files\Finance$", string domain = "contoso.com") =>
        Diagnostics.ParseSmbTarget(input, domain).Target!;

    static List<TestGroup> Run(FakeProbe probe, JoinProfile profile = JoinProfile.Domain, SmbTarget? target = null, string domain = "contoso.com") =>
        Diagnostics.TestSmb(target ?? Target(domain: domain), profile, new DiagConfig(domain, "", CancellationToken.None), probe);

    static TestEntry Row(List<TestGroup> groups, string name) => groups.SelectMany(g => g.Tests).First(t => t.Name == name);
    static TestGroup Step(List<TestGroup> groups, string name) => groups.First(g => g.Name == name);

    // ── Reading what was typed ──

    [Theory]
    [InlineData(@"\\files\Finance$", "files.contoso.com", "Finance$")]
    [InlineData(@"files\Finance$", "files.contoso.com", "Finance$")]
    [InlineData("//files/Finance$/2026/q3", "files.contoso.com", "Finance$")]
    [InlineData("FILES.corp.contoso.com", "files.corp.contoso.com", null)]
    [InlineData(@"\\10.20.5.40\data", "10.20.5.40", "data")]
    [InlineData(@"\\10\data", "10.contoso.com", "data")] // a name, not 0.0.0.10
    public void ReadsServerAndShare(string input, string server, string? share)
    {
        var (target, error) = Diagnostics.ParseSmbTarget(input, "contoso.com");
        Assert.Null(error);
        Assert.Equal(server, target!.Server);
        Assert.Equal(share, target.Share);
    }

    [Theory]
    [InlineData("")]
    [InlineData(@"\\")]
    [InlineData(@"\\fi les\share")]
    [InlineData(@"\\files'; calc;'\share")]
    [InlineData(@"\\files\bad*share")]
    [InlineData(@"\\files\a;b")]
    [InlineData(@"\\999.1.1.1\share")]
    [InlineData(@"\\fd00::40\share")]
    [InlineData(@"\\files:445\share")]
    [InlineData(@"\\files\..")]
    [InlineData(@"\\files\.")]
    [InlineData(@"\\files\share. ")]
    public void RejectsWhatCantBeAServerOrShare(string input)
    {
        var (target, error) = Diagnostics.ParseSmbTarget(input, "contoso.com");
        Assert.Null(target);
        Assert.NotNull(error);
    }

    [Fact]
    public void AShortNameStaysShortWithNoDomain()
    {
        Assert.Equal("files", Diagnostics.ParseSmbTarget("files", "").Target!.Server);
    }

    // ── The whole path ──

    [Fact]
    public void AHealthyPathPassesEveryStepInOrder()
    {
        var reported = new List<string>();
        var groups = Diagnostics.TestSmb(Target(), JoinProfile.Domain, new DiagConfig("contoso.com", "", CancellationToken.None), Machine(), g => reported.Add(g.Name));

        Assert.Equal([.. Diagnostics.SmbSteps, Diagnostics.SmbSettings], reported);
        Assert.All(groups.Where(g => g.Name != Diagnostics.SmbSettings).SelectMany(g => g.Tests), t => Assert.Equal(Status.Pass, t.Status));
        Assert.Equal("Kerberos", Row(groups, Diagnostics.SmbNegotiationRow).Detail);
        Assert.Contains("14 entries", Row(groups, Diagnostics.SmbShareRow).Detail);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups);
        Assert.Equal(Status.Pass, verdict.Status);
        Assert.Contains(@"Opened \\files.contoso.com\Finance$ with Kerberos", verdict.Text);
    }

    [Fact]
    public void ANameThatDoesntResolveStopsThePath()
    {
        var probe = Machine();
        probe.Hosts.Clear();
        var groups = Run(probe);

        Assert.Equal(Status.Fail, Row(groups, Diagnostics.SmbNameRow).Status);
        foreach (var step in Diagnostics.SmbSteps.Skip(1))
            Assert.All(Step(groups, step).Tests, t => Assert.StartsWith("Not checked: the name didn't resolve", t.Detail));
        Assert.Empty(probe.ConnectCalls);
        Assert.Contains(groups, g => g.Name == Diagnostics.SmbSettings); // read whatever happened
        Assert.StartsWith("Stopped at Name", Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups).Text);
    }

    [Fact]
    public void AClosedPortStopsThePathWithAFirewallFix()
    {
        var probe = Machine();
        probe.OpenPorts.Clear();
        var groups = Run(probe);

        Assert.Equal(Status.Fail, Row(groups, Diagnostics.SmbPortRow).Status);
        Assert.Equal(Status.Skip, Row(groups, Diagnostics.SmbShareRow).Status);
        Assert.Empty(probe.ShareCalls);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups);
        Assert.StartsWith("Stopped at Port 445", verdict.Text);
        Assert.Contains("firewall", verdict.Fix);
    }

    [Fact]
    public void IPv6OnlyIsANote()
    {
        var probe = Machine();
        probe.Hosts[Server] = [IPAddress.Parse("fd00:20::40")];
        Assert.Equal(Status.Info, Row(Run(probe), Diagnostics.SmbAddressesRow).Status);
    }

    // ── Kerberos and sign-in, by profile ──

    static FakeProbe NoSpn(FakeProbe probe)
    {
        probe.Spn = "NONE";
        probe.Sspi[$"Kerberos cifs/{Server}"] = new(unchecked((int)0x80090303), null);
        probe.Sspi[$"Negotiate cifs/{Server}"] = new(SspiResult.ContinueNeeded, "NTLM");
        return probe;
    }

    [Fact]
    public void AMissingSpnFallsBackToNtlmOnADomainJoinedPc()
    {
        var groups = Run(NoSpn(Machine()));

        Assert.Equal(Status.Warn, Row(groups, Diagnostics.SmbSpnRow).Status);
        Assert.Contains("PRINCIPAL_UNKNOWN", Row(groups, Diagnostics.SmbTicketRow).Detail);
        Assert.Equal(Status.Skip, Row(groups, Diagnostics.SmbEncryptionRow).Status);
        Assert.Equal(Status.Warn, Row(groups, Diagnostics.SmbNegotiationRow).Status);
        Assert.Equal(Status.Pass, Row(groups, Diagnostics.SmbShareRow).Status);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups);
        Assert.Equal(Status.Warn, verdict.Status);
        Assert.Contains("but with NTLM", verdict.Text);
        Assert.Contains("setspn -S cifs/files.contoso.com FILES", verdict.Fix);
    }

    [Fact]
    public void OnAnEntraJoinedPcWithHelloAMissingSpnLeavesNothingToSignInWith()
    {
        var probe = NoSpn(Machine());
        probe.Tools["dsregcmd /status"] = Dsreg(ngc: "YES");
        probe.Shares = _ => new(null, 1326, "The user name or password is incorrect.");
        var groups = Run(probe, JoinProfile.Entra);

        Assert.Equal(Status.Pass, Row(groups, Diagnostics.SmbCloudTrustRow).Status);
        Assert.DoesNotContain(groups.SelectMany(g => g.Tests), t => t.Name == Diagnostics.SmbKpasswdRow);
        Assert.Contains("no password hash", Row(groups, Diagnostics.SmbNtlmRow).Detail);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Entra, groups);
        Assert.StartsWith("Stopped at Share", verdict.Text);
        Assert.Contains("Windows Hello", verdict.Fix);
    }

    [Fact]
    public void OnAnEntraJoinedPcWithoutOnPremTgtKerberosFails()
    {
        var probe = Machine();
        probe.Tools["dsregcmd /status"] = Dsreg(ngc: "YES", onPrem: "NO");
        probe.Shares = _ => new(null, 1326, "denied");
        var groups = Run(probe, JoinProfile.Entra);

        Assert.Equal(Status.Fail, Row(groups, Diagnostics.SmbCloudTrustRow).Status);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Entra, groups);
        Assert.StartsWith("Stopped at Kerberos", verdict.Text);
        Assert.Contains("Set-AzureADKerberosServer", verdict.Fix);
    }

    [Fact]
    public void KerberosFailingAloneDoesntStopAConnectionThatWorked()
    {
        var probe = Machine();
        probe.Tools["dsregcmd /status"] = Dsreg(ngc: "NO", onPrem: "NO");
        var groups = Run(probe, JoinProfile.Entra);

        Assert.Equal(Status.Fail, Row(groups, Diagnostics.SmbCloudTrustRow).Status);
        Assert.NotEqual(Status.Fail, Diagnostics.SmbVerdictFor(Target(), JoinProfile.Entra, groups).Status);
    }

    [Theory]
    [InlineData("NO", "YES", null)]
    [InlineData("YES", "YES", "Pass")]
    [InlineData("YES", "NO", "Warn")]
    public void AHybridJoinedPcChecksCloudTrustOnlyWithHello(string ngc, string onPrem, string? expected)
    {
        var probe = Machine();
        probe.Tools["dsregcmd /status"] = Dsreg(ngc, onPrem);
        var row = Run(probe, JoinProfile.Hybrid).SelectMany(g => g.Tests).FirstOrDefault(t => t.Name == Diagnostics.SmbCloudTrustRow);
        Assert.Equal(expected, row?.Status.ToString());
    }

    [Fact]
    public void DsregcmdRunsOncePerTest()
    {
        var probe = Machine();
        probe.Tools["dsregcmd /status"] = Dsreg(ngc: "YES");
        Run(probe, JoinProfile.Entra);
        Assert.Single(probe.ToolCalls, c => c.StartsWith("dsregcmd"));
    }

    [Fact]
    public void ADomainJoinedPcNeverAsksAboutCloudTrust()
    {
        var probe = Machine();
        Assert.DoesNotContain(Run(probe).SelectMany(g => g.Tests), t => t.Name == Diagnostics.SmbCloudTrustRow);
    }

    [Fact]
    public void WithNoOnPremDomainTheDomainChecksWait()
    {
        var groups = Run(Machine(), JoinProfile.Entra, Target(@"\\files.contoso.com\Finance$", domain: ""), domain: "");

        Assert.Equal("Not checked: type the on-prem domain", Row(groups, Diagnostics.SmbTgtRow).Detail);
        Assert.Equal("Not checked: type the on-prem domain", Row(groups, Diagnostics.SmbSpnRow).Detail);
        Assert.Equal(Status.Pass, Row(groups, Diagnostics.SmbTicketRow).Status);
    }

    [Fact]
    public void AMissingKpasswdRecordWarnsWithoutStopping()
    {
        var probe = Machine();
        probe.Srv.Clear();
        var groups = Run(probe);

        Assert.Equal(Status.Warn, Row(groups, Diagnostics.SmbKpasswdRow).Status);
        Assert.Equal(Status.Pass, Row(groups, Diagnostics.SmbShareRow).Status);
        Assert.Contains("nltest /dsregdns", Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups).Fix);
    }

    [Fact]
    public void ADuplicateSpnFails()
    {
        var probe = Machine();
        probe.Spn = "SPN|FILES$|cifs/files.contoso.com\nSPN|OLDFILES$|HOST/files.contoso.com";
        var row = Row(Run(probe), Diagnostics.SmbSpnRow);
        Assert.Equal(Status.Fail, row.Status);
        Assert.Contains("FILES$ and OLDFILES$", row.Detail);
    }

    [Fact]
    public void AHostSpnCoversCifs()
    {
        var probe = Machine();
        probe.Spn = "SPN|FILES$|HOST/files.contoso.com";
        Assert.Contains("covers cifs", Row(Run(probe), Diagnostics.SmbSpnRow).Detail);
    }

    [Fact]
    public void AnRc4TicketWarns()
    {
        var probe = Machine();
        probe.Tools["klist"] = Klist("RSADSI RC4-HMAC(NT)");
        Assert.Equal(Status.Warn, Row(Run(probe), Diagnostics.SmbEncryptionRow).Status);
    }

    [Theory]
    [InlineData(null, "Pass")]
    [InlineData(65535, "Pass")]
    [InlineData(12000, "Warn")]
    public void MaxTokenSize(int? size, string expected)
    {
        var probe = Machine();
        if (size is { } s) probe.Registry[@"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"] = new() { ["MaxTokenSize"] = s };
        Assert.Equal(expected, Row(Run(probe), Diagnostics.SmbTokenRow).Status.ToString());
    }

    [Theory]
    [InlineData(null, "Pass")]
    [InlineData(5, "Pass")]
    [InlineData(1, "Warn")]
    public void LanManagerLevel(int? level, string expected)
    {
        var probe = Machine();
        if (level is { } l) probe.Registry[@"SYSTEM\CurrentControlSet\Control\Lsa"] = new() { ["LmCompatibilityLevel"] = l };
        Assert.Equal(expected, Row(Run(probe), Diagnostics.SmbNtlmRow).Status.ToString());
    }

    [Fact]
    public void AnAddressSkipsKerberosAndSignsInWithNtlm()
    {
        var probe = Machine();
        probe.Sspi["Negotiate cifs/10.20.5.40"] = new(SspiResult.ContinueNeeded, "NTLM");
        var groups = Run(probe, target: Target(@"\\10.20.5.40\Finance$"));

        Assert.Equal(Status.Info, Row(groups, Diagnostics.SmbNameRow).Status);
        Assert.Equal(Status.Skip, Row(groups, Diagnostics.SmbTicketRow).Status);
        Assert.Equal(Status.Info, Row(groups, Diagnostics.SmbNegotiationRow).Status);
        Assert.Equal(Status.Pass, Row(groups, Diagnostics.SmbShareRow).Status);
    }

    [Fact]
    public void ASignInWindowsCantStartStopsThePath()
    {
        var probe = Machine();
        probe.Sspi[$"Negotiate cifs/{Server}"] = new(unchecked((int)0x8009030E), null);
        var groups = Run(probe);

        Assert.Equal(Status.Fail, Row(groups, Diagnostics.SmbNegotiationRow).Status);
        Assert.Equal("Not checked: sign-in failed", Row(groups, Diagnostics.SmbShareRow).Detail);
        Assert.StartsWith("Stopped at Sign-in", Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups).Text);
    }

    // ── Saved credentials and the share ──

    [Fact]
    public void ASavedCredentialReplacingYourSignInIsNamedWhenTheShareRefusesIt()
    {
        var probe = Machine();
        probe.Tools["cmdkey /list"] = SavedForFiles;
        probe.Shares = _ => new(null, 5, "Access is denied.");
        var groups = Run(probe);

        var saved = Row(groups, Diagnostics.SmbSavedRow);
        Assert.Equal(Status.Info, saved.Status);
        Assert.Contains(@"CONTOSO\svc-scan", saved.Detail);
        var verdict = Diagnostics.SmbVerdictFor(Target(), JoinProfile.Domain, groups);
        Assert.StartsWith("Stopped at Share: ", verdict.Text);
        Assert.Contains("Credential Manager", verdict.Fix);
    }

    [Fact]
    public void ReadsSavedCredentialsAndTheirUsers()
    {
        var saved = Diagnostics.ParseSavedCredentials(SavedForFiles);
        Assert.Equal([("files", @"CONTOSO\svc-scan")], saved);
    }

    [Fact]
    public void NoShareMeansTheServerAloneIsTested()
    {
        var probe = Machine();
        var groups = Run(probe, target: Target("files"));
        Assert.Equal(Status.Skip, Row(groups, Diagnostics.SmbShareRow).Status);
        Assert.Empty(probe.ShareCalls);
        Assert.Contains("Type a share", Diagnostics.SmbVerdictFor(Target("files"), JoinProfile.Domain, groups).Text);
    }

    [Theory]
    [InlineData(5, "access denied")]
    [InlineData(67, "no share by that name")]
    [InlineData(1272, "guest")]
    [InlineData(1219, "different user")]
    [InlineData(4242, "error 4242: boom")]
    public void ShareErrorsReadByNumber(int error, string expected)
    {
        Assert.Contains(expected, Diagnostics.ShareErrorText(new(null, error, "boom")));
    }

    // ── This PC's SMB settings ──

    [Fact]
    public void SettingsAtWindowsDefaults()
    {
        var settings = Step(Run(Machine()), Diagnostics.SmbSettings);
        Assert.Equal(Status.Info, settings.Tests.First(t => t.Name == Diagnostics.SmbSigningRow).Status);
        Assert.Equal(Status.Pass, settings.Tests.First(t => t.Name == Diagnostics.SmbV1Row).Status);
        Assert.Equal(Status.Pass, settings.Tests.First(t => t.Name == Diagnostics.SmbGuestRow).Status);
    }

    [Fact]
    public void SettingsThatNeedFixing()
    {
        var probe = Machine();
        probe.Registry[@"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"] = new() { ["RequireSecuritySignature"] = 1, ["AllowInsecureGuestAuth"] = 0 };
        probe.Registry[@"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"] = new() { ["AllowInsecureGuestAuth"] = 1 };
        probe.Registry[@"SYSTEM\CurrentControlSet\Services\mrxsmb10"] = new() { ["Start"] = 2 };
        var settings = Step(Run(probe), Diagnostics.SmbSettings);

        Assert.Equal(Status.Pass, settings.Tests.First(t => t.Name == Diagnostics.SmbSigningRow).Status);
        Assert.Equal(Status.Warn, settings.Tests.First(t => t.Name == Diagnostics.SmbV1Row).Status);
        var guest = settings.Tests.First(t => t.Name == Diagnostics.SmbGuestRow);
        Assert.Equal(Status.Warn, guest.Status); // the policy wins over the local value
        Assert.Contains("Group Policy", guest.Detail);
    }

    // ── The AD search ──

    [Fact]
    public void TheSpnScriptTakesOnlyPlainNames()
    {
        Assert.Contains("cifs/files.contoso.com", Diagnostics.SpnScript("contoso.com", "files.contoso.com"));
        Assert.Throws<ArgumentException>(() => Diagnostics.SpnScript("contoso.com", "files')(x"));
        Assert.Throws<ArgumentException>(() => Diagnostics.SpnScript("contoso.com'", "files"));
    }

    [Fact]
    public void AnAdSearchErrorSkipsTheSpnRow()
    {
        var probe = Machine();
        probe.Spn = "ERROR|The server is not operational.";
        var row = Row(Run(probe), Diagnostics.SmbSpnRow);
        Assert.Equal(Status.Skip, row.Status);
        Assert.Contains("server is not operational", row.Detail);
    }
}
