using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// The age of the Seamless SSO, cloud Kerberos trust and krbtgt keys, from each account's pwdLastSet
public class KdcKeyTests
{
    static readonly DateTime Now = new(2026, 10, 23, 9, 0, 0, DateTimeKind.Utc);

    static string Keys(int seamlessDays, int cloudDays, int krbtgtDays) =>
        $"KEY|AZUREADSSOACC$|{Now.AddDays(-seamlessDays):o}\nKEY|krbtgt_AzureAD|{Now.AddDays(-cloudDays):o}\nKEY|krbtgt|{Now.AddDays(-krbtgtDays):o}";

    static List<TestEntry> Check(FakeProbe probe, string domain = "contoso.com") =>
        Diagnostics.KeyAgeChecks(probe, domain, Now,
        [
            ("Seamless SSO Key", "AZUREADSSOACC$", TimeSpan.FromDays(30), "Update-AzureADSSOForest"),
            ("Cloud Kerberos Key", "krbtgt_AzureAD", TimeSpan.FromDays(180), "Set-AzureADKerberosServer -RotateServerKey"),
            ("krbtgt Key", "krbtgt", TimeSpan.FromDays(180), "reset krbtgt twice, a day apart"),
        ], default);

    [Fact]
    public void FreshKeys_Pass()
    {
        var rows = Check(new FakeProbe { KeyAges = Keys(10, 90, 170) });

        Assert.All(rows, r => Assert.Equal(Status.Pass, r.Status));
        Assert.Contains("AZUREADSSOACC$ key last set", rows[0].Detail);
        Assert.Contains("(10d ago)", rows[0].Detail);
    }

    [Fact]
    public void OldKeys_WarnWithTheRollover()
    {
        var rows = Check(new FakeProbe { KeyAges = Keys(45, 400, 900) });

        Assert.All(rows, r => Assert.Equal(Status.Warn, r.Status));
        Assert.Contains("every 30 days (Update-AzureADSSOForest)", rows[0].Detail);
        Assert.Contains("Set-AzureADKerberosServer -RotateServerKey", rows[1].Detail);
    }

    [Fact]
    public void MissingAccount_IsNotChecked()
    {
        var rows = Check(new FakeProbe { KeyAges = $"NOTFOUND|AZUREADSSOACC$\nKEY|krbtgt_AzureAD|{Now:o}\nKEY|krbtgt|{Now:o}" });

        Assert.Equal((Status.Skip, "Not checked: no AZUREADSSOACC$ account in contoso.com"), (rows[0].Status, rows[0].Detail));
        Assert.Equal(Status.Pass, rows[1].Status);
    }

    [Fact]
    public void QueryError_SkipsEveryKey()
    {
        var rows = Check(new FakeProbe { KeyAges = "ERROR|The server is not operational." });

        Assert.All(rows, r => Assert.Equal("Not checked: could not query AD: The server is not operational.", r.Detail));
    }

    [Theory]
    [InlineData("")]
    [InlineData("contoso.com'; Remove-Item C:\\")]
    public void NoUsableDomain_RunsNothing(string domain)
    {
        var probe = new FakeProbe();
        Assert.All(Check(probe, domain), r => Assert.Equal("Not checked: no domain to ask", r.Detail));
        Assert.Throws<ArgumentException>(() => Diagnostics.KeyAgeScript(domain, ["krbtgt"]));
    }

    [Fact]
    public void Script_NamesOnlyTheDomainAndTheAccounts()
    {
        string script = Diagnostics.KeyAgeScript("contoso.com", ["AZUREADSSOACC$", "krbtgt"]);

        Assert.Contains("[adsi]'LDAP://contoso.com'", script);
        Assert.Contains("@('AZUREADSSOACC$','krbtgt')", script);
    }

    [Fact]
    public void EntraJoined_WithOnPremTgt_ChecksTheCloudKerberosKeyOnly()
    {
        var probe = new FakeProbe { KeyAges = Keys(10, 400, 10) };
        probe.Tools["dsregcmd /status"] = "AzureAdJoined : YES\nDomainJoined : NO\nDeviceAuthStatus : SUCCESS\nAzureAdPrt : YES\nOnPremTgt : YES\nCloudTgt : YES\n";

        var group = Diagnostics.TestEntraSso(new DiagConfig("contoso.com", "", default), probe);

        Assert.DoesNotContain(group.Tests, t => t.Name == "Seamless SSO Key");
        Assert.Equal(Status.Warn, group.Tests.Single(t => t.Name == "Cloud Kerberos Key").Status);
    }
}
