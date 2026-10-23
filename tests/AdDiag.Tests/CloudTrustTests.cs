using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// Cloud Kerberos trust on an Entra joined PC: group memberships the Entra Kerberos server object's policy denies
public class CloudTrustTests
{
    const string Dsreg = "AzureAdJoined : YES\nDomainJoined : NO\nDeviceAuthStatus : SUCCESS\nAzureAdPrt : YES\nCloudTgt : YES\nOnPremTgt : NO\n";
    const string Policy = "DENY|S-1-5-21-1-2-3-512|Domain Admins\nDENY|S-1-5-32-544|Administrators\nALLOW|S-1-5-21-1-2-3-513|Domain Users";

    static TestGroup Run(string cloudTrust, string domain = "contoso.com", string? upn = "jdoe@contoso.com")
    {
        var probe = new FakeProbe { CloudTrust = cloudTrust, Upn = upn };
        probe.Tools["dsregcmd /status"] = Dsreg;
        probe.Hosts["login.microsoftonline.com"] = [System.Net.IPAddress.Parse("20.190.151.68")];
        probe.OpenPorts.Add(443);
        return Diagnostics.TestEntraSso(new DiagConfig(domain, "", default), probe);
    }

    static TestEntry Row(TestGroup group) => Assert.Single(group.Tests, t => t.Name == "Cloud Trust Groups");

    [Fact]
    public void DomainAdmin_IsBlocked_AndTheVerdictIsCloudOnly()
    {
        var group = Run("USER|S-1-5-21-1-2-3-1105\nGROUP|S-1-5-21-1-2-3-513\nGROUP|S-1-5-21-1-2-3-512\nGROUP|S-1-5-32-544\n" + Policy);

        var row = Row(group);
        Assert.Equal(Status.Warn, row.Status);
        Assert.StartsWith("Member of Domain Admins, Administrators", row.Detail);
        Assert.Equal(new Readiness(Status.Warn, "Ready for cloud apps, not for on-premises resources.", true), group.Readiness);
    }

    [Fact]
    public void OrdinaryUser_Passes() =>
        Assert.Equal(Status.Pass, Row(Run("USER|S-1-5-21-1-2-3-1105\nGROUP|S-1-5-21-1-2-3-513\n" + Policy)).Status);

    [Fact]
    public void NotInAnyAllowedGroup_Warns()
    {
        var row = Row(Run("USER|S-1-5-21-1-2-3-1105\nGROUP|S-1-5-21-1-2-3-999\n" + Policy));

        Assert.Equal(Status.Warn, row.Status);
        Assert.StartsWith("Not in any group the Microsoft Entra Kerberos server object allows (Domain Users)", row.Detail);
    }

    [Theory]
    [InlineData("NOSERVER", "Info", "No Microsoft Entra Kerberos server object in contoso.com")]
    [InlineData("NOUSER", "Skip", "Not checked: no account with UPN jdoe@contoso.com in contoso.com")]
    [InlineData("ERROR|The server is not operational.", "Skip", "Not checked: could not query AD: The server is not operational.")]
    public void Problems_AreReported(string output, string status, string detail)
    {
        var row = Row(Run(output));
        Assert.Equal(Enum.Parse<Status>(status), row.Status);
        Assert.StartsWith(detail, row.Detail);
    }

    [Theory]
    [InlineData("", "jdoe@contoso.com")]
    [InlineData("contoso.com", null)]
    [InlineData("contoso.com", "o'brien@contoso.com")]  // a quote would end the script's string
    [InlineData("contoso.com", "*)(cn=*@contoso.com")]  // LDAP filter characters
    public void NothingUsableToAskWith_IsNotChecked(string domain, string? upn) =>
        Assert.Equal(Status.Skip, Row(Run(Policy, domain, upn)).Status);

    [Fact]
    public void Script_RefusesWhatItCannotQuoteSafely()
    {
        Assert.Throws<ArgumentException>(() => Diagnostics.CloudTrustScript("contoso.com", "o'brien@contoso.com"));
        Assert.Contains("(userPrincipalName=jdoe@contoso.com)", Diagnostics.CloudTrustScript("contoso.com", "jdoe@contoso.com"));
    }
}
