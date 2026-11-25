using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// Credentials & Windows Hello: Hello and its trust, sign-in methods, the TPM, ticket encryption and saved credentials
public class CredentialsTests
{
    const string Sid = "S-1-12-1-1000";
    const string AesKlist = """

        Current LogonId is 0:0x3e7a1

        Cached Tickets: (1)

        #0>	Client: alice @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        	Session Key Type: AES-256-CTS-HMAC-SHA1-96
        """;

    const string Cmdkey = """

        Currently stored credentials:

            Target: Domain:target=fs01.contoso.com
            Type: Domain Password
            User: CONTOSO\alice

            Target: LegacyGeneric:target=git:https://github.com
            Type: Generic
            User: alice

            Target: MicrosoftAccount:user=alice@outlook.com
            Type: Generic
            Local machine persistence
        """;

    static string Dsreg(string entra = "YES", string domain = "NO", string ngc = "YES", string tpm = "YES") => $"""
                     AzureAdJoined : {entra}
                      DomainJoined : {domain}
                      TpmProtected : {tpm}
                            NgcSet : {ngc}
        """;

    static FakeProbe Machine(string dsreg, string klist = AesKlist, string cmdkey = "\r\nCurrently stored credentials:\r\n\r\n* NONE *\r\n")
    {
        var probe = new FakeProbe { Sid = Sid };
        probe.Tools["dsregcmd /status"] = dsreg;
        probe.Tools["klist"] = klist;
        probe.Tools["cmdkey /list"] = cmdkey;
        return probe;
    }

    static TestGroup Run(FakeProbe probe) => Diagnostics.TestCredentials(new DiagConfig("contoso.com", "", default), probe);
    static TestEntry Entry(TestGroup group, string name) => Assert.Single(group.Tests, t => t.Name == name);

    [Fact]
    public void Hello_CloudTrustByGroupPolicy_AndBiometrics()
    {
        var probe = Machine(Dsreg());
        probe.Registry[@"SOFTWARE\Policies\Microsoft\PassportForWork"] = new() { ["UseCloudTrustForOnPremAuth"] = 1 };
        probe.Registry[$@"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{Sid}"] = new() { ["EnrolledFactors"] = 0x0A };

        var group = Run(probe);

        Assert.Equal(["Windows Hello", "Hello Trust", "Sign-in Methods", "TPM", "Ticket Encryption", "Saved Credentials"],
            group.Tests.Select(t => t.Name));
        Assert.Equal("Cloud Kerberos trust, set by Group Policy", Entry(group, "Hello Trust").Detail);
        Assert.Equal("PIN, fingerprint, face", Entry(group, "Sign-in Methods").Detail);
        Assert.Equal(Status.Pass, Entry(group, "TPM").Status);
        Assert.Contains("TpmProtected: YES", Entry(group, "TPM").Detail);
    }

    [Fact]
    public void Hello_TrustFromIntune_ReadsTheTenantsPolicy()
    {
        var probe = Machine(Dsreg());
        probe.Registry[@"SOFTWARE\Microsoft\Policies\PassportForWork\72f988bf-0000-4000-8000-000000000001\Device\Policies"] =
            new() { ["UseCertificateForOnPremAuth"] = "true" };

        Assert.Equal("Certificate trust, set by Intune", Entry(Run(probe), "Hello Trust").Detail);
    }

    [Theory]
    [InlineData("YES", "NO", "Info")]  // Entra joined: Hello reaches cloud apps only
    [InlineData("YES", "YES", "Pass")] // hybrid: key trust
    public void Hello_NoTrustSet_DependsOnTheJoin(string entra, string domain, string status) =>
        Assert.Equal(Enum.Parse<Status>(status), Entry(Run(Machine(Dsreg(entra, domain))), "Hello Trust").Status);

    [Fact]
    public void Hello_NotSetUp_IsANoteWithNoTrustOrMethodRows()
    {
        var group = Run(Machine(Dsreg(ngc: "NO")));

        Assert.Equal(Status.Info, Entry(group, "Windows Hello").Status);
        Assert.DoesNotContain(group.Tests, t => t.Name is "Hello Trust" or "Sign-in Methods");
    }

    // A local account's PIN, a personal Microsoft account, a passkey and an app's key; another user's key is left out
    static readonly string HelloKeyStore = $"""
        Microsoft Passport Key Storage Provider:
          {Sid}/a8704955-0000-4000-8000-000000000001/{Sid}//uvkey-C12AA6914D51832372A87791933508D7
          RSA


          {Sid}/a8704955-0000-4000-8000-000000000001/FIDO_AUTHENTICATOR//901de5b86ca5875505f8_5364
          ECDSA_P256
          RSA


          {Sid}/a8704955-0000-4000-8000-000000000001/app.0000//BIO_E9DF75DEE7694EBA
          RSA


          {Sid}/a8704955-0000-4000-8000-000000000001/login.live.com//542e980917c83113
          RSA


          S-1-5-21-1-2-3-1002/b1/login.windows.net//other-user
          RSA

        CertUtil: -key command completed successfully.
        """;

    [Fact]
    public void Hello_NotForBusiness_ReadsTheKeyStore()
    {
        var probe = Machine(Dsreg(ngc: "NO"));
        probe.Tools["certutil -csp"] = HelloKeyStore;

        var entry = Entry(Run(probe), "Windows Hello");

        Assert.Equal(Status.Info, entry.Status);
        Assert.Equal("Set up for this user: a PIN, a personal Microsoft account, a passkey and a key for another app; none for a work account (NgcSet: NO)", entry.Detail);
    }

    [Fact]
    public void Hello_KeyStoreEmpty_SaysPassword()
    {
        var probe = Machine(Dsreg(ngc: "NO"));
        probe.Tools["certutil -csp"] = "Microsoft Passport Key Storage Provider:\nCertUtil: -key command completed successfully.\n";

        Assert.StartsWith("Not set up for this user (NgcSet: NO, no Windows Hello keys)", Entry(Run(probe), "Windows Hello").Detail);
    }

    [Fact]
    public void HelloKeys_WorkAccount_AndOnlyTheUsersOwn()
    {
        Assert.Equal(new Diagnostics.HelloKeys(false, true, false, 0, 0),
            Diagnostics.ParseHelloKeys("  S-1-5-21-1-2-3-1002/b1/login.windows.net//k\n", "S-1-5-21-1-2-3-1002"));
        Assert.True(Diagnostics.ParseHelloKeys(HelloKeyStore, "S-1-5-21-9-9-9-1003").IsEmpty);
    }

    [Fact]
    public void HelloPolicy_Denied_NeedsAdmin()
    {
        var probe = Machine(Dsreg());
        probe.Denied.Add(@"SOFTWARE\Policies\Microsoft\PassportForWork");

        var entry = Entry(Run(probe), "Hello Trust");

        Assert.Equal(Status.Skip, entry.Status);
        Assert.True(entry.NeedsAdmin);
    }

    [Fact]
    public void Biometrics_Denied_NeedsAdmin()
    {
        var probe = Machine(Dsreg());
        probe.Denied.Add($@"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{Sid}");

        var entry = Entry(Run(probe), "Sign-in Methods");

        Assert.Equal(Status.Skip, entry.Status);
        Assert.True(entry.NeedsAdmin);
    }

    [Theory]
    [InlineData(null, "YES", "NO", "Warn")]  // Entra joined without a TPM
    [InlineData(null, "NO", "YES", "Info")]  // domain joined only: nothing of Entra's to protect
    [InlineData(2, "NO", "YES", "Pass")]
    [InlineData(1, "YES", "NO", "Warn")]     // TPM 1.2
    public void Tpm_ByVersionAndJoin(int? version, string entra, string domain, string status)
    {
        var probe = Machine(Dsreg(entra, domain));
        probe.Tpm = version;
        Assert.Equal(Enum.Parse<Status>(status), Entry(Run(probe), "TPM").Status);
    }

    [Fact]
    public void Tpm_DeviceKeyOutsideTheTpm_Warns()
    {
        var entry = Entry(Run(Machine(Dsreg(tpm: "NO"))), "TPM");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("TpmProtected: NO", entry.Detail);
    }

    [Fact]
    public void TicketEncryption_Rc4_WarnsWithTheService()
    {
        var entry = Entry(Run(Machine(Dsreg(), klist: Samples.Klist)), "Ticket Encryption");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.StartsWith("RC4 on cifs/DC01.contoso.com", entry.Detail);
    }

    [Fact]
    public void TicketEncryption_AllAes_Passes() =>
        Assert.Equal("The cached ticket uses AES", Entry(Run(Machine(Dsreg())), "Ticket Encryption").Detail);

    [Fact]
    public void SavedCredentials_OnlyWindowsCredentialsCount()
    {
        Assert.Equal(["fs01.contoso.com"], Diagnostics.ParseSavedTargets(Cmdkey));

        var entry = Entry(Run(Machine(Dsreg(), cmdkey: Cmdkey)), "Saved Credentials");
        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("fs01.contoso.com", entry.Detail);
    }

    [Fact]
    public void SavedCredentials_None_Passes() =>
        Assert.Equal(Status.Pass, Entry(Run(Machine(Dsreg())), "Saved Credentials").Status);
}
