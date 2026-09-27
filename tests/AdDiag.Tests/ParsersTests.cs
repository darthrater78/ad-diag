using System.Globalization;
using System.Net;
using Xunit;

namespace AdDiag.Tests;

public class ParsersTests
{
    public static TheoryData<bool> LineEndings => new() { false, true };

    static string Eol(string s, bool crlf) => crlf ? Samples.Crlf(s) : s;

    // ── gpresult ───────────────────────────────────────────

    [Theory, MemberData(nameof(LineEndings))]
    public void GpResult_ParsesBothScopes(bool crlf)
    {
        var scopes = Parsers.ParseGpResult(Eol(Samples.GpResult, crlf));

        Assert.Equal(["Computer", "User"], scopes.Select(s => s.Name));

        var computer = scopes[0];
        Assert.Equal("7/16/2026 at 9:58:41 AM", computer.LastApplied);
        Assert.Equal("HQ", computer.Site);
        Assert.Equal(["Workstation Baseline", "Default Domain Policy"], computer.Applied);
        Assert.Equal([("Local Group Policy", "Not Applied (Empty)"), ("Server Hardening", "Denied (Security)")], computer.Denied);

        var user = scopes[1];
        Assert.Equal("7/16/2026 at 10:01:12 AM", user.LastApplied);
        Assert.Equal("HQ", user.Site);
        Assert.Equal(["Drive Mappings"], user.Applied);
        Assert.Equal([("Local Group Policy", "Not Applied (Empty)")], user.Denied);
    }

    [Theory, MemberData(nameof(LineEndings))]
    public void GpResult_UserOnly_IgnoresNA(bool crlf)
    {
        var scope = Assert.Single(Parsers.ParseGpResult(Eol(Samples.GpResultUserOnly, crlf)));
        Assert.Equal("User", scope.Name);
        Assert.Empty(scope.Applied);
        Assert.Empty(scope.Denied);
    }

    [Fact]
    public void GpResult_Unrecognised_ReturnsNoScopes() =>
        Assert.Empty(Parsers.ParseGpResult("ERROR: Access denied."));

    [Fact]
    public void GpTime_ParsesGpresultFormat()
    {
        var saved = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
        try
        {
            Assert.Equal(new DateTime(2026, 7, 16, 9, 58, 41), Parsers.ParseGpTime("7/16/2026 at 9:58:41 AM"));
            Assert.Null(Parsers.ParseGpTime("not a date"));
        }
        finally { CultureInfo.CurrentCulture = saved; }
    }

    // ── klist ──────────────────────────────────────────────

    [Theory, MemberData(nameof(LineEndings))]
    public void Klist_ParsesTickets(bool crlf)
    {
        var (headers, tickets) = Parsers.ParseKlist(Eol(Samples.Klist, crlf));

        Assert.Equal(["Current LogonId is 0:0x3e7a1", "Cached Tickets: (2)"], headers);
        Assert.Equal(2, tickets.Count);

        var tgt = tickets[0];
        Assert.Equal("krbtgt/CONTOSO.COM @ CONTOSO.COM", tgt.Server);
        Assert.Equal("alice @ CONTOSO.COM", tgt.Fields["Client"]);
        Assert.Equal("AES-256-CTS-HMAC-SHA1-96", tgt.Fields["KerbTicket Encryption Type"]);
        Assert.StartsWith("0x40e10000 -> forwardable", tgt.Fields["Ticket Flags"]);
        Assert.Equal("0x1 -> PRIMARY", tgt.Fields["Cache Flags"]);
        Assert.Equal("7/16/2026 19:58:40 (local)", tgt.Fields["End Time"]);
        Assert.Equal("DC01.contoso.com", tgt.Fields["kdc called"]); // keys are case-insensitive

        Assert.Equal("cifs/DC01.contoso.com @ CONTOSO.COM", tickets[1].Server);
        Assert.Equal("RSADSI RC4-HMAC(NT)", tickets[1].Fields["KerbTicket Encryption Type"]);
    }

    [Fact]
    public void Klist_EmptyCache_HasHeadersButNoTickets()
    {
        var (headers, tickets) = Parsers.ParseKlist(Samples.KlistEmpty);
        Assert.Equal(2, headers.Count);
        Assert.Empty(tickets);
    }

    [Theory]
    [InlineData("")]
    [InlineData("klist failed with 0xc000005f/-1073741729: A specified logon session does not exist. It may already have been terminated. (no credentials)")]
    public void Klist_NoCredentials_IsEmpty(string raw)
    {
        var (headers, tickets) = Parsers.ParseKlist(raw);
        Assert.Empty(headers);
        Assert.Empty(tickets);
    }

    // ── nltest ─────────────────────────────────────────────

    [Theory, MemberData(nameof(LineEndings))]
    public void DcLocator_FindsDc(bool crlf) =>
        Assert.Equal("DC01.contoso.com", Parsers.ParseDcLocator(Eol(Samples.NltestDsGetDc, crlf)));

    [Fact]
    public void DcLocator_Failure_ReturnsNull()
    {
        Assert.Null(Parsers.ParseDcLocator(Samples.NltestDsGetDcFailed));
        Assert.Equal("ERROR_NO_SUCH_DOMAIN", Parsers.NltestError(Samples.NltestDsGetDcFailed));
    }

    [Theory, MemberData(nameof(LineEndings))]
    public void Site_Success(bool crlf)
    {
        string output = Eol(Samples.NltestDsGetSite, crlf);
        Assert.Equal("HQ", Parsers.ParseSite(output));
        Assert.Null(Parsers.NltestError(output));
    }

    [Fact]
    public void Site_Failure_IsNotReportedAsSite()
    {
        Assert.Null(Parsers.ParseSite(Samples.NltestDsGetSiteFailed));
        Assert.Equal("ERROR_NO_SITENAME", Parsers.NltestError(Samples.NltestDsGetSiteFailed));
    }

    [Fact]
    public void Site_German() =>
        Assert.Equal("Zürich-HQ", Parsers.ParseSite(Samples.NltestDsGetSiteGerman));

    [Fact]
    public void DcLocator_German() =>
        Assert.Equal("DC01.contoso.com", Parsers.ParseDcLocator(Samples.NltestDsGetDcGerman));

    [Fact]
    public void NltestError_IgnoresSuccessStatuses() =>
        Assert.Null(Parsers.NltestError(Samples.NltestScVerify));

    [Theory]
    [InlineData(Samples.NltestScVerify)]
    [InlineData(Samples.NltestScVerifyGerman)]
    public void ScVerify_Healthy(string output)
    {
        var r = Parsers.ParseScVerify(output);
        Assert.True(r.Ok);
        Assert.False(r.AccessDenied);
        Assert.Equal("Verified with DC01.contoso.com", r.Detail);
    }

    [Theory]
    [InlineData(Samples.NltestScVerifyBroken)]
    [InlineData(Samples.NltestScVerifyBrokenGerman)]
    public void ScVerify_BrokenTrust_FailsDespiteCommandSuccess(string output)
    {
        var r = Parsers.ParseScVerify(output);
        Assert.False(r.Ok);
        Assert.False(r.AccessDenied);
        Assert.Equal("1311 0x51f ERROR_NO_LOGON_SERVERS", r.Detail);
    }

    [Fact]
    public void ScVerify_AccessDenied()
    {
        var r = Parsers.ParseScVerify(Samples.NltestScVerifyAccessDenied);
        Assert.False(r.Ok);
        Assert.True(r.AccessDenied);
    }

    [Fact]
    public void ScVerify_NoStatus_Fails() =>
        Assert.False(Parsers.ParseScVerify("The command completed successfully").Ok);

    [Fact]
    public void NltestError_FallsBackToHexStatus() =>
        Assert.Equal("0x77f", Parsers.NltestError("Getting DC Site failed: Status = 1919 0x77f"));

    static readonly string?[] OwnDomain = ["CONTOSO", "contoso.com"];

    [Theory, MemberData(nameof(LineEndings))]
    public void Trusts_ExcludesPrimaryDomain(bool crlf)
    {
        var trusts = Parsers.ParseTrusts(Eol(Samples.NltestTrusts, crlf), OwnDomain);
        Assert.Equal(2, trusts.Count);
        Assert.StartsWith("CHILD child.contoso.com (NT 5)", trusts[0]);
        Assert.StartsWith("FABRIKAM fabrikam.com (NT 5)", trusts[1]);
    }

    [Fact]
    public void Trusts_SingleDomain_IsEmpty() =>
        Assert.Empty(Parsers.ParseTrusts(Samples.NltestTrustsSingleDomain, OwnDomain));

    [Theory]
    [InlineData("CONTOSO", null)]
    [InlineData(null, "contoso.com")]
    [InlineData(null, null)] // falls back to the English "(Primary Domain)" marker
    public void Trusts_PrimaryDomain_MatchedByEitherName(string? netbios, string? dns) =>
        Assert.Empty(Parsers.ParseTrusts(Samples.NltestTrustsSingleDomain, [netbios, dns]));

    [Fact]
    public void Trusts_German_ExcludesPrimaryByName()
    {
        var trust = Assert.Single(Parsers.ParseTrusts(Samples.NltestTrustsGerman, OwnDomain));
        Assert.StartsWith("CHILD child.contoso.com", trust);
    }

    [Fact]
    public void Trusts_Failure_IsDetected()
    {
        Assert.Empty(Parsers.ParseTrusts(Samples.NltestTrustsFailed, OwnDomain));
        Assert.Equal("ERROR_NO_SUCH_DOMAIN", Parsers.NltestError(Samples.NltestTrustsFailed));
        Assert.Null(Parsers.NltestError(Samples.NltestTrusts));
    }

    // ── w32tm ──────────────────────────────────────────────

    [Theory]
    [InlineData("en-US")]
    [InlineData("de-DE")] // comma decimal separator; "." is the group separator
    [InlineData("fr-FR")]
    public void Skew_IsCultureInvariant(string culture)
    {
        var saved = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(culture);
        try
        {
            Assert.Equal(0.0206779, Parsers.ParseStripchartSkew(Samples.W32tmStripchart)!.Value, 7);
        }
        finally { CultureInfo.CurrentCulture = saved; }
    }

    [Fact]
    public void Skew_NegativeOffset_IsAbsolute() =>
        Assert.Equal(312.5, Parsers.ParseStripchartSkew(Samples.W32tmStripchartNegative)!.Value, 7);

    [Fact]
    public void Skew_Error_ReturnsNull() =>
        Assert.Null(Parsers.ParseStripchartSkew(Samples.W32tmStripchartError));

    [Fact]
    public void Skew_CommaDecimalOutput() =>
        Assert.Equal(0.0206779, Parsers.ParseStripchartSkew(Samples.W32tmStripchartComma)!.Value, 7);

    [Fact]
    public void TimeSource_Parses() =>
        Assert.Equal("DC01.contoso.com", Parsers.ParseTimeSource(Samples.W32tmSource));

    [Theory]
    [InlineData(Samples.W32tmSourceError)]
    [InlineData("")]
    public void TimeSource_Error_ReturnsNull(string output) =>
        Assert.Null(Parsers.ParseTimeSource(output));

    static IPAddress[] Resolve(string host) =>
        host == "contoso.com" ? [IPAddress.Parse("10.0.0.10"), IPAddress.Parse("10.0.0.11")] : throw new Exception("NXDOMAIN");

    [Theory]
    [InlineData("DC01.contoso.com", true)]
    [InlineData("dc01.CONTOSO.com,0x9", true)]
    [InlineData("contoso.com", true)]
    [InlineData("10.0.0.11", true)]
    [InlineData("10.0.0.99", false)]
    [InlineData("time.windows.com,0x9", false)]
    [InlineData("Local CMOS Clock", false)]
    [InlineData("Free-running System Clock", false)]
    [InlineData("VM IC Time Synchronization Provider", false)]
    [InlineData("evilcontoso.com", false)]
    public void TimeSource_DomainDetection(string source, bool expected) =>
        Assert.Equal(expected, Parsers.IsDomainTimeSource(source, "contoso.com", Resolve));

    [Fact]
    public void TimeSource_ResolveFailure_IsNotDomain() =>
        Assert.False(Parsers.IsDomainTimeSource("10.0.0.10", "fabrikam.com", Resolve));
}
