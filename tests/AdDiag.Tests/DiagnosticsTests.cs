using System.Net;
using System.Net.Sockets;
using Xunit;

namespace AdDiag.Tests;

// The verdict each check reaches from what the machine reports, with the machine faked.
public class DiagnosticsTests
{
    const string Domain = "contoso.com";
    internal static readonly IPAddress DcIp = IPAddress.Parse("10.20.0.11");
    internal static readonly IPAddress ClientIp = IPAddress.Parse("10.20.4.18");

    internal sealed class FakeProbe : IProbe
    {
        // Keyed by the start of "tool arguments"; a tool with no entry behaves as one that never answers
        public Dictionary<string, string> Tools = new();
        public List<string> ToolCalls = [];
        public string PasswordAge = $"OK|contoso.com|{DateTime.UtcNow.AddDays(-10):o}";
        public string Rsop = $"SCOPE|Computer|OK|{DateTime.UtcNow.AddHours(-1):o}|HQ\nGPO|Computer|{{A}}|1|1|1|0|1|Default Domain Policy\nGPO|Computer|{{B}}|0|1|1|1|1|Server Hardening";
        public Dictionary<string, IPAddress[]> Hosts = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<int> OpenPorts = [];
        public List<int> ConnectCalls = [];
        public Dictionary<string, List<string>?> Srv = new();
        public Func<string, int?> Share = _ => 3;
        public List<string> ShareCalls = [];
        public (string, string) Suffixes = ("contoso.com,corp.contoso.com", "contoso.com");
        public (string, string) Identity = ("PC042", "contoso.com");
        public List<NetAdapter> NetAdapters = [new("Ethernet", "Intel(R) Ethernet Connection", false, true, [ClientIp], [DcIp])];
        public Dictionary<string, SoaRecord> Soa = new(StringComparer.OrdinalIgnoreCase);
        public List<string> SoaCalls = [];
        public List<IPAddress?> SoaServers = [];
        // What one DNS server answers, where it differs from Soa; null for a server that never answers
        public Dictionary<IPAddress, Dictionary<string, SoaRecord>?> SoaByServer = new();
        // What a DNS server holds for a name; the server is null when the configured servers are asked
        public Func<string, IPAddress?, IPAddress[]> Records = (_, _) => [ClientIp];
        public bool Elevated = true;
        public Func<string> DnsEvents = () => "EVENTS|0";
        public int DnsEventQueries;

        public string RunTool(string tool, string arguments, int timeoutMs, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            string call = $"{tool} {arguments}".Trim();
            ToolCalls.Add(call);
            string? key = Tools.Keys.OrderByDescending(k => k.Length).FirstOrDefault(k => call.StartsWith(k, StringComparison.Ordinal));
            return key != null ? Tools[key] : throw new TimeoutException($"{tool} timed out after {timeoutMs / 1000}s");
        }

        public string RunPowerShell(string script, int timeoutMs, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (script.Contains("Get-WinEvent"))
            {
                DnsEventQueries++;
                return DnsEvents();
            }
            return script.Contains("pwdLastSet") ? PasswordAge : Rsop;
        }

        public IPAddress[] Resolve(string host, CancellationToken ct) =>
            Hosts.TryGetValue(host, out var ips) ? ips : throw new SocketException((int)SocketError.HostNotFound);

        public Task<bool> TcpConnect(IPAddress ip, int port, CancellationToken ct)
        {
            lock (ConnectCalls) ConnectCalls.Add(port);
            return Task.FromResult(OpenPorts.Contains(port));
        }

        public List<string>? QuerySrv(string record, CancellationToken ct) => Srv.GetValueOrDefault(record);

        public int? ShareEntries(string path, CancellationToken ct)
        {
            ShareCalls.Add(path);
            return Share(path);
        }

        public string CurrentUser() => @"CONTOSO\jdoe";
        public (string SearchList, string Domain) DnsSuffixConfig() => Suffixes;
        public string?[] OwnDomainNames() => ["CONTOSO", "contoso.com"];
        public (string Host, string Suffix) HostIdentity() => Identity;
        public List<NetAdapter> Adapters() => NetAdapters;

        public SoaRecord? QuerySoa(string name, IPAddress? server, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            SoaCalls.Add(name);
            SoaServers.Add(server);
            if (server == null || !SoaByServer.TryGetValue(server, out var zones))
                return Soa.GetValueOrDefault(name);
            return zones != null ? zones.GetValueOrDefault(name) : throw new TimeoutException($"SOA query for {name} timed out after 8s");
        }

        public IPAddress[] QueryAddresses(string name, IPAddress? server, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Records(name, server);
        }

        public bool IsElevated() => Elevated;
    }

    // A machine where everything works
    internal static FakeProbe Healthy() => new()
    {
        Tools =
        {
            ["dsregcmd /status"] = "  AzureAdJoined : NO\n  DomainJoined : YES\n",
            ["nltest /sc_verify"] = Samples.NltestScVerify,
            ["nltest /dsgetsite"] = Samples.NltestDsGetSite,
            ["nltest /dsgetdc"] = Samples.NltestDsGetDc,
            ["nltest /domain_trusts"] = Samples.NltestTrusts,
            ["klist"] = Samples.Klist,
            ["w32tm /stripchart"] = Samples.W32tmStripchart,
            ["w32tm /query /source"] = Samples.W32tmSource,
            ["ipconfig /registerdns"] = Samples.IpconfigRegisterDns,
        },
        Hosts = { [Domain] = [DcIp], ["DC01.contoso.com"] = [DcIp] },
        OpenPorts = [389, 636, 88, 445, 135, 464, 53, 3268],
        Srv =
        {
            ["_ldap._tcp.contoso.com"] = ["dc01.contoso.com:389"],
            ["_kerberos._tcp.contoso.com"] = ["dc01.contoso.com:88"],
            ["_gc._tcp.contoso.com"] = ["dc01.contoso.com:3268"],
        },
        Soa = { [Domain] = new(Domain, "dc01.contoso.com") },
    };

    static DiagConfig Config(string dc = "", CancellationToken ct = default) => new(Domain, dc, ct);

    static Status StatusOf(TestGroup group, string test) => group.Tests.Single(t => t.Name == test).Status;
    static string DetailOf(TestGroup group, string test) => group.Tests.Single(t => t.Name == test).Detail;

    [Fact]
    public void HealthyMachine_NothingFailsOrWarns()
    {
        var probe = Healthy();
        var groups = new[]
        {
            Diagnostics.TestDomainMembership(Config(), probe), Diagnostics.TestDcConnectivity(Config(), probe),
            Diagnostics.TestDnsForAd(Config(), probe), Diagnostics.TestSysvolNetlogon(Config(), probe),
            Diagnostics.TestGroupPolicy(Config(), probe), Diagnostics.TestTrusts(Config(), probe),
            Diagnostics.TestKerberosAndTime(Config(), probe), Diagnostics.TestDnsRegistration(Config(), probe),
        };
        Assert.Equal(35, groups.Sum(g => g.Tests.Count));
        Assert.All(groups.SelectMany(g => g.Tests), t => Assert.True(t.Status == Status.Pass, $"{t.Name}: {t.Status} — {t.Detail}"));
    }

    // The original hang: tools that never answer must leave every test with a verdict
    [Fact]
    public void Membership_ToolsThatNeverAnswer_AreReportedNotWaitedFor()
    {
        var group = Diagnostics.TestDomainMembership(Config(), new FakeProbe { PasswordAge = "" });
        Assert.Equal(5, group.Tests.Count);
        Assert.Equal(Status.Fail, StatusOf(group, "Domain Joined"));
        Assert.Contains("timed out", DetailOf(group, "Domain Joined"));
        Assert.Equal(Status.Warn, StatusOf(group, "Secure Channel"));
        Assert.Equal(Status.Warn, StatusOf(group, "Site Assignment"));
        Assert.Equal(Status.Warn, StatusOf(group, "Computer Password Age"));
        Assert.Equal(Status.Pass, StatusOf(group, "Logged-on User"));
    }

    [Fact]
    public void Membership_CancelledRun_StartsNoTools()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var probe = Healthy();
        Diagnostics.TestDomainMembership(Config(ct: cts.Token), probe);
        Assert.Empty(probe.ToolCalls);
    }

    [Theory]
    [InlineData(Samples.NltestScVerifyBroken, "Fail")]
    [InlineData(Samples.NltestScVerifyAccessDenied, "Warn")]
    public void Membership_SecureChannelVerdict(string nltest, string expected)
    {
        var probe = Healthy();
        probe.Tools["nltest /sc_verify"] = nltest;
        Assert.Equal(expected, StatusOf(Diagnostics.TestDomainMembership(Config(), probe), "Secure Channel").ToString());
    }

    [Theory]
    [InlineData(10, "Pass")]
    [InlineData(60, "Warn")]
    [InlineData(120, "Fail")]
    public void Membership_PasswordAgeThresholds(int days, string expected)
    {
        var probe = Healthy();
        probe.PasswordAge = $"OK|contoso.com|{DateTime.UtcNow.AddDays(-days):o}";
        Assert.Equal(expected, StatusOf(Diagnostics.TestDomainMembership(Config(), probe), "Computer Password Age").ToString());
    }

    [Fact]
    public void DcConnectivity_RequiredPortClosedFails_OptionalPortClosedWarns()
    {
        var probe = Healthy();
        probe.OpenPorts.Remove(445);
        probe.OpenPorts.Remove(636);
        var group = Diagnostics.TestDcConnectivity(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Port 445 (SMB)"));
        Assert.Equal(Status.Warn, StatusOf(group, "Port 636 (LDAPS)"));
        Assert.Equal(Status.Pass, StatusOf(group, "Port 389 (LDAP)"));
    }

    [Fact]
    public void DcConnectivity_UnresolvableDc_SkipsPortsWithoutConnecting()
    {
        var probe = Healthy();
        probe.Hosts.Clear();
        var group = Diagnostics.TestDcConnectivity(Config(), probe);
        Assert.Equal(Status.Pass, StatusOf(group, "Locate DC"));
        Assert.All(group.Tests.Where(t => t.Name.StartsWith("Port ")), t => Assert.Equal(Status.Skip, t.Status));
        Assert.Empty(probe.ConnectCalls);
    }

    [Fact]
    public void DcConnectivity_NoDcLocated_FailsAndFallsBackToTheDomainName()
    {
        var probe = Healthy();
        probe.Tools["nltest /dsgetdc"] = Samples.NltestDsGetDcFailed;
        var group = Diagnostics.TestDcConnectivity(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Locate DC"));
        Assert.Contains(Domain, DetailOf(group, "Port 389 (LDAP)"));
    }

    [Fact]
    public void Dns_MissingRequiredSrvFails_MissingGcWarns()
    {
        var probe = Healthy();
        probe.Srv.Clear();
        var group = Diagnostics.TestDnsForAd(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "_ldap._tcp SRV"));
        Assert.Equal(Status.Fail, StatusOf(group, "_kerberos._tcp SRV"));
        Assert.Equal(Status.Warn, StatusOf(group, "_gc._tcp SRV"));
    }

    [Fact]
    public void Dns_UnresolvableDomainFails_AndSuffixListWithoutDomainWarns()
    {
        var probe = Healthy();
        probe.Hosts.Clear();
        probe.Suffixes = ("fabrikam.com", "fabrikam.com");
        var group = Diagnostics.TestDnsForAd(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "DC A Record"));
        Assert.Equal(Status.Warn, StatusOf(group, "DNS Suffix Search List"));
    }

    // Opening a share on a domain that doesn't answer is the call that blocked for minutes
    [Fact]
    public void Shares_NotOpenedWhenSmbDoesNotAnswer()
    {
        var probe = Healthy();
        probe.OpenPorts.Remove(445);
        var group = Diagnostics.TestSysvolNetlogon(Config(), probe);
        Assert.All(group.Tests, t => Assert.Equal(Status.Fail, t.Status));
        Assert.Contains("port 445", DetailOf(group, "SYSVOL Access"));
        Assert.Empty(probe.ShareCalls);
    }

    [Fact]
    public void Shares_NotOpenedWhenTheDomainDoesNotResolve()
    {
        var probe = Healthy();
        probe.Hosts.Clear();
        var group = Diagnostics.TestSysvolNetlogon(Config(), probe);
        Assert.All(group.Tests, t => Assert.Equal(Status.Fail, t.Status));
        Assert.Empty(probe.ShareCalls);
    }

    [Fact]
    public void Shares_MissingFails_AccessDeniedWarns_TimeoutFails()
    {
        var probe = Healthy();
        probe.Share = path => path.EndsWith("SYSVOL") ? null : throw new UnauthorizedAccessException();
        var group = Diagnostics.TestSysvolNetlogon(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "SYSVOL Access"));
        Assert.Equal(Status.Warn, StatusOf(group, "NETLOGON Access"));

        probe.Share = path => throw new TimeoutException($"Opening {path} timed out after 20s");
        group = Diagnostics.TestSysvolNetlogon(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "SYSVOL Access"));
        Assert.Contains("timed out", DetailOf(group, "SYSVOL Access"));
    }

    [Fact]
    public void GroupPolicy_NoResults_WarnsAndSkips()
    {
        var group = Diagnostics.TestGroupPolicy(Config(), new FakeProbe { Rsop = "" });
        Assert.Equal(Status.Warn, StatusOf(group, "GP Last Refresh"));
        Assert.Equal(Status.Skip, StatusOf(group, "Applied GPOs"));
        Assert.Equal(Status.Skip, StatusOf(group, "Denied GPOs"));
    }

    [Fact]
    public void GroupPolicy_StaleRefreshFails()
    {
        var probe = new FakeProbe { Rsop = $"SCOPE|Computer|OK|{DateTime.UtcNow.AddDays(-30):o}|HQ\nGPO|Computer|{{A}}|1|1|1|0|1|Default Domain Policy" };
        var group = Diagnostics.TestGroupPolicy(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "GP Last Refresh"));
        Assert.Equal(Status.Pass, StatusOf(group, "Applied GPOs"));
    }

    [Fact]
    public void Trusts_NltestFailureWarns()
    {
        var probe = Healthy();
        probe.Tools["nltest /domain_trusts"] = Samples.NltestTrustsFailed;
        Assert.Equal(Status.Warn, StatusOf(Diagnostics.TestTrusts(Config(), probe), "Domain Trusts"));
    }

    [Fact]
    public void Kerberos_NoCachedTgt_RequestsOne()
    {
        var probe = Healthy();
        probe.Tools["klist"] = Samples.KlistEmpty;
        probe.Tools["klist get"] = Samples.KlistGetSuccess;
        var group = Diagnostics.TestKerberosAndTime(Config(), probe);
        Assert.Equal(Status.Pass, StatusOf(group, "TGT Present"));
        Assert.Contains("klist get krbtgt/CONTOSO.COM", probe.ToolCalls);

        probe.Tools["klist get"] = Samples.KlistGetFailed;
        Assert.Equal(Status.Fail, StatusOf(Diagnostics.TestKerberosAndTime(Config(), probe), "TGT Present"));
    }

    [Fact]
    public void Kerberos_SkewBeyondFiveMinutesFails_ForeignTimeSourceWarns()
    {
        var probe = Healthy();
        probe.Tools["w32tm /stripchart"] = Samples.W32tmStripchartNegative;
        probe.Tools["w32tm /query /source"] = "time.windows.com,0x9\r\n";
        var group = Diagnostics.TestKerberosAndTime(Config(), probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Clock Skew"));
        Assert.Equal(Status.Warn, StatusOf(group, "Time Source"));
    }

    [Fact]
    public void Kerberos_UsesTheGivenDcForTheClockCheck()
    {
        var probe = Healthy();
        Diagnostics.TestKerberosAndTime(Config(dc: "DC02.contoso.com"), probe);
        Assert.Contains(probe.ToolCalls, c => c.StartsWith("w32tm /stripchart /computer:DC02.contoso.com "));
    }
}
