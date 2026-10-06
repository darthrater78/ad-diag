using System.Net;
using Xunit;
using FakeProbe = AdDiag.Tests.DiagnosticsTests.FakeProbe;

namespace AdDiag.Tests;

// Dynamic DNS registration: the read-only checks and the traced registration, with the machine faked.
public class DnsRegistrationTests
{
    static readonly IPAddress DcIp = DiagnosticsTests.DcIp, ClientIp = DiagnosticsTests.ClientIp;
    static readonly IPAddress HomeIp = IPAddress.Parse("192.168.1.50"), TunnelIp = IPAddress.Parse("100.64.0.7");
    static readonly IPAddress TunnelDns = IPAddress.Parse("100.64.0.2");

    static FakeProbe Healthy() => DiagnosticsTests.Healthy();

    // A laptop at home behind a ZTNA client: its own adapter registers a home address, the client's adapter doesn't register
    static FakeProbe BehindZtna()
    {
        var probe = Healthy();
        probe.NetAdapters =
        [
            new("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", false, true, [HomeIp], [TunnelDns]),
            new("Ethernet 3", "Zscaler Network Adapter 1.0.2.0", false, false, [TunnelIp], [TunnelDns]),
        ];
        return probe;
    }

    static DiagConfig Config(CancellationToken ct = default) => new("contoso.com", "", ct);
    static TestGroup Run(FakeProbe probe) => Diagnostics.TestDnsRegistration(Config(), probe);
    static Status StatusOf(TestGroup group, string test) => group.Tests.Single(t => t.Name == test).Status;
    static string DetailOf(TestGroup group, string test) => group.Tests.Single(t => t.Name == test).Detail;

    [Fact]
    public void Healthy_FindsTheZoneByWalkingUpFromTheHostName()
    {
        var probe = Healthy();
        var group = Run(probe);
        Assert.Equal(["Registration Name", "ZTNA / VPN Client", "Registering Adapters", "Zone Primary Server",
            "Update Path (Port 53)", "Registered Record", "Registration Errors"], group.Tests.Select(t => t.Name));
        Assert.Equal("PC042.contoso.com", DetailOf(group, "Registration Name"));
        Assert.Equal(["PC042.contoso.com", "contoso.com"], probe.SoaCalls);
        Assert.Equal("contoso.com -> dc01.contoso.com (10.20.0.11)", DetailOf(group, "Zone Primary Server"));
        Assert.Equal("dc01.contoso.com holds 10.20.4.18", DetailOf(group, "Registered Record"));
        Assert.Contains(53, probe.ConnectCalls);
    }

    [Fact]
    public void NoPrimarySuffix_WarnsAndSkipsTheServerChecks()
    {
        var probe = Healthy();
        probe.Identity = ("PC042", "");
        var group = Run(probe);
        Assert.Equal(Status.Warn, StatusOf(group, "Registration Name"));
        Assert.All(new[] { "Zone Primary Server", "Update Path (Port 53)", "Registered Record" },
            name => Assert.Equal(Status.Skip, StatusOf(group, name)));
        Assert.Empty(probe.SoaCalls);
    }

    [Theory]
    [InlineData("100.64.0.0", true)]
    [InlineData("100.127.255.255", true)]
    [InlineData("100.63.255.255", false)]
    [InlineData("100.128.0.0", false)]
    [InlineData("10.64.0.1", false)]
    [InlineData("fd00::1", false)]
    public void Cgnat_IsExactlyOneHundredSixtyFourSlashTen(string ip, bool expected) =>
        Assert.Equal(expected, Diagnostics.IsCgnat(IPAddress.Parse(ip)));

    [Fact]
    public void Ztna_DetectedByAdapterNameAndItsDnsProxy_IsInformational()
    {
        var group = Run(BehindZtna());
        Assert.Equal(Status.Pass, StatusOf(group, "ZTNA / VPN Client"));
        Assert.Equal("Zscaler adapter (100.64.0.7); DNS answered by its local proxy (100.64.0.2) (informational)", DetailOf(group, "ZTNA / VPN Client"));
        // The home address is what gets registered; that is worth saying but is how ZTNA clients work
        Assert.Equal(Status.Pass, StatusOf(group, "Registering Adapters"));
        Assert.StartsWith("Wi-Fi: 192.168.1.50 — behind the ZTNA client", DetailOf(group, "Registering Adapters"));
        Assert.Equal(Status.Warn, StatusOf(group, "Registered Record")); // DNS still holds the office address
        Assert.Contains("the record is stale", DetailOf(group, "Registered Record"));
    }

    [Fact]
    public void Ztna_UnknownTunnelAdapterDetected_WindowsOwnTunnelsAndLoopbackDnsAreNot()
    {
        var teredo = new NetAdapter("Teredo Tunneling Pseudo-Interface", "Microsoft Teredo Tunneling Adapter", true, false, [IPAddress.Parse("2001:0:1::1")], []);
        // A domain controller uses itself for DNS
        var dc = new NetAdapter("Ethernet", "Hyper-V Network Adapter", false, true, [DcIp], [IPAddress.Loopback]);
        Assert.Null(Diagnostics.DescribeZtna([teredo, dc]));

        var vpn = new NetAdapter("Corp VPN", "WAN Miniport (IKEv2)", true, true, [IPAddress.Parse("10.99.0.5")], [DcIp]);
        Assert.Equal("tunnel adapter \"Corp VPN\" (10.99.0.5)", Diagnostics.DescribeZtna([vpn]));
        var warp = new NetAdapter("CloudflareWARP", "Cloudflare WARP Interface Tunnel", true, false, [IPAddress.Parse("172.16.0.2")], [IPAddress.Parse("127.0.2.2")]);
        Assert.Equal("Cloudflare WARP adapter (172.16.0.2); DNS answered by its local proxy (127.0.2.2)", Diagnostics.DescribeZtna([warp]));
    }

    [Fact]
    public void Adapters_RegisteringATunnelAddressWarns_NoneRegisteringWarns()
    {
        var probe = BehindZtna();
        probe.NetAdapters[1] = probe.NetAdapters[1] with { RegistersInDns = true };
        var group = Run(probe);
        Assert.Equal(Status.Warn, StatusOf(group, "Registering Adapters"));
        Assert.Contains("100.64.0.7 is a 100.64.0.0/10 tunnel address", DetailOf(group, "Registering Adapters"));

        probe.NetAdapters = [new("Ethernet", "Intel", false, false, [ClientIp], [DcIp])];
        group = Run(probe);
        Assert.Equal(Status.Warn, StatusOf(group, "Registering Adapters"));
        Assert.Equal(Status.Pass, StatusOf(group, "Registered Record")); // nothing to compare with, so just reported
    }

    [Fact]
    public void Adapters_LinkLocalAddressesAreNotCounted()
    {
        var probe = Healthy();
        probe.NetAdapters = [new("Ethernet", "Intel", false, true, [IPAddress.Parse("fe80::1"), IPAddress.Parse("169.254.3.4"), ClientIp], [DcIp])];
        Assert.Equal("Ethernet: 10.20.4.18", DetailOf(Run(probe), "Registering Adapters"));
    }

    [Fact]
    public void Zone_NoSoaFails_AndBehindZtnaNamesTheProxy()
    {
        var probe = Healthy();
        probe.Soa.Clear();
        var group = Run(probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Zone Primary Server"));
        Assert.Equal("No SOA record for PC042.contoso.com or its parent zones", DetailOf(group, "Zone Primary Server"));
        Assert.Equal(Status.Skip, StatusOf(group, "Update Path (Port 53)"));
        // The record is still looked up, through the configured servers
        Assert.Equal("the configured DNS servers holds 10.20.4.18", DetailOf(group, "Registered Record"));

        probe = BehindZtna();
        probe.Soa.Clear();
        Assert.Contains("a ZTNA DNS proxy often answers only A/AAAA/SRV", DetailOf(Run(probe), "Zone Primary Server"));
    }

    [Fact]
    public void Zone_SoaLookupThatTimesOutFails()
    {
        var probe = Healthy();
        probe.Soa = null!; // QuerySoa throws
        var group = Run(probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Zone Primary Server"));
        Assert.StartsWith("SOA lookup failed:", DetailOf(group, "Zone Primary Server"));
    }

    [Fact]
    public void Zone_PrimaryWithASyntheticAddressWarns_UnresolvablePrimaryFails()
    {
        var probe = BehindZtna();
        probe.Hosts["dc01.contoso.com"] = [IPAddress.Parse("100.64.1.9")];
        var group = Run(probe);
        Assert.Equal(Status.Warn, StatusOf(group, "Zone Primary Server"));
        Assert.Contains("synthetic 100.64.0.0/10 address", DetailOf(group, "Zone Primary Server"));

        probe.Hosts.Remove("dc01.contoso.com");
        group = Run(probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Zone Primary Server"));
        Assert.Equal(Status.Skip, StatusOf(group, "Update Path (Port 53)"));
    }

    [Fact]
    public void UpdatePath_ClosedPortFails_AndBehindZtnaNamesThePolicy()
    {
        var probe = Healthy();
        probe.OpenPorts.Remove(53);
        var group = Run(probe);
        Assert.Equal(Status.Fail, StatusOf(group, "Update Path (Port 53)"));
        Assert.DoesNotContain("ZTNA", DetailOf(group, "Update Path (Port 53)"));

        probe = BehindZtna();
        probe.OpenPorts.Remove(53);
        Assert.Contains("the ZTNA policy must allow TCP and UDP 53", DetailOf(Run(probe), "Update Path (Port 53)"));
    }

    [Fact]
    public void Record_MissingWarns_PartlyStaleWarns_TunnelAddressWarns()
    {
        var probe = Healthy();
        probe.Records = (_, _) => [];
        Assert.Equal(Status.Warn, StatusOf(Run(probe), "Registered Record"));
        Assert.Contains("it is not registered", DetailOf(Run(probe), "Registered Record"));

        probe.Records = (_, _) => [ClientIp, HomeIp];
        Assert.Equal(Status.Warn, StatusOf(Run(probe), "Registered Record"));
        Assert.EndsWith("this machine no longer has 192.168.1.50", DetailOf(Run(probe), "Registered Record"));

        probe.NetAdapters = [new("Ethernet 3", "Zscaler Network Adapter", false, true, [TunnelIp], [DcIp])];
        probe.Records = (_, _) => [TunnelIp];
        Assert.Equal(Status.Warn, StatusOf(Run(probe), "Registered Record"));
    }

    [Fact]
    public void Record_AsksThePrimaryItself_AndFallsBackWhenItDoesNotAnswer()
    {
        var probe = Healthy();
        var asked = new List<IPAddress?>();
        probe.Records = (_, server) =>
        {
            asked.Add(server);
            return server != null ? throw new TimeoutException("timed out") : [ClientIp];
        };
        var group = Run(probe);
        Assert.Equal([DcIp, null], asked);
        Assert.Equal(Status.Pass, StatusOf(group, "Registered Record"));
        Assert.Equal("the configured DNS servers (dc01.contoso.com did not answer a direct query) holds 10.20.4.18", DetailOf(group, "Registered Record"));

        probe.Records = (_, _) => throw new TimeoutException("A/AAAA query timed out after 8s");
        Assert.Equal(Status.Warn, StatusOf(Run(probe), "Registered Record"));
    }

    [Fact]
    public void Errors_RecentFailureEventsWarn_UnreadableLogWarns()
    {
        var probe = Healthy();
        probe.DnsEvents = () => Samples.DnsClientEventsRefused;
        var group = Run(probe);
        Assert.Equal(Status.Warn, StatusOf(group, "Registration Errors"));
        Assert.StartsWith("2 in the last 24 hours; latest: event 8015 at ", DetailOf(group, "Registration Errors"));
        Assert.Contains("refused the update request", DetailOf(group, "Registration Errors"));

        probe.DnsEvents = () => "ERROR|Access is denied";
        Assert.Equal("Could not read the System event log: Access is denied", DetailOf(Run(probe), "Registration Errors"));
    }

    // ── Register now ───────────────────────────────────────

    static (Status Verdict, List<TestEntry> Steps) Register(FakeProbe probe, int attempts = 3)
    {
        var steps = new List<TestEntry>();
        var verdict = Diagnostics.RegisterDns(Config(), probe, steps.Add, attempts, pollMs: 0);
        return (verdict, steps);
    }

    static TestEntry Step(List<TestEntry> steps, string name) => steps.Single(s => s.Name == name);

    [Fact]
    public void Register_NotElevated_StopsBeforeSendingAnything()
    {
        var probe = Healthy();
        probe.Elevated = false;
        var (verdict, steps) = Register(probe);
        Assert.Equal(Status.Fail, verdict);
        Assert.Equal(Status.Fail, steps[^1].Status);
        Assert.Contains("requires running as Administrator", steps[^1].Detail);
        Assert.Empty(probe.ToolCalls);
    }

    [Fact]
    public void Register_StaleRecordReplaced_Passes()
    {
        var probe = Healthy();
        var stale = IPAddress.Parse("10.20.9.9");
        probe.Records = (_, _) => probe.ToolCalls.Contains("ipconfig /registerdns") ? [ClientIp] : [stale];
        var (verdict, steps) = Register(probe);
        Assert.Equal(Status.Pass, verdict);
        Assert.Equal(["Registration Name", "Zone Primary Server", "Record Before", "Send", "Wait", "Record After"], steps.Select(s => s.Name));
        Assert.Equal("PC042.contoso.com with 10.20.4.18", Step(steps, "Registration Name").Detail);
        Assert.Equal(Status.Warn, Step(steps, "Record Before").Status);
        Assert.StartsWith("ipconfig /registerdns ran: Windows IP Configuration Registration of the DNS resource records", Step(steps, "Send").Detail);
        Assert.Equal("dc01.contoso.com holds 10.20.4.18 — registered", Step(steps, "Record After").Detail);
    }

    [Fact]
    public void Register_RecordAlreadyRight_WaitsForAFailureBeforePassing()
    {
        var probe = Healthy();
        var (verdict, steps) = Register(probe, attempts: 5);
        Assert.Equal(Status.Pass, verdict);
        Assert.Equal(2, probe.DnsEventQueries);
        Assert.Contains("unchanged", Step(steps, "Record After").Detail);
    }

    [Fact]
    public void Register_FailureEvent_FailsEvenIfTheRecordLooksRight_AndReportsEachEventOldestFirst()
    {
        var probe = BehindZtna();
        probe.NetAdapters[0] = probe.NetAdapters[0] with { Addresses = [ClientIp] };
        probe.DnsEvents = () => Samples.DnsClientEventsRefused;
        var (verdict, steps) = Register(probe);
        Assert.Equal(Status.Fail, verdict);
        Assert.Equal(1, probe.DnsEventQueries);
        var events = steps.Where(s => s.Name == "DNS Client Event").ToList();
        Assert.Equal(2, events.Count);
        Assert.StartsWith("event 8018", events[0].Detail);
        Assert.All(events, e => Assert.Equal(Status.Fail, e.Status));
        Assert.Equal(Status.Warn, Step(steps, "Record After").Status);
        // Behind ZTNA the trace ends by saying what the tunnel has to carry
        Assert.Equal("ZTNA / VPN Client", steps[^1].Name);
        Assert.Equal(Status.Warn, steps[^1].Status);
        Assert.Contains("TCP and UDP 53 to dc01.contoso.com", steps[^1].Detail);
    }

    [Fact]
    public void Register_NothingChangesAndNothingIsLogged_WarnsAfterEveryAttempt()
    {
        var probe = Healthy();
        probe.Records = (_, _) => [];
        var (verdict, steps) = Register(probe, attempts: 4);
        Assert.Equal(Status.Warn, verdict);
        Assert.Equal(4, probe.DnsEventQueries);
        Assert.Contains("no failure logged yet", Step(steps, "Record After").Detail);
    }

    [Fact]
    public void Register_IpconfigThatNeverAnswers_Fails()
    {
        var probe = Healthy();
        probe.Tools.Remove("ipconfig /registerdns");
        var (verdict, steps) = Register(probe);
        Assert.Equal(Status.Fail, verdict);
        Assert.Contains("timed out", Step(steps, "Send").Detail);
        Assert.Equal(0, probe.DnsEventQueries);
    }

    [Fact]
    public void Register_Cancelled_SendsNothing()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var probe = Healthy();
        Assert.ThrowsAny<OperationCanceledException>(() => Diagnostics.RegisterDns(Config(cts.Token), probe, _ => { }, 3, 0));
        Assert.Empty(probe.ToolCalls);
    }

    // ── Event query output ─────────────────────────────────

    [Theory, MemberData(nameof(ParsersTests.LineEndings), MemberType = typeof(ParsersTests))]
    public void DnsClientEvents_Parsed(bool crlf)
    {
        var result = Parsers.ParseDnsClientEvents(crlf ? Samples.Crlf(Samples.DnsClientEventsRefused) : Samples.DnsClientEventsRefused);
        Assert.Null(result.Error);
        Assert.Equal([8015, 8018], result.Events.Select(e => e.Id));
        Assert.Equal(new DateTime(2026, 10, 5, 12, 2, 14, DateTimeKind.Utc), result.Events[0].TimeUtc);
        Assert.EndsWith("refused the update request.", result.Events[0].Message);
    }

    [Theory]
    [InlineData("EVENTS|0\r\n", null)]
    [InlineData("ERROR|The RPC server is unavailable", "The RPC server is unavailable")]
    [InlineData("", "No output from PowerShell")]
    [InlineData("#< CLIXML\r\n<Objs/>", "#< CLIXML")]
    public void DnsClientEvents_NoEventsIsNotAnError_AnythingElseIs(string output, string? error)
    {
        var result = Parsers.ParseDnsClientEvents(output);
        Assert.Empty(result.Events);
        Assert.Equal(error, result.Error);
    }
}
