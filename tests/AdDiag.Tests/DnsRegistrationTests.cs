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
        // Asked of the registering adapter's own DNS server, and the detail says who answered
        Assert.Equal([DcIp, DcIp], probe.SoaServers);
        Assert.Equal("contoso.com -> dc01.contoso.com (10.20.0.11), answered by 10.20.0.11 (DNS server of Ethernet)", DetailOf(group, "Zone Primary Server"));
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
    public void Ztna_VirtualAdapterWithARealAddressDetected_HostAndAddresslessOnesAreNot()
    {
        var lan = new NetAdapter("IOT", "Red Hat VirtIO Ethernet Adapter #2", false, true, [ClientIp], [DcIp]);
        // A client in "VPN mode": no tunnel type, no 100.64 address, only a software adapter and a loopback DNS proxy
        var client = new NetAdapter("Acme Access", "Acme Access Virtual Adapter", false, false,
            [IPAddress.Parse("fe80::1"), IPAddress.Parse("172.16.50.3")], [IPAddress.Parse("127.73.83.76")], Virtual: true);
        Assert.Equal("virtual adapter \"Acme Access\" (172.16.50.3); DNS answered by its local proxy (127.73.83.76)",
            Diagnostics.DescribeZtna([lan, client]));
        var island = client with { Name = "Island Private Access", Description = "Island Private Access Virtual Adapter Tunnel" };
        Assert.StartsWith("Island adapter (172.16.50.3)", Diagnostics.DescribeZtna([lan, island]));

        var miniport = new NetAdapter("Local Area Connection* 6", "WAN Miniport (IP)", false, false, [], [], Virtual: true);
        var vswitch = new NetAdapter("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", false, true, [IPAddress.Parse("172.22.0.1")], [], Virtual: true);
        var vmnet = new NetAdapter("VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter for VMnet8", false, true, [IPAddress.Parse("192.168.80.1")], [], Virtual: true);
        Assert.Null(Diagnostics.DescribeZtna([lan, miniport, vswitch, vmnet]));
    }

    [Fact]
    public void Ztna_SlashThirtyTwoWithNoGatewayDetected()
    {
        var lan = new NetAdapter("Ethernet", "Intel(R) Ethernet Connection", false, true, [ClientIp], [DcIp]);
        var client = new NetAdapter("Ethernet 4", "Acme Adapter", false, false, [IPAddress.Parse("172.16.50.3")], [], PointToPoint: true);
        Assert.Equal("tunnel adapter \"Ethernet 4\" (172.16.50.3)", Diagnostics.DescribeZtna([lan, client]));
    }

    [Fact]
    public void Ztna_TaggedAdapterCounts_NoneOverridesDetection_MissingTagIsSaid()
    {
        var lan = new NetAdapter("Ethernet", "Intel(R) Ethernet Connection", false, true, [ClientIp], [DcIp]);
        var plain = new NetAdapter("Ethernet 4", "Acme Adapter", false, false, [IPAddress.Parse("10.99.0.5")], [IPAddress.Parse("127.0.0.53")]);
        Assert.Null(Diagnostics.DescribeZtna([lan, plain]));
        Assert.Equal("adapter \"Ethernet 4\" (10.99.0.5), tagged by you; DNS answered by its local proxy (127.0.0.53)",
            Diagnostics.DescribeZtna([lan, plain], "Ethernet 4"));
        Assert.Equal("tagged adapter \"Gone\" is not connected", Diagnostics.DescribeZtna([lan], "Gone"));

        var probe = BehindZtna();
        Assert.Null(Diagnostics.DescribeZtna(probe.NetAdapters, ""));
        var group = Diagnostics.TestDnsRegistration(new("contoso.com", "", default, ""), probe);
        Assert.Equal("None, as set by you", DetailOf(group, "ZTNA / VPN Client"));
    }

    [Fact]
    public void AdapterChoices_ListAddressedAdaptersWithTheirSignals()
    {
        var choices = Diagnostics.AdapterChoices(
        [
            new("IOT", "Red Hat VirtIO Ethernet Adapter", false, true, [IPAddress.Parse("fe80::1"), ClientIp], [DcIp]),
            new("Acme Access", "Acme Virtual Adapter", false, false, [IPAddress.Parse("172.16.50.3")], [], Virtual: true, PointToPoint: true),
            new("Local Area Connection* 6", "WAN Miniport (IP)", false, false, [], [], Virtual: true),
            new("Teredo Tunneling Pseudo-Interface", "Microsoft Teredo Tunneling Adapter", true, false, [IPAddress.Parse("2001:0:1::1")], []),
        ]);
        Assert.Equal([("IOT", $"IOT — {ClientIp}"), ("Acme Access", "Acme Access — 172.16.50.3 · virtual · /32, no gateway")], choices);
    }

    [Fact]
    public void Adapters_ClientAddressNotRegisteredIsNoted()
    {
        var probe = new FakeProbe();
        probe.NetAdapters.Add(new("Acme Access", "Acme Access Virtual Adapter", false, false, [IPAddress.Parse("172.16.50.3")], [], Virtual: true));
        var group = Run(probe);
        Assert.Equal(Status.Pass, StatusOf(group, "Registering Adapters"));
        Assert.Contains("the client's own address (172.16.50.3) is not registered", DetailOf(group, "Registering Adapters"));
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
        Assert.Equal("No SOA record for PC042.contoso.com or its parent zones from 10.20.0.11 (DNS server of Ethernet)", DetailOf(group, "Zone Primary Server"));
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
        Assert.Contains("(asked 10.20.0.11 (DNS server of Ethernet))", DetailOf(group, "Zone Primary Server"));
    }

    [Fact]
    public void Zone_AskedOfTheRegisteringAdaptersServers_NotTheClientsProxy()
    {
        // The client's adapter does not register, so its proxy, which knows only the public zone, is never asked
        var proxy = IPAddress.Parse("127.73.83.76");
        var probe = Healthy();
        probe.NetAdapters.Add(new("Acme Access", "Acme Access Virtual Adapter", false, false, [IPAddress.Parse("172.16.50.3")], [proxy], Virtual: true));
        probe.SoaByServer[proxy] = new() { ["contoso.com"] = new("contoso.com", "amit.ns.cloudflare.com") };
        var group = Run(probe);
        Assert.DoesNotContain(proxy, probe.SoaServers);
        Assert.StartsWith("contoso.com -> dc01.contoso.com (10.20.0.11), answered by 10.20.0.11", DetailOf(group, "Zone Primary Server"));
    }

    [Fact]
    public void Zone_ServerThatDoesNotAnswerIsPassedOver_IPv6ServersAreNotAsked()
    {
        var dead = IPAddress.Parse("10.20.0.12");
        var probe = Healthy();
        probe.NetAdapters = [new("Ethernet", "Intel", false, true, [ClientIp], [IPAddress.Parse("fd00::53"), dead, DcIp, DcIp])];
        probe.SoaByServer[dead] = null;
        var group = Run(probe);
        Assert.Equal([dead, DcIp, DcIp], probe.SoaServers);
        Assert.Equal(Status.Pass, StatusOf(group, "Zone Primary Server"));

        // Every server silent is a failed lookup; one that answers "no zone" is not
        probe.NetAdapters = [new("Ethernet", "Intel", false, true, [ClientIp], [dead])];
        Assert.StartsWith("SOA lookup failed: SOA query for PC042.contoso.com timed out", DetailOf(Run(probe), "Zone Primary Server"));
        probe.NetAdapters = [new("Ethernet", "Intel", false, true, [ClientIp], [dead, DcIp])];
        probe.Soa.Clear();
        Assert.StartsWith("No SOA record for PC042.contoso.com or its parent zones from 10.20.0.12 (DNS server of Ethernet), 10.20.0.11 (DNS server of Ethernet)",
            DetailOf(Run(probe), "Zone Primary Server"));
    }

    [Fact]
    public void Zone_NoRegisteringAdapter_AsksTheConfiguredServers()
    {
        var probe = Healthy();
        probe.NetAdapters = [new("Ethernet", "Intel", false, false, [ClientIp], [DcIp])];
        var group = Run(probe);
        Assert.Equal([null, null], probe.SoaServers);
        Assert.EndsWith("answered by the configured DNS servers", DetailOf(group, "Zone Primary Server"));
    }

    [Theory]
    [InlineData("172.64.32.10", true)]    // a public name server
    [InlineData("2606:4700::10", true)]
    [InlineData("172.31.254.252", false)] // the top of 172.16.0.0/12
    [InlineData("192.168.1.2", false)]
    [InlineData("fd12::2", false)]
    public void Zone_PrimaryWithAPublicAddressWarns(string address, bool isPublic)
    {
        var probe = Healthy();
        probe.Hosts["dc01.contoso.com"] = [IPAddress.Parse(address)];
        var group = Run(probe);
        Assert.Equal(isPublic ? Status.Warn : Status.Pass, StatusOf(group, "Zone Primary Server"));
        Assert.Equal(isPublic, DetailOf(group, "Zone Primary Server").Contains("a public address"));
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
