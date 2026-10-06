using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;

#nullable enable
namespace AdDiag;

/// <summary>A connected network adapter, as far as DNS registration is concerned.</summary>
/// <param name="Virtual">A software adapter with no hardware behind it, which is what a ZTNA or VPN client installs.</param>
/// <param name="PointToPoint">Holds an IPv4 /32 address and has no default gateway, the usual shape of a client's adapter.</param>
record NetAdapter(string Name, string Description, bool Tunnel, bool RegistersInDns, IPAddress[] Addresses, IPAddress[] DnsServers,
    bool Virtual = false, bool PointToPoint = false);
record SoaRecord(string Zone, string PrimaryServer);

// Dynamic DNS registration: whether this machine's own host record can reach, and is right on, the DNS server
// that owns its zone. The checks only read; RegisterDns is the one thing here that changes DNS, and only when asked.
//
// A ZTNA or VPN client changes what each step means: its DNS proxy may answer A/AAAA but not SOA (so Windows can't
// find where to send an update), may hand back synthetic 100.64.0.0/10 addresses instead of real ones, and may
// carry queries but not updates. So the client is detected first and the failures that follow say so.
static partial class Diagnostics
{
    const string RegName = "Registration Name", RegZtna = "ZTNA / VPN Client", RegAdapters = "Registering Adapters",
        RegZone = "Zone Primary Server", RegPath = "Update Path (Port 53)", RegRecord = "Registered Record",
        RegErrors = "Registration Errors";
    /// <summary>The step RegisterDns reports while it waits on Windows; not a verdict.</summary>
    public const string RegWait = "Wait";

    // Matched against an adapter's name and description
    static readonly (string Match, string Client)[] ZtnaClients =
    [
        ("zscaler", "Zscaler"), ("cloudflare warp", "Cloudflare WARP"), ("netskope", "Netskope"),
        ("pangp", "GlobalProtect"), ("globalprotect", "GlobalProtect"), ("twingate", "Twingate"),
        ("tailscale", "Tailscale"), ("global secure access", "Microsoft Global Secure Access"),
        ("anyconnect", "Cisco AnyConnect"), ("cisco secure client", "Cisco Secure Client"),
        ("fortinet", "FortiClient"), ("citrix secure access", "Citrix Secure Access"), ("appgate", "Appgate"),
        ("cato networks", "Cato"), ("check point", "Check Point"), ("banyan", "Banyan"), ("ip-https", "DirectAccess"),
        ("wireguard", "WireGuard"), ("openvpn", "OpenVPN"), ("tap-windows", "OpenVPN"), ("wintun", "Wintun"),
        ("island private access", "Island"),
    ];

    // Software adapters that belong to this machine's own hypervisor or radios, not to a ZTNA or VPN client
    static readonly string[] HostVirtual = ["hyper-v", "vmware", "virtualbox", "wsl", "loopback", "wi-fi direct", "bluetooth", "npcap"];

    // Windows' own IPv6 transition adapters report themselves as tunnels but carry no corporate traffic
    static readonly string[] PseudoTunnels = ["teredo", "isatap", "6to4"];

    /// <summary>100.64.0.0/10, carrier-grade NAT space: what ZTNA clients use for tunnel and synthetic addresses.</summary>
    public static bool IsCgnat(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = ip.GetAddressBytes();
        return b[0] == 100 && (b[1] & 0xC0) == 64;
    }

    // Addresses Windows would put in DNS: not loopback, link-local (169.254/16, fe80::/10) or site-local placeholders
    static bool IsRegistrable(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return false;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.AddressFamily == AddressFamily.InterNetworkV6;
        byte[] b = ip.GetAddressBytes();
        return !(b[0] == 169 && b[1] == 254);
    }

    static string Join(IEnumerable<IPAddress> addresses) => string.Join(", ", addresses);

    /// <summary>
    /// The adapters a ZTNA or VPN client owns, each with a label. A client is recognised by name, by a tunnel adapter
    /// type, by a 100.64.0.0/10 address, by a /32 address with no gateway, or by being a software adapter that holds
    /// an address: a client in "VPN mode" gives its adapter a real routable address, so the range alone says nothing.
    /// </summary>
    static List<(NetAdapter Adapter, string Label)> ClientAdapters(List<NetAdapter> adapters, string? tag)
    {
        var found = new List<(NetAdapter, string)>();
        if (tag == "") return found;
        foreach (var adapter in adapters)
        {
            string text = $"{adapter.Name} {adapter.Description}";
            bool tagged = adapter.Name == tag;
            if (!tagged && PseudoTunnels.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase))) continue;
            string? client = ZtnaClients.FirstOrDefault(c => text.Contains(c.Match, StringComparison.OrdinalIgnoreCase)).Client;
            var addresses = adapter.Addresses.Where(IsRegistrable).ToArray();
            bool tunnel = adapter.Tunnel || adapter.PointToPoint || addresses.Any(IsCgnat);
            // WAN Miniports and filter bindings are software adapters too, but hold no address
            bool software = adapter.Virtual && addresses.Length > 0
                && !HostVirtual.Any(h => text.Contains(h, StringComparison.OrdinalIgnoreCase));
            if (client == null && !tunnel && !software && !tagged) continue;
            string kind = client != null ? $"{client} adapter"
                : $"{(tunnel ? "tunnel " : software ? "virtual " : "")}adapter \"{adapter.Name}\"";
            found.Add((adapter, kind + (addresses.Length > 0 ? $" ({Join(addresses)})" : "") + (tagged ? ", tagged by you" : "")));
        }
        return found;
    }

    /// <summary>
    /// The ZTNA or VPN client the adapters give away, e.g. "Zscaler adapter (100.64.0.7)"; null if none.
    /// <paramref name="tag"/> is the user's own answer (<see cref="DiagConfig.ZtnaAdapter"/>), for a client this misses.
    /// </summary>
    public static string? DescribeZtna(List<NetAdapter> adapters, string? tag = null)
    {
        var found = ClientAdapters(adapters, tag).Select(c => c.Label).ToList();
        if (!string.IsNullOrEmpty(tag) && adapters.All(a => a.Name != tag))
            found.Add($"tagged adapter \"{tag}\" is not connected");
        if (tag == "") return null;

        var dnsServers = adapters.SelectMany(a => a.DnsServers).Distinct().ToArray();
        // A loopback DNS server alone proves nothing (a domain controller points at itself); beside a tunnel it is the client's proxy
        var proxies = dnsServers.Where(d => IsCgnat(d) || (found.Count > 0 && IPAddress.IsLoopback(d))).ToArray();
        if (proxies.Length > 0)
            found.Add($"DNS answered by its local proxy ({Join(proxies)})");
        return found.Count == 0 ? null : string.Join("; ", found);
    }

    /// <summary>
    /// The adapters a user can tag as the client's: each connected one that holds an address, with the signals
    /// detection saw on it, e.g. "Ethernet 4 — 172.16.50.3 · virtual · /32, no gateway".
    /// </summary>
    public static List<(string Name, string Text)> AdapterChoices(List<NetAdapter> adapters) =>
        adapters.Where(a => a.Addresses.Any(IsRegistrable)
                && !PseudoTunnels.Any(p => $"{a.Name} {a.Description}".Contains(p, StringComparison.OrdinalIgnoreCase)))
            .Select(a => (a.Name, $"{a.Name} — {Join(a.Addresses.Where(IsRegistrable))}"
                + (a.Tunnel ? " · tunnel" : "") + (a.Virtual ? " · virtual" : "") + (a.PointToPoint ? " · /32, no gateway" : "")))
            .ToList();

    // Routable addresses on a client's adapter that Windows will not put in DNS, as that adapter has registration off
    static IPAddress[] UnregisteredClientAddresses(List<NetAdapter> adapters, string? tag) =>
        ClientAdapters(adapters, tag).Where(c => !c.Adapter.RegistersInDns)
            .SelectMany(c => c.Adapter.Addresses).Where(a => IsRegistrable(a) && !IsCgnat(a)).Distinct().ToArray();

    // The addresses this machine would register: those of connected adapters with DNS registration on
    static IPAddress[] RegisteringAddresses(List<NetAdapter> adapters) =>
        adapters.Where(a => a.RegistersInDns).SelectMany(a => a.Addresses).Where(IsRegistrable).Distinct().ToArray();

    record UpdateTarget(SoaRecord Soa, IPAddress[] Addresses)
    {
        public string Server => Soa.PrimaryServer;
        // Prefer IPv4, as the port checks do
        public IPAddress? Address => Addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).FirstOrDefault();
    }

    /// <summary>What the search for the zone found: its SOA record (null if none), who was asked, and the error if nobody answered.</summary>
    record ZoneLookup(SoaRecord? Soa, string Asked, string? Error = null);

    // The DNS servers Windows asks where to send an update: those of each adapter that registers, not whichever
    // the system resolver prefers. Behind a ZTNA or VPN client the two differ, and can name different zones.
    // IPv4 only, as that is what a direct query can be sent to.
    static (IPAddress Server, string Adapter)[] RegistrationResolvers(List<NetAdapter> adapters) =>
        adapters.Where(a => a.RegistersInDns && a.Addresses.Any(IsRegistrable))
            .SelectMany(a => a.DnsServers.Where(d => d.AddressFamily == AddressFamily.InterNetwork).Select(d => (Server: d, Adapter: a.Name)))
            .DistinctBy(r => r.Server).ToArray();

    // The SOA of the name, then of each parent, asked of one server (null for the configured ones)
    static SoaRecord? WalkUpToZone(IProbe probe, string fqdn, IPAddress? server, CancellationToken ct)
    {
        for (string name = fqdn.TrimEnd('.'); name.Contains('.'); name = name[(name.IndexOf('.') + 1)..])
        {
            if (probe.QuerySoa(name, server, ct) is { } soa)
                return new(soa.Zone.TrimEnd('.'), soa.PrimaryServer.TrimEnd('.'));
        }
        return null;
    }

    /// <summary>
    /// The zone that holds <paramref name="fqdn"/> and its primary server, found the way Windows finds where to
    /// send an update: ask the registering adapters' DNS servers for the SOA of the name, then of each parent.
    /// The first server that knows a zone wins; one that fails is passed over for the next.
    /// </summary>
    static ZoneLookup FindZone(IProbe probe, string fqdn, List<NetAdapter> adapters, CancellationToken ct)
    {
        var resolvers = RegistrationResolvers(adapters);
        if (resolvers.Length == 0)
        {
            const string configured = "the configured DNS servers";
            try { return new(WalkUpToZone(probe, fqdn, null, ct), configured); }
            catch (Exception ex) when (ex is not OperationCanceledException) { return new(null, configured, ex.Message); }
        }

        string? error = null;
        bool answered = false;
        foreach (var (server, adapter) in resolvers)
        {
            try
            {
                if (WalkUpToZone(probe, fqdn, server, ct) is { } soa)
                    return new(soa, $"{server} (DNS server of {adapter})");
                answered = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { error = ex.Message; }
        }
        string asked = string.Join(", ", resolvers.Select(r => $"{r.Server} (DNS server of {r.Adapter})"));
        return new(null, asked, answered ? null : error);
    }

    /// <summary>The host records for <paramref name="fqdn"/>, from the zone's primary server itself where it answers.</summary>
    static (IPAddress[] Records, string Source) QueryRecord(IProbe probe, string fqdn, UpdateTarget? target, CancellationToken ct)
    {
        string source = "the configured DNS servers";
        if (target?.Addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) is { } server)
        {
            try { return (probe.QueryAddresses(fqdn, server, ct), target.Server); }
            catch (OperationCanceledException) { throw; }
            catch { source += $" ({target.Server} did not answer a direct query)"; }
        }
        return (probe.QueryAddresses(fqdn, null, ct), source);
    }

    static (Status Status, string Detail) CompareRecord(IPAddress[] records, IPAddress[] local, string source)
    {
        if (records.Length == 0)
            return (Status.Warn, $"{source} holds no A or AAAA record for this machine — it is not registered");
        string holds = $"{source} holds {Join(records)}";
        if (records.Any(IsCgnat))
            holds += " (a 100.64.0.0/10 tunnel address, which other hosts cannot route to)";
        if (local.Length == 0)
            return (Status.Pass, holds);
        var stale = records.Except(local).ToArray();
        if (stale.Length == records.Length)
            return (Status.Warn, $"{holds}; this machine has {Join(local)} — the record is stale");
        if (stale.Length > 0)
            return (Status.Warn, $"{holds}; this machine no longer has {Join(stale)}");
        return (records.Any(IsCgnat) ? Status.Warn : Status.Pass, holds);
    }

    // DNS Client logs a warning (IDs in the 8000s) to the System log each time a registration or deregistration
    // fails; success is silent. Output: "EVENTS|<count>" then "EVT|<id>|<UTC ISO>|<message>" newest first, or
    // "ERROR|<message>". The message is Windows' own (translated) text; the ID is not.
    const string DnsClientEventsScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        try {
            $since = [datetime]::Parse('__SINCE__', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
            $filter = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-DNS-Client'; StartTime = $since }
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -ge 8000 -and $_.Id -le 8099 } | Select-Object -First 20)
            "EVENTS|$($events.Count)"
            foreach ($e in $events) {
                "EVT|$($e.Id)|" + $e.TimeCreated.ToUniversalTime().ToString('o') + '|' + ("$($e.Message)" -replace '\s+', ' ')
            }
        } catch {
            "ERROR|" + ($_.Exception.Message -replace '\s+', ' ')
        }
        """;

    static DnsClientEvents QueryDnsClientEvents(IProbe probe, DateTime sinceUtc, CancellationToken ct) =>
        Parsers.ParseDnsClientEvents(probe.RunPowerShell(
            DnsClientEventsScript.Replace("__SINCE__", sinceUtc.ToString("o", CultureInfo.InvariantCulture)), 15000, ct));

    static string Shorten(string text, int max) => text.Length <= max ? text : text[..max].TrimEnd() + "…";

    // Not cut short: Windows puts the reason (refused, timed out, not authoritative...) at the end of a long message
    static string DescribeEvent(DnsClientEvent e) =>
        $"event {e.Id} at {e.TimeUtc.ToLocalTime():g}" + (e.Message.Length > 0 ? $" — {Shorten(e.Message, 1500)}" : "");

    public static TestGroup TestDnsRegistration(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();
        string? fqdn = CheckName(probe, tests.Add);
        var (adapters, ztna) = CheckAdapters(cfg, probe, tests.Add);
        if (fqdn != null)
        {
            CheckServer(probe, fqdn, adapters, ztna, cfg.Cancel, tests.Add);
        }
        else
        {
            foreach (string name in new[] { RegZone, RegPath, RegRecord })
                tests.Add(new(name, Status.Skip, "No registration name"));
        }
        tests.Add(CheckErrors(probe, cfg.Cancel));
        return new("Dynamic DNS Registration", tests);
    }

    // The name Windows registers; null if this machine has none
    static string? CheckName(IProbe probe, Action<TestEntry> report)
    {
        try
        {
            var (host, suffix) = probe.HostIdentity();
            if (!string.IsNullOrWhiteSpace(suffix))
            {
                report(new(RegName, Status.Pass, $"{host}.{suffix}"));
                return $"{host}.{suffix}";
            }
            report(new(RegName, Status.Warn, $"{host} has no primary DNS suffix, so Windows registers no name for it (not domain-joined?)"));
        }
        catch (Exception ex)
        {
            report(new(RegName, Status.Warn, $"Could not read the host name: {ex.Message}"));
        }
        return null;
    }

    static (List<NetAdapter> Adapters, string? Ztna) CheckAdapters(DiagConfig cfg, IProbe probe, Action<TestEntry> report)
    {
        try
        {
            var adapters = probe.Adapters();
            string? ztna = DescribeZtna(adapters, cfg.ZtnaAdapter);
            report(new(RegZtna, Status.Pass, ztna != null ? $"{ztna} (informational)"
                : cfg.ZtnaAdapter == "" ? "None, as set by you" : "No ZTNA or VPN adapter detected"));
            report(RegisteringAdaptersEntry(adapters, ztna, cfg.ZtnaAdapter));
            return (adapters, ztna);
        }
        catch (Exception ex)
        {
            report(new(RegZtna, Status.Warn, $"Could not read the network adapters: {ex.Message}"));
            report(new(RegAdapters, Status.Skip, "Network adapters unavailable"));
            return ([], null);
        }
    }

    static TestEntry RegisteringAdaptersEntry(List<NetAdapter> adapters, string? ztna, string? tag)
    {
        var registering = adapters.Where(a => a.RegistersInDns && a.Addresses.Any(IsRegistrable)).ToList();
        var tunnelOnly = RegisteringAddresses(adapters).Where(IsCgnat).ToArray();
        string list = string.Join(" · ", registering.Select(a => $"{a.Name}: {Join(a.Addresses.Where(IsRegistrable))}"));
        if (registering.Count == 0)
            return new(RegAdapters, Status.Warn, "No connected adapter has \"Register this connection's addresses in DNS\" turned on");
        if (tunnelOnly.Length > 0)
            return new(RegAdapters, Status.Warn, $"{list} — {Join(tunnelOnly)} is a 100.64.0.0/10 tunnel address, which other hosts cannot route to");
        if (ztna == null)
            return new(RegAdapters, Status.Pass, list);
        if (UnregisteredClientAddresses(adapters, tag) is { Length: > 0 } unregistered)
            return new(RegAdapters, Status.Pass, $"{list} — the client's own address ({Join(unregistered)}) is not registered, because "
                + "registration is off on its adapter; if servers reach this machine through the client, that is the address DNS should hold");
        return new(RegAdapters, Status.Pass, list
            + " — behind the ZTNA client this is the local network's address, which servers cannot use to reach this machine");
    }

    // The three checks that need the zone's primary server: who it is, whether updates can reach it, what it holds
    static void CheckServer(IProbe probe, string fqdn, List<NetAdapter> adapters, string? ztna, CancellationToken ct, Action<TestEntry> report)
    {
        var target = FindUpdateTarget(probe, fqdn, adapters, ztna, ct, report);

        if (target?.Address is not { } address)
            report(new(RegPath, Status.Skip, "No primary server to test"));
        else if (probe.TcpConnect(address, 53, ct).GetAwaiter().GetResult())
            report(new(RegPath, Status.Pass, $"{target.Server} ({address}) reachable over TCP"));
        else
            report(new(RegPath, Status.Fail, $"{target.Server} ({address}) does not answer on TCP port 53, so updates cannot be delivered"
                + (ztna != null ? " — the ZTNA policy must allow TCP and UDP 53 to this server" : "")));

        try
        {
            var (records, source) = QueryRecord(probe, fqdn, target, ct);
            var (status, detail) = CompareRecord(records, RegisteringAddresses(adapters), source);
            report(new(RegRecord, status, detail));
        }
        catch (Exception ex)
        {
            report(new(RegRecord, Status.Warn, $"Could not query the record: {ex.Message}"));
        }
    }

    static TestEntry CheckErrors(IProbe probe, CancellationToken ct)
    {
        try
        {
            var events = QueryDnsClientEvents(probe, DateTime.UtcNow.AddHours(-24), ct);
            if (events.Error != null)
                return new(RegErrors, Status.Warn, $"Could not read the System event log: {events.Error}");
            if (events.Events.Count == 0)
                return new(RegErrors, Status.Pass, "No DNS Client registration errors in the last 24 hours");
            return new(RegErrors, Status.Warn, $"{events.Events.Count} in the last 24 hours; latest: {DescribeEvent(events.Events[0])}");
        }
        catch (Exception ex)
        {
            return new(RegErrors, Status.Warn, $"Event log query failed: {ex.Message}");
        }
    }

    // An address the internet routes: not private, carrier-grade NAT, loopback or link-local space
    static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || IsCgnat(ip) || !IsRegistrable(ip)) return false;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return !ip.IsIPv6UniqueLocal;
        byte[] b = ip.GetAddressBytes();
        return !(b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168));
    }

    // Finds the zone's primary server and its addresses, reporting the verdict as the "Zone Primary Server" entry
    static UpdateTarget? FindUpdateTarget(IProbe probe, string fqdn, List<NetAdapter> adapters, string? ztna, CancellationToken ct,
        Action<TestEntry> report)
    {
        string proxyHint = ztna != null
            ? " — a ZTNA DNS proxy often answers only A/AAAA/SRV; without the SOA record Windows cannot find where to send updates"
            : "";
        var zone = FindZone(probe, fqdn, adapters, ct);
        if (zone.Soa is not { } soa)
        {
            report(new(RegZone, Status.Fail, zone.Error != null
                ? $"SOA lookup failed: {zone.Error} (asked {zone.Asked}){proxyHint}"
                : $"No SOA record for {fqdn} or its parent zones from {zone.Asked}{proxyHint}"));
            return null;
        }

        IPAddress[] addresses = [];
        try { addresses = probe.Resolve(soa.PrimaryServer, ct); }
        catch (OperationCanceledException) { throw; }
        catch { }
        var target = new UpdateTarget(soa, addresses);
        if (target.Address is not { } address)
        {
            report(new(RegZone, Status.Fail, $"{soa.Zone} -> {soa.PrimaryServer}, which does not resolve; answered by {zone.Asked}"));
            return target;
        }
        string found = $"{soa.Zone} -> {soa.PrimaryServer} ({address}), answered by {zone.Asked}";
        if (IsCgnat(address))
            report(new(RegZone, Status.Warn, $"{found} — a synthetic 100.64.0.0/10 address from the ZTNA client; "
                + "updates reach the real server only if the client forwards port 53 for it"));
        else if (IsPublic(address))
            report(new(RegZone, Status.Warn, $"{found} — a public address: this looks like the zone's internet-facing copy, "
                + "which does not take updates from this machine"));
        else
            report(new(RegZone, Status.Pass, found));
        return target;
    }

    /// <summary>What a registration is about: the name, the adapters, the addresses they register, and the client in the way.</summary>
    record Registration(string Fqdn, List<NetAdapter> Adapters, IPAddress[] Local, string? Ztna);

    static Status Stop(Action<TestEntry> report, string step, string detail)
    {
        report(new(step, Status.Fail, detail));
        return Status.Fail;
    }

    /// <summary>
    /// Asks Windows to register this machine in DNS (<c>ipconfig /registerdns</c>, so the DNS Client service sends
    /// the update as the computer account) and traces what happens, reporting each step as it completes. The
    /// service works in the background and says nothing on success, so the outcome is read from the two places
    /// it shows: the record on the zone's primary server, and the DNS Client's failure events.
    /// Returns the overall verdict.
    /// </summary>
    public static Status RegisterDns(DiagConfig cfg, IProbe probe, Action<TestEntry> report, int attempts = 6, int pollMs = 5000)
    {
        var ct = cfg.Cancel;
        if (ReadRegistration(cfg, probe, report) is not { } reg)
            return Status.Fail;
        if (!probe.IsElevated())
            return Stop(report, "Elevation", "ipconfig /registerdns requires running as Administrator");

        var target = FindUpdateTarget(probe, reg.Fqdn, reg.Adapters, reg.Ztna, ct, report);
        var before = ReadRecord(probe, reg, target, ct);
        report(new("Record Before", before.Status, before.Detail));

        // Event times have whole-second precision in the query, so start a moment early
        DateTime startedUtc = DateTime.UtcNow.AddSeconds(-2);
        if (!SendRegistration(probe, report, ct))
            return Status.Fail;

        report(new(RegWait, Status.Skip, $"Watching the server and the DNS Client event log for up to {attempts * pollMs / 1000}s"));
        var (after, events) = WatchRegistration(probe, startedUtc, () => ReadRecord(probe, reg, target, ct), before, attempts, pollMs, ct);
        Status verdict = ReportOutcome(before, after, events, report);

        if (verdict != Status.Pass && reg.Ztna != null)
            report(new(RegZtna, Status.Warn, "Through a ZTNA or VPN client a secure update needs Kerberos (port 88 to a domain controller) and "
                + $"TCP and UDP 53 to {target?.Server ?? "the zone's primary server"} to pass the tunnel as real traffic, not through the client's DNS proxy"));
        return verdict;
    }

    // Reports the name being registered and any client in the way; null (after reporting why) if there is no name
    static Registration? ReadRegistration(DiagConfig cfg, IProbe probe, Action<TestEntry> report)
    {
        string fqdn;
        List<NetAdapter> adapters;
        try
        {
            var (host, suffix) = probe.HostIdentity();
            if (string.IsNullOrWhiteSpace(suffix))
            {
                Stop(report, RegName, $"{host} has no primary DNS suffix, so Windows has no name to register");
                return null;
            }
            fqdn = $"{host}.{suffix}";
            adapters = probe.Adapters();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Stop(report, RegName, $"Could not read this machine's name and adapters: {ex.Message}");
            return null;
        }
        var reg = new Registration(fqdn, adapters, RegisteringAddresses(adapters), DescribeZtna(adapters, cfg.ZtnaAdapter));
        report(new(RegName, Status.Pass, fqdn + (reg.Local.Length > 0 ? $" with {Join(reg.Local)}" : " — no adapter has DNS registration turned on")));
        if (reg.Ztna != null)
            report(new(RegZtna, Status.Pass, $"{reg.Ztna} (informational)"));
        return reg;
    }

    static (Status Status, string Detail) ReadRecord(IProbe probe, Registration reg, UpdateTarget? target, CancellationToken ct)
    {
        try
        {
            var (records, source) = QueryRecord(probe, reg.Fqdn, target, ct);
            return CompareRecord(records, reg.Local, source);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (Status.Warn, $"Could not query the record: {ex.Message}");
        }
    }

    static bool SendRegistration(IProbe probe, Action<TestEntry> report, CancellationToken ct)
    {
        try
        {
            string output = Regex.Replace(probe.RunTool("ipconfig", "/registerdns", 20000, ct), @"\s+", " ").Trim();
            report(new("Send", Status.Pass, "ipconfig /registerdns ran" + (output.Length > 0 ? $": {Shorten(output, 200)}" : "")));
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Stop(report, "Send", $"ipconfig /registerdns failed: {ex.Message}");
            return false;
        }
    }

    // Polls the record and the DNS Client's failure events until one of them settles the outcome
    static ((Status Status, string Detail) After, DnsClientEvents Events) WatchRegistration(IProbe probe, DateTime startedUtc,
        Func<(Status Status, string Detail)> readRecord, (Status Status, string Detail) before, int attempts, int pollMs, CancellationToken ct)
    {
        var after = before;
        var events = new DnsClientEvents([], null);
        for (int attempt = 1; attempt <= attempts; attempt++)
        {
            if (ct.WaitHandle.WaitOne(pollMs)) ct.ThrowIfCancellationRequested();
            try { events = QueryDnsClientEvents(probe, startedUtc, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { events = new([], ex.Message); }
            after = readRecord();
            // A record that was already right proves nothing on its own, so give a failure time to be logged
            if (events.Events.Count > 0 || (after.Status == Status.Pass && attempt >= 2)) break;
        }
        return (after, events);
    }

    // Reports the failure events and the record as it ended up; returns the verdict they add up to
    static Status ReportOutcome((Status Status, string Detail) before, (Status Status, string Detail) after, DnsClientEvents events,
        Action<TestEntry> report)
    {
        foreach (var e in events.Events.AsEnumerable().Reverse())
            report(new("DNS Client Event", Status.Fail, DescribeEvent(e)));
        if (events.Error != null)
            report(new("DNS Client Event", Status.Warn, $"Could not read the System event log: {events.Error}"));

        if (events.Events.Count > 0)
        {
            report(new("Record After", after.Status == Status.Pass ? Status.Warn : after.Status,
                after.Detail + " — Windows logged a registration failure (above)"));
            return Status.Fail;
        }
        if (after.Status == Status.Pass)
        {
            report(new("Record After", Status.Pass, after.Detail + (before.Status == Status.Pass
                ? " — unchanged; refreshing a correct record shows only as the absence of errors"
                : " — registered")));
            return Status.Pass;
        }
        report(new("Record After", Status.Warn, after.Detail
            + " — no failure logged yet; Windows can take longer, and reports failures in the System event log (source DNS Client Events)"));
        return Status.Warn;
    }
}
