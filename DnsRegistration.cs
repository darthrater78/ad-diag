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

    /// <summary>
    /// The zone that holds <paramref name="fqdn"/> and its primary server, found the way Windows finds where to
    /// send an update: ask for the SOA of the name, then of each parent. Null if no zone answers.
    /// </summary>
    static SoaRecord? FindZone(IProbe probe, string fqdn, CancellationToken ct)
    {
        for (string name = fqdn.TrimEnd('.'); name.Contains('.'); name = name[(name.IndexOf('.') + 1)..])
        {
            if (probe.QuerySoa(name, ct) is { } soa)
                return new(soa.Zone.TrimEnd('.'), soa.PrimaryServer.TrimEnd('.'));
        }
        return null;
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
        var ct = cfg.Cancel;

        string? fqdn = null;
        try
        {
            var (host, suffix) = probe.HostIdentity();
            if (string.IsNullOrWhiteSpace(suffix))
                tests.Add(new(RegName, Status.Warn, $"{host} has no primary DNS suffix, so Windows registers no name for it (not domain-joined?)"));
            else
                tests.Add(new(RegName, Status.Pass, fqdn = $"{host}.{suffix}"));
        }
        catch (Exception ex)
        {
            tests.Add(new(RegName, Status.Warn, $"Could not read the host name: {ex.Message}"));
        }

        var adapters = new List<NetAdapter>();
        string? ztna = null;
        try
        {
            adapters = probe.Adapters();
            ztna = DescribeZtna(adapters, cfg.ZtnaAdapter);
            tests.Add(new(RegZtna, Status.Pass, ztna != null ? $"{ztna} (informational)"
                : cfg.ZtnaAdapter == "" ? "None, as set by you" : "No ZTNA or VPN adapter detected"));

            var registering = adapters.Where(a => a.RegistersInDns && a.Addresses.Any(IsRegistrable)).ToList();
            var tunnelOnly = RegisteringAddresses(adapters).Where(IsCgnat).ToArray();
            string list = string.Join(" · ", registering.Select(a => $"{a.Name}: {Join(a.Addresses.Where(IsRegistrable))}"));
            if (registering.Count == 0)
                tests.Add(new(RegAdapters, Status.Warn, "No connected adapter has \"Register this connection's addresses in DNS\" turned on"));
            else if (tunnelOnly.Length > 0)
                tests.Add(new(RegAdapters, Status.Warn, $"{list} — {Join(tunnelOnly)} is a 100.64.0.0/10 tunnel address, which other hosts cannot route to"));
            else if (ztna == null)
                tests.Add(new(RegAdapters, Status.Pass, list));
            else if (UnregisteredClientAddresses(adapters, cfg.ZtnaAdapter) is { Length: > 0 } unregistered)
                tests.Add(new(RegAdapters, Status.Pass, $"{list} — the client's own address ({Join(unregistered)}) is not registered, because "
                    + "registration is off on its adapter; if servers reach this machine through the client, that is the address DNS should hold"));
            else
                tests.Add(new(RegAdapters, Status.Pass, list
                    + " — behind the ZTNA client this is the local network's address, which servers cannot use to reach this machine"));
        }
        catch (Exception ex)
        {
            tests.Add(new(RegZtna, Status.Warn, $"Could not read the network adapters: {ex.Message}"));
            tests.Add(new(RegAdapters, Status.Skip, "Network adapters unavailable"));
        }

        if (fqdn == null)
        {
            foreach (string name in new[] { RegZone, RegPath, RegRecord })
                tests.Add(new(name, Status.Skip, "No registration name"));
        }
        else
        {
            var target = FindUpdateTarget(probe, fqdn, ztna, ct, tests.Add);

            if (target?.Address is not { } address)
                tests.Add(new(RegPath, Status.Skip, "No primary server to test"));
            else if (probe.TcpConnect(address, 53, ct).GetAwaiter().GetResult())
                tests.Add(new(RegPath, Status.Pass, $"{target.Server} ({address}) reachable over TCP"));
            else
                tests.Add(new(RegPath, Status.Fail, $"{target.Server} ({address}) does not answer on TCP port 53, so updates cannot be delivered"
                    + (ztna != null ? " — the ZTNA policy must allow TCP and UDP 53 to this server" : "")));

            try
            {
                var (records, source) = QueryRecord(probe, fqdn, target, ct);
                var (status, detail) = CompareRecord(records, RegisteringAddresses(adapters), source);
                tests.Add(new(RegRecord, status, detail));
            }
            catch (Exception ex)
            {
                tests.Add(new(RegRecord, Status.Warn, $"Could not query the record: {ex.Message}"));
            }
        }

        try
        {
            var events = QueryDnsClientEvents(probe, DateTime.UtcNow.AddHours(-24), ct);
            if (events.Error != null)
                tests.Add(new(RegErrors, Status.Warn, $"Could not read the System event log: {events.Error}"));
            else if (events.Events.Count == 0)
                tests.Add(new(RegErrors, Status.Pass, "No DNS Client registration errors in the last 24 hours"));
            else
                tests.Add(new(RegErrors, Status.Warn, $"{events.Events.Count} in the last 24 hours; latest: {DescribeEvent(events.Events[0])}"));
        }
        catch (Exception ex)
        {
            tests.Add(new(RegErrors, Status.Warn, $"Event log query failed: {ex.Message}"));
        }

        return new("Dynamic DNS Registration", tests);
    }

    // Finds the zone's primary server and its addresses, reporting the verdict as the "Zone Primary Server" entry
    static UpdateTarget? FindUpdateTarget(IProbe probe, string fqdn, string? ztna, CancellationToken ct, Action<TestEntry> report)
    {
        string proxyHint = ztna != null
            ? " — a ZTNA DNS proxy often answers only A/AAAA/SRV; without the SOA record Windows cannot find where to send updates"
            : "";
        SoaRecord? soa;
        try
        {
            soa = FindZone(probe, fqdn, ct);
        }
        catch (Exception ex)
        {
            report(new(RegZone, Status.Fail, $"SOA lookup failed: {ex.Message}{proxyHint}"));
            return null;
        }
        if (soa == null)
        {
            report(new(RegZone, Status.Fail, $"No SOA record for {fqdn} or its parent zones{proxyHint}"));
            return null;
        }

        IPAddress[] addresses = [];
        try { addresses = probe.Resolve(soa.PrimaryServer, ct); }
        catch (OperationCanceledException) { throw; }
        catch { }
        var target = new UpdateTarget(soa, addresses);
        if (target.Address is not { } address)
            report(new(RegZone, Status.Fail, $"{soa.Zone} -> {soa.PrimaryServer}, which does not resolve"));
        else if (IsCgnat(address))
            report(new(RegZone, Status.Warn, $"{soa.Zone} -> {soa.PrimaryServer} ({address}) — a synthetic 100.64.0.0/10 address from the ZTNA client; "
                + "updates reach the real server only if the client forwards port 53 for it"));
        else
            report(new(RegZone, Status.Pass, $"{soa.Zone} -> {soa.PrimaryServer} ({address})"));
        return target;
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
        Status Stop(string step, string detail)
        {
            report(new(step, Status.Fail, detail));
            return Status.Fail;
        }

        string fqdn;
        List<NetAdapter> adapters;
        try
        {
            var (host, suffix) = probe.HostIdentity();
            if (string.IsNullOrWhiteSpace(suffix))
                return Stop(RegName, $"{host} has no primary DNS suffix, so Windows has no name to register");
            fqdn = $"{host}.{suffix}";
            adapters = probe.Adapters();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Stop(RegName, $"Could not read this machine's name and adapters: {ex.Message}");
        }
        var local = RegisteringAddresses(adapters);
        string? ztna = DescribeZtna(adapters, cfg.ZtnaAdapter);
        report(new(RegName, Status.Pass, fqdn + (local.Length > 0 ? $" with {Join(local)}" : " — no adapter has DNS registration turned on")));
        if (ztna != null)
            report(new(RegZtna, Status.Pass, $"{ztna} (informational)"));

        if (!probe.IsElevated())
            return Stop("Elevation", "ipconfig /registerdns requires running as Administrator");

        var target = FindUpdateTarget(probe, fqdn, ztna, ct, report);

        (Status Status, string Detail) ReadRecord()
        {
            try
            {
                var (records, source) = QueryRecord(probe, fqdn, target, ct);
                return CompareRecord(records, local, source);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return (Status.Warn, $"Could not query the record: {ex.Message}");
            }
        }

        var before = ReadRecord();
        report(new("Record Before", before.Status, before.Detail));

        // Event times have whole-second precision in the query, so start a moment early
        DateTime startedUtc = DateTime.UtcNow.AddSeconds(-2);
        try
        {
            string output = Regex.Replace(probe.RunTool("ipconfig", "/registerdns", 20000, ct), @"\s+", " ").Trim();
            report(new("Send", Status.Pass, "ipconfig /registerdns ran" + (output.Length > 0 ? $": {Shorten(output, 200)}" : "")));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Stop("Send", $"ipconfig /registerdns failed: {ex.Message}");
        }

        report(new(RegWait, Status.Skip, $"Watching the server and the DNS Client event log for up to {attempts * pollMs / 1000}s"));
        var after = before;
        var events = new DnsClientEvents([], null);
        for (int attempt = 1; attempt <= attempts; attempt++)
        {
            if (ct.WaitHandle.WaitOne(pollMs)) ct.ThrowIfCancellationRequested();
            try { events = QueryDnsClientEvents(probe, startedUtc, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { events = new([], ex.Message); }
            after = ReadRecord();
            // A record that was already right proves nothing on its own, so give a failure time to be logged
            if (events.Events.Count > 0 || (after.Status == Status.Pass && attempt >= 2)) break;
        }

        foreach (var e in events.Events.AsEnumerable().Reverse())
            report(new("DNS Client Event", Status.Fail, DescribeEvent(e)));
        if (events.Error != null)
            report(new("DNS Client Event", Status.Warn, $"Could not read the System event log: {events.Error}"));

        Status verdict;
        if (events.Events.Count > 0)
        {
            verdict = Status.Fail;
            report(new("Record After", after.Status == Status.Pass ? Status.Warn : after.Status,
                after.Detail + " — Windows logged a registration failure (above)"));
        }
        else if (after.Status == Status.Pass)
        {
            verdict = Status.Pass;
            report(new("Record After", Status.Pass, after.Detail + (before.Status == Status.Pass
                ? " — unchanged; refreshing a correct record shows only as the absence of errors"
                : " — registered")));
        }
        else
        {
            verdict = Status.Warn;
            report(new("Record After", Status.Warn, after.Detail
                + " — no failure logged yet; Windows can take longer, and reports failures in the System event log (source DNS Client Events)"));
        }

        if (verdict != Status.Pass && ztna != null)
            report(new(RegZtna, Status.Warn, "Through a ZTNA or VPN client a secure update needs Kerberos (port 88 to a domain controller) and "
                + $"TCP and UDP 53 to {target?.Server ?? "the zone's primary server"} to pass the tunnel as real traffic, not through the client's DNS proxy"));
        return verdict;
    }
}
