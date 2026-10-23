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
/// <param name="DnsSuffix">The connection-specific DNS suffix, set by hand or by DHCP.</param>
/// <param name="Id">The adapter's GUID, "{…}", which DNS Client events name it by.</param>
/// <param name="RegistersSuffix">"Use this connection's DNS suffix in DNS registration" is on, so Windows also registers host.DnsSuffix.</param>
record NetAdapter(string Name, string Description, bool Tunnel, bool RegistersInDns, IPAddress[] Addresses, IPAddress[] DnsServers,
    bool Virtual = false, bool PointToPoint = false, string DnsSuffix = "", bool RegistersSuffix = false, string Id = "");
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
        // Generic tunnel drivers other clients build on, so a product name above wins
        ("wireguard", "WireGuard"), ("openvpn", "OpenVPN"), ("tap-windows", "OpenVPN"), ("wintun", "Wintun"),
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

    /// <summary>
    /// Ranges reserved for documentation, which nothing routes: 3fff::/20 and 2001:db8::/32, and 192.0.2.0/24,
    /// 198.51.100.0/24 and 203.0.113.0/24. Some clients give their adapter 3fff:: as a placeholder.
    /// </summary>
    public static bool IsDocumentation(IPAddress ip)
    {
        byte[] b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return (b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8);
        return ip.AddressFamily == AddressFamily.InterNetwork
            && ((b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113));
    }

    // An address other hosts cannot reach this machine on, so it is no use in DNS
    static bool IsUnusable(IPAddress ip) => IsCgnat(ip) || IsDocumentation(ip);

    // One line per unusable address, saying why, e.g. "3fff:: is in 3fff::/20, reserved for documentation, ..."
    static string WhyUnusable(IEnumerable<IPAddress> addresses) => string.Join("\n", addresses.Where(IsUnusable).Distinct().Select(a =>
        $"{a} is " + (IsCgnat(a) ? "a 100.64.0.0/10 tunnel address" : "in a range reserved for documentation (a client's placeholder)")
        + ", which other hosts cannot route to"));

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
        // A client's second, address-less interface (a filter binding named "<adapter>-…") adds nothing but its name again
        return found.Where(f => !found.Any(o => !ReferenceEquals(o.Item1, f.Item1) && o.Item1.Addresses.Any(IsRegistrable)
            && !f.Item1.Addresses.Any(IsRegistrable) && f.Item1.Name != tag
            && (o.Item2.StartsWith(f.Item2 + " (", StringComparison.Ordinal) || f.Item1.Name.StartsWith(o.Item1.Name + "-", StringComparison.OrdinalIgnoreCase))))
            .ToList();
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
    /// <summary>
    /// The adapters without the copies a filter driver adds: Npcap and some VPN and firewall filters show up as a second
    /// interface named "&lt;adapter&gt;-&lt;filter&gt;-0000" with the same addresses, which isn't another adapter.
    /// </summary>
    internal static List<NetAdapter> DropFilterBindings(List<NetAdapter> adapters) =>
        adapters.Where(a => !adapters.Any(b => !ReferenceEquals(a, b) && a.Name.StartsWith(b.Name + "-", StringComparison.OrdinalIgnoreCase)
            && a.Addresses.Length > 0 && a.Addresses.ToHashSet().SetEquals(b.Addresses))).ToList();

    static IPAddress[] UnregisteredClientAddresses(List<NetAdapter> adapters, string? tag) =>
        UnregisteredClients(adapters, tag).SelectMany(a => a.Addresses).Where(a => IsRegistrable(a) && !IsUnusable(a)).Distinct().ToArray();

    static List<NetAdapter> UnregisteredClients(List<NetAdapter> adapters, string? tag) =>
        ClientAdapters(adapters, tag).Where(c => !c.Adapter.RegistersInDns).Select(c => c.Adapter).ToList();

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
        if (records.Any(IsUnusable))
            holds += "\n" + WhyUnusable(records);
        if (local.Length == 0)
            return (Status.Pass, holds);
        var stale = records.Except(local).ToArray();
        if (stale.Length == records.Length)
            return (Status.Warn, $"{holds}; this machine has {Join(local)} — the record is stale");
        if (stale.Length > 0)
            return (Status.Warn, $"{holds}; this machine no longer has {Join(stale)}");
        return (records.Any(IsUnusable) ? Status.Warn : Status.Pass, holds);
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
                # The named fields, whose names (unlike the message) are not translated
                foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) {
                    if ($d -is [System.Xml.XmlElement]) { "DATA|$($d.GetAttribute('Name'))|" + ("$($d.InnerText)" -replace '\s+', ' ') }
                }
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
    static string DescribeEvent(DnsClientEvent e, List<NetAdapter>? adapters = null)
    {
        string head = $"event {e.Id} at {e.TimeUtc.ToLocalTime():g}";
        if (EventLayout(e, adapters) is { } laid) return $"{head}\n{laid}";
        return head + (e.Message.Length > 0 ? $" — {Shorten(e.Message, 1500)}" : "");
    }

    /// <summary>
    /// The event as lines: the message's opening, one line per data field, then the message's reason. The message is
    /// translated, so it is split where the fields' values appear in it, which are the same in every language. Null
    /// (use the message as it is) when the event has no named fields or their values are not found in order.
    /// </summary>
    static string? EventLayout(DnsClientEvent e, List<NetAdapter>? adapters)
    {
        var fields = (e.Data ?? []).Where(d => d.Value.Length > 0).ToList();
        if (fields.Count == 0 || fields.Any(d => d.Name.Length == 0)) return null;

        // Each value's place in the message, in order; a value missing from it (often the error code) is skipped
        int first = -1, end = 0;
        foreach (var (_, value) in fields)
        {
            if (value.Length < 2) continue;
            int at = e.Message.IndexOf(value, end, StringComparison.Ordinal);
            if (at < 0) continue;
            if (first < 0) first = at;
            end = at + value.Length;
        }
        if (first < 0) return null;

        // The opening ends at the colon before the first field's label ("...with settings: Adapter Name : {GUID}")
        string lead = e.Message[..first];
        int labelColon = lead.LastIndexOf(':');
        int openingColon = labelColon > 0 ? lead.LastIndexOf(':', labelColon - 1) : -1;
        string opening = openingColon > 0 ? lead[..(openingColon + 1)].Trim() : "";
        string reason = e.Message[end..].Trim();

        var lines = new List<string>();
        if (opening.Length > 0) lines.Add(opening);
        lines.AddRange(fields.Select(d => $"{FieldLabel(d.Name)}: {FieldValue(d.Name, d.Value, adapters)}"));
        if (reason.Length > 0) lines.Add(Shorten(reason, 1000));
        return string.Join("\n", lines);
    }

    // English labels for the DNS Client's field names (AdapterName, HostName, DnsServerList, ...); others are spaced out
    static string FieldLabel(string name)
    {
        string n = name.ToLowerInvariant();
        if (n.Contains("adapter") && !n.Contains("suffix") && !n.Contains("domain")) return "Adapter";
        if (n.Contains("host")) return "Host name";
        if (n.Contains("suffix") || n.Contains("domain")) return "DNS suffix";
        if (n.Contains("sent") || n.Contains("update")) return "Sent update to";
        if (n.Contains("server")) return "DNS servers";
        if (n.Contains("ip") || n.Contains("address")) return "Addresses";
        if (n.Contains("error") || n.Contains("status")) return "Error code";
        return Regex.Replace(name, "(?<=[a-z])(?=[A-Z])", " ");
    }

    // The adapter's GUID with its name in front, and an error code with what it means
    static string FieldValue(string name, string value, List<NetAdapter>? adapters)
    {
        string label = FieldLabel(name);
        if (label == "Adapter" && adapters?.FirstOrDefault(a => a.Id.Length > 0 && a.Id.Equals(value, StringComparison.OrdinalIgnoreCase)) is { } a)
            return $"{a.Name} ({value})";
        if (label == "Error code" && int.TryParse(value, out int code) && DnsErrors.TryGetValue(code, out string? meaning))
            return $"{value} ({meaning})";
        return value;
    }

    // The DNS_ERROR_RCODE_* codes an update comes back with, and the timeout
    static readonly Dictionary<int, string> DnsErrors = new()
    {
        [1460] = "timed out", [9001] = "the server could not read the update", [9002] = "server failure",
        [9003] = "name does not exist", [9004] = "the server does not take dynamic updates", [9005] = "refused",
        [9006] = "a name that should not exist does", [9007] = "a record that should not exist does",
        [9008] = "a record that should exist does not", [9009] = "the server is not authoritative for the zone",
        [9010] = "the name is not in the zone", [9017] = "bad signature", [9018] = "bad key", [9019] = "bad time stamp",
    };

    public static TestGroup TestDnsRegistration(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();
        var adapterTests = new List<TestEntry>();
        var (adapters, ztna) = CheckAdapters(cfg, probe, adapterTests.Add);
        string? fqdn = CheckName(probe, adapters, tests.Add);
        if (fqdn != null)
        {
            tests.AddRange(adapterTests);
            CheckServer(probe, fqdn, adapters, ztna, cfg.Cancel, tests.Add);
        }
        else
        {
            // With no name nothing is registered, so the adapter list is only what would register once there is one
            tests.AddRange(adapterTests.Select(t => t.Name == RegAdapters && t.Status != Status.Skip ? WithoutName(adapters) : t));
            foreach (string name in new[] { RegZone, RegPath, RegRecord })
                tests.Add(new(name, Status.Skip, "No registration name"));
        }
        var errors = CheckErrors(probe, adapters, cfg.Cancel);
        tests.Add(fqdn == null && errors.Status == Status.Pass
            ? errors with { Detail = errors.Detail + " (with no name, Windows attempts no registration)" } : errors);
        return new("Dynamic DNS Registration", tests);
    }

    // The name Windows registers (the first, when there are several); null if this machine has none
    static string? CheckName(IProbe probe, List<NetAdapter> adapters, Action<TestEntry> report)
    {
        try
        {
            var (host, suffix) = probe.HostIdentity();
            var names = RegistrationNames(host, suffix, adapters);
            if (names.Count > 0)
            {
                report(new(RegName, Status.Pass, string.Join(" · ", names.Select(n => n.Source == null ? n.Fqdn : $"{n.Fqdn} ({n.Source})"))));
                return names[0].Fqdn;
            }
            report(new(RegName, Status.Warn, NoNameReason(host, adapters)));
        }
        catch (Exception ex)
        {
            report(new(RegName, Status.Skip, $"Not checked: could not read the host name: {ex.Message}"));
        }
        return null;
    }

    /// <summary>
    /// The names Windows registers: host plus the primary DNS suffix from every registering adapter, and host plus an
    /// adapter's own suffix where "Use this connection's DNS suffix in DNS registration" is on (Source names the adapter).
    /// </summary>
    internal static List<(string Fqdn, string? Source)> RegistrationNames(string host, string? suffix, List<NetAdapter> adapters)
    {
        var names = new List<(string Fqdn, string? Source)>();
        if (!string.IsNullOrWhiteSpace(suffix)) names.Add(($"{host}.{suffix.Trim('.')}", null));
        foreach (var a in adapters.Where(a => a.RegistersInDns && a.RegistersSuffix && a.DnsSuffix.Trim('.').Length > 0))
        {
            string fqdn = $"{host}.{a.DnsSuffix.Trim('.')}";
            if (!names.Any(n => n.Fqdn.Equals(fqdn, StringComparison.OrdinalIgnoreCase))) names.Add((fqdn, a.Name));
        }
        return names;
    }

    // Why nothing is registered: no primary suffix, and no adapter registers under its own suffix. Windows has two
    // separate switches per adapter, and "Register this connection's addresses in DNS" being on is easy to read as
    // registration working, so each adapter says which of the two is off.
    static string NoNameReason(string host, List<NetAdapter> adapters)
    {
        var suffixed = adapters.Where(a => a.DnsSuffix.Trim('.').Length > 0).ToList();
        if (suffixed.Count == 0)
            return $"Nothing is registered: {host} has no primary DNS suffix and no adapter has a DNS suffix, so there is no name to register";
        string lines = string.Join("\n", suffixed.Select(a => $"{a.Name}: {a.DnsSuffix.Trim('.')} — "
            + (a.RegistersInDns ? "\"Use this connection's DNS suffix in DNS registration\" is off, so the suffix is used for lookups only"
                : "\"Register this connection's addresses in DNS\" is off")));
        return $"Nothing is registered: {host} has no primary DNS suffix, and no adapter registers under its own suffix\n{lines}\n"
            + $"To register as {host}.<suffix>, turn both on for the adapter servers should reach this machine through "
            + "(adapter > IPv4 > Advanced > DNS), or set a primary DNS suffix";
    }

    // The Registering Adapters row when there is no name: not a pass, since nothing gets registered
    static TestEntry WithoutName(List<NetAdapter> adapters)
    {
        var registering = adapters.Where(a => a.RegistersInDns && a.Addresses.Any(IsRegistrable)).ToList();
        if (registering.Count == 0)
            return new(RegAdapters, Status.Skip, "No registration name, and no connected adapter has \"Register this connection's addresses in DNS\" on");
        var addresses = registering.SelectMany(a => a.Addresses).Where(IsRegistrable).ToList();
        return new(RegAdapters, Status.Skip, "No registration name. Once there is one, these addresses are registered:\n"
            + string.Join("\n", registering.Select(a => $"{a.Name}: {Join(a.Addresses.Where(IsRegistrable))}"))
            + (addresses.Any(IsUnusable) ? "\n" + WhyUnusable(addresses) : ""));
    }

    static (List<NetAdapter> Adapters, string? Ztna) CheckAdapters(DiagConfig cfg, IProbe probe, Action<TestEntry> report)
    {
        try
        {
            var adapters = probe.Adapters();
            string? ztna = DescribeZtna(adapters, cfg.ZtnaAdapter);
            // Information, not a verdict: the checks below say what the client changes
            report(ztna != null ? new(RegZtna, Status.Info, ztna)
                : new(RegZtna, Status.Pass, cfg.ZtnaAdapter == "" ? "None, as set by you" : "No ZTNA or VPN adapter detected"));
            report(RegisteringAdaptersEntry(adapters, ztna, cfg.ZtnaAdapter));
            return (adapters, ztna);
        }
        catch (Exception ex)
        {
            report(new(RegZtna, Status.Skip, $"Not checked: could not read the network adapters: {ex.Message}"));
            report(new(RegAdapters, Status.Skip, "Network adapters unavailable"));
            return ([], null);
        }
    }

    // The adapter verdict, then a warning on top for any address registered that no other host can use
    static TestEntry RegisteringAdaptersEntry(List<NetAdapter> adapters, string? ztna, string? tag)
    {
        var entry = AdapterVerdict(adapters, ztna, tag);
        var unusable = RegisteringAddresses(adapters).Where(IsUnusable).ToArray();
        return unusable.Length == 0 ? entry : entry with { Status = Status.Warn, Detail = $"{entry.Detail}\n{WhyUnusable(unusable)}" };
    }

    static TestEntry AdapterVerdict(List<NetAdapter> adapters, string? ztna, string? tag)
    {
        var registering = adapters.Where(a => a.RegistersInDns && a.Addresses.Any(IsRegistrable)).ToList();
        // One adapter per line
        string list = string.Join("\n", registering.Select(a => $"{a.Name}: {Join(a.Addresses.Where(IsRegistrable))}"));
        if (registering.Count == 0)
            return new(RegAdapters, Status.Warn, "No connected adapter has \"Register this connection's addresses in DNS\" turned on");
        if (ztna == null)
            return new(RegAdapters, Status.Pass, list);
        // The client's own adapter registers: say whether the local network's address goes into DNS beside it
        var clients = ClientAdapters(adapters, tag).Select(c => c.Adapter).ToList();
        var registeringClients = registering.Where(clients.Contains).ToList();
        if (registeringClients.Count > 0)
        {
            string clientNames = string.Join(", ", registeringClients.Select(a => a.Name));
            var others = registering.Except(registeringClients).ToList();
            if (others.Count == 0)
                return new(RegAdapters, Status.Pass, $"{list}\n{clientNames} is the client's own adapter, so DNS gets the address servers reach this machine through");
            string otherNames = string.Join(", ", others.Select(a => a.Name));
            return new(RegAdapters, Status.Info, $"{list}\nBoth the client's adapter ({clientNames}) and {otherNames} register, so DNS holds both; "
                + $"servers that reach this machine through the client cannot use {otherNames}'s address. To register only the client's, "
                + $"turn off \"Register this connection's addresses in DNS\" on {otherNames}");
        }
        if (UnregisteredClientAddresses(adapters, tag) is { Length: > 0 } unregistered)
        {
            string names = string.Join(", ", UnregisteredClients(adapters, tag).Select(a => a.Name));
            return new(RegAdapters, Status.Pass, $"{list}\nNot registered: {names} ({Join(unregistered)}), the client's own adapter, "
                + "where registration is off; if servers reach this machine through the client, that is the address DNS should hold");
        }
        return new(RegAdapters, Status.Pass, list
            + "\nBehind the ZTNA client this is the local network's address, which servers cannot use to reach this machine");
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

    static TestEntry CheckErrors(IProbe probe, List<NetAdapter> adapters, CancellationToken ct)
    {
        try
        {
            var events = QueryDnsClientEvents(probe, DateTime.UtcNow.AddHours(-24), ct);
            if (events.Error != null)
                return new(RegErrors, Status.Skip, $"Not checked: could not read the System event log: {events.Error}");
            if (events.Events.Count == 0)
                return new(RegErrors, Status.Pass, "No DNS Client registration errors in the last 24 hours");
            return new(RegErrors, Status.Warn, $"{events.Events.Count} in the last 24 hours; latest: {DescribeEvent(events.Events[0], adapters)}");
        }
        catch (Exception ex)
        {
            return new(RegErrors, Status.Skip, $"Not checked: event log query failed: {ex.Message}");
        }
    }

    // An address the internet routes: not private, carrier-grade NAT, loopback or link-local space
    static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || IsUnusable(ip) || !IsRegistrable(ip)) return false;
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
            report(new(RegZone, Status.Info, $"{found} — a synthetic 100.64.0.0/10 address from the ZTNA client; "
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
        Status verdict = ReportOutcome(before, after, events, reg.Adapters, report);

        if (verdict != Status.Pass && reg.Ztna != null)
            report(new(RegZtna, Status.Info, "Through a ZTNA or VPN client a secure update needs Kerberos (port 88 to a domain controller) and "
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
            adapters = probe.Adapters();
            var names = RegistrationNames(host, suffix, adapters);
            if (names.Count == 0)
            {
                Stop(report, RegName, NoNameReason(host, adapters));
                return null;
            }
            fqdn = names[0].Fqdn;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Stop(report, RegName, $"Could not read this machine's name and adapters: {ex.Message}");
            return null;
        }
        var reg = new Registration(fqdn, adapters, RegisteringAddresses(adapters), DescribeZtna(adapters, cfg.ZtnaAdapter));
        report(new(RegName, Status.Pass, fqdn + (reg.Local.Length > 0 ? $" with {Join(reg.Local)}" : " — no adapter has DNS registration turned on")));
        if (reg.Ztna != null)
            report(new(RegZtna, Status.Info, reg.Ztna));
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
        List<NetAdapter> adapters, Action<TestEntry> report)
    {
        foreach (var e in events.Events.AsEnumerable().Reverse())
            report(new("DNS Client Event", Status.Fail, DescribeEvent(e, adapters)));
        if (events.Error != null)
            report(new("DNS Client Event", Status.Skip, $"Not checked: could not read the System event log: {events.Error}"));

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
