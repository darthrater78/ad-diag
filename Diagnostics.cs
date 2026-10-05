using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace AdDiag;

/// <summary>
/// Everything the diagnostics ask of the machine: Windows tools, DNS, TCP, shares, the registry. The app answers
/// with the real thing (MainForm.WindowsProbe); tests answer with canned output, so the checks' verdicts can be
/// tested on any platform. Every call returns within a deadline or throws.
/// </summary>
interface IProbe
{
    /// <summary>Output of a System32 tool ("nltest", "klist", ...). Throws <see cref="TimeoutException"/> on timeout.</summary>
    string RunTool(string tool, string arguments, int timeoutMs, CancellationToken ct);
    string RunPowerShell(string script, int timeoutMs, CancellationToken ct);
    IPAddress[] Resolve(string host, CancellationToken ct);
    Task<bool> TcpConnect(IPAddress ip, int port, CancellationToken ct);
    /// <summary>SRV targets ("host:port"), best first; null if the record doesn't exist.</summary>
    List<string>? QuerySrv(string record, CancellationToken ct);
    /// <summary>Number of entries in a share's root; null if the share doesn't exist.</summary>
    int? ShareEntries(string path, CancellationToken ct);
    string CurrentUser();
    /// <summary>The machine's DNS suffix search list (comma-separated) and primary DNS domain.</summary>
    (string SearchList, string Domain) DnsSuffixConfig();
    /// <summary>This machine's own domain: its NetBIOS name and its primary DNS suffix.</summary>
    string?[] OwnDomainNames();
}

record DiagConfig(string Domain, string Dc, CancellationToken Cancel);
enum Status { Pass, Fail, Warn, Skip }
record TestEntry(string Name, Status Status = Status.Skip, string Detail = "");
record TestGroup(string Name, List<TestEntry> Tests);

// The seven test groups. Kept free of any WinForms dependency so they can be unit tested (see tests/AdDiag.Tests).
static class Diagnostics
{
    public static TestGroup TestDomainMembership(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();
        string? dsreg = null;

        try
        {
            dsreg = probe.RunTool("dsregcmd", "/status", 15000, cfg.Cancel);
            var m = Regex.Match(dsreg, @"DomainJoined\s*:\s*(\S+)");
            bool domJoined = m.Success && m.Groups[1].Value == "YES";
            tests.Add(new("Domain Joined",
                domJoined ? Status.Pass : Status.Fail,
                m.Success ? $"DomainJoined: {m.Groups[1].Value}" : "Could not determine"));
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Joined", Status.Fail, $"dsregcmd error: {ex.Message}"));
        }

        try
        {
            tests.Add(new("Logged-on User", Status.Pass, probe.CurrentUser()));
        }
        catch (Exception ex)
        {
            tests.Add(new("Logged-on User", Status.Fail, $"Cannot get identity: {ex.Message}"));
        }

        try
        {
            string scVerify = probe.RunTool("nltest", $"/sc_verify:{cfg.Domain}", 10000, cfg.Cancel);
            var sc = Parsers.ParseScVerify(scVerify);
            if (sc.AccessDenied)
                tests.Add(new("Secure Channel", Status.Warn, "Requires elevation (Run as Administrator)"));
            else
                tests.Add(new("Secure Channel", sc.Ok ? Status.Pass : Status.Fail, sc.Detail));
        }
        catch (Exception ex)
        {
            tests.Add(new("Secure Channel", Status.Warn, $"nltest failed: {ex.Message}"));
        }

        try
        {
            string dsGetSite = probe.RunTool("nltest", "/dsgetsite", 5000, cfg.Cancel);
            string? siteError = Parsers.NltestError(dsGetSite);
            string site = Parsers.ParseSite(dsGetSite) ?? "";
            string noSite = "No site returned" + (siteError != null ? $" ({siteError})" : "")
                + " - subnet may not be registered in AD Sites and Services";
            tests.Add(new("Site Assignment",
                !string.IsNullOrEmpty(site) ? Status.Pass : Status.Warn,
                !string.IsNullOrEmpty(site) ? $"Site: {site}" : noSite));
        }
        catch (Exception ex)
        {
            tests.Add(new("Site Assignment", Status.Warn, $"nltest failed: {ex.Message}"));
        }

        try
        {
            var result = Parsers.ParsePasswordAgeQuery(probe.RunPowerShell(PasswordAgeScript, 15000, cfg.Cancel));
            string where = result.Domain == null ? ""
                : result.Domain.Equals(cfg.Domain, StringComparison.OrdinalIgnoreCase) ? ""
                : $" (account is in {result.Domain}, not the target domain)";
            if (result.Error != null)
            {
                tests.Add(new("Computer Password Age", Status.Warn, $"Could not query AD: {result.Error}"));
            }
            else if (result.LastSetUtc is not { } lastSetUtc)
            {
                tests.Add(new("Computer Password Age", Status.Skip, $"Computer object not found in {result.Domain}"));
            }
            else if (lastSetUtc.Year < 1700)
            {
                // pwdLastSet = 0 converts to 1601-01-01
                tests.Add(new("Computer Password Age", Status.Warn, $"pwdLastSet is 0 — the computer account password was reset or never set{where}"));
            }
            else
            {
                var lastChanged = lastSetUtc.ToLocalTime();
                var age = DateTime.Now - lastChanged;
                tests.Add(new("Computer Password Age",
                    age.TotalDays < 45 ? Status.Pass : age.TotalDays < 90 ? Status.Warn : Status.Fail,
                    $"Last changed: {lastChanged:g} ({(int)age.TotalDays}d ago)" + (age.TotalDays >= 45 ? " — may indicate broken auto-rotation" : "") + where));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("Computer Password Age", Status.Warn, $"AD query failed: {ex.Message}"));
        }

        return new("Domain Membership & Identity", tests);
    }

    public static TestGroup TestDcConnectivity(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();
        string? dcHost = null;

        try
        {
            string dsGetDc = probe.RunTool("nltest", $"/dsgetdc:{cfg.Domain}", 8000, cfg.Cancel);
            dcHost = Parsers.ParseDcLocator(dsGetDc);
            if (dcHost != null)
            {
                tests.Add(new("Locate DC", Status.Pass, $"Found {dcHost}"));
            }
            else
            {
                tests.Add(new("Locate DC", Status.Fail, "Could not locate a domain controller"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("Locate DC", Status.Fail, $"nltest error: {ex.Message}"));
        }

        string kdc = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : (dcHost ?? cfg.Domain);
        IPAddress? kdcIp = null;
        try
        {
            kdcIp = probe.Resolve(kdc, cfg.Cancel)
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1) // prefer IPv4, fall back to IPv6
                .FirstOrDefault();
        }
        catch { }

        var ports = new (string Name, int Port)[]
        {
            ("Port 389 (LDAP)", 389), ("Port 636 (LDAPS)", 636), ("Port 88 (Kerberos)", 88), ("Port 445 (SMB)", 445),
            ("Port 135 (RPC)", 135), ("Port 464 (Kpasswd)", 464), ("Port 53 (DNS)", 53), ("Port 3268 (Global Catalog)", 3268),
        };
        bool[] reachable = kdcIp == null ? new bool[ports.Length]
            : Task.WhenAll(ports.Select(p => probe.TcpConnect(kdcIp, p.Port, cfg.Cancel))).GetAwaiter().GetResult();

        foreach (var ((name, port), open) in ports.Zip(reachable))
        {
            bool required = port is 389 or 88 or 445;
            if (kdcIp == null)
                tests.Add(new(name, Status.Skip, $"Cannot resolve {kdc}"));
            else
                tests.Add(new(name,
                    open ? Status.Pass : (required ? Status.Fail : Status.Warn),
                    open ? $"Reachable at {kdc} ({kdcIp})" : $"Unreachable at {kdc} ({kdcIp})"));
        }

        return new("DC Discovery & Connectivity", tests);
    }

    public static TestGroup TestDnsForAd(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>
        {
            LookupSrv(probe, $"_ldap._tcp.{cfg.Domain}", "_ldap._tcp SRV", required: true, cfg.Cancel),
            LookupSrv(probe, $"_kerberos._tcp.{cfg.Domain}", "_kerberos._tcp SRV", required: true, cfg.Cancel),
            LookupSrv(probe, $"_gc._tcp.{cfg.Domain}", "_gc._tcp SRV", required: false, cfg.Cancel),
        };

        try
        {
            string host = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : cfg.Domain;
            var addrs = probe.Resolve(host, cfg.Cancel);
            tests.Add(new("DC A Record",
                addrs.Length > 0 ? Status.Pass : Status.Fail,
                addrs.Length > 0 ? $"{host} -> {string.Join(", ", addrs.Select(a => a.ToString()))}" : $"Cannot resolve {host}"));
        }
        catch (Exception ex)
        {
            tests.Add(new("DC A Record", Status.Fail, $"Resolution failed: {ex.Message}"));
        }

        try
        {
            var (searchList, domain) = probe.DnsSuffixConfig();
            var suffixes = new List<string>();
            if (!string.IsNullOrWhiteSpace(searchList))
                suffixes.AddRange(searchList.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0));
            else if (!string.IsNullOrWhiteSpace(domain))
                suffixes.Add(domain);

            if (suffixes.Count > 0)
            {
                bool hasDomain = suffixes.Any(s => s.Contains(cfg.Domain, StringComparison.OrdinalIgnoreCase));
                tests.Add(new("DNS Suffix Search List",
                    hasDomain ? Status.Pass : Status.Warn,
                    string.Join(", ", suffixes) + (hasDomain ? "" : $" — target domain {cfg.Domain} not in suffix list")));
            }
            else
            {
                tests.Add(new("DNS Suffix Search List", Status.Warn, "No DNS suffix configured"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("DNS Suffix Search List", Status.Warn, $"Registry read failed: {ex.Message}"));
        }

        return new("DNS for Active Directory", tests);
    }

    static TestEntry LookupSrv(IProbe probe, string record, string testName, bool required, CancellationToken ct)
    {
        string optional = required ? "" : " (optional)";
        try
        {
            var targets = probe.QuerySrv(record, ct);
            if (targets == null)
                return new(testName, required ? Status.Fail : Status.Warn, $"No {record} record{optional}");

            string hosts = string.Join(", ", targets.Take(3)) + (targets.Count > 3 ? $" (+{targets.Count - 3} more)" : "");
            return new(testName, Status.Pass, $"{record} -> {hosts}{optional}");
        }
        catch (Exception ex)
        {
            return new(testName, Status.Warn, $"DNS query failed: {ex.Message}");
        }
    }

    public static TestGroup TestSysvolNetlogon(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();

        // Opening a share on a domain that doesn't answer blocks for 30s or more inside Windows, where nothing
        // can cancel it, and the app can't exit while a thread is stuck there. So prove SMB answers first.
        string? unreachable = null;
        try
        {
            var addrs = probe.Resolve(cfg.Domain, cfg.Cancel);
            if (addrs.Length == 0)
                unreachable = $"cannot resolve {cfg.Domain}";
            else if (!Task.WhenAll(addrs.Take(8).Select(a => probe.TcpConnect(a, 445, cfg.Cancel))).GetAwaiter().GetResult().Any(open => open))
                unreachable = $"no domain controller for {cfg.Domain} answers on port 445 (SMB)";
        }
        catch (Exception ex)
        {
            unreachable = ex.Message;
        }

        void TestShare(string shareName, string testName)
        {
            string path = $@"\\{cfg.Domain}\{shareName}";
            if (unreachable != null)
            {
                tests.Add(new(testName, Status.Fail, $"{path} not accessible — {unreachable}"));
                return;
            }
            try
            {
                int? entries = probe.ShareEntries(path, cfg.Cancel);
                if (entries != null)
                    tests.Add(new(testName, Status.Pass, $"{path} accessible ({entries} entries)"));
                else
                    tests.Add(new(testName, Status.Fail, $"{path} not accessible"));
            }
            catch (UnauthorizedAccessException)
            {
                tests.Add(new(testName, Status.Warn, $"{path} exists but access denied — check permissions"));
            }
            catch (Exception ex)
            {
                tests.Add(new(testName, Status.Fail, $"{path} — {ex.Message}"));
            }
        }

        TestShare("SYSVOL", "SYSVOL Access");
        TestShare("NETLOGON", "NETLOGON Access");

        return new("SYSVOL & NETLOGON", tests);
    }

    public static TestGroup TestGroupPolicy(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();

        try
        {
            var scopes = QueryRsop(probe, out _, cfg.Cancel);
            var computer = scopes.FirstOrDefault(s => s.Name == "Computer");
            var user = scopes.FirstOrDefault(s => s.Name == "User");
            var primary = computer?.State == GpScopeState.Ok ? computer : user?.State == GpScopeState.Ok ? user : null;

            if (primary == null)
            {
                string why = scopes.Count == 0 ? "Could not read Group Policy results"
                    : string.Join("; ", scopes.Select(GpScopeUnavailable));
                tests.Add(new("GP Last Refresh", Status.Warn, why));
                tests.Add(new("Applied GPOs", Status.Skip, "No scope data available"));
                tests.Add(new("Denied GPOs", Status.Skip, "No scope data available"));
                return new("Group Policy", tests);
            }

            string scopeLabel = primary.Name;
            string elevationNote = computer?.State == GpScopeState.AccessDenied ? " (run as Administrator for Computer scope)" : "";

            if (primary.LastAppliedUtc is { } lastUtc)
            {
                var lastTime = lastUtc.ToLocalTime();
                var age = DateTime.Now - lastTime;
                tests.Add(new("GP Last Refresh",
                    age.TotalHours < 24 ? Status.Pass : age.TotalDays < 7 ? Status.Warn : Status.Fail,
                    $"{scopeLabel}: {lastTime:g} ({FormatTimeSpan(age)} ago){elevationNote}"));
            }
            else
            {
                tests.Add(new("GP Last Refresh", Status.Warn,
                    $"Could not determine last refresh time{elevationNote}"));
            }

            int appliedCount = primary.Applied.Count;
            tests.Add(new("Applied GPOs",
                appliedCount > 0 ? Status.Pass : Status.Warn,
                appliedCount > 0
                    ? $"{scopeLabel}: {appliedCount} GPO(s) applied{elevationNote}"
                    : $"{scopeLabel}: No applied GPOs found{elevationNote}"));

            int deniedCount = primary.Denied.Count;
            tests.Add(new("Denied GPOs", Status.Pass,
                $"{scopeLabel}: {deniedCount} GPO(s) filtered out (informational){elevationNote}"));
        }
        catch (Exception ex)
        {
            tests.Add(new("GP Last Refresh", Status.Fail, $"Group Policy query error: {ex.Message}"));
            tests.Add(new("Applied GPOs", Status.Skip, "Group Policy results unavailable"));
            tests.Add(new("Denied GPOs", Status.Skip, "Group Policy results unavailable"));
        }

        return new("Group Policy", tests);
    }

    public static TestGroup TestTrusts(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();

        try
        {
            string trusts = probe.RunTool("nltest", "/domain_trusts", 8000, cfg.Cancel);
            string? trustError = Parsers.NltestError(trusts);
            var lines = Parsers.ParseTrusts(trusts, probe.OwnDomainNames());

            if (trustError != null)
                tests.Add(new("Domain Trusts", Status.Warn, $"nltest /domain_trusts failed: {trustError}"));
            else if (lines.Count > 0)
                tests.Add(new("Domain Trusts", Status.Pass, $"{lines.Count} trust(s): {string.Join(" | ", lines.Take(5))}"));
            else
                tests.Add(new("Domain Trusts", Status.Pass, "No additional trusts found (single-domain environment)"));
        }
        catch (Exception ex)
        {
            tests.Add(new("Domain Trusts", Status.Warn, $"nltest failed: {ex.Message}"));
        }

        return new("Trust Relationships", tests);
    }

    public static TestGroup TestKerberosAndTime(DiagConfig cfg, IProbe probe)
    {
        var tests = new List<TestEntry>();
        string realm = cfg.Domain.ToUpperInvariant();

        try
        {
            // The cache alone is unreliable: other tests running in parallel may populate it, and an
            // elevated session starts with its own empty cache. So if no TGT is cached, request one.
            string klist = probe.RunTool("klist", "", 5000, cfg.Cancel);
            if (Parsers.HasTgt(klist, realm))
            {
                tests.Add(new("TGT Present", Status.Pass, $"krbtgt/{realm} cached"));
            }
            else
            {
                string get = probe.RunTool("klist", $"get krbtgt/{realm}", 10000, cfg.Cancel);
                if (Parsers.HasTgt(get, realm))
                    tests.Add(new("TGT Present", Status.Pass, $"krbtgt/{realm} obtained from KDC (was not cached)"));
                else
                    tests.Add(new("TGT Present", Status.Fail,
                        $"Could not obtain a TGT for {realm}" + (Parsers.KlistError(get) is { } err ? $" ({err})" : "") + " - no KDC contact"));
            }
        }
        catch (Exception ex)
        {
            tests.Add(new("TGT Present", Status.Fail, $"klist error: {ex.Message}"));
        }

        string kdc = !string.IsNullOrEmpty(cfg.Dc) ? cfg.Dc : cfg.Domain;
        try
        {
            string w32 = probe.RunTool("w32tm", $"/stripchart /computer:{kdc} /samples:1 /dataonly", 5000, cfg.Cancel);
            if (Parsers.ParseStripchartSkew(w32) is { } skew)
            {
                tests.Add(new("Clock Skew",
                    skew < 60 ? Status.Pass : skew < 300 ? Status.Warn : Status.Fail,
                    $"{skew:F2}s drift from {kdc}" + (skew >= 300 ? " - exceeds Kerberos 5min tolerance" : "")));
            }
            else
                tests.Add(new("Clock Skew", Status.Warn, "Cannot measure (DC unreachable?)"));
        }
        catch (Exception ex) { tests.Add(new("Clock Skew", Status.Warn, $"w32tm failed: {ex.Message}")); }

        try
        {
            string w32source = probe.RunTool("w32tm", "/query /source", 5000, cfg.Cancel);
            if (Parsers.ParseTimeSource(w32source) is not { } source)
                throw new InvalidOperationException(w32source.Trim());
            bool fromDomain = Parsers.IsDomainTimeSource(source, cfg.Domain, host => probe.Resolve(host, cfg.Cancel));
            tests.Add(new("Time Source",
                fromDomain ? Status.Pass : Status.Warn,
                source + (fromDomain ? "" : $" - not a {cfg.Domain} DC; not syncing from domain hierarchy")));
        }
        catch (Exception ex)
        {
            tests.Add(new("Time Source", Status.Warn, $"w32tm failed: {ex.Message}"));
        }

        return new("Kerberos & Time Sync", tests);
    }

    // The computer account lives in the computer's domain, which isn't necessarily the logged-on user's
    // (the default [adsisearcher] root) or the target domain. Output: "OK|<domain>|<UTC ISO>", "NOTFOUND|<domain>"
    // or "ERROR|<message>" — errors go to stdout because -EncodedCommand serializes stderr as CLIXML.
    const string PasswordAgeScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        try {
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
            $filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)`$))"
            $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$d", $filter, @('pwdLastSet'))
            $r = $s.FindOne()
            if ($r) { "OK|$d|" + [datetime]::FromFileTimeUtc([int64]$r.Properties['pwdlastset'][0]).ToString('o') }
            else { "NOTFOUND|$d" }
        } catch {
            $e = $_.Exception
            if ($e.InnerException) { $e = $e.InnerException }
            "ERROR|" + ($e.Message -replace '\s+', ' ')
        }
        """;

    // Group Policy results from the RSoP logging data in WMI (what gpresult itself reads), which, unlike gpresult's
    // text, is the same in every display language. Output format: see Parsers.ParseRsop. The last-applied time
    // comes from the GP engine's own State key, falling back to when the RSoP session was logged.
    const string RsopScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        function Clean($s) { "$s" -replace '\s+', ' ' }
        function Flag($b) { if ($b) { '1' } else { '0' } }
        function Get-LastApplied($stateKey) {
            try {
                $p = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\$stateKey\Extension-List\{00000000-0000-0000-0000-000000000000}"
                $ft = ([int64]$p.EndTimeHi -shl 32) -bor ([int64]$p.EndTimeLo -band 0xFFFFFFFF)
                if ($ft -gt 0) { [datetime]::FromFileTimeUtc($ft) }
            } catch { }
        }
        function Write-Scope($scope, $ns, $stateKey) {
            try {
                $session = Get-CimInstance -Namespace $ns -ClassName RSOP_Session | Select-Object -First 1
                $gpos = @{}
                Get-CimInstance -Namespace $ns -ClassName RSOP_GPO | ForEach-Object { $gpos[$_.id] = $_ }
                $links = @(Get-CimInstance -Namespace $ns -ClassName RSOP_GPLink)
            } catch {
                $e = $_.Exception
                $code = if ($e -is [Microsoft.Management.Infrastructure.CimException]) { "$($e.NativeErrorCode)" } else { '' }
                if ($code -eq 'AccessDenied') { "SCOPE|$scope|DENIED" }
                elseif ($code -eq 'InvalidNamespace') { "SCOPE|$scope|NODATA" }
                else { "SCOPE|$scope|ERROR|" + (Clean $e.Message) }
                return
            }
            if (-not $session) { "SCOPE|$scope|NODATA"; return }
            $last = Get-LastApplied $stateKey
            if (-not $last -and $session.creationTime) { $last = $session.creationTime.ToUniversalTime() }
            "SCOPE|$scope|OK|" + $(if ($last) { $last.ToString('o') } else { '' }) + '|' + (Clean $session.site)
            foreach ($l in $links) {
                $g = $gpos[$l.GPO.id]
                if (-not $g) { continue }
                "GPO|$scope|$($g.id)|$([int]$l.appliedOrder)|$(Flag $l.enabled)|$(Flag $g.enabled)|$(Flag $g.accessDenied)|$(Flag $g.filterAllowed)|" + (Clean $g.name)
            }
        }
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Write-Scope 'Computer' 'root\rsop\computer' 'Machine'
        Write-Scope 'User' "root\rsop\user\$($sid -replace '-', '_')" $sid
        """;

    public static List<GpScope> QueryRsop(IProbe probe, out string raw, CancellationToken ct = default)
    {
        raw = probe.RunPowerShell(RsopScript, 25000, ct);
        return Parsers.ParseRsop(raw);
    }

    public static string GpScopeUnavailable(GpScope scope) => scope.State switch
    {
        GpScopeState.AccessDenied => $"{scope.Name} scope requires running as Administrator",
        GpScopeState.NoData => $"No Group Policy results recorded for the {scope.Name} scope (RSoP logging may be disabled)",
        _ => $"Could not read the {scope.Name} scope: {scope.Detail}",
    };

    public static string FormatTimeSpan(TimeSpan ts)
    {
        if (ts.TotalDays >= 1) return $"{(int)ts.TotalDays}d {ts.Hours}h";
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        return $"{(int)ts.TotalMinutes}m";
    }
}
