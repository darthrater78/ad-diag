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

/// <summary>What a file server or share path names: the server as Windows will use it, and the share, if given.</summary>
/// <param name="Typed">The server as the user typed it, before the domain was added.</param>
record SmbTarget(string Server, string? Share, string Typed)
{
    public bool IsAddress => IPAddress.TryParse(Server, out _);
    public string Spn => $"cifs/{Server}";
    public string Unc => Share == null ? $@"\\{Server}" : $@"\\{Server}\{Share}";
}

/// <summary>The outcome of one SSPI handshake's first step: its SECURITY_STATUS and, for Negotiate, the package it chose.</summary>
record SspiResult(int Status, string? Package)
{
    public const int Ok = 0, ContinueNeeded = 0x00090312;
    public bool Succeeded => Status is Ok or ContinueNeeded;
}

/// <summary>Opening a share: how many entries its root holds, or the Win32 error that stopped it.</summary>
record ShareOpen(int? Entries, int Error, string Message);

/// <summary>Where the test stopped or what it found, and what to do about it.</summary>
record SmbVerdict(Status Status, string Text, string? Fix);

// The SMB tab: from this PC to a file share, one connection point at a time (name, port 445, Kerberos, sign-in,
// share), plus this PC's SMB client settings. It runs only when the user asks, never with the AD run. Everything is
// read only: DNS, a TCP connect, the registry, klist and cmdkey, an LDAP search, an SSPI handshake that is never
// sent anywhere, and listing the share's root. Nothing is written, and no credential is prompted for or stored.
static partial class Diagnostics
{
    public const string SmbName = "Name", SmbPort = "Port 445", SmbKerberos = "Kerberos", SmbSignIn = "Sign-in",
        SmbShare = "Share", SmbSettings = "This PC's SMB settings";

    /// <summary>The connection points in the order a connection passes them.</summary>
    public static readonly string[] SmbSteps = [SmbName, SmbPort, SmbKerberos, SmbSignIn, SmbShare];

    // Row names, shared with the Guide and the verdict
    public const string SmbNameRow = "Name", SmbAddressesRow = "Addresses", SmbPortRow = "Port 445 (SMB)",
        SmbCloudTrustRow = "Cloud Kerberos Trust", SmbTgtRow = "Ticket-granting ticket", SmbKpasswdRow = "_kpasswd._tcp SRV",
        SmbSpnRow = "SPN", SmbTicketRow = "Service ticket", SmbEncryptionRow = "Ticket encryption", SmbTokenRow = "Max Token Size",
        SmbNegotiationRow = "Negotiation", SmbNtlmRow = "LAN Manager auth level", SmbSavedRow = "Saved credential",
        SmbShareRow = "Share access", SmbSigningRow = "Signing", SmbV1Row = "SMBv1 client", SmbGuestRow = "Insecure guest logons";

    // A share name may not hold these (or control characters); a path below the share isn't needed to test it
    static readonly char[] BadShareChars = ['"', '/', '\\', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '?', '*'];

    // Only the dotted form: IPAddress.TryParse also takes "10" (0.0.0.10) and "0x7f.1", which no one means
    static readonly Regex DottedIPv4 = new(@"^\d{1,3}(\.\d{1,3}){3}$");

    /// <summary>
    /// Reads what the user typed: "\\server\share", "server\share", "//server/share" or a bare "server". A server
    /// with no dot gets <paramref name="domain"/> added, as Windows' suffix search would. A path below the share
    /// is dropped. Returns an error to show instead when it can't be a server or share.
    /// </summary>
    public static (SmbTarget? Target, string? Error) ParseSmbTarget(string input, string domain)
    {
        string text = input.Trim().Replace('/', '\\').TrimStart('\\');
        if (text.Length == 0) return (null, "Type a file server, as in files or files.contoso.com");
        string[] parts = text.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        string server = parts[0].TrimEnd('.');
        string? share = parts.Length > 1 ? parts[1] : null;

        if (server.Contains(':'))
            return (null, "A Windows path can't hold an IPv6 address or a port; use the server's name");
        bool address = DottedIPv4.IsMatch(server) && IPAddress.TryParse(server, out _);
        if (!address && (server.Length > 253 || !DomainName.IsMatch(server) || DottedIPv4.IsMatch(server)))
            return (null, $"\"{server}\" isn't a server name: use letters, digits, hyphens and dots");
        if (share != null && (share.Length > 80 || share.IndexOfAny(BadShareChars) >= 0 || share.Any(char.IsControl)
            || share.Trim('.', ' ').Length == 0 || share != share.TrimEnd('.', ' ')))
            return (null, $"\"{share}\" isn't a share name");

        string full = !address && !server.Contains('.') && domain.Length > 0 && DomainName.IsMatch(domain) ? $"{server}.{domain}" : server;
        return (new SmbTarget(full.ToLowerInvariant(), share, server), null);
    }

    /// <summary>
    /// Reads the File server and Share fields. The server field may also hold a whole path ("\\files\Finance"),
    /// pasted from Explorer, as long as the share isn't typed twice.
    /// </summary>
    public static (SmbTarget? Target, string? Error) ParseSmbTarget(string server, string share, string domain)
    {
        share = share.Trim().Trim('\\', '/');
        var (target, error) = ParseSmbTarget(server, domain);
        if (target == null || share.Length == 0) return (target, error);
        if (target.Share != null) return (null, "The share is typed in both boxes; clear one of them");
        if (share.IndexOfAny(['\\', '/']) >= 0) return (null, "Type only the share's name in Share, without a folder");
        return ParseSmbTarget($@"\\{target.Typed}\{share}", domain);
    }

    /// <summary>
    /// Tests the path to <paramref name="target"/> one step at a time, reporting each step as it finishes so the
    /// UI can light it up. A step that fails stops the ones after it, except Kerberos: Windows can still sign in
    /// with NTLM. This PC's SMB settings are read last, whatever happened.
    /// </summary>
    public static List<TestGroup> TestSmb(SmbTarget target, JoinProfile profile, DiagConfig cfg, IProbe probe, Action<TestGroup>? report = null)
    {
        var groups = new List<TestGroup>();
        string? stopped = null;
        TestGroup Add(TestGroup group)
        {
            groups.Add(group);
            report?.Invoke(group);
            return group;
        }
        TestGroup NotReached(string step, string why) =>
            new(step, [new(step == SmbShare ? SmbShareRow : step, Status.Skip, $"Not checked: {why}")]);

        // dsregcmd is slow and both the Kerberos and Sign-in steps may need it; it runs once, when first asked
        var dsreg = new Lazy<(Dictionary<string, string>? Fields, string? Error)>(() =>
        {
            try { return (Parsers.ParseDsreg(probe.RunTool("dsregcmd", "/status", 15000, cfg.Cancel)), null); }
            catch (Exception ex) when (ex is not OperationCanceledException) { return (null, ex.Message); }
        });
        IPAddress[] addresses = [];
        foreach (string step in SmbSteps)
        {
            cfg.Cancel.ThrowIfCancellationRequested();
            if (stopped != null)
            {
                Add(NotReached(step, stopped));
                continue;
            }
            DiagLog.Section = step;
            TestGroup group;
            switch (step)
            {
                case SmbName:
                    (group, addresses) = SmbNameStep(target, cfg, probe);
                    if (Failed(group)) stopped = "the name didn't resolve";
                    break;
                case SmbPort:
                    group = SmbPortStep(addresses, cfg, probe);
                    if (Failed(group)) stopped = "port 445 is unreachable";
                    break;
                case SmbKerberos:
                    group = SmbKerberosStep(target, profile, cfg, probe, dsreg);
                    break;
                case SmbSignIn:
                    group = SmbSignInStep(target, profile, cfg, probe, dsreg);
                    if (group.Tests.Any(t => t.Name == SmbNegotiationRow && t.Status == Status.Fail)) stopped = "sign-in failed";
                    break;
                default:
                    group = SmbShareStep(target, cfg, probe);
                    break;
            }
            Add(group);
        }
        DiagLog.Section = SmbSettings;
        Add(SmbSettingsGroup(probe));
        DiagLog.Section = null;
        return groups;
    }

    static bool Failed(TestGroup group) => group.Tests.Any(t => t.Status == Status.Fail);

    // ── Name ──

    static (TestGroup, IPAddress[]) SmbNameStep(SmbTarget target, DiagConfig cfg, IProbe probe)
    {
        if (target.IsAddress)
        {
            var ip = IPAddress.Parse(target.Server);
            return (new(SmbName, [
                new(SmbNameRow, Status.Info, $"{target.Server} is an address, not a name; Kerberos needs a name, so Windows signs in with NTLM"),
                new(SmbAddressesRow, Status.Pass, target.Server)]), [ip]);
        }
        string named = target.Typed.Equals(target.Server, StringComparison.OrdinalIgnoreCase) ? target.Server : $"{target.Server} (typed {target.Typed})";
        IPAddress[] found;
        try { found = probe.Resolve(target.Server, cfg.Cancel); }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
        {
            return (new(SmbName, [new(SmbNameRow, Status.Fail, $"{target.Server}: no such name in DNS")]), []);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (new(SmbName, [new(SmbNameRow, Status.Fail, $"{target.Server}: the lookup failed: {ex.Message}")]), []);
        }
        if (found.Length == 0)
            return (new(SmbName, [new(SmbNameRow, Status.Fail, $"{target.Server}: the name has no addresses")]), []);

        var v4 = found.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
        var v6 = found.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).ToArray();
        string list = string.Join(", ", found.Take(4)) + (found.Length > 4 ? $" and {found.Length - 4} more" : "");
        var addresses = v4.Length == 0
            ? new TestEntry(SmbAddressesRow, Status.Info, $"{list} (IPv6 only); apps and networks that need IPv4 can't reach it")
            : new TestEntry(SmbAddressesRow, Status.Pass, $"{list} ({(v6.Length == 0 ? "IPv4 only" : "IPv4 and IPv6")})");
        // Windows tries IPv6 first when this PC has it; the port step tries IPv4 first, the common path on a LAN or VPN
        return (new(SmbName, [new(SmbNameRow, Status.Pass, named), addresses]), [.. v4, .. v6]);
    }

    // ── Port 445 ──

    static TestGroup SmbPortStep(IPAddress[] addresses, DiagConfig cfg, IProbe probe)
    {
        foreach (var ip in addresses.Take(4))
        {
            cfg.Cancel.ThrowIfCancellationRequested();
            if (probe.TcpConnect(ip, 445, cfg.Cancel).GetAwaiter().GetResult())
                return new(SmbPort, [new(SmbPortRow, Status.Pass, $"Reachable at {ip}")]);
        }
        return new(SmbPort, [new(SmbPortRow, Status.Fail, $"No answer on TCP 445 from {string.Join(", ", addresses.Take(4))}")]);
    }

    // ── Kerberos ──

    static TestGroup SmbKerberosStep(SmbTarget target, JoinProfile profile, DiagConfig cfg, IProbe probe,
        Lazy<(Dictionary<string, string>? Fields, string? Error)> dsreg)
    {
        if (target.IsAddress)
            return new(SmbKerberos, [new(SmbTicketRow, Status.Skip, "Not checked: Kerberos can't name a server by its address; Windows uses NTLM")]);

        var tests = new List<TestEntry>();
        if (profile != JoinProfile.Domain && CloudTrustEntry(profile, dsreg.Value) is { } trust) tests.Add(trust);

        bool haveDomain = cfg.Domain.Length > 0 && DomainName.IsMatch(cfg.Domain);
        string noDomain = profile == JoinProfile.Entra ? "Not checked: type the on-prem domain" : "Not checked: no domain";
        tests.Add(haveDomain ? TgtWithRetry(cfg, probe) : new(SmbTgtRow, Status.Skip, noDomain));
        if (profile != JoinProfile.Entra)
            tests.Add(haveDomain ? KpasswdEntry(cfg, probe) : new(SmbKpasswdRow, Status.Skip, noDomain));
        tests.Add(haveDomain ? SpnEntry(target, cfg, probe) : new(SmbSpnRow, Status.Skip, noDomain));

        var (ticket, tries, first) = AuthenticateWithRetry(probe, "Kerberos", target.Spn, cfg.Cancel);
        tests.Add((ticket.Succeeded
            ? tries == 1
                ? new TestEntry(SmbTicketRow, Status.Pass, $"{target.Spn} issued")
                : new TestEntry(SmbTicketRow, Status.Info, $"{target.Spn} issued on try {tries}; the first failed: {SspiStatusText(first!.Status)}. "
                    + "A slow first answer is common over a VPN, or just after sign-in while Windows fetches its ticket")
            : new TestEntry(SmbTicketRow, Status.Warn, $"{target.Spn}: {SspiStatusText(ticket.Status)}"
                + (tries > 1 ? $" ({tries} tries, {SmbRetryDelayMs / 1000} s apart)" : ""))) with { Tries = tries });
        tests.Add(ticket.Succeeded ? TicketEtypeEntry(target, cfg, probe) : new(SmbEncryptionRow, Status.Skip, "Not checked: no service ticket"));
        tests.Add(MaxTokenSizeEntry(probe));
        return new(SmbKerberos, tests);
    }

    // On an Entra joined PC the only way to an on-prem Kerberos ticket is Cloud Kerberos Trust; on a hybrid joined
    // one it matters only when the user signs in with Windows Hello, so it shows only when Hello is set up
    static TestEntry? CloudTrustEntry(JoinProfile profile, (Dictionary<string, string>? Fields, string? Error) dsreg)
    {
        if (dsreg.Fields is not { } ds)
            return profile == JoinProfile.Entra ? new(SmbCloudTrustRow, Status.Skip, $"Not checked: dsregcmd failed: {dsreg.Error}") : null;
        bool? hello = Parsers.DsregFlag(ds, "NgcSet");
        if (profile == JoinProfile.Hybrid && hello != true) return null;
        string flags = $"CloudTgt: {Flag(ds, "CloudTgt")}, OnPremTgt: {Flag(ds, "OnPremTgt")}";
        return Parsers.DsregFlag(ds, "OnPremTgt") == true
            ? new(SmbCloudTrustRow, Status.Pass, flags)
            : profile == JoinProfile.Entra
                ? new(SmbCloudTrustRow, Status.Fail, $"{flags}; without OnPremTgt this PC gets no Kerberos ticket for on-prem servers")
                : new(SmbCloudTrustRow, Status.Warn, $"{flags}; a Windows Hello sign-in gets no Kerberos ticket, so SMB falls back to NTLM");
    }

    static string Flag(Dictionary<string, string> ds, string name) => Parsers.DsregFlag(ds, name) switch { true => "YES", false => "NO", _ => "?" };

    static TestEntry KpasswdEntry(DiagConfig cfg, IProbe probe)
    {
        string record = $"_kpasswd._tcp.{cfg.Domain}";
        try
        {
            var targets = probe.QuerySrv(record, cfg.Cancel);
            return targets is { Count: > 0 }
                ? new(SmbKpasswdRow, Status.Pass, $"{targets.Count} record{(targets.Count == 1 ? "" : "s")}: {string.Join(", ", targets.Take(3))}")
                : new(SmbKpasswdRow, Status.Warn, $"No record in {cfg.Domain}; password changes from this PC fail (sign-in still works)");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbKpasswdRow, Status.Skip, $"Not checked: {ex.Message}");
        }
    }

    /// <summary>
    /// The script that finds the accounts holding cifs/ or HOST/ for <paramref name="server"/> (cifs is an alias of
    /// HOST in AD). Only names that passed <see cref="DomainName"/> go in it. Output: "SPN|&lt;account&gt;|&lt;spn&gt;"
    /// per match, "NONE", or "ERROR|&lt;message&gt;".
    /// </summary>
    internal static string SpnScript(string domain, string server)
    {
        if (!DomainName.IsMatch(domain)) throw new ArgumentException($"Not a domain name: {domain}");
        if (!DomainName.IsMatch(server)) throw new ArgumentException($"Not a server name: {server}");
        return $$"""
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            try {
                $root = [adsi]'LDAP://{{domain}}'
                $s = New-Object System.DirectoryServices.DirectorySearcher($root, '(|(servicePrincipalName=cifs/{{server}})(servicePrincipalName=HOST/{{server}}))', @('sAMAccountName','servicePrincipalName'))
                $s.ClientTimeout = [TimeSpan]::FromSeconds(10)
                $found = $s.FindAll()
                if ($found.Count -eq 0) { 'NONE' }
                foreach ($r in $found) {
                    foreach ($spn in $r.Properties['serviceprincipalname']) {
                        if ($spn -ieq 'cifs/{{server}}' -or $spn -ieq 'HOST/{{server}}') { 'SPN|' + $r.Properties['samaccountname'][0] + '|' + $spn }
                    }
                }
            } catch {
                $e = $_.Exception
                if ($e.InnerException) { $e = $e.InnerException }
                'ERROR|' + ($e.Message -replace '\s+', ' ')
            }
            """;
    }

    /// <summary>The (account, SPN) pairs the script found, or its error.</summary>
    internal static (List<(string Account, string Spn)> Found, string? Error) ParseSpnOutput(string output)
    {
        var found = new List<(string, string)>();
        foreach (var parts in output.Split('\n').Select(l => l.Trim().Split('|')))
        {
            if (parts[0] == "ERROR") return (found, string.Join("|", parts[1..]).Trim());
            if (parts.Length == 3 && parts[0] == "SPN") found.Add((parts[1], parts[2]));
        }
        return (found, null);
    }

    static TestEntry SpnEntry(SmbTarget target, DiagConfig cfg, IProbe probe)
    {
        string output;
        try { output = probe.RunPowerShell(SpnScript(cfg.Domain, target.Server), 20000, cfg.Cancel); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbSpnRow, Status.Skip, $"Not checked: could not search AD: {ex.Message}");
        }
        var (found, error) = ParseSpnOutput(output);
        if (error != null) return new(SmbSpnRow, Status.Skip, $"Not checked: could not search AD: {error}");
        var accounts = found.Select(f => f.Account).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (accounts.Count == 0)
            return new(SmbSpnRow, Status.Warn, $"No account in {cfg.Domain} has cifs/{target.Server} or HOST/{target.Server}");
        if (accounts.Count > 1)
            return new(SmbSpnRow, Status.Fail, $"Duplicate: {string.Join(" and ", accounts)} both hold it; the KDC can't tell which key to use");
        string spn = found.Any(f => f.Spn.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase)) ? $"cifs/{target.Server}" : $"HOST/{target.Server} (covers cifs)";
        return new(SmbSpnRow, Status.Pass, $"{spn} on account {accounts[0]}");
    }

    static TestEntry TicketEtypeEntry(SmbTarget target, DiagConfig cfg, IProbe probe)
    {
        try
        {
            var ticket = Parsers.ParseKlist(probe.RunTool("klist", "", 5000, cfg.Cancel)).Tickets
                .FirstOrDefault(t => t.Server.Split('@')[0].Trim().Equals(target.Spn, StringComparison.OrdinalIgnoreCase));
            if (ticket == null || !ticket.Fields.TryGetValue("KerbTicket Encryption Type", out var etype))
                return new(SmbEncryptionRow, Status.Skip, "Not checked: the ticket isn't in klist's list");
            return UsesRc4(ticket.Fields)
                ? new(SmbEncryptionRow, Status.Warn, $"{etype}; set the server's account to AES (msDS-SupportedEncryptionTypes)")
                : new(SmbEncryptionRow, Status.Pass, etype);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbEncryptionRow, Status.Skip, $"Not checked: klist failed: {ex.Message}");
        }
    }

    const string KerberosParameters = @"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters";
    const int DefaultMaxTokenSize = 48000;

    static TestEntry MaxTokenSizeEntry(IProbe probe)
    {
        try
        {
            var values = probe.RegistryValues(KerberosParameters);
            if (values?.GetValueOrDefault("MaxTokenSize") is not int size)
                return new(SmbTokenRow, Status.Pass, $"Default ({DefaultMaxTokenSize} bytes)");
            return size >= DefaultMaxTokenSize
                ? new(SmbTokenRow, Status.Pass, $"{size} bytes")
                : new(SmbTokenRow, Status.Warn, $"{size} bytes; a user in many groups can fail Kerberos sign-in. The default is {DefaultMaxTokenSize}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbTokenRow, Status.Skip, $"Not checked: {ex.Message}");
        }
    }

    // ── Retrying Kerberos ──

    /// <summary>The wait between tries of a Kerberos request; tests set it to 0.</summary>
    internal static int SmbRetryDelayMs = 2000;
    const int SmbTries = 3;
    // A request that timed out, as an SSPI status: HRESULT_FROM_WIN32(ERROR_TIMEOUT)
    const int SspiTimedOut = unchecked((int)0x800705B4);

    // The first Kerberos request after sign-in, or over a VPN, can fail while Windows finds a DC or (on an Entra
    // joined PC) trades its cloud TGT for an on-prem one, and then work a moment later. These are worth another try;
    // the rest (no SPN, clock skew, no common encryption type) give the same answer every time
    static bool IsTransient(int status) => unchecked((uint)status) is 0x80090311 or 0x8009030E or 0x800705B4 or 0x80090304;

    /// <summary>
    /// Runs an SSPI request, trying again after <see cref="SmbRetryDelayMs"/> while it fails for a reason that can
    /// pass, up to <see cref="SmbTries"/> tries. A request that throws (a timeout) counts as a failed try, never as
    /// the end of the test. Returns the last result, the tries it took and the first failure.
    /// </summary>
    static (SspiResult Result, int Tries, SspiResult? First) AuthenticateWithRetry(IProbe probe, string package, string spn, CancellationToken ct)
    {
        SspiResult? first = null;
        for (int attempt = 1; ; attempt++)
        {
            SspiResult result;
            try { result = probe.Authenticate(package, spn, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { result = new(SspiTimedOut, null); }
            if (result.Succeeded || !IsTransient(result.Status) || attempt == SmbTries) return (result, attempt, first);
            first ??= result;
            if (ct.WaitHandle.WaitOne(SmbRetryDelayMs)) ct.ThrowIfCancellationRequested();
        }
    }

    // The TGT check, once more after a pause if it failed: the same slow first answer as above
    static TestEntry TgtWithRetry(DiagConfig cfg, IProbe probe)
    {
        var first = TgtCheck(cfg, probe) with { Name = SmbTgtRow };
        if (first.Status != Status.Fail) return first;
        if (cfg.Cancel.WaitHandle.WaitOne(SmbRetryDelayMs)) cfg.Cancel.ThrowIfCancellationRequested();
        var second = TgtCheck(cfg, probe) with { Name = SmbTgtRow, Tries = 2 };
        return second.Status == Status.Fail
            ? second with { Detail = second.Detail + " (2 tries)" }
            : second with { Status = Status.Info, Detail = $"{second.Detail}, on try 2; the first failed: {first.Detail}" };
    }

    /// <summary>What an SSPI status means, by number: the text Windows gives is translated.</summary>
    internal static string SspiStatusText(int status) => unchecked((uint)status) switch
    {
        0x80090303 => "the KDC doesn't know this name (KDC_ERR_S_PRINCIPAL_UNKNOWN); no account has the SPN",
        0x80090311 => "no domain controller answered (SEC_E_NO_AUTHENTICATING_AUTHORITY)",
        0x8009030E => "this sign-in has no Kerberos credentials (SEC_E_NO_CREDENTIALS)",
        0x80090324 => "this PC's clock is too far from the DC's (SEC_E_TIME_SKEW)",
        0x80090322 => "the name belongs to a different account than the one that answered (SEC_E_WRONG_PRINCIPAL)",
        0x8009030C => "the KDC refused the request (SEC_E_LOGON_DENIED)",
        0x80090342 => "no encryption type in common with the server's account (SEC_E_KDC_UNKNOWN_ETYPE)",
        0x80090350 => "a downgrade was detected (SEC_E_DOWNGRADE_DETECTED)",
        0x80090308 => "the request was malformed (SEC_E_INVALID_TOKEN)",
        0x8009030F => "the request failed (SEC_E_MESSAGE_ALTERED)",
        0x80090345 => "the server's account doesn't allow delegation (SEC_E_DELEGATION_REQUIRED)",
        0x80090346 => "the KDC refused the ticket's options (SEC_E_BAD_BINDINGS)",
        0x800705B4 => "no answer in time (timed out)",
        0x80090304 => "Windows' security subsystem failed (SEC_E_INTERNAL_ERROR)",
        _ => $"SSPI error 0x{status:X8}",
    };

    // ── Sign-in ──

    static TestGroup SmbSignInStep(SmbTarget target, JoinProfile profile, DiagConfig cfg, IProbe probe,
        Lazy<(Dictionary<string, string>? Fields, string? Error)> dsreg)
    {
        var saved = SavedCredentialFor(target, cfg, probe);
        var tests = new List<TestEntry>();

        // What Windows' own sign-in would do; a saved credential takes its place on the real connection
        var (negotiate, _, _) = AuthenticateWithRetry(probe, "Negotiate", target.Spn, cfg.Cancel);
        string package = negotiate.Package ?? "";
        string asSaved = saved.Entry.Status == Status.Info ? "; the connection uses the saved credential instead" : "";
        tests.Add(!negotiate.Succeeded
            ? new(SmbNegotiationRow, Status.Fail, $"Windows couldn't start a sign-in: {SspiStatusText(negotiate.Status)}")
            : package.Equals("Kerberos", StringComparison.OrdinalIgnoreCase)
                ? new(SmbNegotiationRow, Status.Pass, "Kerberos" + asSaved)
                : package.Equals("NTLM", StringComparison.OrdinalIgnoreCase)
                    ? new(SmbNegotiationRow, target.IsAddress ? Status.Info : Status.Warn,
                        (target.IsAddress ? "NTLM, since the server was given by address" : "Fell back to NTLM: Kerberos had no ticket for " + target.Spn) + asSaved)
                    : new(SmbNegotiationRow, Status.Info, $"{(package.Length > 0 ? package : "An unknown package")}{asSaved}"));
        tests.Add(NtlmEntry(profile, probe, dsreg));
        tests.Add(saved.Entry);
        return new(SmbSignIn, tests);
    }

    const string LsaKey = @"SYSTEM\CurrentControlSet\Control\Lsa";

    // How NTLM answers when it's used; on an Entra joined PC it adds that a Windows Hello sign-in leaves NTLM nothing to use
    static TestEntry NtlmEntry(JoinProfile profile, IProbe probe, Lazy<(Dictionary<string, string>? Fields, string? Error)> dsreg)
    {
        string hello = profile == JoinProfile.Entra && dsreg.Value.Fields is { } ds && Parsers.DsregFlag(ds, "NgcSet") == true
            ? "; after a Windows Hello sign-in there is no password hash, so NTLM can't sign in and Kerberos must work" : "";
        try
        {
            var values = probe.RegistryValues(LsaKey);
            int? level = values?.GetValueOrDefault("LmCompatibilityLevel") as int?;
            return level switch
            {
                null => new(SmbNtlmRow, hello.Length > 0 ? Status.Info : Status.Pass, "Level 3 (OS default): sends NTLMv2 only" + hello),
                >= 3 and <= 5 => new(SmbNtlmRow, hello.Length > 0 ? Status.Info : Status.Pass, $"Level {level}: sends NTLMv2 only" + hello),
                _ => new(SmbNtlmRow, Status.Warn, $"Level {level} (LmCompatibilityLevel): sends LM or NTLMv1, which can be cracked offline" + hello),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbNtlmRow, Status.Skip, $"Not checked: {ex.Message}");
        }
    }

    /// <summary>
    /// Windows credentials in <c>cmdkey /list</c> and their users. The labels are translated; the "Domain:target="
    /// prefix and the values aren't. The user is the value two lines below the target (after the type).
    /// </summary>
    internal static List<(string Target, string? User)> ParseSavedCredentials(string cmdkeyOutput)
    {
        var lines = cmdkeyOutput.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        var result = new List<(string, string?)>();
        for (int i = 0; i < lines.Count; i++)
        {
            var m = WindowsCredentialTarget.Match(lines[i]);
            if (!m.Success) continue;
            string? user = null;
            if (i + 2 < lines.Count && !WindowsCredentialTarget.IsMatch(lines[i + 2]))
            {
                int colon = lines[i + 2].IndexOfAny([':', '：']);
                if (colon >= 0) user = lines[i + 2][(colon + 1)..].Trim();
            }
            result.Add((m.Groups[1].Value, string.IsNullOrEmpty(user) ? null : user));
        }
        return result;
    }

    static (TestEntry Entry, string? User) SavedCredentialFor(SmbTarget target, DiagConfig cfg, IProbe probe)
    {
        string me;
        try { me = probe.CurrentUser(); } catch (Exception) { me = "your sign-in"; }
        List<(string Target, string? User)> saved;
        try { saved = ParseSavedCredentials(probe.RunTool("cmdkey", "/list", 15000, cfg.Cancel)); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (new(SmbSavedRow, Status.Skip, $"Not checked: cmdkey failed: {ex.Message}"), null);
        }
        string shortName = target.Server.Split('.')[0];
        var match = saved.FirstOrDefault(s => s.Target.Equals(target.Server, StringComparison.OrdinalIgnoreCase)
            || s.Target.Equals(shortName, StringComparison.OrdinalIgnoreCase)
            || s.Target.Equals(target.Typed, StringComparison.OrdinalIgnoreCase)
            || (s.Target.StartsWith("*.", StringComparison.Ordinal) && target.Server.EndsWith(s.Target[1..], StringComparison.OrdinalIgnoreCase)));
        if (match.Target == null)
            return (new(SmbSavedRow, Status.Pass, $"None for {target.Server}; signs in as {me}"), null);
        string who = match.User ?? "another account";
        return (new(SmbSavedRow, Status.Info, $"Credential Manager holds {who} for {match.Target}; Windows signs in to this server as {who}, not as {me}"), match.User);
    }

    // ── Share ──

    static TestGroup SmbShareStep(SmbTarget target, DiagConfig cfg, IProbe probe)
    {
        if (target.Share == null)
            return new(SmbShare, [new(SmbShareRow, Status.Skip, "Not checked: no share given; type one in Share to test opening it")]);
        ShareOpen open;
        try { open = probe.OpenShare(target.Unc, cfg.Cancel); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SmbShare, [new(SmbShareRow, Status.Fail, $"{target.Unc}: {ex.Message}")]);
        }
        if (open.Entries is { } n)
            return new(SmbShare, [new(SmbShareRow, Status.Pass, $"{target.Unc} opened; {(n >= 1000 ? "1000 or more entries" : $"{n} entr{(n == 1 ? "y" : "ies")}")} in its root")]);
        return new(SmbShare, [new(SmbShareRow, Status.Fail, $"{target.Unc}: {ShareErrorText(open)}")]);
    }

    /// <summary>What a failure to open a share means, by its Win32 error number.</summary>
    internal static string ShareErrorText(ShareOpen open) => open.Error switch
    {
        5 => "access denied (error 5); the account has no permission on the share or its folder",
        53 => "the network path wasn't found (error 53); SMB didn't answer at that name",
        67 => "no share by that name (error 67)",
        86 or 1326 => $"the server refused the sign-in (error {open.Error}); wrong or stale password, or no way to sign in",
        1219 => "already connected to this server as a different user (error 1219); disconnect with 'net use \\\\server /delete'",
        1272 => "the server allows only guest access, which this PC blocks (error 1272)",
        1311 => "no domain controller could check the sign-in (error 1311)",
        1789 => "the trust between this PC and the domain failed (error 1789)",
        1907 => "the password must be changed first (error 1907)",
        1909 => "the account is locked out (error 1909)",
        _ => $"error {open.Error}: {open.Message}",
    };

    // ── This PC's SMB settings ──

    const string WorkstationParameters = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    const string WorkstationPolicy = @"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
    const string Smb1Driver = @"SYSTEM\CurrentControlSet\Services\mrxsmb10";

    static TestGroup SmbSettingsGroup(IProbe probe)
    {
        TestEntry Read(string name, Func<TestEntry> read)
        {
            try { return read(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { return new(name, Status.Skip, $"Not checked: {ex.Message}"); }
        }

        var parameters = new Lazy<Dictionary<string, object>?>(() => probe.RegistryValues(WorkstationParameters));
        return new(SmbSettings, [
            // SMB2 and later ignore EnableSecuritySignature: signing is on whenever either side requires it
            Read(SmbSigningRow, () => parameters.Value?.GetValueOrDefault("RequireSecuritySignature") is int require && require != 0
                ? new(SmbSigningRow, Status.Pass, "Required (RequireSecuritySignature=1)")
                : new(SmbSigningRow, Status.Info, "Not required (RequireSecuritySignature=0); packets are signed only when the server requires it")),
            Read(SmbV1Row, () => probe.RegistryValues(Smb1Driver) is not { } driver
                ? new(SmbV1Row, Status.Pass, "Not installed (no mrxsmb10 driver)")
                : driver.GetValueOrDefault("Start") is int start && start == 4
                    ? new(SmbV1Row, Status.Pass, "Disabled (mrxsmb10 Start=4)")
                    : new(SmbV1Row, Status.Warn, $"Enabled (mrxsmb10 Start={driver.GetValueOrDefault("Start") ?? "?"}); SMBv1 has no encryption and is open to EternalBlue-style attacks")),
            Read(SmbGuestRow, () =>
            {
                if (probe.RegistryValues(WorkstationPolicy)?.GetValueOrDefault("AllowInsecureGuestAuth") is int policy)
                    return policy != 0
                        ? new(SmbGuestRow, Status.Warn, "Allowed by Group Policy (AllowInsecureGuestAuth=1); shares can open with no password and no signing")
                        : new(SmbGuestRow, Status.Pass, "Blocked by Group Policy");
                if (parameters.Value?.GetValueOrDefault("AllowInsecureGuestAuth") is int local)
                    return local != 0
                        ? new(SmbGuestRow, Status.Warn, "Allowed (AllowInsecureGuestAuth=1); shares can open with no password and no signing")
                        : new(SmbGuestRow, Status.Pass, "Blocked (AllowInsecureGuestAuth=0)");
                return new(SmbGuestRow, Status.Pass, "Not set: Windows' default, which blocks it on Enterprise and Education, and on Pro since Windows 11 24H2");
            }),
        ]);
    }

    // ── Verdict ──

    /// <summary>The line under the path: the first step that failed and its fix, or that it connected, and how.</summary>
    public static SmbVerdict SmbVerdictFor(SmbTarget target, JoinProfile profile, List<TestGroup> groups)
    {
        TestEntry? Row(string name) => groups.SelectMany(g => g.Tests).FirstOrDefault(t => t.Name == name);
        foreach (var group in groups.Where(g => SmbSteps.Contains(g.Name)))
        {
            var failed = group.Tests.FirstOrDefault(t => t.Status == Status.Fail);
            if (failed == null) continue;
            // Kerberos failing alone doesn't stop the connection; the share or the sign-in step says whether NTLM made it
            if (group.Name == SmbKerberos && groups.Any(g => g.Name == SmbShare && g.Tests.All(t => t.Status != Status.Fail))) continue;
            return new(Status.Fail, $"Stopped at {group.Name}: {failed.Detail}", SmbFix(target, profile, group.Name, failed, Row));
        }

        bool shareTested = Row(SmbShareRow) is { Status: Status.Pass };
        string reached = shareTested ? $"Opened {target.Unc}" : $"Reached {target.Server}";
        var negotiation = Row(SmbNegotiationRow);
        if (negotiation is { Status: Status.Warn })
        {
            var cause = groups.Find(g => g.Name == SmbKerberos)?.Tests.FirstOrDefault(t => t.Status is Status.Warn or Status.Fail);
            return new(Status.Warn, $"{reached}, but with NTLM. Kerberos failed at {cause?.Name ?? "the service ticket"}.",
                cause != null ? SmbFix(target, profile, SmbKerberos, cause, Row) : null);
        }
        string how = negotiation?.Detail.StartsWith("Kerberos", StringComparison.Ordinal) == true ? "with Kerberos" : "";
        string tail = shareTested ? "" : target.Share == null ? " Type a share to test opening it too." : "";
        var warn = groups.SelectMany(g => g.Tests).FirstOrDefault(t => t.Status == Status.Warn);
        return warn == null
            ? new(Status.Pass, $"{reached} {how}. Every step passed.{tail}".Replace("  ", " "), null)
            : new(Status.Warn, $"{reached} {how}, with a warning: {warn.Name}.{tail}".Replace("  ", " "), SmbFix(target, profile, "", warn, Row));
    }

    static string? SmbFix(SmbTarget target, JoinProfile profile, string step, TestEntry row, Func<string, TestEntry?> rowNamed)
    {
        string server = target.Server, shortName = server.Split('.')[0].ToUpperInvariant();
        return row.Name switch
        {
            SmbNameRow => profile == JoinProfile.Entra
                ? "Check the name and the on-prem domain, and that this PC's DNS servers (on a VPN, its DNS settings) can answer for that domain."
                : "Check the spelling, and that the server has an A record. If DNS for Active Directory fails on the Active Directory tab, fix that first.",
            SmbPortRow => "A firewall between this PC and the server, or the server's Server service is stopped. On a VPN, check that it routes the server's network.",
            SmbCloudTrustRow => "Create the Microsoft Entra Kerberos server object in the domain (Set-AzureADKerberosServer), then sign out and back in. The Entra Seamless SSO group shows the same flags.",
            SmbTgtRow => "This PC has no Kerberos ticket for the domain: check DC Discovery & Connectivity and Kerberos & Time Sync on the Active Directory tab.",
            SmbKpasswdRow => "Have a DC register its SRV records: run 'nltest /dsregdns' on a DC, or restart its Netlogon service.",
            SmbSpnRow when row.Status == Status.Fail => "Remove the SPN from all but the server's own account: 'setspn -Q cifs/" + server + "' lists them, 'setspn -D' removes one.",
            SmbSpnRow or SmbTicketRow when rowNamed(SmbSpnRow) is { Status: Status.Warn } || row.Detail.Contains("PRINCIPAL_UNKNOWN")
                => $"Register the SPN on the server's account: 'setspn -S cifs/{server} {shortName}'. If users reach the server by an alias, register the alias too.",
            SmbTicketRow when row.Detail.Contains("TIME_SKEW") => "Fix this PC's clock: see Kerberos & Time Sync on the Active Directory tab.",
            SmbTicketRow when row.Detail.Contains("NO_AUTHENTICATING_AUTHORITY") => "No DC answered: see DC Discovery & Connectivity on the Active Directory tab.",
            SmbTicketRow => "See the Kerberos step's rows for the cause; the Guide's SMB section explains each.",
            SmbEncryptionRow => "Set the server's account to AES: 'Set-ADComputer " + shortName + " -KerberosEncryptionType AES128,AES256', then purge tickets on the Kerberos tickets tab.",
            SmbTokenRow => @"Delete MaxTokenSize under HKLM\" + KerberosParameters + ", or set it to 48000.",
            SmbNegotiationRow => "Sign out and back in. If it persists, check the Domain Membership & Identity group on the Active Directory tab.",
            SmbNtlmRow => "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only' (level 3) or higher in Group Policy.",
            SmbSavedRow or SmbShareRow when rowNamed(SmbSavedRow) is { Status: Status.Info } && row.Detail.Contains("error 5") || row.Detail.Contains("error 1326") && rowNamed(SmbSavedRow) is { Status: Status.Info }
                => $"Remove the saved credential (Control Panel > Credential Manager > Windows Credentials > {server}) to sign in as yourself, or give that account access.",
            SmbShareRow when row.Detail.Contains("error 5") => "Give the account access in the share's permissions and the folder's security (NTFS) permissions.",
            SmbShareRow when row.Detail.Contains("error 67") => $"Check the share name: 'net view \\\\{server}' lists the server's shares.",
            SmbShareRow when row.Detail.Contains("error 1326") || row.Detail.Contains("error 86") => profile == JoinProfile.Entra
                ? "With no Kerberos ticket and a Windows Hello sign-in there is nothing to sign in with: fix the Kerberos step first."
                : "Check the account's password and that it isn't locked out; fix the Kerberos step if it failed.",
            SmbShareRow when row.Detail.Contains("error 1272") => "Turn on the server's sign-in (stop sharing as guest), rather than allowing insecure guest logons here.",
            SmbShareRow => "The Guide's SMB section explains the common errors.",
            SmbV1Row => "Turn SMBv1 off: Windows Features > SMB 1.0/CIFS File Sharing Support > clear SMB 1.0/CIFS Client.",
            SmbGuestRow => "Disable 'Enable insecure guest logons' (Computer Configuration > Administrative Templates > Network > Lanman Workstation).",
            _ => null,
        };
    }
}
