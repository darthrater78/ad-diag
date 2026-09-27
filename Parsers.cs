using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

#nullable enable
namespace AdDiag;

// Pure parsers for the output of the Windows tools the app shells out to. Kept free of any
// WinForms dependency so they can be unit tested on any platform (see tests/AdDiag.Tests).
static class Parsers
{
    // Tool output is translated on non-English Windows, so parsers anchor on structure, numbers
    // and symbolic codes (e.g. "Status = 1311 0x51f ERROR_NO_LOGON_SERVERS"), never on English labels.

    static readonly Regex NltestStatusPattern = new(@"Status\s*=\s*(\d+)\s+(0x[0-9a-f]+)\s*([A-Z][A-Z0-9_]*)?", RegexOptions.IgnoreCase);
    static readonly Regex UncNamePattern = new(@"\\\\([^\s\\]+)");

    record NltestStatus(int Code, string Hex, string Name)
    {
        public string Label => Name.Length > 0 ? Name : Hex;
    }

    static List<NltestStatus> NltestStatuses(string output) =>
        NltestStatusPattern.Matches(output)
            .Select(m => new NltestStatus(int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), m.Groups[2].Value, m.Groups[3].Value))
            .ToList();

    /// <summary>The first failure nltest reported, e.g. "ERROR_NO_SITENAME" (or the hex status if unnamed); null if none.</summary>
    public static string? NltestError(string output) =>
        NltestStatuses(output).FirstOrDefault(s => s.Code != 0)?.Label;

    /// <summary>
    /// Result of <c>nltest /sc_verify</c>. nltest reports success for the command itself even when
    /// verification failed, so the verdict comes only from the "Status = N" codes, all of which must be 0.
    /// </summary>
    public static ScVerifyResult ParseScVerify(string output)
    {
        var statuses = NltestStatuses(output);
        if (statuses.Count == 0)
            return new(false, false, string.IsNullOrWhiteSpace(output) ? "No output from nltest" : output.Trim());

        var failure = statuses.FirstOrDefault(s => s.Code != 0);
        if (failure != null)
            return new(false, failure.Code == 5, $"{failure.Code} {failure.Hex} {failure.Name}".Trim()); // 5 = ERROR_ACCESS_DENIED

        var dc = UncNamePattern.Match(output);
        return new(true, false, dc.Success ? $"Verified with {dc.Groups[1].Value}" : "Verified");
    }

    /// <summary>Site name from <c>nltest /dsgetsite</c> (its first line), or null if none was returned.</summary>
    public static string? ParseSite(string output)
    {
        // On failure nltest prints e.g. "Getting DC Site failed: Status = 1919 0x77f ERROR_NO_SITENAME"
        if (NltestError(output) != null) return null;
        string? site = output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return string.IsNullOrEmpty(site) ? null : site;
    }

    /// <summary>DC hostname from <c>nltest /dsgetdc</c> (the first \\name, ahead of the \\address), or null if none was located.</summary>
    public static string? ParseDcLocator(string output)
    {
        if (NltestError(output) != null) return null;
        var m = UncNamePattern.Match(output);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>
    /// Trusts from <c>nltest /domain_trusts</c>, excluding the machine's own domain. Entries look like
    /// "0: CONTOSO contoso.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)"; the primary domain is
    /// recognised by matching its NetBIOS or DNS name against <paramref name="ownDomainNames"/>.
    /// </summary>
    public static List<string> ParseTrusts(string output, IEnumerable<string?> ownDomainNames)
    {
        var own = new HashSet<string>(ownDomainNames.Where(n => !string.IsNullOrWhiteSpace(n))!, StringComparer.OrdinalIgnoreCase);
        var trusts = new List<string>();
        foreach (var rawLine in output.Split('\n'))
        {
            var m = Regex.Match(rawLine.Trim(), @"^\d+:\s+(\S+)(?:\s+([^\s(]\S*))?(.*)$");
            if (!m.Success) continue;
            if (own.Contains(m.Groups[1].Value) || (m.Groups[2].Success && own.Contains(m.Groups[2].Value))
                || m.Groups[3].Value.Contains("(Primary Domain)", StringComparison.OrdinalIgnoreCase)) // English-only fallback
                continue;
            trusts.Add(Regex.Replace(rawLine.Trim(), @"^\d+:\s+", ""));
        }
        return trusts;
    }

    /// <summary>
    /// Absolute offset in seconds from <c>w32tm /stripchart /dataonly</c>, e.g. "10:21:47, +00.0206779s".
    /// Accepts "," as the decimal separator too.
    /// </summary>
    public static double? ParseStripchartSkew(string output)
    {
        var m = Regex.Match(output, @"([+-]?\d+[.,]\d+)s\b");
        return m.Success ? Math.Abs(double.Parse(m.Groups[1].Value.Replace(',', '.'), CultureInfo.InvariantCulture)) : null;
    }

    /// <summary>
    /// The source from <c>w32tm /query /source</c>, which prints just the value (no label to translate).
    /// Null if w32tm failed, which it reports with an HRESULT such as "(0x80070426)".
    /// </summary>
    public static string? ParseTimeSource(string output)
    {
        if (Regex.IsMatch(output, @"0x8[0-9a-f]{7}", RegexOptions.IgnoreCase)) return null;
        string? source = output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
        return string.IsNullOrEmpty(source) ? null : source;
    }

    /// <summary>
    /// Whether a w32tm time source is a DC of <paramref name="domain"/>. The source is a DC hostname
    /// (optionally with a ",0x9"-style flag suffix) or IP when syncing from the domain hierarchy;
    /// anything else (Local CMOS, Free-running, VM IC, external NTP) isn't.
    /// </summary>
    public static bool IsDomainTimeSource(string source, string domain, Func<string, IPAddress[]> resolve)
    {
        string host = Regex.Replace(source, @",0x[0-9a-f]+$", "", RegexOptions.IgnoreCase).Trim();
        if (host.Equals(domain, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!IPAddress.TryParse(host, out var ip)) return false;
        try { return resolve(domain).Contains(ip); }
        catch { return false; }
    }

    /// <summary>
    /// Whether <c>klist</c> (or <c>klist get</c>) output holds a TGT for <paramref name="realm"/>: either the
    /// realm's own "krbtgt/REALM @ REALM" or a cross-realm referral "krbtgt/REALM @ OTHERREALM".
    /// </summary>
    public static bool HasTgt(string klistOutput, string realm) =>
        Regex.IsMatch(klistOutput, $@"krbtgt/{Regex.Escape(realm)}\s*@\s*\S", RegexOptions.IgnoreCase);

    /// <summary>The NTSTATUS error from a failed <c>klist get</c>, e.g. "0xc000018b"; null if none.</summary>
    public static string? KlistError(string output)
    {
        var m = Regex.Match(output, @"\b0xc0[0-9a-f]{6}\b", RegexOptions.IgnoreCase);
        return m.Success ? m.Value.ToLowerInvariant() : null;
    }

    /// <summary>
    /// Parses the password-age query's output: "OK|&lt;domain&gt;|&lt;ISO 8601 UTC&gt;", "NOTFOUND|&lt;domain&gt;"
    /// or "ERROR|&lt;message&gt;". Anything else (e.g. PowerShell failing to start the script) is also an error.
    /// </summary>
    public static PasswordAgeResult ParsePasswordAgeQuery(string output)
    {
        string line = output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "";
        var parts = line.Split('|');
        if (parts.Length >= 2 && parts[0] == "ERROR")
            return new(null, null, string.Join("|", parts[1..]).Trim());
        if (parts.Length == 2 && parts[0] == "NOTFOUND")
            return new(parts[1], null, null);
        if (parts.Length == 3 && parts[0] == "OK"
            && DateTime.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc))
            return new(parts[1], utc.ToUniversalTime(), null);
        return new(null, null, line.Length > 0 ? line : "No output from PowerShell");
    }

    /// <summary>
    /// Parses the RSoP query's output, one line per scope and per GPO link:
    /// <code>
    /// SCOPE|Computer|OK|&lt;last applied, ISO 8601 UTC, or empty&gt;|&lt;site&gt;
    /// SCOPE|Computer|DENIED            (not elevated)
    /// SCOPE|User|NODATA                (no RSoP logging data for this scope)
    /// SCOPE|User|ERROR|&lt;message&gt;
    /// GPO|&lt;scope&gt;|&lt;GPO id&gt;|&lt;appliedOrder&gt;|&lt;link enabled&gt;|&lt;GPO enabled&gt;|&lt;access denied&gt;|&lt;WMI filter allowed&gt;|&lt;name&gt;
    /// </code>
    /// Flags are 1/0. A GPO with appliedOrder 0 was not applied. Returns no scopes if the script didn't run.
    /// </summary>
    public static List<GpScope> ParseRsop(string output)
    {
        var scopes = new List<GpScope>();
        var links = new List<(string Scope, string Id, int Order, string Name, string Reason)>();

        foreach (var rawLine in output.Split('\n'))
        {
            var parts = rawLine.TrimEnd('\r').Split('|');
            if (parts.Length >= 3 && parts[0] == "SCOPE")
            {
                var (state, detail) = parts[2] switch
                {
                    "OK" => (GpScopeState.Ok, ""),
                    "DENIED" => (GpScopeState.AccessDenied, ""),
                    "NODATA" => (GpScopeState.NoData, ""),
                    _ => (GpScopeState.Error, string.Join("|", parts[3..]).Trim()),
                };
                DateTime? lastApplied = state == GpScopeState.Ok && parts.Length > 3
                    && DateTime.TryParse(parts[3], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var t)
                    ? t.ToUniversalTime() : null;
                string site = state == GpScopeState.Ok && parts.Length > 4 ? string.Join("|", parts[4..]).Trim() : "";
                scopes.Add(new(parts[1], state, detail, lastApplied, site, [], []));
            }
            else if (parts.Length >= 9 && parts[0] == "GPO" && int.TryParse(parts[3], out int order))
            {
                bool Flag(int i) => parts[i].Trim() == "1";
                links.Add((parts[1], parts[2], order, string.Join("|", parts[8..]).Trim(),
                    GpDeniedReason(Flag(4), Flag(5), Flag(6), Flag(7))));
            }
        }

        foreach (var scope in scopes)
        {
            var mine = links.Where(l => l.Scope == scope.Name).ToList();
            // Highest appliedOrder wins, so list it first (as gpresult does). A GPO linked more than once
            // shows up once: as applied if any of its links applied.
            var applied = mine.Where(l => l.Order > 0).OrderByDescending(l => l.Order).DistinctBy(l => l.Id).ToList();
            scope.Applied.AddRange(applied.Select(l => l.Name));
            scope.Denied.AddRange(mine.Where(l => l.Order <= 0 && !applied.Any(a => a.Id == l.Id))
                .DistinctBy(l => l.Id).Select(l => (l.Name, l.Reason)));
        }

        return scopes;
    }

    /// <summary>Why an unapplied GPO was filtered out, using gpresult's wording.</summary>
    public static string GpDeniedReason(bool linkEnabled, bool gpoEnabled, bool accessDenied, bool filterAllowed) =>
        !linkEnabled ? "Disabled (Link)"
        : !gpoEnabled ? "Disabled (GPO)"
        : accessDenied ? "Denied (Security)"
        : !filterAllowed ? "Denied (WMI Filter)"
        : "Not Applied (Empty)";

    // klist prints each ticket's fields in a fixed order; the labels are translated on non-English Windows,
    // so fields are keyed by position. Older Windows omits the trailing ones.
    static readonly string[] KlistFieldOrder =
    [
        "Client", "Server", "KerbTicket Encryption Type", "Ticket Flags", "Start Time", "End Time",
        "Renew Time", "Session Key Type", "Cache Flags", "Kdc Called",
    ];

    /// <summary>
    /// Header lines and tickets from <c>klist</c>. No tickets and no headers means an empty cache. Field keys are
    /// the English labels (<see cref="KlistFieldOrder"/>) whatever the display language.
    /// </summary>
    public static KlistOutput ParseKlist(string raw)
    {
        var headers = new List<string>();
        var tickets = new List<KlistTicket>();

        string? currentServer = null;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int fieldIndex = 0;
        bool inTicket = false;

        void ParseField(string text)
        {
            string label, value;
            // "Ticket Flags 0x40e10000 -> forwardable ..." has no colon (in English at least), and a flags value
            // is always "0x... -> ..."; everything else is "Label: value" (times contain colons, so split once)
            var flags = Regex.Match(text, @"\b0x[0-9a-f]+\s*->.*$", RegexOptions.IgnoreCase);
            int colon = text.IndexOfAny([':', '：']);
            if (flags.Success && (colon < 0 || colon > flags.Index))
            {
                label = text[..flags.Index].Trim().TrimEnd(':', '：').Trim();
                value = flags.Value.Trim();
            }
            else if (colon >= 0)
            {
                label = text[..colon].Trim();
                value = text[(colon + 1)..].Trim();
            }
            else return;

            string key = KlistFieldOrder.FirstOrDefault(k => k.Equals(label, StringComparison.OrdinalIgnoreCase))
                ?? (fieldIndex < KlistFieldOrder.Length ? KlistFieldOrder[fieldIndex] : label);
            fieldIndex++;

            if (key == "Server")
                currentServer = value;
            else
                fields[key] = value;
        }

        void Flush()
        {
            if (currentServer != null)
                tickets.Add(new(currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));
            currentServer = null;
            fields.Clear();
            fieldIndex = 0;
        }

        foreach (string rawLine in raw.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line)) continue;

            string trimmedLine = line.TrimStart();
            if (Regex.IsMatch(trimmedLine, @"^#\d+>"))
            {
                Flush();
                inTicket = true;

                // The ticket marker line can carry a field on the same line, e.g. "#0>     Client: user @ REALM"
                string rest = trimmedLine[(trimmedLine.IndexOf('>') + 1)..].Trim();
                if (rest.Length > 0) ParseField(rest);
                continue;
            }

            // Lines before the first ticket are headers ("Current LogonId is ...", "Cached Tickets: (n)")
            if (inTicket) ParseField(line);
            else headers.Add(line.Trim());
        }
        Flush();

        // A failed klist (e.g. "klist failed with 0xc000005f ... (no credentials)") has no cache to show
        if (tickets.Count == 0 && KlistError(raw) != null)
            headers.Clear();

        return new(headers, tickets);
    }
}

/// <summary>Computer account's domain and pwdLastSet (UTC); both null with <c>Error</c> set if the query failed. LastSetUtc null with Domain set means not found.</summary>
record PasswordAgeResult(string? Domain, DateTime? LastSetUtc, string? Error);
record ScVerifyResult(bool Ok, bool AccessDenied, string Detail);
enum GpScopeState { Ok, AccessDenied, NoData, Error }
/// <summary>One RSoP scope ("Computer" or "User"). When State isn't Ok the lists are empty; Detail holds any error.</summary>
record GpScope(string Name, GpScopeState State, string Detail, DateTime? LastAppliedUtc, string Site,
    List<string> Applied, List<(string Name, string Reason)> Denied);
record KlistTicket(string Server, Dictionary<string, string> Fields);
record KlistOutput(List<string> Headers, List<KlistTicket> Tickets);
