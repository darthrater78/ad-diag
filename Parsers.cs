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

    /// <summary>Parses a gpresult timestamp such as "7/16/2026 at 10:00:00 AM" in the current culture.</summary>
    public static DateTime? ParseGpTime(string value) =>
        DateTime.TryParse(Regex.Replace(value, @"\s+at\s+", " "), out var t) ? t : null;

    public static List<GpScope> ParseGpResult(string raw)
    {
        var scopes = new List<GpScope>();
        var sectionPattern = new Regex(@"(COMPUTER SETTINGS|USER SETTINGS)\s*\r?\n-+\s*\r?\n([\s\S]*?)(?=\r?\nCOMPUTER SETTINGS|\r?\nUSER SETTINGS|\z)", RegexOptions.IgnoreCase);

        // "Site Name:" normally sits in the header block above the scope sections
        var headerSite = Regex.Match(raw, @"^\s*Site Name:\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);

        foreach (Match sm in sectionPattern.Matches(raw))
        {
            string name = sm.Groups[1].Value.Equals("COMPUTER SETTINGS", StringComparison.OrdinalIgnoreCase) ? "Computer" : "User";
            string body = sm.Groups[2].Value;

            var lastAppliedMatch = Regex.Match(body, @"Last time Group Policy was applied:\s*(.+)", RegexOptions.IgnoreCase);
            var siteMatch = Regex.Match(body, @"^\s*Site Name:\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline);

            var applied = new List<string>();
            var appliedSection = Regex.Match(body, @"Applied Group Policy Objects\s*\r?\n\s*-+\s*\r?\n([\s\S]*?)(?=\r?\n\s*\r?\n|\r?\n\s*The following GPOs|\z)", RegexOptions.IgnoreCase);
            if (appliedSection.Success)
            {
                foreach (var line in appliedSection.Groups[1].Value.Split('\n'))
                {
                    string t = line.Trim();
                    if (t.Length > 0 && !t.Equals("N/A", StringComparison.OrdinalIgnoreCase)) applied.Add(t);
                }
            }

            var denied = new List<(string, string)>();
            var deniedSection = Regex.Match(body, @"The following GPOs were not applied because they were filtered out\s*\r?\n\s*-+\s*\r?\n([\s\S]*?)(?=\r?\n\s*The \w+ is a part of the following security groups|\r?\n\s*\r?\n\s*\r?\n|\z)", RegexOptions.IgnoreCase);
            if (deniedSection.Success)
            {
                string? currentName = null;
                foreach (var rawLine in deniedSection.Groups[1].Value.Split('\n'))
                {
                    string line = rawLine.TrimEnd('\r');
                    string trimmed = line.Trim();
                    if (trimmed.Length == 0) continue;

                    // Indented "Filtering: <reason>" lines describe the GPO just above them
                    if (trimmed.StartsWith("Filtering:", StringComparison.OrdinalIgnoreCase))
                    {
                        string reason = trimmed["Filtering:".Length..].Trim();
                        if (currentName != null)
                            denied.Add((currentName, reason));
                        currentName = null;
                    }
                    else
                    {
                        if (currentName != null) denied.Add((currentName, ""));
                        currentName = trimmed;
                    }
                }
                if (currentName != null) denied.Add((currentName, ""));
            }

            scopes.Add(new GpScope(name,
                lastAppliedMatch.Success ? lastAppliedMatch.Groups[1].Value.Trim() : "",
                siteMatch.Success ? siteMatch.Groups[1].Value.Trim() : headerSite.Success ? headerSite.Groups[1].Value.Trim() : "",
                applied, denied));
        }

        return scopes;
    }

    /// <summary>Header lines and tickets from <c>klist</c>. No tickets and no headers means an empty cache.</summary>
    public static KlistOutput ParseKlist(string raw)
    {
        var headers = new List<string>();
        var tickets = new List<KlistTicket>();
        if (string.IsNullOrWhiteSpace(raw) || raw.Contains("no credentials", StringComparison.OrdinalIgnoreCase))
            return new(headers, tickets);

        string? currentServer = null;
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void ParseField(string text)
        {
            var kv = text.Split(':', 2);
            if (kv.Length == 2)
            {
                string key = kv[0].Trim();
                string val = kv[1].Trim();
                if (key.Equals("Server", StringComparison.OrdinalIgnoreCase))
                    currentServer = val;
                else
                    fields[key] = val;
                return;
            }

            // "Ticket Flags 0x... -> ..." has no colon separator
            var flagsMatch = Regex.Match(text, @"^\s*Ticket Flags\s+(.*)$", RegexOptions.IgnoreCase);
            if (flagsMatch.Success)
                fields["Ticket Flags"] = flagsMatch.Groups[1].Value.Trim();
        }

        void Flush()
        {
            if (currentServer != null)
                tickets.Add(new(currentServer, new Dictionary<string, string>(fields, StringComparer.OrdinalIgnoreCase)));
            currentServer = null;
            fields.Clear();
        }

        foreach (string rawLine in raw.Split('\n'))
        {
            string line = rawLine.TrimEnd('\r');
            if (string.IsNullOrWhiteSpace(line)) continue;

            if (line.StartsWith("Current LogonId", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Cached Tickets", StringComparison.OrdinalIgnoreCase))
            {
                headers.Add(line);
                continue;
            }

            string trimmedLine = line.TrimStart();
            if (trimmedLine.StartsWith("#"))
            {
                Flush();

                // The ticket marker line can carry a field on the same line, e.g. "#0>     Client: user @ REALM"
                int markerEnd = trimmedLine.IndexOf('>');
                if (markerEnd >= 0 && markerEnd + 1 < trimmedLine.Length)
                    ParseField(trimmedLine[(markerEnd + 1)..].Trim());
                continue;
            }

            ParseField(line);
        }
        Flush();

        return new(headers, tickets);
    }
}

record ScVerifyResult(bool Ok, bool AccessDenied, string Detail);
record GpScope(string Name, string LastApplied, string Site, List<string> Applied, List<(string Name, string Reason)> Denied);
record KlistTicket(string Server, Dictionary<string, string> Fields);
record KlistOutput(List<string> Headers, List<KlistTicket> Tickets);
