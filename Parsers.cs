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
    static readonly Regex NltestErrorPattern = new(@"Status\s*=\s*\d+\s+(0x[0-9a-f]+)\s*(\S*)", RegexOptions.IgnoreCase);

    /// <summary>The error name (or hex status) if nltest reported a failure, e.g. "ERROR_NO_SITENAME"; otherwise null.</summary>
    public static string? NltestError(string output)
    {
        var m = NltestErrorPattern.Match(output);
        if (!m.Success) return null;
        return m.Groups[2].Value.Length > 0 ? m.Groups[2].Value : m.Groups[1].Value;
    }

    /// <summary>Site name from <c>nltest /dsgetsite</c>, or null if none was returned.</summary>
    public static string? ParseSite(string output)
    {
        // On failure nltest prints e.g. "Getting DC Site failed: Status = 1919 0x77f ERROR_NO_SITENAME"
        if (NltestError(output) != null) return null;
        string? site = output.Trim().Split('\n')
            .FirstOrDefault(l => !l.Contains("command completed", StringComparison.OrdinalIgnoreCase))?.Trim();
        return string.IsNullOrEmpty(site) ? null : site;
    }

    /// <summary>DC hostname from <c>nltest /dsgetdc</c>, or null if none was located.</summary>
    public static string? ParseDcLocator(string output)
    {
        var m = Regex.Match(output, @"DC:\s*\\\\(\S+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>
    /// Trusts from <c>nltest /domain_trusts</c>, excluding the machine's own (primary) domain.
    /// Entries look like "0: CONTOSO contoso.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)".
    /// </summary>
    public static List<string> ParseTrusts(string output) =>
        output.Split('\n')
            .Select(l => l.Trim())
            .Where(l => Regex.IsMatch(l, @"^\d+:\s+\S") && !l.Contains("(Primary Domain)", StringComparison.OrdinalIgnoreCase))
            .Select(l => Regex.Replace(l, @"^\d+:\s+", ""))
            .ToList();

    /// <summary>Absolute offset in seconds from <c>w32tm /stripchart /dataonly</c>, e.g. "10:21:47, +00.0206779s".</summary>
    public static double? ParseStripchartSkew(string output)
    {
        var m = Regex.Match(output, @"([+-]?\d+\.\d+)s");
        return m.Success ? Math.Abs(double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)) : null;
    }

    /// <summary>The "Source:" value from <c>w32tm /query /status</c>, or null if absent.</summary>
    public static string? ParseTimeSource(string output)
    {
        var m = Regex.Match(output, @"Source:\s*(.+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : null;
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

record GpScope(string Name, string LastApplied, string Site, List<string> Applied, List<(string Name, string Reason)> Denied);
record KlistTicket(string Server, Dictionary<string, string> Fields);
record KlistOutput(List<string> Headers, List<KlistTicket> Tickets);
