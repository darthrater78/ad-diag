using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

#nullable enable
namespace AdDiag;

/// <summary>
/// A run or another action (a Group Policy query, a DNS registration) whose lines the log shows under one heading.
/// Set <see cref="DiagLog.Block"/> to it at the start of an async method: every line logged by that method, and by
/// the tasks and threads it starts, joins it.
/// </summary>
sealed class LogBlock(string title, string detail)
{
    public string Title { get; } = title;
    public string Detail { get; } = detail;
    /// <summary>The outcome once it is known, such as "32 passed · 0 failed · 3 warnings".</summary>
    public string? Totals { get; set; }
    /// <summary>Each section's counts once it has finished, by section name.</summary>
    public ConcurrentDictionary<string, string> SectionNotes { get; } = new();
}

record LogLine(long Seq, DateTime Time, bool Debug, string Source, string Message, LogBlock? Block = null, string? Section = null);

/// <summary>One row of the log as shown: a block's heading, a section's heading inside a block, or a line.</summary>
abstract record LogItem;
sealed record LogBlockHeading(LogBlock Block) : LogItem;
sealed record LogSectionHeading(LogBlock Block, string Section) : LogItem;
sealed record LogEntry(LogLine Line) : LogItem;

/// <summary>
/// The app's log: what it did and what came back. Held in memory only (the app writes nothing to disk unless the
/// user saves the log) and bounded, so the oldest lines go first. Debug lines, which carry raw tool output, are
/// recorded only while <see cref="DebugEnabled"/> is on. Safe to call from any thread. Kept free of any WinForms
/// dependency so it can be unit tested (see tests/AdDiag.Tests).
/// </summary>
sealed class DiagLog(Func<DateTime>? clock = null)
{
    public const int MaxLines = 5000;
    public const int MaxMessageChars = 8000;

    readonly Queue<LogLine> _lines = new();
    readonly Func<DateTime> _clock = clock ?? (() => DateTime.Now);
    long _seq;
    int _clears;
    volatile bool _debug;

    public bool DebugEnabled { get => _debug; set => _debug = value; }

    static readonly AsyncLocal<LogBlock?> CurrentBlock = new();
    static readonly AsyncLocal<string?> CurrentSection = new();

    /// <summary>The block that lines logged from here join; it flows into the tasks and threads started from here.</summary>
    public static LogBlock? Block { get => CurrentBlock.Value; set => CurrentBlock.Value = value; }

    /// <summary>The results section that lines logged from here belong to, within <see cref="Block"/>.</summary>
    public static string? Section { get => CurrentSection.Value; set => CurrentSection.Value = value; }

    /// <summary>The number of the last line added: changes whenever a line is.</summary>
    public long LastSeq
    {
        get { lock (_lines) return _seq; }
    }

    public void Info(string source, string message) => Add(false, source, message);

    public void Debug(string source, string message)
    {
        if (_debug) Add(true, source, message);
    }

    /// <summary>For messages that cost something to build: <paramref name="message"/> runs only when debug is on.</summary>
    public void Debug(string source, Func<string> message)
    {
        if (_debug) Add(true, source, message());
    }

    void Add(bool debug, string source, string message)
    {
        message = message.Replace("\r\n", "\n").TrimEnd();
        if (message.Length > MaxMessageChars)
            message = message[..MaxMessageChars] + $"\n... ({message.Length - MaxMessageChars} more characters not logged)";
        lock (_lines)
        {
            _lines.Enqueue(new(++_seq, _clock(), debug, source, message, Block, Section));
            while (_lines.Count > MaxLines) _lines.Dequeue();
        }
    }

    /// <summary>Lines added after the one numbered <paramref name="seq"/> (0 for all of them), oldest first.</summary>
    public List<LogLine> Since(long seq)
    {
        lock (_lines) return _lines.Where(l => l.Seq > seq).ToList();
    }

    /// <summary>How many times the log has been cleared: tells a caller whether a line it wrote earlier can still be there.</summary>
    public int Clears => Volatile.Read(ref _clears);

    public void Clear()
    {
        lock (_lines)
        {
            _lines.Clear();
            _clears++;
        }
    }

    public const int SectionColumn = 17;

    /// <summary>
    /// "14:02:03.118  dns     " — the fixed-width start of a line, followed in the By time view by its section's
    /// short name in a column of its own; continuation lines are indented to match.
    /// </summary>
    public static string Prefix(LogLine line, string? section = null) =>
        $"{line.Time:HH:mm:ss.fff}  {line.Source,-7} " + (section == null ? "" : Fit(section, SectionColumn - 1).PadRight(SectionColumn));

    static string Fit(string text, int width) => text.Length <= width ? text : text[..(width - 1)] + "…";

    public static string Body(LogLine line, int prefixLength)
    {
        string text = (line.Debug ? "DEBUG " : "") + line.Message;
        return text.Replace("\n", "\n" + new string(' ', prefixLength + (line.Debug ? 6 : 0)));
    }

    public static string Body(LogLine line) => Body(line, Prefix(line).Length);

    /// <summary>
    /// A result line taken apart for the formatted views: the status word, the check's name and its detail. The
    /// section's name in front of the check's is left out, since both views show the section beside or above the
    /// line. Null for any other line.
    /// </summary>
    public static (string Word, string Name, string Detail)? ParseResult(LogLine line)
    {
        // Written by the app as "Warning  Group / Check: detail"
        if (line.Source != "result" || line.Message.Length < 9) return null;
        string word = line.Message[..8].Trim();
        string rest = line.Message[8..].TrimStart();
        if (line.Section is { } section && rest.StartsWith(section + " / ", StringComparison.Ordinal))
            rest = rest[(section.Length + 3)..];
        int colon = rest.IndexOf(": ", StringComparison.Ordinal);
        return colon < 0 ? (word, rest, "") : (word, rest[..colon], rest[(colon + 2)..]);
    }

    public const int KindColumn = 10;

    /// <summary>
    /// A line as the Sections and By time views write it: the time (with milliseconds only By time), a kind column
    /// holding a result's status or the line's source, By time's <paramref name="section"/> column, then the
    /// message: a result's "Check: detail" without its section's name, any other message without a DEBUG label.
    /// Further lines, such as raw tool output, line up under the message.
    /// </summary>
    public static string Formatted(LogLine line, bool bySection, string? section)
    {
        string time = bySection ? $"{line.Time:HH:mm:ss}  " : $"{line.Time:HH:mm:ss.fff}  ";
        var result = ParseResult(line);
        string prefix = time + (result?.Word ?? line.Source).PadRight(KindColumn)
            + (section == null ? "" : Fit(section, SectionColumn - 1).PadRight(SectionColumn));
        string message = result is { } r ? (r.Detail.Length > 0 ? $"{r.Name}: {r.Detail}" : r.Name) : line.Message;
        return prefix + message.Replace("\n", "\n" + new string(' ', prefix.Length));
    }

    /// <summary>A run's "Started" and "Complete" lines, which its heading already says in the Sections view.</summary>
    public static bool IsRunBookend(LogLine line) =>
        line.Source == "run" && line.Block != null && line.Section == null
        && (line.Message.StartsWith("Started", StringComparison.Ordinal) || line.Message.StartsWith("Complete", StringComparison.Ordinal));

    /// <summary>
    /// The lines in the order they show. By section: a block's lines go under its heading where the block first
    /// appears, its own lines first, then each section's under a heading of its own, in <paramref name="sectionOrder"/>
    /// (others after, as they first appear), and its own lines from after its sections began below them; lines outside
    /// any block stay where they fall. By time: every line in
    /// order, with a block's heading before its first line and again where its lines resume after another block's.
    /// </summary>
    public static List<LogItem> Arrange(IReadOnlyList<LogLine> lines, bool bySection, IReadOnlyList<string> sectionOrder) =>
        bySection ? ArrangeBySection(lines, sectionOrder) : ArrangeByTime(lines);

    static List<LogItem> ArrangeByTime(IReadOnlyList<LogLine> lines)
    {
        var items = new List<LogItem>();
        LogBlock? current = null;
        foreach (var line in lines)
        {
            if (line.Block != null && line.Block != current)
            {
                items.Add(new LogBlockHeading(line.Block));
                current = line.Block;
            }
            items.Add(new LogEntry(line));
        }
        return items;
    }

    static List<LogItem> ArrangeBySection(IReadOnlyList<LogLine> lines, IReadOnlyList<string> sectionOrder)
    {
        var rank = sectionOrder.Select((section, i) => (section, i)).DistinctBy(p => p.section).ToDictionary(p => p.section, p => p.i);
        var byBlock = lines.Where(l => l.Block != null).ToLookup(l => l.Block!); // keeps each block's lines in order
        var items = new List<LogItem>();
        var seen = new HashSet<LogBlock>();
        foreach (var line in lines)
        {
            if (line.Block is not { } block)
                items.Add(new LogEntry(line));
            else if (seen.Add(block))
                AddBlock(items, block, byBlock[block].ToList(), rank);
        }
        return items;
    }

    // A block's heading, its own lines from before its sections began (such as "Started"), each section under its
    // heading in the given order (others after, as they first appear), then the block's later lines
    static void AddBlock(List<LogItem> items, LogBlock block, List<LogLine> mine, Dictionary<string, int> rank)
    {
        items.Add(new LogBlockHeading(block));
        long sectionsStart = mine.FirstOrDefault(l => l.Section != null)?.Seq ?? long.MaxValue;
        items.AddRange(mine.Where(l => l.Section == null && l.Seq < sectionsStart).Select(l => new LogEntry(l)));
        var sections = mine.Select(l => l.Section).OfType<string>().Distinct()
            .Select((section, first) => (section, first))
            .OrderBy(p => rank.GetValueOrDefault(p.section, int.MaxValue)).ThenBy(p => p.first);
        foreach (var (section, _) in sections)
        {
            items.Add(new LogSectionHeading(block, section));
            items.AddRange(mine.Where(l => l.Section == section).Select(l => new LogEntry(l)));
        }
        items.AddRange(mine.Where(l => l.Section == null && l.Seq > sectionsStart).Select(l => new LogEntry(l)));
    }

    /// <summary>The whole log as plain text, one line after another: the order lines were added in.</summary>
    public string Text()
    {
        var sb = new StringBuilder();
        foreach (var line in Since(0))
            sb.Append(Prefix(line)).AppendLine(Body(line));
        return sb.ToString();
    }

    /// <summary>
    /// The whole log as plain text in the view on screen: what Save log writes and Copy log puts on the clipboard.
    /// <paramref name="sections"/> gives the results sections in order, each with the short name By time shows.
    /// </summary>
    public string Text(bool bySection, IReadOnlyList<(string Name, string Short)> sections)
    {
        var shortNames = sections.ToDictionary(s => s.Name, s => s.Short);
        var rule = new string('=', 72);
        var sb = new StringBuilder();
        foreach (var item in Arrange(Since(0), bySection, sections.Select(s => s.Name).ToList()))
        {
            switch (item)
            {
                case LogBlockHeading { Block: var block }:
                    if (sb.Length > 0) sb.AppendLine();
                    sb.AppendLine(rule).AppendLine($"{block.Title}  {block.Detail}");
                    if (block.Totals != null) sb.AppendLine(block.Totals);
                    sb.AppendLine(rule);
                    break;
                case LogSectionHeading { Block: var block, Section: var section }:
                    string note = block.SectionNotes.TryGetValue(section, out var n) ? $" ({n})" : "";
                    sb.AppendLine().AppendLine($"--- {section}{note} ".PadRight(rule.Length, '-'));
                    break;
                case LogEntry { Line: var line } when bySection && IsRunBookend(line):
                    break; // the banner above says it
                case LogEntry { Line: var line }:
                    string? column = bySection ? null : line.Section == null ? "" : shortNames.GetValueOrDefault(line.Section, line.Section);
                    sb.AppendLine(Formatted(line, bySection, column));
                    break;
            }
        }
        return sb.ToString();
    }
}

/// <summary>
/// Wraps the real probe so every question the diagnostics ask of the machine is logged: failures always, and
/// with debug on, each call with its duration and what came back.
/// </summary>
sealed class LoggingProbe(IProbe inner, DiagLog log) : IProbe
{
    T Call<T>(string source, string what, Func<T> call, Func<T, string> describe)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            T result = call();
            log.Debug(source, () => $"{what} ({sw.ElapsedMilliseconds} ms)\n{describe(result)}");
            return result;
        }
        catch (OperationCanceledException)
        {
            log.Debug(source, $"{what} cancelled after {sw.ElapsedMilliseconds} ms");
            throw;
        }
        catch (Exception ex)
        {
            log.Info(source, $"{what} failed after {sw.ElapsedMilliseconds} ms: {Describe(ex)}");
            throw;
        }
    }

    // The Windows error text is translated; the number isn't
    static string Describe(Exception ex) =>
        ex is Win32Exception win32 ? $"{ex.Message} (error {win32.NativeErrorCode})" : $"{ex.Message} ({ex.GetType().Name})";

    static string Addresses(IEnumerable<IPAddress> addresses)
    {
        string list = string.Join(", ", addresses);
        return list.Length > 0 ? list : "(none)";
    }

    public string RunTool(string tool, string arguments, int timeoutMs, CancellationToken ct) =>
        Call("tool", $"{tool} {arguments}".Trim(), () => inner.RunTool(tool, arguments, timeoutMs, ct), output => output);

    readonly object _scriptLock = new();
    string? _loggedScript;
    int _loggedClears;

    public string RunPowerShell(string script, int timeoutMs, CancellationToken ct)
    {
        if (log.DebugEnabled)
        {
            // A trace runs the same script on every poll; its text is logged once, not once per poll
            bool repeat;
            lock (_scriptLock)
            {
                repeat = script == _loggedScript && log.Clears == _loggedClears;
                (_loggedScript, _loggedClears) = (script, log.Clears);
            }
            log.Debug("tool", repeat ? "powershell script: the same as the last one logged" : "powershell script:\n" + script);
        }
        return Call("tool", "powershell", () => inner.RunPowerShell(script, timeoutMs, ct), output => output);
    }

    public IPAddress[] Resolve(string host, CancellationToken ct) =>
        Call("dns", $"Resolve {host}", () => inner.Resolve(host, ct), Addresses);

    public async Task<bool> TcpConnect(IPAddress ip, int port, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        bool open = await inner.TcpConnect(ip, port, ct).ConfigureAwait(false);
        log.Debug("tcp", $"Connect {ip} port {port}: {(open ? "open" : "no answer")} ({sw.ElapsedMilliseconds} ms)");
        return open;
    }

    public List<string>? QuerySrv(string record, CancellationToken ct) =>
        Call("dns", $"SRV {record}", () => inner.QuerySrv(record, ct), targets => targets == null ? "no record" : string.Join(", ", targets));

    public int? ShareEntries(string path, CancellationToken ct) =>
        Call("share", $"Open {path}", () => inner.ShareEntries(path, ct), entries => entries == null ? "does not exist" : $"{entries} entries");

    public string CurrentUser() => Call("machine", "Current user", inner.CurrentUser, user => user);

    public (string SearchList, string Domain) DnsSuffixConfig() =>
        Call("machine", "DNS suffix configuration", inner.DnsSuffixConfig, c => $"search list \"{c.SearchList}\", primary domain \"{c.Domain}\"");

    public string?[] OwnDomainNames() =>
        Call("machine", "Own domain names", inner.OwnDomainNames, names => string.Join(", ", names.Select(n => n ?? "(none)")));

    public (string Host, string Suffix) HostIdentity() =>
        Call("machine", "Host name and primary DNS suffix", inner.HostIdentity, id => $"{id.Host}, suffix \"{id.Suffix}\"");

    public List<NetAdapter> Adapters() => Call("machine", "Network adapters", inner.Adapters, DescribeAdapters);

    // Windows reports many connected adapters that hold no address (WAN Miniports, filter bindings); they get one line between them
    static string DescribeAdapters(List<NetAdapter> adapters)
    {
        if (adapters.Count == 0) return "(none connected)";
        var lines = adapters.Where(a => a.Addresses.Length > 0).Select(a =>
            $"{a.Name} [{a.Description}]{(a.Tunnel ? " tunnel" : "")}{(a.Virtual ? " virtual" : "")}{(a.PointToPoint ? " /32 no gateway" : "")}: addresses {Addresses(a.Addresses)}; DNS servers {Addresses(a.DnsServers)}; registers in DNS: {(a.RegistersInDns ? "yes" : "no")}").ToList();
        var bare = adapters.Where(a => a.Addresses.Length == 0).Select(a => a.Name).ToList();
        if (bare.Count > 0)
            lines.Add($"{bare.Count} with no address, not detailed: {string.Join(", ", bare)}");
        return string.Join("\n", lines);
    }

    static string From(IPAddress? server) => $"from {(server == null ? "the configured DNS servers" : server.ToString())}";

    public string[]? RegistrySubKeys(string hklmPath) =>
        Call("registry", $@"Subkeys of HKLM\{hklmPath}", () => inner.RegistrySubKeys(hklmPath), keys => keys == null ? "no such key" : $"{keys.Length} subkeys");

    public Dictionary<string, object>? RegistryValues(string hklmPath) =>
        Call("registry", $@"Values of HKLM\{hklmPath}", () => inner.RegistryValues(hklmPath), values => values == null ? "no such key" : $"{values.Count} values");

    public int? ServiceState(string name) =>
        Call("machine", $"Service {name}", () => inner.ServiceState(name), state => state == null ? "not installed" : $"state {state}");

    public string? CurrentUserSid() => Call("machine", "Current user SID", inner.CurrentUserSid, sid => sid ?? "(unknown)");

    public SoaRecord? QuerySoa(string name, IPAddress? server, CancellationToken ct) =>
        Call("dns", $"SOA {name} {From(server)}", () => inner.QuerySoa(name, server, ct), soa => soa == null ? "no record" : $"zone {soa.Zone}, primary server {soa.PrimaryServer}");

    public IPAddress[] QueryAddresses(string name, IPAddress? server, CancellationToken ct) =>
        Call("dns", $"A/AAAA {name} {From(server)}", () => inner.QueryAddresses(name, server, ct), Addresses);

    public bool IsElevated() => Call("machine", "Elevation", inner.IsElevated, elevated => elevated ? "running as Administrator" : "not elevated");

    public UrlSecurity UrlSecurity(string url, CancellationToken ct) =>
        Call("machine", $"Internet settings for {url}", () => inner.UrlSecurity(url, ct),
            s => $"zone {s.Zone}, logon policy 0x{s.Logon:x}, status bar policy {s.StatusBar}");
}
