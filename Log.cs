using System;
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

record LogLine(long Seq, DateTime Time, bool Debug, string Source, string Message);

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
            _lines.Enqueue(new(++_seq, _clock(), debug, source, message));
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

    /// <summary>"14:02:03.118  dns     " — the fixed-width start of a line; continuation lines are indented to match.</summary>
    public static string Prefix(LogLine line) => $"{line.Time:HH:mm:ss.fff}  {line.Source,-7} ";

    public static string Body(LogLine line)
    {
        string text = (line.Debug ? "DEBUG " : "") + line.Message;
        return text.Replace("\n", "\n" + new string(' ', Prefix(line).Length + (line.Debug ? 6 : 0)));
    }

    /// <summary>The whole log as plain text: what Save log writes and Copy log puts on the clipboard.</summary>
    public string Text()
    {
        var sb = new StringBuilder();
        foreach (var line in Since(0))
            sb.Append(Prefix(line)).AppendLine(Body(line));
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

    public SoaRecord? QuerySoa(string name, IPAddress? server, CancellationToken ct) =>
        Call("dns", $"SOA {name} {From(server)}", () => inner.QuerySoa(name, server, ct), soa => soa == null ? "no record" : $"zone {soa.Zone}, primary server {soa.PrimaryServer}");

    public IPAddress[] QueryAddresses(string name, IPAddress? server, CancellationToken ct) =>
        Call("dns", $"A/AAAA {name} {From(server)}", () => inner.QueryAddresses(name, server, ct), Addresses);

    public bool IsElevated() => Call("machine", "Elevation", inner.IsElevated, elevated => elevated ? "running as Administrator" : "not elevated");
}
