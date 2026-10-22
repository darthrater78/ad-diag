using System.ComponentModel;
using System.Net;
using Xunit;

namespace AdDiag.Tests;

public class LogTests
{
    static readonly DateTime At = new(2026, 10, 5, 14, 2, 3, 118);
    static DiagLog NewLog(bool debug = false) => new(() => At) { DebugEnabled = debug };

    [Fact]
    public void DebugLines_AreRecordedOnlyWhileDebugIsOn_AndNotEvenBuiltOtherwise()
    {
        var log = NewLog();
        log.Info("run", "Started");
        log.Debug("tool", "raw output");
        log.Debug("tool", () => throw new InvalidOperationException("built a message nobody asked for"));
        Assert.Equal(["Started"], log.Since(0).Select(l => l.Message));

        log.DebugEnabled = true;
        log.Debug("tool", () => "raw output");
        Assert.Equal([false, true], log.Since(0).Select(l => l.Debug));
    }

    [Fact]
    public void Since_ReturnsOnlyNewerLines_AndClearDoesNotReuseNumbers()
    {
        var log = NewLog();
        log.Info("run", "one");
        log.Info("run", "two");
        long last = log.Since(0)[^1].Seq;
        Assert.Empty(log.Since(last));
        log.Clear();
        log.Info("run", "three");
        Assert.Equal(["three"], log.Since(last).Select(l => l.Message));
    }

    [Fact]
    public void Log_IsBounded_OldestLinesGoFirst_AndLongMessagesAreCut()
    {
        var log = NewLog();
        for (int i = 0; i < DiagLog.MaxLines + 10; i++) log.Info("run", $"line {i}");
        var lines = log.Since(0);
        Assert.Equal(DiagLog.MaxLines, lines.Count);
        Assert.Equal("line 10", lines[0].Message);

        log.Info("tool", new string('x', DiagLog.MaxMessageChars + 500));
        Assert.EndsWith("(500 more characters not logged)", log.Since(0)[^1].Message);
    }

    [Fact]
    public void Text_IndentsContinuationLinesUnderTheMessage()
    {
        var log = NewLog(debug: true);
        log.Info("run", "Started");
        log.Debug("tool", "klist (12 ms)\r\nCached Tickets: (2)\r\n");
        Assert.Equal(
            "14:02:03.118  run     Started" + Environment.NewLine +
            "14:02:03.118  tool    DEBUG klist (12 ms)\n" +
            "                            Cached Tickets: (2)" + Environment.NewLine,
            log.Text());
    }

    [Fact]
    public async Task LoggingProbe_LogsFailuresAlways_AndCallsWithTheirOutputOnlyInDebug()
    {
        var log = NewLog();
        var inner = DiagnosticsTests.Healthy();
        var probe = new LoggingProbe(inner, log);

        Assert.Equal(Samples.Klist, probe.RunTool("klist", "", 5000, default));
        Assert.Empty(log.Since(0));
        Assert.Throws<TimeoutException>(() => probe.RunTool("gpupdate", "/force", 90000, default));
        var failure = Assert.Single(log.Since(0));
        Assert.False(failure.Debug);
        Assert.Matches(@"^gpupdate /force failed after \d+ ms: gpupdate timed out after 90s \(TimeoutException\)$", failure.Message);

        log.Clear();
        log.DebugEnabled = true;
        probe.RunTool("klist", "", 5000, default);
        Assert.True(await probe.TcpConnect(DiagnosticsTests.DcIp, 53, default));
        probe.QuerySoa("contoso.com", DiagnosticsTests.DcIp, default);
        probe.QueryAddresses("pc042.contoso.com", DiagnosticsTests.DcIp, default);
        var lines = log.Since(0);
        Assert.Matches(@"^klist \(\d+ ms\)\n", lines[0].Message);
        Assert.Contains("krbtgt/CONTOSO.COM", lines[0].Message);
        Assert.Matches(@"^Connect 10\.20\.0\.11 port 53: open \(\d+ ms\)$", lines[1].Message);
        Assert.Matches(@"^SOA contoso\.com from 10\.20\.0\.11 \(\d+ ms\)\nzone contoso\.com, primary server dc01\.contoso\.com$", lines[2].Message);
        Assert.Matches(@"^A/AAAA pc042\.contoso\.com from 10\.20\.0\.11 \(\d+ ms\)\n10\.20\.4\.18$", lines[3].Message);
    }

    [Fact]
    public void LoggingProbe_LogsARepeatedScriptOnce_UntilTheLogIsCleared()
    {
        var log = NewLog();
        log.DebugEnabled = true;
        var probe = new LoggingProbe(DiagnosticsTests.Healthy(), log);
        string[] Scripts() => log.Since(0).Where(l => l.Message.StartsWith("powershell script")).Select(l => l.Message).ToArray();

        probe.RunPowerShell("Get-WinEvent -MaxEvents 1", 5000, default);
        probe.RunPowerShell("Get-WinEvent -MaxEvents 1", 5000, default);
        probe.RunPowerShell("Get-WinEvent -MaxEvents 2", 5000, default);
        Assert.Equal(["powershell script:\nGet-WinEvent -MaxEvents 1", "powershell script: the same as the last one logged",
            "powershell script:\nGet-WinEvent -MaxEvents 2"], Scripts());

        log.Clear();
        probe.RunPowerShell("Get-WinEvent -MaxEvents 2", 5000, default);
        Assert.Equal(["powershell script:\nGet-WinEvent -MaxEvents 2"], Scripts());
    }

    [Fact]
    public void LoggingProbe_AdaptersWithNoAddressShareOneLine()
    {
        var log = NewLog();
        log.DebugEnabled = true;
        var inner = DiagnosticsTests.Healthy();
        inner.NetAdapters.Add(new("Local Area Connection* 6", "WAN Miniport (IP)", false, false, [], [], Virtual: true));
        inner.NetAdapters.Add(new("Local Area Connection* 7", "WAN Miniport (IPv6)", false, false, [], [], Virtual: true));
        new LoggingProbe(inner, log).Adapters();
        string[] lines = log.Since(0)[0].Message.Split('\n');
        Assert.Equal(3, lines.Length);
        Assert.StartsWith("Ethernet [Intel(R) Ethernet Connection]: addresses 10.20.4.18", lines[1]);
        Assert.Equal("2 with no address, not detailed: Local Area Connection* 6, Local Area Connection* 7", lines[2]);
    }

    [Fact]
    public void LoggingProbe_NamesWindowsErrorsByNumber_AndLogsCancellationOnlyInDebug()
    {
        var log = NewLog();
        var inner = DiagnosticsTests.Healthy();
        inner.Records = (_, _) => throw new Win32Exception(9005, "DNS operation refused.");
        var probe = new LoggingProbe(inner, log);
        Assert.Throws<Win32Exception>(() => probe.QueryAddresses("pc042.contoso.com", null, default));
        Assert.EndsWith("ms: DNS operation refused. (error 9005)", log.Since(0)[0].Message);

        log.Clear();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => probe.RunTool("klist", "", 5000, cts.Token));
        Assert.Empty(log.Since(0));
    }

    // A run whose two sections ran side by side, so their lines arrive interleaved, then a line outside any run
    static (DiagLog Log, LogBlock Run) SectionedLog()
    {
        var log = NewLog();
        var run = new LogBlock("Run 14:02:03", "contoso.com · DC01 · all sections") { Totals = "5 passed · 0 failed · 1 warning" };
        run.SectionNotes["DNS for Active Directory"] = "5 checks";
        DiagLog.Block = run;
        log.Info("run", "Started");
        DiagLog.Section = "DNS for Active Directory";
        log.Info("dns", "dns one");
        DiagLog.Section = "DC Discovery & Connectivity";
        log.Info("tcp", "dc one");
        DiagLog.Section = "DNS for Active Directory";
        log.Info("dns", "dns two");
        DiagLog.Section = null;
        log.Info("run", "Complete");
        DiagLog.Block = null;
        log.Info("log", "Debug logging off");
        return (log, run);
    }

    static readonly (string Name, string Short)[] Order =
        [("DC Discovery & Connectivity", "DC Discovery"), ("DNS for Active Directory", "DNS for AD")];

    static string Describe(LogItem item) => item switch
    {
        LogBlockHeading h => "# " + h.Block.Title,
        LogSectionHeading h => "## " + h.Section,
        LogEntry e => e.Line.Message,
        _ => "?",
    };

    [Fact]
    public void Arrange_BySection_GroupsARunsLinesUnderItsSectionsInResultsOrder()
    {
        var (log, _) = SectionedLog();

        var items = DiagLog.Arrange(log.Since(0), bySection: true, Order.Select(o => o.Name).ToList());

        Assert.Equal(["# Run 14:02:03", "Started",
            "## DC Discovery & Connectivity", "dc one",
            "## DNS for Active Directory", "dns one", "dns two",
            "Complete", "Debug logging off"], items.Select(Describe));
    }

    [Fact]
    public void Arrange_ByTime_KeepsTheOrderAndRepeatsAHeadingOnlyWhenItsRunResumes()
    {
        var (log, run) = SectionedLog();
        var other = new LogBlock("Kerberos tickets 14:03:00", "klist");
        DiagLog.Block = other;
        log.Info("tool", "klist");
        DiagLog.Block = run;
        log.Info("run", "late line");
        DiagLog.Block = null;

        var items = DiagLog.Arrange(log.Since(0), bySection: false, []);

        Assert.Equal(["# Run 14:02:03", "Started", "dns one", "dc one", "dns two", "Complete", "Debug logging off",
            "# Kerberos tickets 14:03:00", "klist", "# Run 14:02:03", "late line"], items.Select(Describe));
    }

    [Fact]
    public void Text_BySection_HasRunBannersAndSectionRules()
    {
        var (log, _) = SectionedLog();
        string nl = Environment.NewLine, rule = new('=', 72);

        string text = log.Text(bySection: true, Order);

        Assert.StartsWith(rule + nl + "Run 14:02:03  contoso.com · DC01 · all sections" + nl + "5 passed · 0 failed · 1 warning" + nl + rule + nl, text);
        Assert.Contains(nl + "--- DNS for Active Directory (5 checks) ".PadRight(72, '-') + nl, text);
        Assert.Contains(nl + "--- DC Discovery & Connectivity ".PadRight(72, '-') + nl, text);
        Assert.True(text.IndexOf("dc one") < text.IndexOf("dns one"));
    }

    [Fact]
    public void Text_ByTime_NamesEachLinesSectionInAColumn()
    {
        var (log, _) = SectionedLog();

        string text = log.Text(bySection: false, Order);

        string column(string section) => section.PadRight(DiagLog.SectionColumn);
        string kind(string source) => source.PadRight(DiagLog.KindColumn);
        Assert.Contains("14:02:03.118  " + kind("tcp") + column("DC Discovery") + "dc one", text);
        // A run's own lines, and lines outside any run, leave the column blank so the messages line up
        Assert.Contains("14:02:03.118  " + kind("run") + column("") + "Complete", text);
        Assert.Contains("14:02:03.118  " + kind("log") + column("") + "Debug logging off", text);
    }

    [Fact]
    public void Text_BySection_DropsTheRunsBookendsAndShortensTheTime()
    {
        var (log, _) = SectionedLog();

        string text = log.Text(bySection: true, Order);

        Assert.DoesNotContain("Started", text);
        Assert.DoesNotContain("Complete", text);
        Assert.Contains("14:02:03  " + "dns".PadRight(DiagLog.KindColumn) + "dns one", text);
        Assert.DoesNotContain("14:02:03.118", text.Split(Environment.NewLine).Where(l => l.Contains("dns one")).Single());
    }

    [Fact]
    public void Formatted_ResultShowsStatusAndCheck_DebugDropsItsLabel_RawOutputLinesUp()
    {
        DiagLog.Block = new LogBlock("Run", "");
        DiagLog.Section = "Group Policy";
        var log = NewLog();
        log.DebugEnabled = true;
        log.Info("result", "Warning  Group Policy / GP Last Refresh: 3 days ago");
        log.Debug("tool", "RSoP query (840 ms)\n2 computer GPOs");
        DiagLog.Block = null;
        DiagLog.Section = null;
        var lines = log.Since(0);

        Assert.Equal("14:02:03  Warning   GP Last Refresh: 3 days ago", DiagLog.Formatted(lines[0], bySection: true, null));
        string pad = new(' ', "14:02:03  ".Length + DiagLog.KindColumn);
        Assert.Equal($"14:02:03  {"tool".PadRight(DiagLog.KindColumn)}RSoP query (840 ms)\n{pad}2 computer GPOs",
            DiagLog.Formatted(lines[1], bySection: true, null));
        // The raw log keeps every line as written
        Assert.Contains("Warning  Group Policy / GP Last Refresh", log.Text());
        Assert.Contains("DEBUG RSoP query", log.Text());
    }

    [Fact]
    public async Task BlockAndSection_FollowLinesIntoTasksAndThreads_AndStayOutOfTheCaller()
    {
        var log = NewLog();
        var run = new LogBlock("Run", "");

        async Task Run()
        {
            DiagLog.Block = run;
            await Task.Factory.StartNew(() =>
            {
                DiagLog.Section = "Group Policy";
                var thread = new Thread(() => log.Info("tool", "from a thread"));
                thread.Start();
                thread.Join();
            }, TaskCreationOptions.LongRunning);
            log.Info("run", "back in the run");
        }
        await Run();
        log.Info("log", "after the run");

        var lines = log.Since(0);
        Assert.Equal((run, "Group Policy"), (lines[0].Block, lines[0].Section));
        Assert.Equal((run, (string?)null), (lines[1].Block, lines[1].Section));
        Assert.Equal((null, null), (lines[2].Block, lines[2].Section));
    }
}
