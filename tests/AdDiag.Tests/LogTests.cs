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
        probe.QuerySoa("contoso.com", default);
        probe.QueryAddresses("pc042.contoso.com", DiagnosticsTests.DcIp, default);
        var lines = log.Since(0);
        Assert.Matches(@"^klist \(\d+ ms\)\n", lines[0].Message);
        Assert.Contains("krbtgt/CONTOSO.COM", lines[0].Message);
        Assert.Matches(@"^Connect 10\.20\.0\.11 port 53: open \(\d+ ms\)$", lines[1].Message);
        Assert.EndsWith("zone contoso.com, primary server dc01.contoso.com", lines[2].Message);
        Assert.Matches(@"^A/AAAA pc042\.contoso\.com from 10\.20\.0\.11 \(\d+ ms\)\n10\.20\.4\.18$", lines[3].Message);
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
}
