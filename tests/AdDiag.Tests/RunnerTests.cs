using Xunit;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace AdDiag.Tests;

// The hang this guards against: a tool or network call that never returns must not hold a run (or the app) open.
public class RunnerTests
{
    // A shell command for the platform the tests run on (CI is Windows, development is often Linux)
    static (string Path, string Args) Shell(string unix, string windows) => OperatingSystem.IsWindows()
        ? (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c " + windows)
        : ("/bin/sh", $"-c \"{unix}\"");

    static string Run((string Path, string Args) cmd, int timeoutMs, CancellationToken ct = default) =>
        Runner.RunProcess(cmd.Path, cmd.Args, timeoutMs, ct);

    static readonly (string, string) Sleeper = Shell("exec sleep 30", "ping -n 30 127.0.0.1");

    [Fact]
    public void RunProcess_ReturnsStdout() =>
        Assert.Equal("hello", Run(Shell("echo hello", "echo hello"), 10000).Trim());

    [Fact]
    public void RunProcess_ReturnsStderrWhenStdoutIsEmpty() =>
        Assert.Equal("oops", Run(Shell("echo oops 1>&2", "echo oops 1>&2"), 10000).Trim());

    [Fact]
    public void RunProcess_TimesOutInsteadOfWaitingForTheTool()
    {
        var clock = Stopwatch.StartNew();
        var ex = Assert.Throws<TimeoutException>(() => Run(Sleeper, 500));
        Assert.Contains("timed out", ex.Message);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"took {clock.Elapsed}");
    }

    [Fact]
    public void RunProcess_CancellationStopsItLongBeforeTheTimeout()
    {
        using var cts = new CancellationTokenSource(300);
        var clock = Stopwatch.StartNew();
        Assert.ThrowsAny<OperationCanceledException>(() => Run(Sleeper, 25000, cts.Token));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"took {clock.Elapsed}");
    }

    [Fact]
    public void RunProcess_DoesNotStartWhenAlreadyCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Run(Shell("echo hello", "echo hello"), 10000, cts.Token));
    }

    // The tool exits at once but leaves a child holding its output pipe: reading to the end would block for the
    // child's whole life
    [Fact]
    public void RunProcess_ReturnsWhenAChildKeepsTheOutputPipeOpen()
    {
        var clock = Stopwatch.StartNew();
        Assert.Throws<TimeoutException>(() => Run(Shell("sleep 30 & echo started", "start /b ping -n 30 127.0.0.1"), 5000));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(15), $"took {clock.Elapsed}");
    }

    [Fact]
    public void RunWithTimeout_ReturnsTheResult() =>
        Assert.Equal(42, Runner.RunWithTimeout(() => 42, 5000, "call", CancellationToken.None));

    [Fact]
    public void RunWithTimeout_GivesUpOnACallThatNeverReturns()
    {
        using var never = new ManualResetEventSlim();
        var clock = Stopwatch.StartNew();
        var ex = Assert.Throws<TimeoutException>(() =>
            Runner.RunWithTimeout(() => { never.Wait(TimeSpan.FromSeconds(30)); return 0; }, 300, "Opening the share", CancellationToken.None));
        Assert.StartsWith("Opening the share timed out", ex.Message);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"took {clock.Elapsed}");
        never.Set();
    }

    [Fact]
    public void RunWithTimeout_RethrowsTheCallsOwnException() =>
        Assert.Throws<UnauthorizedAccessException>(() =>
            Runner.RunWithTimeout<int>(() => throw new UnauthorizedAccessException("denied"), 5000, "call", CancellationToken.None));

    [Fact]
    public void RunWithTimeout_StopsWaitingWhenCancelled()
    {
        using var never = new ManualResetEventSlim();
        using var cts = new CancellationTokenSource(200);
        Assert.ThrowsAny<OperationCanceledException>(() =>
            Runner.RunWithTimeout(() => { never.Wait(TimeSpan.FromSeconds(30)); return 0; }, 25000, "call", cts.Token));
        never.Set();
    }

    [Fact]
    public async Task TryTcpConnect_TrueForAListeningPortFalseOnceClosed()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Assert.True(await Runner.TryTcpConnectAsync(IPAddress.Loopback, port, CancellationToken.None));
        listener.Stop();
        Assert.False(await Runner.TryTcpConnectAsync(IPAddress.Loopback, port, CancellationToken.None, timeoutMs: 1000));
    }

    [Fact]
    public async Task TryTcpConnect_FalseWhenCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.False(await Runner.TryTcpConnectAsync(IPAddress.Loopback, 9, cts.Token));
    }

    [Fact]
    public void ResolveHost_ResolvesLocalhost() =>
        Assert.Contains(Runner.ResolveHost("localhost", CancellationToken.None), IPAddress.IsLoopback);

    [Fact]
    public void ResolveHost_ThrowsWhenCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => Runner.ResolveHost("localhost", cts.Token));
    }

    // tools/screenshots/Shots.cs reaches MainForm's private members by name; a rename would only fail when
    // someone next regenerates the screenshots
    [Fact]
    public void ScreenshotHarness_NamesStillExistInMainForm()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root != null && !File.Exists(Path.Combine(root.FullName, "AdDiag.csproj"))) root = root.Parent;
        Assert.NotNull(root);
        string shots = File.ReadAllText(Path.Combine(root.FullName, "tools", "screenshots", "Shots.cs"));
        string form = File.ReadAllText(Path.Combine(root.FullName, "MainForm.cs"));

        var names = Regex.Matches(shots, @"\b(?:Get<[^>]+>|Set|Call)\(\w+, ""(\w+)""|\bTheme\(""(\w+)""\)")
            .Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).Distinct().ToList();
        Assert.NotEmpty(names);
        Assert.All(names, name => Assert.Matches($@"\b{Regex.Escape(name)}\b", form));
    }
}
