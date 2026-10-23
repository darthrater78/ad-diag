using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

#nullable enable
namespace AdDiag;

// Intune (MDM) management: whether this PC is enrolled, when it last synced, the Intune Management Extension, and the
// policy settings Intune has pushed. Everything comes from the registry the Windows MDM client keeps, so it works on
// any join type and writes nothing. Whether Intune counts the PC as compliant is decided in the service and not
// stored here, so it isn't shown.
static partial class Diagnostics
{
    public const string IntuneGroup = "Intune";
    public const string MdmEnrollmentCheck = "MDM Enrollment", MdmSyncCheck = "Last Sync",
        MdmExtensionCheck = "Management Extension", MdmPoliciesCheck = "Device Policies";

    const string EnrollmentsKey = @"SOFTWARE\Microsoft\Enrollments";
    const string OmadmAccountsKey = @"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts";
    // MSI apps an MDM pushed (EnterpriseDesktopAppManagement CSP), under the device context or a user's SID
    const string DesktopAppsKey = @"SOFTWARE\Microsoft\EnterpriseDesktopAppManagement";
    const string DeviceAppContext = "S-0-0-00-0000000000-0000000000-000000000-000";
    static readonly string[] UninstallKeys =
        [@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"];
    const string IntuneProvider = "MS DM Server";
    const string ExtensionService = "IntuneManagementExtension";
    // A PC that is on syncs about every 8 hours; a week without one means it has been off or can't reach Intune
    static readonly TimeSpan SyncStale = TimeSpan.FromDays(7);

    // PolicyManager keeps bookkeeping values beside each setting; these aren't settings
    static readonly string[] PolicyBookkeeping = ["_ProviderSet", "_WinningProvider", "_LastWrite", "_ADMXInstanceData"];

    // Service states (winsvc.h)
    const int ServiceStopped = 1, ServiceRunning = 4;

    public static TestGroup TestIntune(DiagConfig cfg, IProbe probe) => TestIntune(probe, DateTime.UtcNow);

    /// <param name="zone">The zone the MDM client writes its times in; null for this PC's.</param>
    internal static TestGroup TestIntune(IProbe probe, DateTime nowUtc, TimeZoneInfo? zone = null)
    {
        MdmEnrollment? enrollment;
        try { enrollment = ReadEnrollment(probe); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new(IntuneGroup, [new(MdmEnrollmentCheck, Status.Skip, "Not checked: needs Run as Administrator to read the enrollment") { NeedsAdmin = true }]);
        }

        // Not enrolled: the other checks don't apply, so they aren't shown
        if (enrollment == null)
            return new(IntuneGroup, [new(MdmEnrollmentCheck, Status.Info, "Not enrolled in Intune or another MDM; the other Intune checks don't apply")]);

        var tests = new List<TestEntry> { EnrollmentCheck(enrollment) };
        var state = ReadIntuneState(probe, enrollment, zone);
        tests.Add(SyncCheck(state, nowUtc));
        tests.Add(ExtensionCheck(state));
        tests.Add(PoliciesCheck(state));
        return new(IntuneGroup, tests);
    }

    static TestEntry EnrollmentCheck(MdmEnrollment e)
    {
        string who = e.Upn is { Length: > 0 } upn ? $" as {upn}" : "";
        if (e.State != 1)
            return new(MdmEnrollmentCheck, Status.Warn, $"Enrollment in {e.ProviderName} not complete (EnrollmentState {e.State?.ToString(CultureInfo.InvariantCulture) ?? "not set"}){who}");
        return new(MdmEnrollmentCheck, Status.Pass, $"Enrolled in {e.ProviderName}{who}");
    }

    static TestEntry SyncCheck(IntuneState s, DateTime nowUtc)
    {
        if (s.SyncError is { } error)
            return new(MdmSyncCheck, Status.Skip, $"Not checked: {error}") { NeedsAdmin = true };
        if (s.LastSuccess is not { } success)
            return new(MdmSyncCheck, Status.Skip, "Not checked: Windows has no successful sync recorded");

        var age = Age(success, nowUtc);
        string when = $"{success.ToLocalTime():g} ({FormatTimeSpan(age)} ago)";
        if (s.LastFailure is { } failure && failure > success)
            return new(MdmSyncCheck, Status.Info, $"Last attempt failed {failure.ToLocalTime():g}; last successful sync {when}");
        return age <= SyncStale
            ? new(MdmSyncCheck, Status.Pass, $"Last successful sync {when}")
            : new(MdmSyncCheck, Status.Warn, $"Last successful sync {when}; over a week, so the PC has been off or can't reach Intune");
    }

    static TestEntry ExtensionCheck(IntuneState s) => s.ExtensionError is { } error
        ? new(MdmExtensionCheck, Status.Skip, $"Not checked: the service manager didn't answer: {error}")
        : s.ExtensionState switch
    {
        null => new(MdmExtensionCheck, Status.Info, "Not installed; Intune adds it with the first Win32 app, script or remediation"),
        ServiceRunning => new(MdmExtensionCheck, Status.Pass, "Intune Management Extension service running"),
        ServiceStopped => new(MdmExtensionCheck, Status.Warn, "Intune Management Extension installed but stopped, so Win32 apps and scripts don't arrive"),
        var other => new(MdmExtensionCheck, Status.Info, $"Intune Management Extension service state {other}"),
    };

    static TestEntry PoliciesCheck(IntuneState s)
    {
        if (s.PolicyError is { } error)
            return new(MdmPoliciesCheck, Status.Skip, $"Not checked: {error}") { NeedsAdmin = true };
        string apps = AppsSummary(s);
        // An earlier version's failure is moot once a later one is in place, so only each app's current version counts
        var failed = GroupApps(s.Apps).Where(g => MsiStatus(g.Current.Status).Look == Status.Fail).ToList();
        string failures = failed.Count == 0 ? ""
            : $"; failed: {string.Join(", ", failed.Select(g => $"{g.Name ?? g.Current.ProductCode} ({MsiStatus(g.Current.Status).Text.ToLowerInvariant()})"))}";
        var won = s.Device.Where(p => p.ProviderWins).ToList();
        if (s.Device.Count == 0)
            return new(MdmPoliciesCheck, failed.Count > 0 ? Status.Warn : Status.Info, $"No device settings from Intune yet{apps}{failures}");

        var areas = won.Select(p => p.Area).Distinct().ToList();
        string list = areas.Count == 0 ? "" : $" ({string.Join(", ", areas.Take(3))}{(areas.Count > 3 ? ", ..." : "")})";
        int lost = s.Device.Count - won.Count;
        string overridden = lost > 0 ? $"; {lost} set by another provider instead" : "";
        return new(MdmPoliciesCheck, failed.Count > 0 ? Status.Warn : Status.Pass,
            $"{won.Count} setting{(won.Count == 1 ? "" : "s")} from {s.Enrollment.ProviderName} in {areas.Count} area{(areas.Count == 1 ? "" : "s")}{list}{overridden}{apps}{failures}");
    }

    // The MSI apps, as Settings counts them beside the policy areas; empty when there are none or they weren't read
    static string AppsSummary(IntuneState s)
    {
        if (s.AppsError != null) return "; apps not read";
        int count = GroupApps(s.Apps).Count;
        return count == 0 ? "" : $"; {count} MSI app{(count == 1 ? "" : "s")}";
    }

    /// <summary>
    /// The MDM enrollment Windows keeps under HKLM\SOFTWARE\Microsoft\Enrollments, preferring a completed Intune one;
    /// null when there is none. Entries without an MDM sync account (Windows Hello, provisioning, Windows' own Local,
    /// Deploy and Cloud Authority, the ConfigMgr bridge) are ignored.
    /// </summary>
    internal static MdmEnrollment? ReadEnrollment(IProbe probe)
    {
        // Windows keeps built-in entries here too (Local, Deploy and Cloud Authority, the ConfigMgr bridge) on every
        // PC; only an enrollment with an MDM server has a sync account, so only those count
        var accounts = new HashSet<string>(probe.RegistrySubKeys(OmadmAccountsKey) ?? [], StringComparer.OrdinalIgnoreCase);
        var found = new List<MdmEnrollment>();
        foreach (string id in probe.RegistrySubKeys(EnrollmentsKey) ?? [])
        {
            if (!Guid.TryParse(id, out _) || !accounts.Contains(id)) continue;
            var values = probe.RegistryValues($@"{EnrollmentsKey}\{id}");
            if (values == null || values.GetValueOrDefault("ProviderID") is not string provider || provider.Length == 0) continue;
            int? state = values.GetValueOrDefault("EnrollmentState") is int s ? s : null;
            found.Add(new(id, provider, state, values.GetValueOrDefault("UPN") as string));
        }
        return found.OrderByDescending(e => e.Provider == IntuneProvider).ThenByDescending(e => e.State == 1).FirstOrDefault();
    }

    /// <summary>The enrollment's sync times, the extension's service and the settings it pushed, for the device and this user.</summary>
    internal static IntuneState ReadIntuneState(IProbe probe, MdmEnrollment enrollment, TimeZoneInfo? zone = null)
    {
        DateTime? success = null, failure = null;
        string? syncError = null;
        try
        {
            var conn = probe.RegistryValues($@"{OmadmAccountsKey}\{enrollment.Id}\Protected\ConnInfo");
            success = MdmTime(conn?.GetValueOrDefault("ServerLastSuccessTime"), zone);
            failure = MdmTime(conn?.GetValueOrDefault("ServerLastFailureTime"), zone);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            syncError = "needs Run as Administrator to read the sync times";
        }

        int? extension = null;
        string? extensionError = null;
        try { extension = probe.ServiceState(ExtensionService); }
        catch (Exception ex) when (ex is not OperationCanceledException) { extensionError = ex.Message; }

        List<MdmSetting> device = [], user = [];
        List<MdmApp> apps = [];
        string? policyError = null, appsError = null;
        string? sid = probe.CurrentUserSid();
        try
        {
            string providerRoot = $@"SOFTWARE\Microsoft\PolicyManager\providers\{enrollment.Id}\default";
            device = ReadSettings(probe, $@"{providerRoot}\Device", @"SOFTWARE\Microsoft\PolicyManager\current\device", enrollment.Id);
            if (sid != null)
                user = ReadSettings(probe, $@"{providerRoot}\{sid}", $@"SOFTWARE\Microsoft\PolicyManager\current\{sid}", enrollment.Id);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            policyError = "needs Run as Administrator to read the policy settings";
        }
        try { apps = ReadApps(probe, enrollment.Id, sid); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            appsError = "needs Run as Administrator to read the apps";
        }

        return new(enrollment, success, failure, syncError, extension, extensionError, device, user, policyError, apps, appsError);
    }

    /// <summary>
    /// The MSI apps this enrollment pushed, the list Settings shows under Applications: for the device, then for
    /// <paramref name="sid"/>. Apps another MDM server pushed are left out.
    /// </summary>
    internal static List<MdmApp> ReadApps(IProbe probe, string enrollmentId, string? sid)
    {
        var apps = new List<MdmApp>();
        foreach (var (context, isUser) in new[] { (DeviceAppContext, false), (sid, true) })
        {
            if (context == null) continue;
            string msiPath = $@"{DesktopAppsKey}\{context}\MSI";
            foreach (string key in (probe.RegistrySubKeys(msiPath) ?? []).Order(StringComparer.OrdinalIgnoreCase))
            {
                var values = probe.RegistryValues($@"{msiPath}\{key}");
                if (values == null) continue;
                if (values.GetValueOrDefault("ServerAccountID") is string server && !SameId(server, enrollmentId)) continue;
                // The key and ProductCode wrap the product code in one or two pairs of braces
                string code = key.Trim('{', '}');
                string? installed = InstalledName(probe, code);
                apps.Add(new(code, installed ?? InstallerFile(values), values.GetValueOrDefault("ProductVersion") as string,
                    values.GetValueOrDefault("Status") as int?, values.GetValueOrDefault("LastError") as int?, isUser,
                    InstallerFile(values), installed != null));
            }
        }
        return apps;
    }

    // The installed product's name from its uninstall entry; null when this version isn't installed
    static string? InstalledName(IProbe probe, string code)
    {
        if (Guid.TryParse(code, out var guid))
            foreach (string root in UninstallKeys)
                if (probe.RegistryValues($@"{root}\{guid.ToString("B").ToUpperInvariant()}")?.GetValueOrDefault("DisplayName") is string { Length: > 0 } name)
                    return name;
        return null;
    }

    // The installer's file name, from the download URL's path only (the query can hold a token)
    static string? InstallerFile(Dictionary<string, object> values)
    {
        string? url = values.GetValueOrDefault("CurrentDownloadUrl") as string
            ?? (values.GetValueOrDefault("DownloadUrlList") as string[])?.FirstOrDefault(u => u.Length > 0);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        string file = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
        return file.Length > 0 ? file : null;
    }

    /// <summary>
    /// The apps as one entry each: versions that share an installer file are one app (every MSI version has its own
    /// product code, and Intune keeps an entry for each it pushed). The installed version, else the newest, is the
    /// current one; the app takes the installed version's name, and the rest are the earlier versions it replaced.
    /// </summary>
    internal static List<MdmAppGroup> GroupApps(IEnumerable<MdmApp> apps) =>
        apps.GroupBy(a => (a.User, Key: a.Installer?.ToLowerInvariant() ?? a.ProductCode))
            .Select(g =>
            {
                var byVersion = g.OrderByDescending(a => a.Installed).ThenByDescending(a => ParseVersion(a.Version)).ToList();
                var current = byVersion[0];
                string? name = g.FirstOrDefault(a => a.Installed)?.Name ?? current.Name;
                var earlier = byVersion.Skip(1).OrderByDescending(a => ParseVersion(a.Version)).ToList();
                return new MdmAppGroup(name, current, earlier);
            })
            .OrderBy(g => g.Current.User).ThenBy(g => g.Name ?? "\uffff", StringComparer.OrdinalIgnoreCase).ToList();

    static Version ParseVersion(string? text) => Version.TryParse(text, out var v) ? v : new Version(0, 0);

    /// <summary>An MSI app's Status as Settings words it (EnterpriseDesktopAppManagement CSP), and how it went.</summary>
    internal static (string Text, Status Look) MsiStatus(int? status) => status switch
    {
        10 => ("Initialized", Status.Info),
        20 => ("Download in progress", Status.Info),
        25 => ("Download pending retry", Status.Warn),
        30 => ("Download failed", Status.Fail),
        40 => ("Download completed", Status.Info),
        48 => ("Waiting for the user to sign in", Status.Info),
        50 => ("Install in progress", Status.Info),
        55 => ("Install pending retry", Status.Warn),
        60 => ("Install failed", Status.Fail),
        70 => ("Installed (enforcement completed)", Status.Pass),
        null => ("status not recorded", Status.Info),
        var other => ($"status {other}", Status.Info),
    };

    // What the provider set, area by area, and whether its value is the one in force
    static List<MdmSetting> ReadSettings(IProbe probe, string providerPath, string currentPath, string providerId)
    {
        var settings = new List<MdmSetting>();
        foreach (string area in (probe.RegistrySubKeys(providerPath) ?? []).Order(StringComparer.OrdinalIgnoreCase))
        {
            var values = probe.RegistryValues($@"{providerPath}\{area}");
            if (values == null) continue;
            var current = probe.RegistryValues($@"{currentPath}\{area}");
            foreach (var (name, value) in values.OrderBy(v => v.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (name.Length == 0 || PolicyBookkeeping.Any(suffix => name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))) continue;
                string? winner = current?.GetValueOrDefault(name + "_WinningProvider") as string;
                bool wins = winner == null || SameId(winner, providerId);
                settings.Add(new(area, name, FormatRegistryValue(value), wins, wins ? null : winner));
            }
        }
        return settings;
    }

    static bool SameId(string a, string b) => string.Equals(a.Trim('{', '}', ' '), b.Trim('{', '}', ' '), StringComparison.OrdinalIgnoreCase);

    /// <summary>A registry value as one short line: numbers as they are, text with its whitespace collapsed and cut at 120 characters.</summary>
    internal static string FormatRegistryValue(object? value)
    {
        string text = value switch
        {
            null => "",
            string s => Regex.Replace(s, @"\s+", " ").Trim(),
            string[] lines => string.Join("; ", lines),
            byte[] bytes => $"{bytes.Length} bytes",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? "",
        };
        return text.Length > 120 ? text[..117] + "..." : text;
    }

    /// <summary>
    /// An MDM client time such as "20261023T075203Z", as UTC; null if absent or unreadable. Despite the Z the client
    /// writes the PC's local time (seen on a real PC: a sync at 10:40 local read "…T104004Z"), so it is converted
    /// from <paramref name="zone"/>, this PC's zone when null.
    /// </summary>
    internal static DateTime? MdmTime(object? value, TimeZoneInfo? zone = null)
    {
        if (value is not string s || !DateTime.TryParseExact(s.Trim(), "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var local))
            return null;
        try { return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), zone ?? TimeZoneInfo.Local); }
        catch (ArgumentException) { return null; } // a time skipped by a daylight saving change
    }

    /// <summary>
    /// The scheduled task the MDM client runs to sync now, the one Settings &gt; Accounts &gt; Access work or school
    /// &gt; Sync starts; null when the enrollment id isn't a GUID, so nothing else can reach the command line.
    /// </summary>
    internal static string? SyncTaskPath(MdmEnrollment enrollment) =>
        Guid.TryParse(enrollment.Id, out var id) ? $@"\Microsoft\Windows\EnterpriseMgmt\{id.ToString("D").ToUpperInvariant()}\PushLaunch" : null;

    /// <summary>
    /// The PowerShell that starts <paramref name="taskPath"/> (from <see cref="SyncTaskPath"/>, so it holds only a GUID
    /// and fixed text). It prints a marker line, so the outcome reads the same in every display language.
    /// </summary>
    internal static string SyncScript(string taskPath)
    {
        int split = taskPath.LastIndexOf('\\') + 1;
        return $$"""
            $ErrorActionPreference = 'Stop'
            try { Start-ScheduledTask -TaskPath '{{taskPath[..split]}}' -TaskName '{{taskPath[split..]}}'; 'OK' }
            catch { 'ERROR|' + $_.Exception.Message }
            """;
    }

    /// <summary>Whether the sync script started the task, and if not, why.</summary>
    internal static (bool Started, string Reason) ParseSyncOutput(string output)
    {
        output = output.Trim();
        if (output.StartsWith("OK", StringComparison.Ordinal)) return (true, "");
        return (false, output.StartsWith("ERROR|", StringComparison.Ordinal) ? output[6..] : output.Length > 0 ? output : "no answer from PowerShell");
    }
}

/// <summary>An MDM enrollment: its id (the Enrollments subkey), provider, EnrollmentState (1 = enrolled) and the account that enrolled.</summary>
record MdmEnrollment(string Id, string Provider, int? State, string? Upn)
{
    public string ProviderName => Provider == "MS DM Server" ? "Microsoft Intune" : Provider;
}

/// <summary>One setting an MDM provider pushed: whether it is the value in force, or which provider's is instead.</summary>
record MdmSetting(string Area, string Name, string Value, bool ProviderWins, string? Winner);

/// <summary>One MSI app an MDM pushed: its product code, name when known, version, CSP Status and LastError, and whether it is the user's.</summary>
/// <param name="Installer">The installer's file name from its download URL; versions of one app share it.</param>
/// <param name="Installed">This version has an uninstall entry, so it is the one on the PC now.</param>
record MdmApp(string ProductCode, string? Name, string? Version, int? Status, int? LastError, bool User,
    string? Installer = null, bool Installed = false);

/// <summary>One app: its name, the version in place (installed, else newest) and the earlier versions Intune pushed.</summary>
record MdmAppGroup(string? Name, MdmApp Current, List<MdmApp> Earlier);

/// <summary>What the Intune group and the Intune policies tab show; an error is the reason a part couldn't be read.</summary>
record IntuneState(MdmEnrollment Enrollment, DateTime? LastSuccess, DateTime? LastFailure, string? SyncError,
    int? ExtensionState, string? ExtensionError, List<MdmSetting> Device, List<MdmSetting> User, string? PolicyError,
    List<MdmApp> Apps, string? AppsError);
