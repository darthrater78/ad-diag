using Xunit;
using static AdDiag.Tests.DiagnosticsTests;

namespace AdDiag.Tests;

// Intune: what the group reports from the MDM client's registry keys, and what it leaves out when they don't apply
public class IntuneTests
{
    static readonly DateTime Now = new(2026, 10, 23, 9, 0, 0, DateTimeKind.Utc);
    const string Id = "5A1B2C3D-0000-4000-8000-000000000042";
    const string Sid = "S-1-12-1-1000";

    // An Intune enrollment that synced at 08:32 UTC, with two device settings and one user setting
    static FakeProbe Enrolled(string lastSuccess = "20261023T083203Z", string? lastFailure = null, int? extension = 4)
    {
        var probe = new FakeProbe { Sid = Sid };
        probe.Registry[$@"SOFTWARE\Microsoft\Enrollments\{Id}"] = new()
        {
            ["ProviderID"] = "MS DM Server", ["EnrollmentState"] = 1, ["UPN"] = "jdoe@contoso.com",
        };
        // Windows Hello and provisioning keep entries here too, without a provider
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\FF000000-0000-4000-8000-000000000001"] = new() { ["EnrollmentType"] = 0 };
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\Context"] = new();

        var conn = new Dictionary<string, object> { ["ServerLastSuccessTime"] = lastSuccess };
        if (lastFailure != null) conn["ServerLastFailureTime"] = lastFailure;
        probe.Registry[$@"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\{Id}\Protected\ConnInfo"] = conn;

        string root = $@"SOFTWARE\Microsoft\PolicyManager\providers\{Id}\default";
        probe.Registry[$@"{root}\Device\Defender"] = new()
        {
            ["AllowRealtimeMonitoring"] = 1, ["AllowRealtimeMonitoring_ProviderSet"] = 1, ["CloudBlockLevel"] = 2,
        };
        probe.Registry[$@"{root}\Device\Update"] = new() { ["ActiveHoursStart"] = 8 };
        probe.Registry[@"SOFTWARE\Microsoft\PolicyManager\current\device\Defender"] = new()
        {
            ["AllowRealtimeMonitoring"] = 1, ["AllowRealtimeMonitoring_WinningProvider"] = Id,
            ["CloudBlockLevel"] = 4, ["CloudBlockLevel_WinningProvider"] = "{0F000000-0000-4000-8000-0000000000AA}",
        };
        probe.Registry[$@"{root}\{Sid}\Edge"] = new() { ["HomepageLocation"] = "https://intranet.contoso.com" };
        if (extension is { } state) probe.Services["IntuneManagementExtension"] = state;
        return probe;
    }

    static TestEntry Entry(TestGroup group, string name) => Assert.Single(group.Tests, t => t.Name == name);

    [Fact]
    public void NotEnrolled_ShowsOneNoteAndNothingElse()
    {
        var group = Diagnostics.TestIntune(new FakeProbe(), Now, TimeZoneInfo.Utc);

        var entry = Assert.Single(group.Tests);
        Assert.Equal(("MDM Enrollment", Status.Info), (entry.Name, entry.Status));
        Assert.StartsWith("Not enrolled", entry.Detail);
    }

    [Fact]
    public void BuiltInAuthoritiesOnly_IsNotEnrolled()
    {
        // As on a real hybrid PC outside Intune: Windows' own entries, none with an MDM sync account
        var probe = new FakeProbe();
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\8345CBE6-CEFC-462A-8219-78F3FC0377C1"] = new() { ["ProviderID"] = "Deploy Authority", ["EnrollmentState"] = 1, ["EnrollmentType"] = 30 };
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\C429BE2D-071B-4E13-B616-4141C334ECDF"] = new() { ["ProviderID"] = "Cloud Authority", ["EnrollmentState"] = 1, ["EnrollmentType"] = 31 };
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\E17005D5-A50E-4E57-BE94-1D4FA69C6F93"] = new() { ["ProviderID"] = "Local Authority", ["EnrollmentState"] = 1, ["EnrollmentType"] = 28 };
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\28293FE1-9327-4C3F-BEF8-29849C6E8036"] = new() { ["ProviderID"] = "WMI_Bridge_SCCM_Server", ["EnrollmentState"] = 1, ["EnrollmentType"] = 12 };

        var entry = Assert.Single(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc).Tests);

        Assert.Equal(Status.Info, entry.Status);
        Assert.StartsWith("Not enrolled", entry.Detail);
    }

    [Fact]
    public void IntuneAmongBuiltInAuthorities_IsChosen()
    {
        var probe = Enrolled();
        probe.Registry[@"SOFTWARE\Microsoft\Enrollments\8345CBE6-CEFC-462A-8219-78F3FC0377C1"] = new() { ["ProviderID"] = "Deploy Authority", ["EnrollmentState"] = 1 };

        Assert.StartsWith("Enrolled in Microsoft Intune", Entry(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc), "MDM Enrollment").Detail);
    }

    [Fact]
    public void Enrolled_AllWell_Passes()
    {
        var group = Diagnostics.TestIntune(Enrolled(), Now, TimeZoneInfo.Utc);

        Assert.Equal(["MDM Enrollment", "Last Sync", "Management Extension", "Device Policies"], group.Tests.Select(t => t.Name));
        Assert.Equal("Enrolled in Microsoft Intune as jdoe@contoso.com", Entry(group, "MDM Enrollment").Detail);
        Assert.Equal(Status.Pass, Entry(group, "Last Sync").Status);
        Assert.Contains("27m ago", Entry(group, "Last Sync").Detail);
        Assert.Equal(Status.Pass, Entry(group, "Management Extension").Status);
        var policies = Entry(group, "Device Policies");
        Assert.Equal(Status.Pass, policies.Status);
        Assert.Equal("2 settings from Microsoft Intune in 2 areas (Defender, Update); 1 set by another provider instead", policies.Detail);
    }

    [Fact]
    public void SyncOlderThanAWeek_Warns()
    {
        var entry = Entry(Diagnostics.TestIntune(Enrolled(lastSuccess: "20261014T080000Z"), Now, TimeZoneInfo.Utc), "Last Sync");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("over a week", entry.Detail);
    }

    [Fact]
    public void FailureAfterLastSuccess_IsInfo()
    {
        // One failed attempt after a recent success is routine (the next scheduled sync retries it)
        var entry = Entry(Diagnostics.TestIntune(Enrolled(lastFailure: "20261023T084500Z"), Now, TimeZoneInfo.Utc), "Last Sync");

        Assert.Equal(Status.Info, entry.Status);
        Assert.StartsWith("Last attempt failed", entry.Detail);
    }

    [Theory]
    [InlineData(null, "Info", "Not installed")]
    [InlineData(1, "Warn", "installed but stopped")]
    public void ManagementExtension_ByServiceState(int? state, string status, string detail)
    {
        var entry = Entry(Diagnostics.TestIntune(Enrolled(extension: state), Now, TimeZoneInfo.Utc), "Management Extension");

        Assert.Equal(Enum.Parse<Status>(status), entry.Status);
        Assert.Contains(detail, entry.Detail);
    }

    [Fact]
    public void SyncTimesDenied_IsNotCheckedNotFailed()
    {
        var probe = Enrolled();
        probe.Denied.Add($@"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\{Id}\Protected\ConnInfo");

        var entry = Entry(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc), "Last Sync");

        Assert.Equal(Status.Skip, entry.Status);
        Assert.Equal("Not checked: needs Run as Administrator to read the sync times", entry.Detail);
        Assert.True(entry.NeedsAdmin);
    }

    [Fact]
    public void SyncTimes_AreThePcsLocalTime()
    {
        // The MDM client writes local time with a Z: 10:40 on a PC at UTC-4 is 14:40 UTC
        var zone = TimeZoneInfo.CreateCustomTimeZone("UTC-4", TimeSpan.FromHours(-4), "UTC-4", "UTC-4");
        Assert.Equal(new DateTime(2026, 10, 23, 14, 40, 4, DateTimeKind.Utc), Diagnostics.MdmTime("20261023T104004Z", zone));
        Assert.Null(Diagnostics.MdmTime("not a time", zone));

        var entry = Entry(Diagnostics.TestIntune(Enrolled(lastSuccess: "20261023T050000Z"), Now, zone), "Last Sync");
        Assert.Contains("(0m ago)", entry.Detail);
    }

    [Fact]
    public void PolicySettingsDenied_NeedsAdmin()
    {
        var probe = Enrolled();
        probe.Denied.Add($@"SOFTWARE\Microsoft\PolicyManager\providers\{Id}\default\Device");

        var entry = Entry(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc), "Device Policies");

        Assert.Equal(Status.Skip, entry.Status);
        Assert.True(entry.NeedsAdmin);
    }

    [Fact]
    public void EnrollmentDenied_IsOneSkippedRow()
    {
        var probe = Enrolled();
        probe.Denied.Add(@"SOFTWARE\Microsoft\Enrollments");

        var entry = Assert.Single(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc).Tests);

        Assert.Equal(Status.Skip, entry.Status);
        Assert.True(entry.NeedsAdmin);
    }

    [Fact]
    public void IncompleteEnrollment_Warns()
    {
        var probe = Enrolled();
        probe.Registry[$@"SOFTWARE\Microsoft\Enrollments\{Id}"]["EnrollmentState"] = 6;

        var entry = Entry(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc), "MDM Enrollment");

        Assert.Equal(Status.Warn, entry.Status);
        Assert.Contains("EnrollmentState 6", entry.Detail);
    }

    [Fact]
    public void State_ListsDeviceAndUserSettingsWithTheirWinner()
    {
        var probe = Enrolled();
        var state = Diagnostics.ReadIntuneState(probe, Diagnostics.ReadEnrollment(probe)!);

        Assert.Equal(["Defender/AllowRealtimeMonitoring", "Defender/CloudBlockLevel", "Update/ActiveHoursStart"],
            state.Device.Select(s => $"{s.Area}/{s.Name}"));
        var lost = Assert.Single(state.Device, s => !s.ProviderWins);
        Assert.Equal("{0F000000-0000-4000-8000-0000000000AA}", lost.Winner);
        Assert.Equal(new MdmSetting("Edge", "HomepageLocation", "https://intranet.contoso.com", true, null), Assert.Single(state.User));
    }

    [Theory]
    [InlineData("  <enabled/>\n  <data id=\"x\" value=\"1\"/>  ", "<enabled/> <data id=\"x\" value=\"1\"/>")]
    [InlineData(42, "42")]
    public void RegistryValues_AreOneLine(object value, string expected) =>
        Assert.Equal(expected, Diagnostics.FormatRegistryValue(value));

    [Fact]
    public void LongValues_AreCut() =>
        Assert.Equal(120, Diagnostics.FormatRegistryValue(new string('x', 500)).Length);

    [Fact]
    public void SyncTask_IsTheEnrollmentsPushLaunch()
    {
        Assert.Equal($@"\Microsoft\Windows\EnterpriseMgmt\{Id}\PushLaunch",
            Diagnostics.SyncTaskPath(new MdmEnrollment(Id.ToLowerInvariant(), "MS DM Server", 1, null)));
        Assert.Null(Diagnostics.SyncTaskPath(new MdmEnrollment("x\" & calc", "MS DM Server", 1, null)));
    }

    [Theory]
    [InlineData("YES", "YES", "Hybrid")]
    [InlineData("YES", "NO", "Entra")]
    [InlineData("NO", "YES", "Domain")]
    [InlineData("NO", "NO", "Domain")]
    public void Profile_FollowsTheJoin(string entra, string domain, string profile) =>
        Assert.Equal(Enum.Parse<JoinProfile>(profile), Diagnostics.DetectProfile(Parsers.ParseDsreg($"AzureAdJoined : {entra}\nDomainJoined : {domain}\n")));

    [Fact]
    public void SyncScript_StartsOnlyTheEnrollmentsTask()
    {
        string script = Diagnostics.SyncScript(Diagnostics.SyncTaskPath(new MdmEnrollment(Id, "MS DM Server", 1, null))!);

        Assert.Contains($@"Start-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\{Id}\' -TaskName 'PushLaunch'", script);
    }

    [Theory]
    [InlineData("OK\r\n", true, "")]
    [InlineData("ERROR|Access is denied.", false, "Access is denied.")]
    [InlineData("", false, "no answer from PowerShell")]
    public void SyncOutput_IsReadByItsMarker(string output, bool started, string reason) =>
        Assert.Equal((started, reason), Diagnostics.ParseSyncOutput(output));
}
