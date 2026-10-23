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

    const string AppsRoot = @"SOFTWARE\Microsoft\EnterpriseDesktopAppManagement";
    const string DeviceContext = "S-0-0-00-0000000000-0000000000-000000000-000";

    // MSI apps as a real PC keeps them: key and ProductCode in double braces, the MDM's account id beside each
    static FakeProbe WithApps()
    {
        var probe = Enrolled();
        probe.Registry[$@"{AppsRoot}\{DeviceContext}\MSI\{{{{DDF6D6BF-887E-4EB3-A89D-2C153BAF3256}}}}"] = new()
        {
            ["Status"] = 70, ["LastError"] = 0, ["ProductVersion"] = "1.105.103.0", ["ServerAccountID"] = Id,
            ["CurrentDownloadUrl"] = "https://imeswda-afd-hotfix.manage.microsoft.com/IntuneWindowsAgent.msi?sig=secret",
        };
        probe.Registry[$@"{AppsRoot}\{DeviceContext}\MSI\{{6A7DFC50-0395-4E1E-BF84-ED1404E72051}}"] = new()
        {
            ["Status"] = 60, ["LastError"] = unchecked((int)0x80070643), ["ServerAccountID"] = Id,
        };
        probe.Registry[@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{6A7DFC50-0395-4E1E-BF84-ED1404E72051}"] =
            new() { ["DisplayName"] = "Contoso VPN Client" };
        // Another MDM server's app
        probe.Registry[$@"{AppsRoot}\{DeviceContext}\MSI\{{0C295A70-0C7C-451D-8D2D-C15DFCF7B226}}"] = new()
        {
            ["Status"] = 70, ["ServerAccountID"] = "0F000000-0000-4000-8000-0000000000AA",
        };
        probe.Registry[$@"{AppsRoot}\{Sid}\MSI\{{A99DF952-D7EE-44E9-B277-9881EAC57B0B}}"] = new() { ["Status"] = 50, ["ServerAccountID"] = Id };
        return probe;
    }

    [Fact]
    public void Apps_ListThisEnrollmentsMsiAppsForDeviceAndUser()
    {
        var probe = WithApps();
        var state = Diagnostics.ReadIntuneState(probe, Diagnostics.ReadEnrollment(probe)!);

        Assert.Null(state.AppsError);
        Assert.Equal(["6A7DFC50-0395-4E1E-BF84-ED1404E72051", "DDF6D6BF-887E-4EB3-A89D-2C153BAF3256", "A99DF952-D7EE-44E9-B277-9881EAC57B0B"],
            state.Apps.Select(a => a.ProductCode));
        var vpn = state.Apps[0];
        Assert.Equal(("Contoso VPN Client", 60, unchecked((int)0x80070643), false), (vpn.Name, vpn.Status, vpn.LastError, vpn.User));
        Assert.True(state.Apps[2].User);
    }

    [Fact]
    public void Apps_NameFallsBackToTheInstallerFileWithoutTheQuery()
    {
        var probe = WithApps();
        var ime = Diagnostics.ReadApps(probe, Id, Sid).Single(a => a.ProductCode.StartsWith("DDF6", StringComparison.Ordinal));
        Assert.Equal(("IntuneWindowsAgent.msi", "1.105.103.0"), (ime.Name, ime.Version));
    }

    [Fact]
    public void Apps_DeniedIsAReasonNotAFailure()
    {
        var probe = WithApps();
        probe.Denied.Add($@"{AppsRoot}\{DeviceContext}\MSI");
        var state = Diagnostics.ReadIntuneState(probe, Diagnostics.ReadEnrollment(probe)!);
        Assert.Empty(state.Apps);
        Assert.Contains("Administrator", state.AppsError);
        Assert.Null(state.PolicyError);
    }

    [Fact]
    public void Policies_CountTheAppsAndWarnOnAFailedInstall()
    {
        var policies = Entry(Diagnostics.TestIntune(WithApps(), Now, TimeZoneInfo.Utc), "Device Policies");
        Assert.Equal("Warn", policies.Status.ToString());
        Assert.EndsWith("; 3 MSI apps; failed: Contoso VPN Client (install failed)", policies.Detail);
    }

    // The user's PC: seven Management Extension versions, only the newest installed
    static readonly (string Code, string Version)[] ImeVersions =
    [
        ("0c295a70-0c7c-451d-8d2d-c15dfcf7b226", "1.106.151.0"), ("58976ff3-87ca-4691-bdfc-671f37f07cb6", "1.103.101.0"),
        ("5d50ad5a-2e84-4d08-a5b6-9bff0dfecd27", "1.102.103.0"), ("6a7dfc50-0395-4e1e-bf84-ed1404e72051", "1.104.102.0"),
        ("7ecaccd0-8601-4884-8860-7a4adf4ed814", "1.105.152.0"), ("a99df952-d7ee-44e9-b277-a9881eac57b0", "1.106.106.0"),
        ("ddf6d6bf-887e-4eb3-a89d-2c153baf3256", "1.105.103.0"),
    ];

    [Fact]
    public void Apps_VersionsOfOneInstallerAreOneAppNamedFromTheInstalledOne()
    {
        var probe = Enrolled();
        foreach (var (code, version) in ImeVersions)
            probe.Registry[$@"{AppsRoot}\{DeviceContext}\MSI\{{{{{code}}}}}"] = new()
            {
                ["Status"] = 70, ["ProductVersion"] = version, ["ServerAccountID"] = Id,
                ["CurrentDownloadUrl"] = "https://imeswda-afd-hotfix.manage.microsoft.com/IntuneWindowsAgent.msi",
            };
        probe.Registry[@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{0C295A70-0C7C-451D-8D2D-C15DFCF7B226}"] =
            new() { ["DisplayName"] = "Microsoft Intune Management Extension" };

        var state = Diagnostics.ReadIntuneState(probe, Diagnostics.ReadEnrollment(probe)!);
        var group = Assert.Single(Diagnostics.GroupApps(state.Apps));
        Assert.Equal(("Microsoft Intune Management Extension", "1.106.151.0", true), (group.Name, group.Current.Version, group.Current.Installed));
        Assert.Equal(["1.106.106.0", "1.105.152.0", "1.105.103.0", "1.104.102.0", "1.103.101.0", "1.102.103.0"],
            group.Earlier.Select(a => a.Version));
        Assert.EndsWith("; 1 MSI app", Entry(Diagnostics.TestIntune(probe, Now, TimeZoneInfo.Utc), "Device Policies").Detail);
    }

    [Fact]
    public void Apps_WithNothingInstalledTheNewestIsCurrent()
    {
        var groups = Diagnostics.GroupApps(
        [
            new("A", "Tool.msi", "1.0.0.0", 70, 0, false, "Tool.msi"),
            new("B", "Tool.msi", "1.2.0.0", 60, 1603, false, "Tool.msi"),
            new("C", "Other.msi", "3.0", 70, 0, true, "Other.msi"),
        ]);
        Assert.Equal(2, groups.Count);
        Assert.Equal(("B", false), (groups[0].Current.ProductCode, groups[0].Current.User));
        Assert.Equal(["A"], groups[0].Earlier.Select(a => a.ProductCode));
        Assert.True(groups[1].Current.User);
    }

    [Theory]
    [InlineData(70, "Pass")]
    [InlineData(60, "Fail")]
    [InlineData(30, "Fail")]
    [InlineData(55, "Warn")]
    [InlineData(50, "Info")]
    [InlineData(99, "Info")]
    public void Apps_StatusLooksLikeSettings(int status, string look) => Assert.Equal(look, Diagnostics.MsiStatus(status).Look.ToString());

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
