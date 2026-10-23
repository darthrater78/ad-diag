using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

#nullable enable
namespace AdDiag;

// The age of the Kerberos keys that should be rolled over: the Seamless SSO account's (AZUREADSSOACC), the
// Microsoft Entra Kerberos server object's (krbtgt_AzureAD, for cloud Kerberos trust) and the domain's own krbtgt.
// A key's age is its account's pwdLastSet, which any domain user can read; nothing is changed.
static partial class Diagnostics
{
    public const string SeamlessKeyCheck = "Seamless SSO Key", CloudKerberosKeyCheck = "Cloud Kerberos Key", KrbtgtKeyCheck = "krbtgt Key";
    public const string SeamlessKeyAccount = "AZUREADSSOACC$", CloudKerberosKeyAccount = "krbtgt_AzureAD", KrbtgtAccount = "krbtgt";

    // Microsoft says to roll the Seamless SSO key over at least every 30 days. For the cloud Kerberos trust key and
    // krbtgt a common practice is at least every 180 days
    static readonly TimeSpan SeamlessKeyMaxAge = TimeSpan.FromDays(30), KerberosKeyMaxAge = TimeSpan.FromDays(180);

    static readonly Regex DomainName = new(@"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$");

    /// <summary>
    /// The script that reads each account's pwdLastSet in <paramref name="domain"/>. Only the domain is put in it,
    /// and only once it is a plain DNS name; the account names are this app's own constants. Output, one per account:
    /// "KEY|&lt;account&gt;|&lt;UTC ISO 8601&gt;", "NOTFOUND|&lt;account&gt;", or one "ERROR|&lt;message&gt;".
    /// </summary>
    internal static string KeyAgeScript(string domain, IEnumerable<string> accounts)
    {
        if (!DomainName.IsMatch(domain)) throw new ArgumentException($"Not a domain name: {domain}");
        string names = string.Join(",", accounts.Select(a => $"'{a}'"));
        return $$"""
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            try {
                $root = [adsi]'LDAP://{{domain}}'
                foreach ($name in @({{names}})) {
                    $s = New-Object System.DirectoryServices.DirectorySearcher($root, "(sAMAccountName=$name)", @('pwdLastSet'))
                    $s.ClientTimeout = [TimeSpan]::FromSeconds(10)
                    $r = $s.FindOne()
                    if ($r -and $r.Properties['pwdlastset'].Count -gt 0) {
                        "KEY|$name|" + [datetime]::FromFileTimeUtc([int64]$r.Properties['pwdlastset'][0]).ToString('o')
                    } else { "NOTFOUND|$name" }
                }
            } catch {
                $e = $_.Exception
                if ($e.InnerException) { $e = $e.InnerException }
                "ERROR|" + ($e.Message -replace '\s+', ' ')
            }
            """;
    }

    /// <summary>When each account's key was last set (null when the account doesn't exist), or the query's error.</summary>
    internal static (Dictionary<string, DateTime?> LastSet, string? Error) ParseKeyAges(string output)
    {
        var lastSet = new Dictionary<string, DateTime?>(StringComparer.OrdinalIgnoreCase);
        foreach (var parts in output.Split('\n').Select(l => l.Trim().Split('|')))
        {
            if (parts[0] == "ERROR") return (lastSet, string.Join("|", parts[1..]).Trim());
            if (parts.Length == 2 && parts[0] == "NOTFOUND") lastSet[parts[1]] = null;
            else if (parts.Length == 3 && parts[0] == "KEY"
                && DateTime.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var utc))
                lastSet[parts[1]] = utc.ToUniversalTime();
        }
        return lastSet.Count > 0 ? (lastSet, null) : (lastSet, output.Trim() is { Length: > 0 } t ? t : "No output from PowerShell");
    }

    /// <summary>One check per account: its key's age against the rollover limit, or why it couldn't be read.</summary>
    internal static List<TestEntry> KeyAgeChecks(IProbe probe, string domain, DateTime nowUtc,
        IReadOnlyList<(string Check, string Account, TimeSpan MaxAge, string Rollover)> keys, System.Threading.CancellationToken ct)
    {
        if (!DomainName.IsMatch(domain))
            return keys.Select(k => new TestEntry(k.Check, Status.Skip, "Not checked: no domain to ask")).ToList();
        Dictionary<string, DateTime?> lastSet;
        string? error;
        try { (lastSet, error) = ParseKeyAges(probe.RunPowerShell(KeyAgeScript(domain, keys.Select(k => k.Account)), 20000, ct)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { (lastSet, error) = ([], ex.Message); }

        return keys.Select(k => error != null
            ? new TestEntry(k.Check, Status.Skip, $"Not checked: could not query AD: {error}")
            : KeyAgeEntry(k.Check, k.Account, lastSet.GetValueOrDefault(k.Account), lastSet.ContainsKey(k.Account), domain, nowUtc, k.MaxAge, k.Rollover))
            .ToList();
    }

    static TestEntry KeyAgeEntry(string check, string account, DateTime? set, bool answered, string domain, DateTime nowUtc,
        TimeSpan maxAge, string rollover)
    {
        if (!answered || set is not { } lastSet)
            return new(check, Status.Skip, $"Not checked: no {account} account in {domain}");
        var age = Age(lastSet, nowUtc);
        string when = $"{account} key last set {lastSet.ToLocalTime():d} ({(int)age.TotalDays}d ago)";
        return age <= maxAge
            ? new(check, Status.Pass, when)
            : new(check, Status.Warn, $"{when}; roll it over at least every {(int)maxAge.TotalDays} days ({rollover})");
    }

    static readonly (string, string, TimeSpan, string) SeamlessKey =
        (SeamlessKeyCheck, SeamlessKeyAccount, SeamlessKeyMaxAge, "Update-AzureADSSOForest");
    static readonly (string, string, TimeSpan, string) CloudKerberosKey =
        (CloudKerberosKeyCheck, CloudKerberosKeyAccount, KerberosKeyMaxAge, "Set-AzureADKerberosServer -RotateServerKey");
    static readonly (string, string, TimeSpan, string) KrbtgtKey =
        (KrbtgtKeyCheck, KrbtgtAccount, KerberosKeyMaxAge, "reset krbtgt twice, a day apart");
}
