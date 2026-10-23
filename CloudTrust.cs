using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

#nullable enable
namespace AdDiag;

// Cloud Kerberos trust on an Entra joined PC: Microsoft Entra ID issues a partial ticket as the Microsoft Entra Kerberos
// server object (AzureADKerberos, which AD treats like a read-only DC), and a domain controller trades it for a full
// one only for accounts that object's password replication policy allows. Members of a denied group (by default
// Domain Admins, Enterprise Admins, Schema Admins, Administrators and the other privileged groups) get no
// on-premises ticket. This reads that policy and the signed-in user's groups from AD and compares them.
static partial class Diagnostics
{
    public const string CloudTrustGroupsCheck = "Cloud Trust Groups";

    static readonly Regex UpnPattern = new(@"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*$");

    /// <summary>
    /// The script that reads the user's groups (tokenGroups, which a user may read on their own account) and the
    /// AzureADKerberos object's allowed and denied groups. Only the domain and the UPN are put in it, and only once
    /// they match strict patterns (no quotes, no LDAP filter characters). Output: "USER|&lt;sid&gt;", one "GROUP|&lt;sid&gt;"
    /// per group, then "DENY|&lt;sid&gt;|&lt;name&gt;" and "ALLOW|&lt;sid&gt;|&lt;name&gt;" per policy group; or "NOUSER",
    /// "NOSERVER" or "ERROR|&lt;message&gt;".
    /// </summary>
    internal static string CloudTrustScript(string domain, string upn)
    {
        if (!DomainName.IsMatch(domain)) throw new ArgumentException($"Not a domain name: {domain}");
        if (!UpnPattern.IsMatch(upn)) throw new ArgumentException($"Not a user principal name: {upn}");
        return $$"""
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            function Sid($bytes) { (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$bytes, 0)).Value }
            function Find($filter, $props) {
                $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]'LDAP://{{domain}}', $filter, $props)
                $s.ClientTimeout = [TimeSpan]::FromSeconds(10)
                $s.FindOne()
            }
            try {
                $u = Find '(&(objectCategory=person)(userPrincipalName={{upn}}))' @('distinguishedName')
                if (-not $u) { 'NOUSER'; return }
                $user = $u.GetDirectoryEntry()
                $user.RefreshCache(@('tokenGroups', 'objectSid'))
                'USER|' + (Sid $user.Properties['objectSid'][0])
                foreach ($g in $user.Properties['tokenGroups']) { 'GROUP|' + (Sid $g) }
                $k = Find '(&(objectClass=computer)(sAMAccountName=AzureADKerberos$))' @('msDS-NeverRevealGroup', 'msDS-RevealOnDemandGroup')
                if (-not $k) { 'NOSERVER'; return }
                foreach ($pair in @(@('DENY', 'msds-neverrevealgroup'), @('ALLOW', 'msds-revealondemandgroup'))) {
                    foreach ($dn in $k.Properties[$pair[1]]) {
                        $e = [adsi]("LDAP://{{domain}}/" + $dn)
                        $pair[0] + '|' + (Sid $e.Properties['objectSid'][0]) + '|' + $e.Properties['name'][0]
                    }
                }
            } catch {
                $e = $_.Exception
                if ($e.InnerException) { $e = $e.InnerException }
                'ERROR|' + ($e.Message -replace '\s+', ' ')
            }
            """;
    }

    /// <summary>What the script found, or why it couldn't (Problem: NOUSER, NOSERVER or an error message).</summary>
    internal record CloudTrustPolicy(HashSet<string> UserSids, List<(string Sid, string Name)> Denied,
        List<(string Sid, string Name)> Allowed, string? Problem);

    internal static CloudTrustPolicy ParseCloudTrust(string output)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        List<(string, string)> denied = [], allowed = [];
        foreach (var parts in output.Split('\n').Select(l => l.Trim().Split('|')).Where(p => p[0].Length > 0))
        {
            switch (parts[0])
            {
                case "NOUSER" or "NOSERVER": return new(sids, denied, allowed, parts[0]);
                case "ERROR": return new(sids, denied, allowed, string.Join("|", parts[1..]).Trim());
                case "USER" or "GROUP" when parts.Length == 2: sids.Add(parts[1]); break;
                case "DENY" when parts.Length >= 3: denied.Add((parts[1], string.Join("|", parts[2..]))); break;
                case "ALLOW" when parts.Length >= 3: allowed.Add((parts[1], string.Join("|", parts[2..]))); break;
            }
        }
        return new(sids, denied, allowed, sids.Count == 0 ? "No output from PowerShell" : null);
    }

    static TestEntry CloudTrustGroupsEntry(DiagConfig cfg, IProbe probe)
    {
        string? upn = null;
        try { upn = probe.CurrentUserUpn(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { } // unknown: reported below
        if (!DomainName.IsMatch(cfg.Domain))
            return new(CloudTrustGroupsCheck, Status.Skip, "Not checked: this user has no on-premises domain to ask (no Kerberos realm)");
        if (upn == null || !UpnPattern.IsMatch(upn))
            return new(CloudTrustGroupsCheck, Status.Skip, "Not checked: the signed-in user's UPN isn't known");

        CloudTrustPolicy policy;
        try { policy = ParseCloudTrust(probe.RunPowerShell(CloudTrustScript(cfg.Domain, upn), 25000, cfg.Cancel)); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(CloudTrustGroupsCheck, Status.Skip, $"Not checked: could not query AD: {ex.Message}");
        }
        return CloudTrustGroupsVerdict(policy, upn, cfg.Domain);
    }

    internal static TestEntry CloudTrustGroupsVerdict(CloudTrustPolicy policy, string upn, string domain)
    {
        switch (policy.Problem)
        {
            case "NOUSER":
                return new(CloudTrustGroupsCheck, Status.Skip, $"Not checked: no account with UPN {upn} in {domain}");
            case "NOSERVER":
                return new(CloudTrustGroupsCheck, Status.Info, $"No Microsoft Entra Kerberos server object in {domain}; cloud Kerberos trust isn't set up there");
            case { } error:
                return new(CloudTrustGroupsCheck, Status.Skip, $"Not checked: could not query AD: {error}");
        }

        var blocking = policy.Denied.Where(d => policy.UserSids.Contains(d.Sid)).Select(d => d.Name).Distinct().ToList();
        if (blocking.Count > 0)
            return new(CloudTrustGroupsCheck, Status.Warn,
                $"Member of {string.Join(", ", blocking)}, which the Microsoft Entra Kerberos server object's password replication policy denies; "
                + "cloud Kerberos trust gives this account no on-premises tickets, so use a separate non-privileged account");
        if (policy.Allowed.Count > 0 && !policy.Allowed.Any(a => policy.UserSids.Contains(a.Sid)))
            return new(CloudTrustGroupsCheck, Status.Warn,
                $"Not in any group the Microsoft Entra Kerberos server object allows ({string.Join(", ", policy.Allowed.Select(a => a.Name).Take(3))}); "
                + "cloud Kerberos trust gives this account no on-premises tickets");
        return new(CloudTrustGroupsCheck, Status.Pass, "No group membership blocks cloud Kerberos trust for this account");
    }
}
