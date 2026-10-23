using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

#nullable enable
namespace AdDiag;

// How this user's sign-in credentials are held: Windows Hello for Business and its trust model, the sign-in methods
// enrolled, the TPM that protects the keys, the encryption of cached Kerberos tickets, and Windows credentials saved
// in Credential Manager, which override single sign-on. All read-only; Credential Manager gives names, never passwords.
static partial class Diagnostics
{
    public const string CredentialsGroup = "Credentials & Windows Hello";
    public const string HelloCheck = "Windows Hello", HelloTrustCheck = "Hello Trust", SignInMethodsCheck = "Sign-in Methods",
        TpmCheck = "TPM", TicketEncryptionCheck = "Ticket Encryption", SavedCredentialsCheck = "Saved Credentials";

    // Where Group Policy and Intune (the PassportForWork CSP, per tenant) set Hello's trust for on-premises sign-in
    const string HelloPolicyKey = @"SOFTWARE\Policies\Microsoft\PassportForWork";
    const string HelloIntuneKey = @"SOFTWARE\Microsoft\Policies\PassportForWork";

    // WINBIO_TYPE bits in a user's EnrolledFactors
    const int BioFace = 0x02, BioFingerprint = 0x08, BioIris = 0x10;

    public static TestGroup TestCredentials(DiagConfig cfg, IProbe probe)
    {
        Dictionary<string, string>? ds = null;
        string? dsError = null;
        try { ds = Parsers.ParseDsreg(probe.RunTool("dsregcmd", "/status", 15000, cfg.Cancel)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { dsError = ex.Message; }

        var hello = HelloStatusCheck(ds, dsError);
        bool helloSet = hello.Status == Status.Pass;
        var kind = ds == null ? null : JoinCheck(ds).Kind;
        var tests = new List<TestEntry> { hello };
        if (helloSet)
        {
            tests.Add(HelloTrustEntry(probe, kind));
            tests.Add(SignInMethodsEntry(probe));
        }
        tests.Add(TpmEntry(probe, ds, kind));
        tests.Add(TicketEncryptionEntry(cfg, probe));
        tests.Add(SavedCredentialsEntry(cfg, probe));
        return new(CredentialsGroup, tests);
    }

    static TestEntry HelloStatusCheck(Dictionary<string, string>? ds, string? dsError)
    {
        if (ds == null)
            return new(HelloCheck, Status.Skip, $"Not checked: dsregcmd failed: {dsError}");
        return Parsers.DsregFlag(ds, "NgcSet") switch
        {
            true => new(HelloCheck, Status.Pass, "Set up for this user (NgcSet: YES)"),
            false => new(HelloCheck, Status.Info, "Not set up for this user (NgcSet: NO); sign-in uses a password or a smart card"),
            null => new(HelloCheck, Status.Skip, "Not checked: dsregcmd reported no Windows Hello state"),
        };
    }

    /// <summary>Hello's trust for on-premises sign-in, from Group Policy or, failing that, Intune; null when neither sets one.</summary>
    internal static (string Model, string Source)? ReadHelloTrust(IProbe probe)
    {
        if (TrustFrom(probe.RegistryValues(HelloPolicyKey)) is { } fromGpo)
            return (fromGpo, "Group Policy");
        foreach (string tenant in probe.RegistrySubKeys(HelloIntuneKey) ?? [])
            if (TrustFrom(probe.RegistryValues($@"{HelloIntuneKey}\{tenant}\Device\Policies")) is { } fromIntune)
                return (fromIntune, "Intune");
        return null;
    }

    static string? TrustFrom(Dictionary<string, object>? values) =>
        values == null ? null
        : IsOn(values.GetValueOrDefault("UseCloudTrustForOnPremAuth")) ? "Cloud Kerberos trust"
        : IsOn(values.GetValueOrDefault("UseCertificateForOnPremAuth")) ? "Certificate trust"
        : null;

    // Policy values arrive as a DWORD from Group Policy and as text from some CSPs
    static bool IsOn(object? value) => value switch
    {
        int i => i != 0,
        string s => s.Trim() is "1" or "true" or "True",
        _ => false,
    };

    static TestEntry HelloTrustEntry(IProbe probe, JoinKind? kind)
    {
        try
        {
            if (ReadHelloTrust(probe) is { } trust)
                return new(HelloTrustCheck, Status.Pass, $"{trust.Model}, set by {trust.Source}");
            // No on-premises trust set: key trust on a PC in a domain; on an Entra joined PC Hello reaches cloud apps only
            return kind == JoinKind.EntraOnly
                ? new(HelloTrustCheck, Status.Info, "No on-premises trust set; Hello signs in to cloud apps, and AD resources need cloud Kerberos trust")
                : new(HelloTrustCheck, Status.Pass, "Key trust (no cloud Kerberos or certificate trust set)");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new(HelloTrustCheck, Status.Skip, "Not checked: needs Run as Administrator to read the Hello policy") { NeedsAdmin = true };
        }
    }

    static TestEntry SignInMethodsEntry(IProbe probe)
    {
        var methods = new List<string> { "PIN" };
        try
        {
            if (probe.CurrentUserSid() is { } sid
                && probe.RegistryValues($@"SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\{sid}")?.GetValueOrDefault("EnrolledFactors") is int factors)
            {
                if ((factors & BioFingerprint) != 0) methods.Add("fingerprint");
                if ((factors & BioFace) != 0) methods.Add("face");
                if ((factors & BioIris) != 0) methods.Add("iris");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new(SignInMethodsCheck, Status.Skip, "Not checked: needs Run as Administrator to read the biometric enrollment") { NeedsAdmin = true };
        }
        return new(SignInMethodsCheck, Status.Pass, string.Join(", ", methods));
    }

    // Hello keys and the device key belong in the TPM; a PC joined to Entra ID without one keeps them in software
    static TestEntry TpmEntry(IProbe probe, Dictionary<string, string>? ds, JoinKind? kind)
    {
        int? version;
        try { version = probe.TpmVersion(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(TpmCheck, Status.Skip, $"Not checked: the TPM service didn't answer: {ex.Message}");
        }

        bool entra = kind is JoinKind.Hybrid or JoinKind.EntraOnly;
        bool? protectedKey = entra && ds != null ? Parsers.DsregFlag(ds, "TpmProtected") : null;
        string key = protectedKey switch
        {
            true => "; the device key is protected by it (TpmProtected: YES)",
            false => "; the device key is not in it (TpmProtected: NO)",
            null => "",
        };
        return version switch
        {
            null => new(TpmCheck, entra ? Status.Warn : Status.Info,
                "No TPM found" + (entra ? "; Windows Hello and the device key are kept in software" : "")),
            1 => new(TpmCheck, Status.Warn, "TPM 1.2" + key + "; Windows Hello for Business needs TPM 2.0 for hardware-backed keys"),
            _ => new(TpmCheck, protectedKey == false ? Status.Warn : Status.Pass, $"TPM {version}.0" + key),
        };
    }

    // RC4 tickets break against domain controllers hardened to AES only, and Microsoft is retiring RC4
    static TestEntry TicketEncryptionEntry(DiagConfig cfg, IProbe probe)
    {
        List<KlistTicket> tickets;
        try { tickets = Parsers.ParseKlist(probe.RunTool("klist", "", 5000, cfg.Cancel)).Tickets; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(TicketEncryptionCheck, Status.Skip, $"Not checked: klist failed: {ex.Message}");
        }
        if (tickets.Count == 0)
            return new(TicketEncryptionCheck, Status.Info, "No Kerberos tickets cached yet");

        var rc4 = tickets.Where(t => UsesRc4(t.Fields)).Select(t => t.Server.Split('@')[0].Trim()).Distinct().ToList();
        return rc4.Count == 0
            ? new(TicketEncryptionCheck, Status.Pass, tickets.Count == 1 ? "The cached ticket uses AES" : $"All {tickets.Count} cached tickets use AES")
            : new(TicketEncryptionCheck, Status.Warn, $"RC4 on {string.Join(", ", rc4.Take(3))}{(rc4.Count > 3 ? $" and {rc4.Count - 3} more" : "")}; set the accounts to AES (msDS-SupportedEncryptionTypes)");
    }

    static bool UsesRc4(Dictionary<string, string> fields) =>
        new[] { "KerbTicket Encryption Type", "Session Key Type" }
            .Any(k => fields.TryGetValue(k, out var v) && v.Contains("RC4", StringComparison.OrdinalIgnoreCase));

    static readonly Regex WindowsCredentialTarget = new(@"Domain:target=(\S+)", RegexOptions.IgnoreCase);

    /// <summary>
    /// The servers that Windows credentials ("Domain:target=…" in <c>cmdkey /list</c>) are saved for. The labels are
    /// translated; the target text isn't. Generic and Microsoft account entries aren't Windows sign-in credentials.
    /// </summary>
    internal static List<string> ParseSavedTargets(string cmdkeyOutput) =>
        WindowsCredentialTarget.Matches(cmdkeyOutput).Select(m => m.Groups[1].Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    // A saved password is used instead of the signed-in user's own sign-in, and locks the account out once it is stale
    static TestEntry SavedCredentialsEntry(DiagConfig cfg, IProbe probe)
    {
        List<string> targets;
        try { targets = ParseSavedTargets(probe.RunTool("cmdkey", "/list", 15000, cfg.Cancel)); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(SavedCredentialsCheck, Status.Skip, $"Not checked: cmdkey failed: {ex.Message}");
        }
        if (targets.Count == 0)
            return new(SavedCredentialsCheck, Status.Pass, "No saved Windows credentials for servers");
        string list = string.Join(", ", targets.Take(3)) + (targets.Count > 3 ? $" and {targets.Count - 3} more" : "");
        return new(SavedCredentialsCheck, Status.Warn,
            $"{targets.Count} saved Windows credential{(targets.Count == 1 ? "" : "s")} ({list}); a saved password replaces single sign-on there and locks the account out once it goes stale");
    }
}
