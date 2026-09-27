namespace AdDiag.Tests;

// Representative output of the Windows tools the app parses (English-language Windows).
// Real tools emit CRLF; tests run each sample with both LF and CRLF line endings.
static class Samples
{
    public static string Crlf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");

    // RsopScript output (MainForm.cs): the app's own format, so identical in every display language
    public const string Rsop = """
        SCOPE|Computer|OK|2026-07-16T09:58:41.0000000Z|HQ
        GPO|Computer|LocalGPO|0|1|1|0|1|Local Group Policy
        GPO|Computer|cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com|1|1|1|0|1|Default Domain Policy
        GPO|Computer|cn={6AC1786C-016F-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com|2|1|1|0|1|Workstation Baseline
        GPO|Computer|cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=contoso,DC=com|0|0|1|0|1|Default Domain Policy
        GPO|Computer|cn={A1111111-0000-0000-0000-000000000001},cn=policies,cn=system,DC=contoso,DC=com|0|1|1|1|1|Server Hardening
        GPO|Computer|cn={A1111111-0000-0000-0000-000000000002},cn=policies,cn=system,DC=contoso,DC=com|0|1|1|0|0|Kiosk Lockdown
        GPO|Computer|cn={A1111111-0000-0000-0000-000000000003},cn=policies,cn=system,DC=contoso,DC=com|0|0|1|0|1|Old Printers
        SCOPE|User|OK|2026-07-16T10:01:12.0000000Z|HQ
        GPO|User|cn={B2222222-0000-0000-0000-000000000001},cn=policies,cn=system,DC=contoso,DC=com|1|1|1|0|1|Laufwerke & Drucker | Zürich
        """;

    // Not elevated: no access to the computer namespace; user scope with no State key, site or links
    public const string RsopNotElevated = """
        SCOPE|Computer|DENIED
        SCOPE|User|OK||
        """;

    public const string Klist = """

        Current LogonId is 0:0x3e7a1

        Cached Tickets: (2)

        #0>	Client: alice @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        	Start Time: 7/16/2026 9:58:40 (local)
        	End Time:   7/16/2026 19:58:40 (local)
        	Renew Time: 7/23/2026 9:58:40 (local)
        	Session Key Type: AES-256-CTS-HMAC-SHA1-96
        	Cache Flags: 0x1 -> PRIMARY
        	Kdc Called: DC01.contoso.com

        #1>	Client: alice @ CONTOSO.COM
        	Server: cifs/DC01.contoso.com @ CONTOSO.COM
        	KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        	Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        	Start Time: 7/16/2026 10:00:02 (local)
        	End Time:   7/16/2026 19:58:40 (local)
        	Renew Time: 7/23/2026 9:58:40 (local)
        	Session Key Type: RSADSI RC4-HMAC(NT)
        	Cache Flags: 0
        	Kdc Called: DC01.contoso.com
        """;

    // Representative German klist: translated labels, and the flags line has no colon
    public const string KlistGerman = """

        Aktuelle Anmelde-ID ist 0:0x3e7a1

        Zwischengespeicherte Tickets: (1)

        #0>	Client: alice @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket (Verschlüsselungstyp): AES-256-CTS-HMAC-SHA1-96
        	Ticketkennzeichen 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        	Startzeit: 16.07.2026 9:58:40 (lokal)
        	Endzeit:   16.07.2026 19:58:40 (lokal)
        	Erneuerungszeit: 23.07.2026 9:58:40 (lokal)
        	Sitzungsschlüsseltyp: AES-256-CTS-HMAC-SHA1-96
        	Cacheflags: 0x1 -> PRIMARY
        	Aufgerufenes KDC: DC01.contoso.com
        """;

    // Older Windows (7 / 2008 R2) klist: no Cache Flags or Kdc Called
    public const string KlistNoCacheFlags = """
        #0>	Client: alice @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        	Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        	Start Time: 7/16/2026 9:58:40 (local)
        	End Time:   7/16/2026 19:58:40 (local)
        	Renew Time: 7/23/2026 9:58:40 (local)
        	Session Key Type: AES-256-CTS-HMAC-SHA1-96
        """;

    public const string KlistEmpty = """

        Current LogonId is 0:0x3e7a1

        Cached Tickets: (0)
        """;

    public const string NltestDsGetDc = """
                   DC: \\DC01.contoso.com
              Address: \\10.0.0.10
             Dom Guid: 2b6e4c1a-0000-4000-8000-000000000001
             Dom Name: contoso.com
          Forest Name: contoso.com
         Dc Site Name: HQ
        Our Site Name: HQ
                Flags: PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10
        The command completed successfully
        """;

    public const string NltestDsGetDcFailed = """
        Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN
        """;

    public const string NltestDsGetSite = """
        HQ
        The command completed successfully
        """;

    public const string NltestDsGetSiteFailed = """
        Getting DC Site failed: Status = 1919 0x77f ERROR_NO_SITENAME
        """;

    public const string NltestTrusts = """
        List of domain trusts:
            0: CHILD child.contoso.com (NT 5) (Forest: 1) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
            1: CONTOSO contoso.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
            2: FABRIKAM fabrikam.com (NT 5) (Direct Outbound) ( Attr: foresttrans )
        The command completed successfully
        """;

    public const string NltestTrustsSingleDomain = """
        List of domain trusts:
            0: CONTOSO contoso.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
        The command completed successfully
        """;

    public const string NltestTrustsFailed = """
        Getting domain trusts failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN
        """;

    public const string W32tmStripchart = """
        Tracking DC01.contoso.com [10.0.0.10:123].
        Collecting 1 samples.
        The current time is 7/16/2026 10:20:00 AM.
        10:20:00, +00.0206779s
        """;

    public const string W32tmStripchartNegative = """
        Tracking DC01.contoso.com [10.0.0.10:123].
        Collecting 1 samples.
        The current time is 7/16/2026 10:20:00 AM.
        10:20:00, -312.5000000s
        """;

    public const string W32tmStripchartError = """
        Tracking DC01.contoso.com [10.0.0.10:123].
        Collecting 1 samples.
        The current time is 7/16/2026 10:20:00 AM.
        10:20:00, error: 0x800705B4
        """;

    // w32tm /query /source prints only the value
    public const string W32tmSource = "DC01.contoso.com\r\n";
    public const string W32tmSourceError = "The following error occurred: The service has not been started. (0x80070426)\r\n";

    // Stripchart on a comma-decimal system
    public const string W32tmStripchartComma = """
        Tracking DC01.contoso.com [10.0.0.10:123].
        Collecting 1 samples.
        The current time is 16.07.2026 10:20:00.
        10:20:00, +00,0206779s
        """;

    public const string NltestScVerify = """
        Flags: b0 HAS_IP  HAS_TIMESERV
        Trusted DC Name \\DC01.contoso.com
        Trusted DC Connection Status Status = 0 0x0 NERR_Success
        Trust Verification Status = 0 0x0 NERR_Success
        The command completed successfully
        """;

    // A broken trust: nltest still says the command completed successfully
    public const string NltestScVerifyBroken = """
        Flags: 0
        Trusted DC Name
        Trusted DC Connection Status Status = 1311 0x51f ERROR_NO_LOGON_SERVERS
        Trust Verification Status = 1311 0x51f ERROR_NO_LOGON_SERVERS
        The command completed successfully
        """;

    public const string NltestScVerifyAccessDenied = """
        I_NetLogonControl failed: Status = 5 0x5 ERROR_ACCESS_DENIED
        """;

    // ── Translated output (German-style; labels differ, structure and codes don't) ──

    public const string NltestScVerifyGerman = """
        Flags: b0 HAS_IP  HAS_TIMESERV
        Name des vertrauenswürdigen DCs \\DC01.contoso.com
        Verbindungsstatus des vertrauenswürdigen DCs Status = 0 0x0 NERR_Success
        Status der Vertrauensüberprüfung = 0 0x0 NERR_Success
        Der Befehl wurde erfolgreich ausgeführt.
        """;

    public const string NltestScVerifyBrokenGerman = """
        Flags: 0
        Name des vertrauenswürdigen DCs
        Verbindungsstatus des vertrauenswürdigen DCs Status = 1311 0x51f ERROR_NO_LOGON_SERVERS
        Status der Vertrauensüberprüfung = 1311 0x51f ERROR_NO_LOGON_SERVERS
        Der Befehl wurde erfolgreich ausgeführt.
        """;

    public const string NltestDsGetSiteGerman = """
        Zürich-HQ
        Der Befehl wurde erfolgreich ausgeführt.
        """;

    public const string NltestDsGetDcGerman = """
                   DC: \\DC01.contoso.com
              Adresse: \\10.0.0.10
            Domänen-GUID: 2b6e4c1a-0000-4000-8000-000000000001
         Domänenname: contoso.com
        Der Befehl wurde erfolgreich ausgeführt.
        """;

    public const string NltestTrustsGerman = """
        Liste der Domänenvertrauensstellungen:
            0: CHILD child.contoso.com (NT 5) (Gesamtstruktur: 1) (Direkt ausgehend) (Direkt eingehend)
            1: CONTOSO contoso.com (NT 5) (Gesamtstruktur-Stamm) (Primärdomäne) (Systemeigen)
        Der Befehl wurde erfolgreich ausgeführt.
        """;

    public const string KlistGetSuccess = """

        Current LogonId is 0:0x3e7a1
        A ticket to krbtgt/CONTOSO.COM has been retrieved successfully.

        Cached Tickets: (1)

        #0>	Client: alice @ CONTOSO.COM
        	Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        """;

    public const string KlistGetFailed = """

        Current LogonId is 0:0x3e7a1
        Error calling API LsaCallAuthenticationPackage (GetTicket substatus): 0x6fb

        klist failed with 0xc000018b/-1073741429: The SAM database on the Windows Server does not have a computer account for this workstation trust relationship.
        """;

    // Cross-realm: a user from another forest holding a referral TGT for the target realm
    public const string KlistCrossRealm = """
        #0>	Client: bob @ FABRIKAM.COM
        	Server: krbtgt/CONTOSO.COM @ FABRIKAM.COM
        """;
}
