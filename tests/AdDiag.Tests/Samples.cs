namespace AdDiag.Tests;

// Representative output of the Windows tools the app parses (English-language Windows).
// Real tools emit CRLF; tests run each sample with both LF and CRLF line endings.
static class Samples
{
    public static string Crlf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");

    public const string GpResult = """

        Microsoft (R) Windows (R) Operating System Group Policy Result tool v2.0
        © Microsoft Corporation. All rights reserved.

        Created on 7/16/2026 at 10:15:02 AM


        RSOP data for CONTOSO\alice on PC01 : Logging Mode
        ---------------------------------------------------

        OS Configuration:            Member Workstation
        OS Version:                  10.0.22631
        Site Name:                   HQ
        Roaming Profile:             N/A
        Local Profile:               C:\Users\alice
        Connected over a slow link?: No


        COMPUTER SETTINGS
        ------------------
            CN=PC01,OU=Workstations,DC=contoso,DC=com
            Last time Group Policy was applied: 7/16/2026 at 9:58:41 AM
            Group Policy was applied from:      DC01.contoso.com
            Group Policy slow link threshold:   500 kbps
            Domain Name:                        CONTOSO
            Domain Type:                        Windows 2008 or later

            Applied Group Policy Objects
            -----------------------------
                Workstation Baseline
                Default Domain Policy

            The following GPOs were not applied because they were filtered out
            -------------------------------------------------------------------
                Local Group Policy
                    Filtering:  Not Applied (Empty)

                Server Hardening
                    Filtering:  Denied (Security)

            The computer is a part of the following security groups
            -------------------------------------------------------
                BUILTIN\Administrators
                Everyone


        USER SETTINGS
        --------------
            CN=Alice,OU=Users,DC=contoso,DC=com
            Last time Group Policy was applied: 7/16/2026 at 10:01:12 AM
            Group Policy was applied from:      DC01.contoso.com
            Group Policy slow link threshold:   500 kbps
            Domain Name:                        CONTOSO
            Domain Type:                        Windows 2008 or later

            Applied Group Policy Objects
            -----------------------------
                Drive Mappings

            The following GPOs were not applied because they were filtered out
            -------------------------------------------------------------------
                Local Group Policy
                    Filtering:  Not Applied (Empty)

            The user is a part of the following security groups
            ---------------------------------------------------
                Domain Users
                Everyone
        """;

    // Non-elevated gpresult: user scope only, with nothing applied
    public const string GpResultUserOnly = """
        RSOP data for CONTOSO\alice on PC01 : Logging Mode
        ---------------------------------------------------

        Site Name:                   HQ

        USER SETTINGS
        --------------
            Last time Group Policy was applied: 7/16/2026 at 10:01:12 AM

            Applied Group Policy Objects
            -----------------------------
                N/A

            The user is a part of the following security groups
            ---------------------------------------------------
                Domain Users
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

    public const string W32tmStatus = """
        Leap Indicator: 0(no warning)
        Stratum: 4 (secondary reference - syncd by (S)NTP)
        Precision: -23 (119.209ns per tick)
        Root Delay: 0.0312500s
        Root Dispersion: 7.8134000s
        ReferenceId: 0x0A00000A (source IP:  10.0.0.10)
        Last Successful Sync Time: 7/16/2026 9:58:40 AM
        Source: DC01.contoso.com
        Poll Interval: 10 (1024s)
        """;
}
