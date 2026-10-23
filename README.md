# AD Diagnostics

Standalone Windows diagnostic tool that checks the health of a domain-joined machine's relationship with Active Directory. Single-exe, no install required.

[GitHub](https://github.com/darthrater78/ad-diag) · [v1.3.0 release notes](https://github.com/darthrater78/ad-diag/releases/tag/v1.3.0)

![Results tab showing a completed diagnostic run](docs/screenshots/results.png)

The header button switches to **Dark mode**, and back to the light theme, **Flashbang**:

![The same Results tab in Dark mode](docs/screenshots/results-dark.png)

## Download

Grab `ad-diag-vX.Y.Z-win-x64.exe` from the [latest release](https://github.com/darthrater78/ad-diag/releases/latest). No installation — just run.

### Verifying a download

Each release includes a `.sha256` checksum file and a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations) proving the exe was built by this repository's release workflow from the tagged source.

```powershell
# Checksum — compare against the .sha256 file from the release
Get-FileHash -Algorithm SHA256 .\ad-diag-vX.Y.Z-win-x64.exe

# Provenance (requires the GitHub CLI)
gh attestation verify .\ad-diag-vX.Y.Z-win-x64.exe --repo darthrater78/ad-diag
```

## Windows SmartScreen

On first launch, Windows SmartScreen may display a warning ("Windows protected your PC"). This is normal for unsigned executables from the internet. The app is not code-signed — it is a self-contained .NET 10 single-file executable built from the source in this repository. Click **More info** then **Run anyway** to proceed.

## Usage

1. Launch `ad-diag.exe`
2. The app reads how the PC is joined (`dsregcmd /status`) and sets the **Profile**: **Domain joined**, **Microsoft Entra hybrid joined** or **Microsoft Entra joined**, marked "(detected)". Each profile shows, runs and logs only what applies to it; pick another profile to check something else (for the session only, nothing is saved). An Entra joined PC has no domain, so its profile hides the Domain and DC fields, the Group Policy tab and the groups that need a domain (see [Profiles](#profiles)).

   ![Results on an Entra joined PC: only Dynamic DNS Registration, Entra Seamless Single Sign-On and Intune](docs/screenshots/results-entra.png)

   On the other profiles the app auto-detects the current domain (from `USERDNSDOMAIN`, `dsregcmd /status`, or the machine's DNS domain suffix) and pre-fills the **Domain** field. Enter target details:
   - **Domain** — e.g. `contoso.com`
   - **DC Hostname** — optional, defaults to domain for DC discovery. **+ domain suffix** is on by default, auto-appending the domain to short names. Uncheck to use the value as-is.
3. Before a run, **Results** lists every group the profile runs, each with its own **Run** button. Open a group to see the checks it will make; when the app isn't running as Administrator, the groups with checks that need it say **Needs admin**:

   ![Results before a run: every group of the profile, not run yet, one opened to its checks](docs/screenshots/before-run.png)

   Click **Run Diagnostics** — results stream in as each test group completes. To run one group on its own, pick it from the arrow next to the button, or click **Run again** at the right of its heading in Results (**Run** on a group that hasn't run; with the keyboard, move to a heading and press Down to reach it). For the same domain and DC as the run on show, its results replace that group there, and the group opens to show them (or stays open) and its heading shows when it ran ("run at 14:32:05"); otherwise it starts a new run where the other groups show **Not run** until you run them. One run goes at a time

   ![The Run button's menu over a run started from one group, the others not run yet](docs/screenshots/run-menu.png)

4. Review results. Every group starts collapsed to its heading, which shows its result (**PASSED**, **WARNING** or **FAILED**, the worst of its checks) and its counts. Click a heading (or use Up, Down and Enter or Space) to open or close it, **Expand all** / **Collapse all** for every group, or tick **Expand all groups after a run** to open them all by default (not saved). Switch to the **Guide** tab for explanations and fix suggestions (each group's section starts folded; click its title to open it), the **Group Policy** tab for a full Computer/User scope breakdown and an in-app **gpupdate**, the **Kerberos Tickets** tab for your full ticket cache and Primary Refresh Token, the **DNS registration** tab to register this computer in DNS and trace the result, the **Intune policies** tab for every setting Intune pushed and an in-app **Sync now**, or the **Log** tab to see what the app ran

Up to 5 diagnostic runs are stored with timestamps — click any run to review it, or **Delete Run** to remove it.

- **Clear** — clears results and run history, keeps input fields
- **Reset** — clears everything including input fields, and returns the Profile to the detected one
- **Export results** — saves a timestamped text report via Save dialog
- **Copy results** — puts the same report on the clipboard, for pasting into a ticket

## Security architecture

How the app is built with regard to security, and what has changed since. Every statement here can be checked against the code.

### No credentials are stored or transmitted

The diagnostic run is **read-only**. Four actions change something, and each asks first: **Run gpupdate**, **Purge all tickets**, **Register now** (which asks Windows to register this computer's records in DNS) and **Sync now** (which starts the MDM client's own Intune sync; when the app isn't running as Administrator, the button reads **Sync in Settings** and opens Settings > Access work or school instead, since the sync task needs Administrator). The app does not store, transmit, or log any credentials, tokens, or secrets.

- **Encryption at rest: not needed, since nothing is stored.** No settings file, cache or credential store exists to encrypt; the only files are the ones you save yourself, as plain text you chose to write.
- **Nothing is written to disk.** The app stores no settings, credentials, tokens, or diagnostic data on disk. All state exists only in memory for the current session. The only files it writes are the ones you save yourself: **Export results** and **Save log**.
- **Two connections leave the corporate network, and they send nothing.** The Entra Seamless Single Sign-On group opens a TCP connection on port 443 to `login.microsoftonline.com` and, on a domain-joined or hybrid joined PC, `autologon.microsoftazuread-sso.com`, then closes it: no TLS handshake, no request, no account name. Everything else the app contacts is your own DNS servers and domain controllers.
- **Saved credentials are listed by name only.** `cmdkey /list` gives the targets of saved Windows credentials; the app never asks Credential Manager for a password.
- **Intune details are read, never changed.** The Intune group and tab read the registry keys the Windows MDM client keeps (`HKLM\SOFTWARE\Microsoft\Enrollments`, `Provisioning\OMADM`, `PolicyManager`), opened read-only, and ask the service manager for one service's state with query rights only. Policy values can name internal hosts or groups; they stay in memory like everything else.
- **Exported reports contain only metadata.** The text export includes test names and diagnostic details (trust names, GPO counts, port status). No raw tokens, password hashes, or credential material is included.
- **External process output is not persisted.** Output from `dsregcmd`, `nltest`, `klist`, `w32tm`, PowerShell queries, and other tools is parsed in memory for specific values only. The raw output is never written to disk, and is kept only while **Debug** is ticked on the Log tab (see below).
- **The log stays in memory.** The Log tab holds the last 5,000 lines until you clear it or close the app. With **Debug** on it includes raw tool output: host names, addresses, GPO names, Kerberos ticket details such as service names and encryption types, and `dsregcmd`'s device and tenant IDs (never keys, passwords or tokens). Read a debug log before sending it to anyone.

### Process isolation

- **Single instance enforced.** A per-session mutex prevents multiple instances from running simultaneously in the same logon session (other users on a shared host can run their own).
- **Nothing outlives the app.** Every external tool is started inside a Windows job object set to kill-on-close, so the tools end with the app however it exits (normal close, crash or End Task). On close, the in-flight diagnostic run is cancelled, the job is emptied and the process terminates itself outright rather than waiting on worker threads.
- **Every network call has a deadline.** DNS lookups (8s), SRV, SOA and host record queries (8s), TCP port checks (3s), share access (20s) and reading the Internet settings (5s) are bounded by the app, since Windows gives them no usable timeout. SYSVOL and NETLOGON are opened only after port 445 answers, so an unreachable domain fails in seconds. Clearing results or closing the app cancels a run: its tools are killed and no further ones start.
- **Input validation on all fields.** Domain and DC fields are validated against `^[a-zA-Z0-9.\-]+$`. No user input is passed to shell commands without validation.
- **No shell execution for diagnostics.** All external processes are launched with `UseShellExecute = false` and `CreateNoWindow = true`, and killed on timeout (a timeout is reported as a failure, never as a partial result).
- **No planted binaries.** Windows tools are launched by their full path in System32, and native DLLs (`dnsapi`, `netapi32`, `kernel32`, `advapi32`, `secur32`, `tbs`, `urlmon`, `user32`) load only from System32, so a `klist.exe` or DLL placed next to a downloaded `ad-diag.exe` is never run, even when the app is elevated.
- **Links open unelevated.** The GitHub and Release Notes links accept only `https` URLs and open through `explorer.exe`, so the browser runs at the desktop's integrity level, never with the app's admin token.

### Changes

Newest first. Dates are when the change was made; unreleased changes ship in the next version.

- **2026-10-23 (unreleased, session 4):** the Intune tab lists the MSI apps Intune pushed, read-only from `EnterpriseDesktopAppManagement` and the uninstall keys; of an installer's download URL only the file name is kept, never the query, which can carry an access token. The DNS registration name also reads each adapter's DNS suffix and its "Use this connection's DNS suffix in DNS registration" setting, read-only.
- **2026-10-23 (unreleased):** the Cloud Trust Groups check reads the signed-in user's own groups and the Entra Kerberos server object's password replication policy from AD; the domain and UPN put into the query must first match strict patterns that allow no quotes or LDAP filter characters.
- **2026-10-23 (unreleased):** the key rollover checks read three accounts' `pwdLastSet` from AD with a fixed query; the only thing put into it is the domain, and only once it is a plain DNS name.
- **2026-10-23 (unreleased):** the Credentials & Windows Hello group reads the Hello policy and the user's biometric enrollment from the registry read-only, the TPM's version from TPM Base Services (which any user may ask), and only the target names of saved credentials from `cmdkey /list`, never their passwords.
- **2026-10-23 (unreleased, later):** unelevated, Sync now becomes **Sync in Settings**: it opens the fixed `ms-settings:workplace` page through `explorer.exe` (no ShellExecute, no elevation prompt) rather than asking for Administrator.
- **2026-10-23 (unreleased):** the Intune group and tab read the MDM client's registry keys read-only, and query one service's state with query rights only; the one new action that changes something, **Sync now**, asks first and starts Windows' own sync task, its path built only from the enrollment's GUID. The Kerberos tickets and Intune panes no longer turn URLs into links, so a policy value can't become something to click.
- **2026-10-22 (unreleased):** the Internet-settings query for the Seamless SSO checks passed a buffer the wrong way to the Windows URL security manager, which could crash the app with memory corruption; it now passes a plain integer.
- **v1.2.0, 2026-10-05:** every network call has a deadline, and every tool runs in a kill-on-close job object, so an unreachable domain can't hang the app and no tool outlives it.
- **v1.1.0, 2026-09-27:** Windows tools launch by full System32 path and native DLLs load only from System32, so copies planted next to the exe never run; header links open unelevated through `explorer.exe` and accept only `https`. Releases gained SHA-pinned actions, a SHA-256 checksum and a build provenance attestation, with CodeQL and dependency review on pull requests.

## Test Groups

Each check ends in one of five results:

- **Passed** — as it should be.
- **Failed** — something that breaks sign-in, Group Policy or registration; fix it.
- **Warning** — a problem to fix, though things may still work for now (a stale record, a clock a minute or two off, a port Group Policy needs).
- **Info** — worth knowing, nothing broken (a port many domains close on purpose, a fallback this PC doesn't use). Counted as notes, never as warnings.
- **Skipped** — not checked, with the reason: it needs Run as Administrator, a tool didn't answer, or it depends on a check that didn't pass.

A group's heading shows the worst of its checks: **FAILED**, **WARNING** or **PASSED** (Info and Skipped don't lower it).

**Run as Administrator:** a few checks read more as Administrator: the secure channel, the computer half of Group Policy, Intune's sync times and policy settings, and possibly the Hello policy and biometric enrollment. When the app isn't elevated and one of them was held back, its row has a shield after its name and its group's heading a **Needs admin** capsule, or **Partially needs admin** when only some of the group's checks need it (hover it for how to elevate). Before a run, an app that isn't elevated shows the capsule on the groups whose checks always need it (the secure channel and Group Policy), and opening the group shows which ones. When the app is elevated, the title bar reads "Administrator: AD Diagnostics" and the header shows **Running as administrator**.

### Profiles

The profile decides which groups run. A check that doesn't apply to how the PC is joined isn't shown or logged at all, rather than showing as skipped.

| Profile | Groups | Left out |
|---|---|---|
| Domain joined | 1–11 | Device Auth and Primary Refresh Token rows (group 9) |
| Microsoft Entra hybrid joined | 1–11 | nothing |
| Microsoft Entra joined | 8 Dynamic DNS Registration, 9 Entra Seamless Single Sign-On, 10 Credentials & Windows Hello, 11 Intune | groups 1–7, the Domain and DC fields, the Group Policy tab, the Seamless SSO rows (group 9) |

Dynamic DNS Registration stays on every profile: behind a ZTNA client an Entra joined PC's registration matters as much as a domain-joined one's.

### 1. Domain Membership & Identity

Parses `dsregcmd /status`, `nltest`, `WindowsIdentity.GetCurrent()`, and AD via ADSI.

- **Domain Joined** — DomainJoined status from dsregcmd
- **Logged-on User** — current Windows identity (DOMAIN\user)
- **Secure Channel** — verifies the computer account's trust relationship via `nltest /sc_verify`
- **Site Assignment** — the AD site this client is assigned to, from `nltest /dsgetsite`
- **Computer Password Age** — queries the computer object's `pwdLastSet` attribute in the computer's own domain (which may differ from the target or logged-on user's domain); warns if stale (>45 days may indicate broken auto-rotation)

### 2. DC Discovery & Connectivity

Locates a domain controller and tests connectivity to required ports. Port checks run in parallel.

- **Locate DC** — `nltest /dsgetdc` finds the nearest available domain controller
- **Port 389 (LDAP)** — directory queries, group policy, logon
- **Port 636 (LDAPS)** — encrypted LDAP; closed is Info, since many DCs have no certificate for it
- **Port 88 (Kerberos)** — KDC port, required for domain authentication
- **Port 445 (SMB)** — required for SYSVOL/NETLOGON share access and Group Policy download
- **Port 135 (RPC)** — RPC endpoint mapper, used for domain join and Group Policy; closed warns
- **Port 464 (Kpasswd)** — Kerberos password change protocol; closed warns, since password changes fail
- **Port 53 (DNS)** — AD-integrated DNS; closed is Info, since the DC need not be a DNS server
- **Port 3268 (Global Catalog)** — forest-wide searches (multi-domain forests); closed is Info

### 3. DNS for Active Directory

SRV records are queried with the Windows DNS API (`DnsQuery`), bypassing the resolver cache, and report the best target (lowest priority, highest weight) first.

- **_ldap._tcp SRV** — required for DC locator
- **_kerberos._tcp SRV** — required for KDC discovery
- **_gc._tcp SRV** (optional) — Global Catalog discovery in multi-domain forests
- **DC A Record** — resolves the target DC hostname to its IPv4 (A) and IPv6 (AAAA) addresses; port checks prefer IPv4 and fall back to IPv6
- **DNS Suffix Search List** — verifies the target domain is in the machine's DNS suffix list; a missing suffix causes short-name resolution failures

### 4. SYSVOL & NETLOGON

Tests access to the domain's SYSVOL and NETLOGON shares. These must be reachable for Group Policy to apply — a pass on port 389 but failure here is a classic troubleshooting scenario.

- **SYSVOL Access** — `\\domain\SYSVOL` reachability and read access
- **NETLOGON Access** — `\\domain\NETLOGON` reachability and read access

### 5. Group Policy

Reads the Resultant Set of Policy logging data from WMI (`root\rsop`), the same data `gpresult` reports. The last refresh time comes from the Group Policy engine's `State` registry key. Computer scope requires running as Administrator, as it does for `gpresult`.

- **GP Last Refresh** — how long since policy was last applied
- **Applied GPOs** — count of policies successfully applied
- **Denied GPOs** — policies filtered out by security filtering or WMI filters (informational)

### 6. Trust Relationships

- **Domain Trusts** — enumerates trust relationships via `nltest /domain_trusts`

### 7. Kerberos & Time Sync

- **TGT Present** — checks for a cached `krbtgt/REALM` ticket; if none is cached (e.g. in an elevated session, which has its own empty cache), requests one with `klist get` — either way proving KDC contact
- **Clock Skew** — measured via `w32tm` against the DC; Kerberos has a strict 5-minute tolerance
- **Time Source** — confirms the client is syncing from the domain hierarchy, not local CMOS
- **krbtgt Key** — when the domain's krbtgt key was last set (`pwdLastSet`, read from AD); older than 180 days warns, since a common practice is rolling it over (twice, a day apart) at least that often

### 8. Dynamic DNS Registration

Checks whether this machine's own host record can reach, and is right on, the DNS server that owns its zone. These checks only read. SOA and host records are queried with the Windows DNS API on the wire, never from the resolver cache or the machine's own knowledge of its name.

- **Registration Name** — the name Windows registers: host name plus primary DNS suffix, and host name plus an adapter's own DNS suffix where "Use this connection's DNS suffix in DNS registration" is on. With neither, it says which adapter suffixes are used for lookups only
- **ZTNA / VPN Client** (informational) — an adapter from a known client (Zscaler, Cloudflare WARP, Netskope, GlobalProtect, Twingate, Tailscale, Island, Microsoft Global Secure Access, Cisco, Fortinet and others), any other tunnel adapter, any other virtual (software) adapter that holds an address, an adapter with a `/32` address and no default gateway, addresses in `100.64.0.0/10`, or DNS answered by the client's local proxy. Hypervisor and loopback adapters are not counted. A client in "VPN mode" gives its adapter a real routable address, so detection does not depend on the address range
- **Registering Adapters** — connected adapters with "Register this connection's addresses in DNS" turned on and the addresses they would register; warns when one is a `100.64.0.0/10` tunnel address that no other host can route to, and notes when a client's adapter holds a routable address but has registration turned off
- **Zone Primary Server** — the zone and its primary server, found the way Windows finds where to send an update: the SOA record of the name, then of each parent, asked of the DNS servers of the adapters that register (IPv4 servers, in order; one that doesn't answer is passed over), not of whichever server the system resolver prefers. The detail names the server that answered. If no registering adapter has an IPv4 DNS server, the configured DNS servers are asked. Warns when the primary server resolves to a public address, which usually means the zone found is the internet-facing copy that takes no updates from this machine; a synthetic `100.64.0.0/10` address from a ZTNA client is Info, since updates reach the real server if the client forwards port 53 for it
- **Update Path (Port 53)** — TCP 53 to the primary server
- **Registered Record** — the A/AAAA records the primary server holds for this machine (asked directly; the configured DNS servers if it doesn't answer), compared with the addresses the machine has now
- **Registration Errors** — DNS Client warnings (event IDs in the 8000s) in the System log in the last 24 hours. Windows logs one per failed registration and nothing on success

**Behind a ZTNA client** the same failures have different causes, and the details say so: the client's DNS proxy can know a different zone than the registering adapter's own DNS server, which is why the zone is looked up through the latter; a DNS proxy that answers A/AAAA/SRV but not SOA leaves Windows unable to find where to send an update; a primary server with a synthetic address is reachable only if the client forwards port 53 for it; and a policy that carries DNS queries doesn't necessarily carry updates, which also need Kerberos (port 88) to a domain controller.

### 9. Entra Seamless Single Sign-On

Whether this PC signs in to Microsoft 365 and other cloud apps that use Microsoft Entra ID without asking for a password, however it is joined: domain joined, hybrid joined or Entra joined. It checks only this PC, for basic readiness: how it is joined, its tokens, the browser settings Seamless SSO needs, and a direct connection to the sign-in endpoints. It can't see whether Seamless SSO is turned on in your tenant, or whether your domain is federated. The group ends with a **Readiness** line, and when the PC isn't ready, a **See the fixes in the Guide** link opens the Guide tab at this group's section, which has the recommended fix for each check.

How the PC is joined decides what is checked. Entra joined and hybrid joined PCs sign in with their Primary Refresh Token, which Edge, Chrome and Office use on Windows; domain-joined PCs use Seamless SSO. On a hybrid joined PC Seamless SSO is only the fallback, for browsers and apps that can't use the token, so while the token is in place a Seamless SSO problem is Info, not a warning, and the verdict reads "Ready for single sign-on through the Primary Refresh Token; the Seamless SSO fallback is not set up":

- **Join Type** — from `dsregcmd /status`: Microsoft Entra hybrid joined, Microsoft Entra joined, domain joined only, or neither (not ready)
- **Device Auth** — `DeviceAuthStatus` must be `SUCCESS` (Entra and hybrid joined)
- **Primary Refresh Token** — `AzureAdPrt` must be `YES` and renewed in the last 14 days, its lifetime. Windows renews it at sign-in, at unlock and when apps ask for a token, so a day or two old is normal. Missing or expired on a hybrid joined PC warns, since Seamless SSO covers for it; on an Entra joined PC it fails

Domain-joined and hybrid joined PCs (Seamless SSO):

- **Seamless SSO Ticket** — `klist get HTTP/autologon.microsoftazuread-sso.com` must return a ticket from a domain controller; without one the `AZUREADSSOACC` account is missing from the user's domain
- **Intranet Zone** — `https://autologon.microsoftazuread-sso.com` must be in the Local intranet zone, or browsers send it no Kerberos ticket
- **Automatic Logon** — the Local intranet zone must log on automatically with the current user name and password
- **Status Bar Scripts** — "Allow updates to status bar via script" in the Local intranet zone; off is Info, since only older clients need it

The zone and its two settings come from the Windows URL security manager (`urlmon`), the component Edge and Chrome ask, so Group Policy, the user's own zone sites and the zone settings apply in the order they do for the browser.

Microsoft Entra joined PCs (no Seamless SSO, so its rows aren't shown):

- **Cloud Kerberos** — `CloudTgt`: a Microsoft Entra Kerberos ticket for Azure Files and other cloud resources
- **On-premises Kerberos** — `OnPremTgt`: a ticket for AD resources through cloud Kerberos trust. Without it the verdict is "Ready for cloud apps, not for on-premises resources"
- **Cloud Trust Groups** — whether the signed-in user is in a group the Microsoft Entra Kerberos server object's password replication policy denies (by default Domain Admins, Enterprise Admins, Schema Admins, Administrators and the other privileged groups), or in none it allows; such an account gets no on-premises tickets through cloud Kerberos trust, and the verdict is the same as above. Read from AD: the user's own `tokenGroups` and the `AzureADKerberos` object's `msDS-NeverRevealGroup` and `msDS-RevealOnDemandGroup`

Both:

Key rollover, read from AD (each account's `pwdLastSet`; any domain user can read it):

- **Seamless SSO Key** — the `AZUREADSSOACC` account's Kerberos decryption key (domain and hybrid joined PCs). Microsoft says to roll it over at least every 30 days (`Update-AzureADSSOForest`); older warns
- **Cloud Kerberos Key** — the `krbtgt_AzureAD` key of the Microsoft Entra Kerberos server object, where the PC gets on-premises tickets through cloud Kerberos trust (`OnPremTgt: YES`); older than 180 days warns (`Set-AzureADKerberosServer -RotateServerKey`). An Entra joined PC asks the domain of the user's Kerberos realm (`USERDNSDOMAIN`)

- **Entra Endpoints** — a TCP connection on port 443 to `login.microsoftonline.com` (and `autologon.microsoftazuread-sso.com` for Seamless SSO). Nothing is sent. A miss warns rather than fails, since a proxy may still carry the traffic

![Guide tab opened at the Entra Seamless Single Sign-On fixes](docs/screenshots/guide-sso.png)

### 10. Credentials & Windows Hello

How this user's sign-in credentials are held, on every profile.

- **Windows Hello** — whether Hello for Business is set up for this user (`NgcSet` in `dsregcmd /status`); not set up is Info
- **Hello Trust** — how Hello signs in to on-premises resources: cloud Kerberos trust or certificate trust, set by Group Policy or Intune, or key trust when neither is. On an Entra joined PC with none set, Hello reaches cloud apps only (Info). Shown only when Hello is set up
- **Sign-in Methods** — PIN, and the fingerprint, face or iris enrolled for this user. Shown only when Hello is set up
- **TPM** — the TPM's version from TPM Base Services and, on a PC joined to Entra ID, whether the device key is protected by it (`TpmProtected`). No TPM or TPM 1.2 on such a PC, or a device key outside the TPM, warns
- **Ticket Encryption** — warns when a cached Kerberos ticket uses RC4 instead of AES, naming the services
- **Saved Credentials** — Windows credentials saved in Credential Manager for servers (`cmdkey /list`, names only, never passwords), which replace single sign-on there and lock the account out once the password changes

### 11. Intune

Whether this PC is managed by Microsoft Intune (or another MDM), on every profile, since Intune works the same however the PC is joined. Read from the registry the Windows MDM client keeps. Whether Intune counts the PC as compliant is decided in the service and not stored on the PC, so it isn't checked.

- **MDM Enrollment** — enrolled, the MDM and the account that enrolled the PC; an enrollment that isn't complete warns. Not enrolled is Info, and the other checks aren't shown. Only an enrollment with an MDM server counts: Windows' own entries there (Local, Deploy and Cloud Authority) and the ConfigMgr bridge are on PCs that aren't in Intune too
- **Last Sync** — the last successful sync with Intune. A PC that is on syncs about every 8 hours, so over a week warns; a failed attempt since the last success is a note (the next sync retries it)
- **Management Extension** — the Intune Management Extension service, which installs Win32 apps and runs scripts; stopped warns, not installed is Info (Intune adds it with the first such assignment)
- **Device Policies** — how many settings Intune pushed to the device are in force, how many another provider sets instead, and how many MSI apps Intune pushed (the Applications Settings lists). An app whose download or install failed warns, naming it

Reading the sync times or policy settings may need Run as Administrator; without it those checks show as not checked.

## Group Policy Tab

![Group Policy tab with Computer and User scope breakdown](docs/screenshots/group-policy.png)

A dedicated tab (separate from the streaming diagnostics above) that reads the Resultant Set of Policy (see above) into a readable, color-coded breakdown:

- **Computer and User scope**, each showing:
  - Last applied time, with age and a staleness warning past 7 days
  - AD site name
  - Every **applied** GPO
  - Every **denied/filtered** GPO with its filtering reason (security filtering, WMI filter, disabled link, etc.)
- **Refresh** — re-queries the policy results and re-renders the tab
- **Run gpupdate** — runs `gpupdate` (or `gpupdate /force` with the **Force** checkbox) directly from the app, with a confirmation dialog explaining the impact of Force (reapplies all policies, not just changed ones; can briefly disrupt mapped drives/printers; may require a restart for some extensions). Automatically refreshes the tab afterward.

## Kerberos Tickets Tab

![Kerberos Tickets tab showing cached tickets with service badges](docs/screenshots/kerberos-tickets.png)

A dedicated tab that parses `klist` and renders every cached Kerberos ticket with color-coded service type badges:

- **TGT** — Ticket Granting Ticket (your master KDC credential). Shows PRIMARY vs DELEGATION cache flags.
- **CIFS** — SMB file share service tickets
- **LDAP** — Directory service tickets
- **HOST** — Remote admin / WinRM tickets
- **HTTP** — Web service tickets (ADFS, Exchange, etc.)
- **RDP** — Remote Desktop (TERMSRV) tickets
- Plus SQL, DNS, Exchange, and any other service types

Each ticket card shows: server, client, encryption type (AES = green, RC4 = yellow warning), flags, cache type, KDC called, and start/end/renew times with expiry detection.

On an Entra joined or hybrid joined PC a **PRT** card comes first: the Primary Refresh Token isn't a Kerberos ticket, so `klist` never lists it, and the card reads it from `dsregcmd /status`: join type, tenant, status, when it was renewed and expires, its authority, and the Cloud and On-premises Kerberos ticket flags. Its badge follows the same rule as the Results row: green when present and renewed within 14 days; missing or expired is amber on a hybrid joined PC (Seamless SSO covers for it) and red on an Entra joined one.

- **Purge All Tickets** — runs `klist purge` with confirmation dialog
- **Refresh** — re-reads the ticket cache
- **What is this?** — toggles an in-app explainer covering ticket types, encryption, and what purge does

## DNS Registration Tab

![DNS registration tab tracing a registration that timed out behind a ZTNA client](docs/screenshots/dns-registration.png)

Sends a dynamic DNS registration and traces what happens to it.

- **Register now** — after a confirmation, runs `ipconfig /registerdns`, so the DNS Client service sends the update as the computer account, exactly as Windows does on its own. Requires running as Administrator; without it nothing is sent. The service works in the background and reports nothing on success, so the app then watches, for up to 30 seconds, the two places the outcome shows: the record on the zone's primary server (before and after) and the DNS Client's failure events. A failure event fails the trace even if the record looks right. If nothing has changed and nothing is logged, the result is "not confirmed", since Windows can take longer.
- **Check again** — repeats the read-only checks from group 8 without sending anything.
- **ZTNA adapter** — for a client the app does not detect. Lists every connected adapter that holds an address, with the signals seen on it (`tunnel`, `virtual`, `/32, no gateway`); pick the client's adapter and every ZTNA hint applies as if it had been detected, here and in Run Diagnostics. **None** overrides a false detection. The choice is not saved: it lasts until the app closes.

Every step is also written to the log.

## Intune Policies Tab

![Intune policies tab with the enrollment, device and user settings](docs/screenshots/intune-policies.png)

Every setting and MSI app Intune pushed, read from the MDM client's `PolicyManager` and `EnterpriseDesktopAppManagement` keys. **Device scope**, **User scope** and **Applications** start folded to their title and count; click one (or press Enter) to open it:

- **Enrollment** — the MDM and the account that enrolled the PC, the last successful sync (and a failed attempt since), and the Management Extension's state
- **Device scope** and **User scope** — each setting by area, with its value. A green dot is the value in force; an amber dot is a setting another provider (another MDM, a provisioning package) sets instead, with that provider's id
- **Applications** — the MSI apps Intune pushed to the device and to the signed-in user, the list Settings > Accounts > Access work or school > Info shows under Applications: one row per app: its name (from its uninstall entry, else its installer's file name), version and install state, with the error code when it failed. Every MSI version has its own product code and Intune keeps an entry for each it pushed, so versions that share an installer file are one app, named from the installed version; the versions it replaced fold under it. Win32 apps the Management Extension installs aren't kept there, so they aren't listed
- **Refresh** — reads it all again
- **Sync now** — after a confirmation, starts the enrollment's own sync task (`PushLaunch`, the one behind **Sync** in Settings > Accounts > Access work or school). The task needs Run as Administrator, so when the app isn't elevated the button reads **Sync in Settings** and opens that Settings page instead, where Windows' own **Sync** works for a standard user

## Log Tab

![Log tab with Debug on](docs/screenshots/log.png)

What the app did and what came back. **Sections** (the default) groups it by run: each run, single-section run, Group Policy query, gpupdate, ticket refresh or DNS registration starts with a heading carrying its time, what it covered and its totals, and inside a run each results section has a heading of its own, so a section's commands, raw output and results read together even though the sections run side by side. Every run and section starts folded to its heading; click one (or press Enter on it) to open it. A result shows its mark and status, the check's name in bold and its detail; tool output lines up under the command that produced it. **By time** shows the same lines in the order they happened, with each line's section named in a column. **Raw** shows the log exactly as Save log writes it: one plain line each, with no headings or colours. Times on screen follow the Windows clock setting; log lines keep a 24-hour time so they line up and sort. Without **Debug** it records each run, every result, the DNS registration steps and any tool or query that failed. With **Debug** ticked it also records each command, DNS query (with the server it was sent to) and port check with its duration and raw output, and the Windows error number behind a failure. A script that runs again unchanged is logged once, and connected adapters that hold no address share one line. Debug is off at every start.

- **Copy log** / **Save log** — the whole log as text in the view on screen, to the clipboard or to a file you choose
- **Clear log** — empties it

## Architecture

**Runtime:** .NET 10 WinForms, self-contained single-file executable (win-x64, ReadyToRun-precompiled for faster startup).

**Structure:** `MainForm.cs` holds the UI and the Windows-specific calls; `Diagnostics.cs`, `DnsRegistration.cs`, `EntraSso.cs`, `Credentials.cs` and `Intune.cs` hold the eleven test groups and the traced DNS registration, which reach the machine only through the `IProbe` interface so they can be tested against a fake; `Log.cs` holds the in-memory log and the wrapper that logs every `IProbe` call; `Runner.cs` runs tools and network calls with deadlines; `Parsers.cs` holds the pure parsers for tool output (`klist`, `nltest`, `w32tm`, and the app's PowerShell queries), kept free of WinForms so they can be unit tested on any platform.

**UI:** Owner-drawn `Panel` with `TextRenderer.MeasureText` for word-wrapped results. Starts in the Windows light or dark app setting; the header button switches between **Dark mode** and the light theme, **Flashbang**, at any time (the choice is not saved, since the app writes nothing to disk). Scales with the display DPI; every status has its own shape as well as its own colour, and each result row is exposed to screen readers as a list item. The design rules are in [DESIGN.md](DESIGN.md). Test groups stream results in real-time as each completes.

**Non-English Windows:** tool output is translated on localized Windows, so parsers anchor on structure, numeric status codes and symbolic names (e.g. `Status = 1311 0x51f ERROR_NO_LOGON_SERVERS`) rather than English labels, and output is decoded in the console's OEM code page so non-ASCII names aren't garbled. `klist`'s translated field labels are identified by their fixed position in each ticket. Group Policy (RSoP) and DNS lookups (`DnsQuery`) use APIs rather than tool output, so they're language-neutral too. DNS Client events are matched by ID; their text is shown as Windows wrote it. `dsregcmd /status` prints its field names (`AzureAdJoined`, `AzureAdPrt` and so on) untranslated, the Seamless SSO ticket is found by its `SPN @ REALM` line, and the browser zone settings come from an API.

**Input Validation:**
- `HostnamePattern`: `^[a-zA-Z0-9.\-]+$` — domain and DC fields

**Settings:** None — no data is persisted to disk. The app auto-detects the domain on startup.

### External Process Calls

| Process | Purpose | Timeout |
|---|---|---|
| `dsregcmd /status` | Domain join state (and startup domain auto-detect); Entra join, device and token state for single sign-on | 15s (5s at startup) |
| `nltest /sc_verify` | Secure channel verification | 10s |
| `nltest /dsgetsite` | AD site assignment | 5s |
| `nltest /dsgetdc` | DC locator | 8s |
| `nltest /domain_trusts` | Trust enumeration | 8s |
| `gpupdate` / `gpupdate /force` | Manual policy refresh (Group Policy tab) | 90s |
| `klist` | Kerberos ticket cache (diagnostics + tab) | 5s |
| `klist get krbtgt/REALM` | Request a TGT when none is cached | 10s |
| `klist get HTTP/autologon.microsoftazuread-sso.com` | Request the Seamless SSO ticket (domain-joined and hybrid joined PCs) | 10s |
| `klist purge` | Purge cached tickets (Kerberos Tickets tab) | 5s |
| `w32tm /stripchart` | Clock skew measurement | 5s |
| `w32tm /query /source` | Time source | 5s |
| `powershell` (DirectorySearcher) | Computer password age from AD; key ages of `AZUREADSSOACC`, `krbtgt_AzureAD` and `krbtgt`; the user's groups against the Entra Kerberos server object's policy | 15s / 20s / 25s |
| `powershell` (Get-CimInstance, `root\rsop`) | Group Policy results (diagnostics + tab) | 25s |
| `powershell` (Get-WinEvent, System log) | DNS Client registration failures (diagnostics + DNS registration tab) | 15s |
| `ipconfig /registerdns` | Register in DNS (DNS registration tab) | 20s |
| `cmdkey /list` | Names of saved Windows credentials (Credentials & Windows Hello) | 15s |
| `powershell` (Start-ScheduledTask, `PushLaunch`) | Start an Intune sync (Intune policies tab, **Sync now**, elevated only) | 30s |

All launched with `CreateNoWindow`, `UseShellExecute=false`, redirected stdout/stderr, and stdin closed (so a tool that prompts gets EOF instead of hanging). On timeout the process tree is killed and the test reports the timeout; the same deadline covers a tool that exits but leaves its output pipe open.

## Build from Source

Requires [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```
git clone https://github.com/darthrater78/ad-diag.git
cd ad-diag
dotnet publish -c Release -r win-x64 --self-contained true
```

Output: `bin/Release/net10.0-windows/win-x64/publish/ad-diag.exe`

Run the parser tests (works on Windows, Linux or macOS):

```
dotnet test tests/AdDiag.Tests
```

The tests use representative tool output (mostly English, with some German) in `tests/AdDiag.Tests/Samples.cs`. When a parser misreads real output, add that output as a sample and a test.

The README screenshots are generated from mock data by `tools/screenshots/run.sh` (Linux, under Wine). See [tools/screenshots/README.md](tools/screenshots/README.md).

## Releasing

Bump `<Version>` in `AdDiag.csproj` and add a row to [Version History](#version-history), merge to `main`, then push a tag of the form `vMAJOR.MINOR.PATCH` (or `vMAJOR.MINOR.PATCH-rc1` etc. for a prerelease). The release workflow refuses a tag that isn't on `main` (prereleases excepted), hasn't passed CI, or doesn't match `<Version>`. It builds with the version from the tag, so the in-app badge and file version always match it, and uses the tag's Version History row as the release notes. A final release with no row fails before building; prereleases get GitHub's generated notes only. CI builds every push to any branch (and pull requests from forks), and attaches the built `ad-diag.exe` to the run (kept 14 days) for testing before a release; a change that touches only documentation (Markdown, `docs/`, screenshots) skips the build. Those builds are not release builds: they have no checksum file or provenance attestation, and they report the version in `AdDiag.csproj`. CI also runs the unit tests (parsers, the nine diagnostic groups and the DNS registration trace against a faked machine, the log, and the process and network runner that enforces the deadlines) and builds the screenshot harness. Pull requests also run CodeQL, dependency review (fails on a High or Critical advisory), and actionlint when workflows change.

## Version History

| Version | Date | Changes |
|---|---|---|
| v1.3.0 | 2026-10-06 | New test group, **Dynamic DNS Registration**: the name Windows registers, the adapters that register it, the zone's primary server (found by SOA through the registering adapters' own DNS servers, with the answering server named), TCP 53 to it, the record it holds compared with the machine's addresses, and DNS Client registration errors from the last 24 hours. A primary server with a public or synthetic `100.64.0.0/10` address warns. New **DNS registration** tab: **Register now** runs `ipconfig /registerdns` after a confirmation (Administrator only) and traces the outcome on the primary server and in the DNS Client's failure events; **Check again** repeats the read-only checks. ZTNA and VPN clients are detected by name, tunnel type, virtual adapter, a `/32` address with no gateway, `100.64.0.0/10` addresses or a local DNS proxy, and the failure details say what the client changes; a **ZTNA adapter** picker tags one by hand or overrides a false detection. New **Log** tab: runs, results, registration steps and failures, plus commands, queries, timings and raw output with **Debug** ticked; copy, save or clear it. The log is held in memory and nothing is written unless you save it |
| v1.2.0 | 2026-10-05 | No more hangs when the domain is unreachable: DNS, SRV, port and share checks all have deadlines, and SYSVOL/NETLOGON are opened only after port 445 answers. Closing the app or clearing results cancels the run, tools can no longer outlive the app (kill-on-close job object), and `ad-diag.exe` no longer lingers after its window closes. New look: native Windows styling with a Dark mode / Flashbang (light) switch that starts from the Windows setting, a results grid whose status marks differ by shape as well as colour, plain-text details, per-group counts, and DPI scaling. New **Copy results** button; Enter starts a run; each result row is exposed to screen readers. Fixed `&` missing from group headers and overlapping text in the header and summary. Moved to .NET 10. CI builds every branch, skips docs-only changes, and tests the process and network runner |
| v1.1.0 | 2026-09-27 | Works on non-English Windows: Group Policy is read from RSoP (WMI) instead of `gpresult` text, SRV records via `DnsQuery`, and `nltest`/`klist`/`w32tm` output parsed by structure and status codes, not English labels; a broken secure channel no longer passes on localized Windows. TGT Present requests a ticket when none is cached (elevated sessions); Computer Password Age queries the computer's own domain; DNS and port checks support IPv6-only DCs. Tool timeouts are reported as failures, prompting tools no longer hang, and running tools are killed on exit. Trust enumeration excludes the machine's own domain and warns when `nltest` fails. Windows tools are launched by full System32 path and native DLLs load only from System32, so copies planted next to the exe are never run; header links open unelevated, and Release Notes links to this version's notes. Release pipeline: CI with parser tests, SHA-pinned actions, checksum and provenance attestation, CodeQL and dependency review |
| v1.0.2 | 2026-07-16 | Release asset is now a single self-contained exe (no zip); native libraries are bundled into the single file; fixed the in-app version badge, which was hardcoded and had gone stale |
| v1.0.1 | 2026-07-16 | Fixed 10 correctness bugs: wrong rows shown as running, crash or corrupted history when deleting a run mid-flight, Clear Results not stopping the run, `klist` Client and Ticket Flags fields dropped, Group Policy and Results tabs disagreeing on GPO counts, gpupdate garbling the Group Policy tab, a stuck Group Policy guard, a faulted test group crashing the app, and unobserved exceptions from abandoned TCP connects |
| v1.0.0 | 2026-07-14 | Initial release — domain membership (including computer password age from AD), DC discovery with 8 port checks (LDAP, LDAPS, Kerberos, SMB, RPC, Kpasswd, DNS, Global Catalog), AD DNS SRV records and suffix search list, SYSVOL/NETLOGON share access, Group Policy status, trust relationships, Kerberos ticket and time sync diagnostics; Group Policy tab with Computer/User scope breakdown and in-app gpupdate; Kerberos Tickets tab with full ticket cache viewer, purge, and explainer; auto-detects domain on startup; elevation-aware warnings |
