# AD Diagnostics

Standalone Windows diagnostic tool that checks the health of a domain-joined machine's relationship with Active Directory. Single-exe, no install required.

## Download

Grab `ad-diag.exe` from the [latest release](https://github.com/darthrater78/ad-diag/releases/latest). No installation — just run.

## Windows SmartScreen

On first launch, Windows SmartScreen may display a warning ("Windows protected your PC"). This is normal for unsigned executables from the internet. The app is not code-signed — it is a self-contained .NET 8 single-file executable built from the source in this repository. Click **More info** then **Run anyway** to proceed.

## Usage

1. Launch `ad-diag.exe`
2. Enter target details:
   - **Domain** — e.g. `contoso.com`
   - **DC Hostname** — optional, defaults to domain for DC discovery. **+ domain suffix** is on by default, auto-appending the domain to short names. Uncheck to use the value as-is.
3. Click **Run Diagnostics** — results stream in as each test group completes
4. Review results or switch to the **Guide** tab for explanations and fix suggestions

Input fields remember previously entered values in a dropdown. Up to 5 diagnostic runs are stored with timestamps — click any run to review it, or **Delete Run** to remove it.

- **Clear** — clears results and run history, keeps input fields and saved settings
- **Reset** — clears everything including input fields and deletes the settings file
- **Export Results** — saves a timestamped text report via Save dialog

## Security

### No credentials are stored or transmitted

This tool is **read-only and diagnostic**. It does not store, transmit, or log any credentials, tokens, or secrets.

- **No credentials are written to disk.** The settings file (`%LOCALAPPDATA%\ad-diag\settings.json`) contains only input field history (domain/DC names) — never credentials, tokens, or ticket data.
- **Exported reports contain only metadata.** The text export includes test names and diagnostic details (trust names, GPO counts, port status). No raw tokens, password hashes, or credential material is included.
- **External process output is not persisted.** Output from `dsregcmd`, `nltest`, `klist`, `gpresult`, `w32tm`, and other tools is parsed in memory for specific values only. The raw output is never written to disk or stored beyond the method scope.

### Process isolation

- **Single instance enforced.** A global mutex prevents multiple instances from running simultaneously.
- **Background tasks are cancelled on exit.** All async diagnostic work is cancelled via `CancellationToken` on form close, and `Environment.Exit(0)` is called on `FormClosed` as a backstop to ensure the process cannot linger.
- **Input validation on all fields.** Domain and DC fields are validated against `^[a-zA-Z0-9.\-]+$`. No user input is passed to shell commands without validation.
- **No shell execution for diagnostics.** All external processes are launched with `UseShellExecute = false` and `CreateNoWindow = true`, and killed on timeout.

## Test Groups

### 1. Domain Membership & Identity

Parses `dsregcmd /status`, `nltest`, and `WindowsIdentity.GetCurrent()`.

- **Domain Joined** — DomainJoined status from dsregcmd
- **Logged-on User** — current Windows identity (DOMAIN\user)
- **Secure Channel** — verifies the computer account's trust relationship via `nltest /sc_verify`
- **Site Assignment** — the AD site this client is assigned to, from `nltest /dsgetsite`

### 2. DC Discovery & Connectivity

Locates a domain controller and tests connectivity to required ports. Port checks run in parallel.

- **Locate DC** — `nltest /dsgetdc` finds the nearest available domain controller
- **Port 389 (LDAP)** — directory queries, group policy, logon
- **Port 636 (LDAPS)** — encrypted LDAP (optional)
- **Port 88 (Kerberos)** — KDC port, required for domain authentication
- **Port 53 (DNS)** — AD-integrated DNS
- **Port 3268 (Global Catalog)** — forest-wide searches (multi-domain forests)

### 3. DNS for Active Directory

- **_ldap._tcp SRV** — required for DC locator
- **_kerberos._tcp SRV** — required for KDC discovery
- **_gc._tcp SRV** (optional) — Global Catalog discovery in multi-domain forests
- **DC A Record** — resolves the target DC hostname to an IP address

### 4. Group Policy

Parses `gpresult /r /scope:computer`.

- **GP Last Refresh** — how long since policy was last applied
- **Applied GPOs** — count of policies successfully applied
- **Denied GPOs** — policies filtered out by security filtering or WMI filters (informational)

### 5. Trust Relationships

- **Domain Trusts** — enumerates trust relationships via `nltest /domain_trusts`

### 6. Kerberos & Time Sync

- **TGT Present** — a cached `krbtgt/REALM` ticket proves KDC contact
- **Clock Skew** — measured via `w32tm` against the DC; Kerberos has a strict 5-minute tolerance
- **Time Source** — confirms the client is syncing from the domain hierarchy, not local CMOS

## Architecture

**Runtime:** .NET 8 WinForms, self-contained single-file executable (win-x64, ReadyToRun AOT).

**Structure:** Single-file app (`MainForm.cs`). All UI and diagnostics in one compilation unit.

**UI:** Owner-drawn `Panel` with `TextRenderer.MeasureText` for word-wrapped results. Dark theme. Test groups stream results in real-time as each completes.

**Input Validation:**
- `HostnamePattern`: `^[a-zA-Z0-9.\-]+$` — domain and DC fields

**Settings:** `%LOCALAPPDATA%\ad-diag\settings.json`. Contains input history only — no credentials. Persists across exe updates.

### External Process Calls

| Process | Purpose | Timeout |
|---|---|---|
| `dsregcmd /status` | Domain join state | 15s |
| `nltest /sc_verify` | Secure channel verification | 10s |
| `nltest /dsgetsite` | AD site assignment | 5s |
| `nltest /dsgetdc` | DC locator | 8s |
| `nltest /domain_trusts` | Trust enumeration | 8s |
| `nslookup -type=SRV` | AD DNS SRV records | 5s |
| `gpresult /r /scope:computer` | Group Policy status | 20s |
| `klist` | Kerberos ticket cache | 15s |
| `w32tm /stripchart` | Clock skew measurement | 5s |
| `w32tm /query /status` | Time source | 5s |

All launched with `CreateNoWindow`, `UseShellExecute=false`, `RedirectStandardOutput`, async stdout read, killed on timeout.

## Build from Source

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```
git clone https://github.com/darthrater78/ad-diag.git
cd ad-diag
dotnet publish -c Release -r win-x64 --self-contained true
```

Output: `bin/Release/net8.0-windows/win-x64/publish/ad-diag.exe`

## Version History

| Version | Date | Changes |
|---|---|---|
| v1.0.0 | 2026-07-14 | Initial release — domain membership, DC discovery/connectivity, AD DNS SRV records, Group Policy status, trust relationships, Kerberos ticket and time sync diagnostics |
