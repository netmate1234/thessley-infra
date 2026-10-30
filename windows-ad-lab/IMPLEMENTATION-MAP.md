# AD QR sign-in implementation map

This is a map from the disposable AD lab to the existing Thessley source. It
keeps the AD experiment separate from the current Drupal-backed distributed
Windows login feature.

## Generic AD account tile: current blocker and target

The current request is to use the already-enrolled
`THESSLEYLAB\Administrator` identity at Clone 1's normal Windows sign-in
screen, including through **Other user**. The central phone enrollment and
AD QR SSH path already work. The desktop provider is a separate, incomplete
prototype: it binds to Martin's cached SID and that account's TPM virtual
smart-card container. It cannot yet accept an arbitrary AD username from
**Other user**.

Do not solve this by merely adding more SIDs to
`ad_lab_vsc_config.h`. That would still need a separate TPM smart-card
certificate/key for every account on every PC. It is useful only as a
single-account lab bridge and does not meet the central-phone-key design.

The intended desktop path must:

1. Display a distinct Thessley AD tile for **Other user** and accept a
   qualified AD account name. The provider must not trust that typed name as
   authorization; it must resolve it against AD and check the machine and
   configured access groups.
2. Start the existing SID-bound phone approval against the central service.
   The private phone key stays on the phone; the DC keeps only its public key.
3. Complete a Windows-recognized AD logon without serializing an AD password
   or leaving a persistent per-user key on each PC.
4. Keep Windows password/Hello recovery and the local-account Thessley tile
   available. Do not change the installed provider until a separate test build
   has passed on Clone 1 and has a verified rollback.

The phone approval signature is not itself a Kerberos/PKINIT credential. A
candidate bridge that preserves the central-phone model is to generate a
one-use signing key on the workstation for this login, have the phone approve
the exact account/machine/request, and let a narrowly scoped AD CS Enrollment
Agent issue a short-lived smart-card-logon certificate strongly mapped to
that user's SID. The Credential Provider can then submit a Kerberos
certificate-logon serialization using the ephemeral key. Delete the key and
certificate after the attempt; the persistent phone key remains on the phone
and its public key remains central. This is a **phone-authorized ephemeral
certificate login**, not direct phone-key PKINIT.

This bridge is a hypothesis to validate in the disposable lab, not yet an
implemented or approved production design. Enrollment Agent certificates can
act on behalf of other users, so the agent must be restricted to one dedicated
logon template and the intended user population; every issuance and revocation
must be audited. Before provider work, confirm that the issued certificate
contains a strong SID mapping for the requested user, that the KDC accepts it,
that the certificate-logon serialization can use a machine-held ephemeral
key, and that key/certificate cleanup works on both success and failure. If
any one of these checks fails, stop and retain the built-in password recovery
path; do not fall back to per-user TPM certificates on every PC.

For the immediate lab account, the phone is already enrolled centrally for
`THESSLEYLAB\Administrator`. No additional phone enrollment is needed. The
remaining work is the generic desktop credential and phone-key-to-PKINIT
bridge; AD QR SSH success does not verify either one.

## Existing pieces

| Area | Existing code | Reuse |
|---|---|---|
| Existing Windows sign-in tile | `thessley-pam-windows-update/windows-logon-provider/ThessleyCredential.cpp` | This is the approval-gated password tile. Its account SID, selected user, interactive-vs-unlock context, status, cancellation, and QR matrix transport are useful references, but keep its CLSID and behavior intact. |
| Tile credential submission | `ThessleyCredential.cpp`, `CSampleCredential::GetSerialization` | **Do not reuse for passwordless AD.** It currently loads or accepts a password and serializes `KERB_INTERACTIVE_UNLOCK_LOGON` / packed credentials after approval. That is approval-gated password sign-in. |
| Local approval service | `thessley-pam-windows-update/thessley_pam_win/approve.py`, `protocol.py`, and `listener.py` | Reuse the existing phone signature rules and request display only after adding the standalone service transport and SID-bound registry. |
| Drupal transport | `thessley-pam-windows-update/thessley_pam_win/drupal_agent.py` | **Do not call from the AD project.** It owns Drupal setup, pair, challenge, polling, policy sync, and Drupal-specific errors. |
| Android link parsing/signing | `thessley-passkey-android/.../PamRequest.kt`, `PamCanonicalString.kt`, `PasskeyViewModel.kt`, and `PinnedClient.kt` | Version-2 PAM links already carry and sign the SID hash, principal type, authority, account name, context, nonce, and action. Retain certificate pinning and biometric key use. |
| AD/DNS/CA lab | `infra/windows-ad-lab/configure-domain-controller.ps1`, `join-domain-client.ps1`, and `verify-domain-client.ps1` | Use for AD account, DNS, certificate, and connectivity experiments only. |

## Current Windows VM verification (2026-10-27)

- The client is Windows 11 Pro, domain joined, and `Test-ComputerSecureChannel`
  succeeds. Its active console session is `THESSLEYLAB\martin`; SSH
  maintenance runs as the distinct local account `MARTIN-WM\martin`.
- The AD controller is Windows Server 2025. AD DS and AD CS are running;
  LDAPS on 636 and Global Catalog LDAPS on 3269 accept local connections.
  The controller has DomainController and KerberosAuthentication certificates.
- The DC currently has LAN address `192.168.1.79` and the client has
  `192.168.1.103`. The phone's Wi-Fi can reach the DC's LDAPS ports and the
  client's TCP SSH port; ping is filtered. These LAN addresses come from DHCP,
  so reserve them on the router before relying on them across VM restarts.
- `martin` is in the dedicated `ThessleyADSignInAdmins` group, and the group is
  mapped to the client's local Administrators group. It is not Domain Admins.
- The isolated client helper exposes `enroll-current-user` and
  `enroll-phone --user THESSLEYLAB\\martin`. The first uses the process SID;
  the second resolves the explicitly qualified domain account. A similarly
  named local SSH maintenance account is a different SID and cannot be
  mistaken for the domain user.
- The standalone AD API is deployed as the `ThessleyADApi` SYSTEM task on the
  disposable DC at `https://192.168.1.79:47810`. Its listener and paired client
  machine key were verified. A signed machine check succeeded, and
  `authorization-check --user THESSLEYLAB\\martin` returned authorized from
  the allowlisted AD security group. The service uses Windows LDAP/ADSI and
  SSPI as LocalSystem; it does not require RSAT or store an AD password.
- The DC has one active phone key registered for Martin on the paired test
  client. A fresh QR approval completed successfully after extending the
  request lifetime to three minutes. The client received the one-use approved
  result. The earlier expired request was stale and is not reusable.
- These changes did not alter the local-account credential provider, Windows
  logon providers, published `ThessleyVscLogon` template, or TPM smart-card
  certificate.

## Clone 1 live baseline (2026-10-29)

- Read-only SSH checks reached `MARTIN-WM` as `THESSLEYLAB\martin` on Windows
  11 Pro (`10.0.26300.9711`). The Thessley AD service status and signed
  machine-connection check succeeded.
- The AD service authorized `THESSLEYLAB\Administrator` and denied
  `THESSLEYLAB\startmenutest`. This verifies the server-side group gate, not
  Windows interactive sign-in.
- Both `Thessley AD Passkey (Lab)` and `Thessley Passkey unlock` are registered
  as Credential Providers. The expected per-SID mapping registry root
  `HKLM\SOFTWARE\Thessley\ADCredentialProvider\Users` is absent. Therefore
  the live AD provider's account coverage is not established; do not assume
  that Administrator has a configured VSC mapping or a usable tile.
- The installed `C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd`
  is zero bytes. Its status and authorization commands silently did nothing.
  Calling the installed `ad_main.py` entrypoint directly worked. The source
  activation script now regenerates both command launchers in staging and
  validates the installed test launcher before it reports activation success.
- No VM files, provider registrations, sign-in settings, or scheduled tasks
  were changed during this inspection. The lock-screen tile for Administrator
  still needs a console test; SSH and the AD authorization check cannot prove
  tile enumeration or Kerberos logon.

## Windows Start-menu account flyout delay (2026-10-28)

- The separate issue under investigation is a persistent ~40-second delay when
  opening Start > the account/profile button. The delay reproduces on both
  `THESSLEYLAB\martin` and a fresh domain account, `THESSLEYLAB\startmenutest`.
  This rules out a Martin-only profile issue, but does not rule out machine-wide
  effects from Thessley changes. Do not change VM RAM as a proposed fix; the
  user explicitly ruled that out.
- Windows Error Reporting recorded `svchost.exe_UserManager` crashes on
  2026-10-28 at 13:36 (`ntdll.dll`, `0xc0000710`) and 14:52 (`combase.dll`,
  `0xc0000005`; a companion `svchost.exe` report had `0xc0000602`). These are
  Windows system modules; the recorded reports did not identify a Thessley
  module. The reports were archived without their dump files, so the precise
  faulting call stack is not yet known. Restarting `UserManager` made the menu
  fast temporarily, but signing out/in brought the delay back.
- DISM reported no component-store corruption. `StartMenuExperienceHost` is
  installed and registered. The domain profile's StartMenuExperienceHost
  `LocalState` was unusually sparse compared with the responsive `MenuProbe`
  profile. Its contents were preserved by renaming the directory to
  `LocalState.backup-20261028-1519`; an empty replacement directory was
  created with inherited SYSTEM, Administrators, and domain-user permissions.
  This reset has **not** been verified by a fresh domain sign-in yet; the user
  reports the account button remains slow. Keep the backup until the profile
  has been tested and any needed data recovered.
- The VM was at the sign-in screen with `LastLoggedOnUser= .\\MenuProbe`, and
  the left account list showed `MenuProbe` and `Other user`. The actual domain
  SID still resolves to the provider's configured SID
  `S-1-5-21-1719900462-4250469598-2954734011-1101`; the local `Martin` and
  `MenuProbe` accounts have different machine-local SIDs.
- To restore the AD QR option, the LogonUI values were exported first to
  `C:\\ProgramData\\ThessleyPamWin\\backups\\LogonUI-before-domain-last-user-20261028.reg`.
  The remembered LogonUI account/SID/provider were then set to
  `THESSLEYLAB\\martin`, the domain SID above, and the Thessley AD provider
  `{2678765D-9F74-4BDE-A4DA-2B53234BE053}`. Restarting `LogonUI.exe` caused
  the **Thessley AD approval QR viewer to appear** on the lock screen. The
  user reports QR sign-in is restored. The phone approval/domain sign-in and
  persistence across reboot are not yet independently verified. To restore
  the pre-test LogonUI values, import the backup from an elevated PowerShell
  session with `reg.exe import ...\\LogonUI-before-domain-last-user-20261028.reg`.
- A WPR `GeneralProfile` + `XAMLAppResponsiveness` trace captured the slow
  account-button click at
  `C:\\ProgramData\\ThessleyPamWin\\diagnostics\\start-menu-user-button-20261028.etl`.
  `tracerpt` processed 4,904,058 events across 609 buffers in 176 seconds with
  zero lost events. The generated summary gives provider/event counts, not a
  causal timeline; Windows' built-in `Get-WinEvent` reader exposes blank
  provider names for these raw WPR events. The ETL still needs WPA or an
  equivalent event decoder before attributing the stall.
- A local streaming parse of the CSV export found no 40-second operation in
  `StartMenuExperienceHost`: the longest matched XAML operation was about
  0.99 s and its longest matched RPC call was about 0.26 s. `UserManager` RPCs
  in the capture were also below 0.25 s. This does not explain the observed
  delay; it suggests the stall is outside those measured calls or that the
  trace did not capture the delayed input interval itself.
- The responsive `MenuProbe` account is local, so it did not isolate a
  domain-profile problem. The fresh domain account `THESSLEYLAB\\startmenutest`
  has now signed in and reproduced the same slow account flyout. This points to
  a machine-wide cause, but the recent Thessley AD sign-in and smart-card lab
  changes remain candidates until isolated. The AD QR flow is phone approval,
  not a passwordless AD credential; this comparison used ordinary Windows
  credentials.
- The client is Windows 11 Pro 26H2, build `26300.9711` (`BuildLabEx`
  `26100.1.amd64fre.ge_release.240331-1435`). WER contains two
  `svchost.exe_UserManager` crashes: at 13:36 in `ntdll.dll` (`0xc0000710`)
  and at 14:52 in `combase.dll` (`0xc0000005`), with a companion `svchost.exe`
  failure in `combase.dll` (`0xc0000602`). The UserManager, ProfSvc, and
  StateRepository services are currently running. No corresponding SCM 7031 or
  7034 event was found in the latest query. A corrected Windows Update scan
  found only a Defender intelligence update, not a newer OS cumulative update
  through the VM's configured update source. Microsoft
  published Release Preview build `26300.9807` on 2026-10-16, later than this
  VM's `26300.9711`; see the [official Insider announcement](https://blogs.windows.com/windows-insider/2026/10/16/announcing-new-builds-for-16-october-2026/).
- An active PnP smart-card reader named `ThessleyADTest`
  (`ROOT\\SMARTCARDREADER\\0000`) was found. It was temporarily disabled on
  2026-10-28 as a reversible A/B diagnostic. The user reported the same delay
  with it disabled; it was then re-enabled and verified `Status=OK`. The
  instance registry contains only `0000`; the follow-up PnP query did not
  reveal additional smart-card reader instances.
- The separate Thessley AD Credential Provider was confirmed registered at
  `{2678765D-9F74-4BDE-A4DA-2B53234BE053}`, with its `InprocServer32` pointing
  to `ThessleyADCredentialProvider-diag-next.dll`. For a reversible A/B test,
  only its Credential Providers and COM CLSID registry trees were exported to
  `C:\\ProgramData\\ThessleyPamWin\\backups\\ad-provider-key-20261028-164901.reg`
  and `ad-provider-class-20261028-164901.reg`, then temporarily removed. The
  provider DLL/data, local Thessley provider, PIN/password options, and virtual
  smart-card reader were preserved. The user reported the delay remained while
  this AD provider was unregistered. This test did not exclude the local
  Thessley provider.
- Analyze the existing ETL with WPA-compatible tooling before capturing
  another large trace. Keep the profile backup and ETL until the current
  machine-wide and provider A/B checks are documented.
- Created enabled disposable AD user `THESSLEYLAB\\startmenutest` and added
  it to `ThessleyADSignInAdmins`, matching Martin's relevant group membership
  without granting Domain Admins. Its temporary password is stored only in
  the ignored, mode-0600 `LOCAL-CREDENTIALS.txt`. It signed in and reproduced
  the slow account flyout, confirming this was not specific to Martin's
  profile.

## Start-menu account flyout resolution: dual-NIC DNS route (2026-10-28)

- The user confirmed the Start-menu profile flyout became fast after correcting
  the secondary NIC's DNS configuration. This identifies the delay as a
  network/DNS path problem encountered by the domain-account WPAD/Netlogon path,
  not a change in the Thessley credential-provider UI.
- Clone1 (`MARTIN-WM`) had two connected IPv4 adapters. The LAN adapter
  `Ethernet` (index 15, `192.168.1.103/24`) used DNS `192.168.1.79` and had
  interface metric 25. The libvirt/NAT adapter `Ethernet 2` (index 9,
  `192.168.122.66/24`) was also configured to use `192.168.1.79`, even though
  that adapter could not reach the DC. Both adapters also had default routes
  with equal route and interface metrics.
- Source-bound checks confirmed the path difference: from `192.168.1.103`,
  TCP ports 53, 88, 135, 389, 445, 464, 3268, and 3269 on the DC
  `192.168.1.79` all connected in 1–28 ms. From `192.168.122.66`, TCP 53 to
  `192.168.1.79` timed out after 4 seconds. DNS requests from `.66` to its
  reachable NAT resolver `192.168.122.1` returned promptly.
- A corrected, source-bound UDP probe showed that the DC answered WPAD names
  promptly through the LAN NIC (`wpad.lab.thessley.test` and `wpad.home` with
  NXDOMAIN; bare `wpad` with SERVFAIL, all within 52 ms). The same requests
  sent from `.66` to `192.168.1.79` timed out after 1.8 seconds. The earlier
  first version of this custom probe had a malformed header and its results
  were discarded; the corrected probe used a complete 12-byte DNS header.
- On `Ethernet 2`, DNS was changed from the unreachable DC resolver
  `192.168.1.79` to the reachable NAT resolver `192.168.122.1`. Its IPv4
  interface metric was changed from automatic 25 to fixed 500, making the LAN
  adapter the preferred default route while retaining the `.66` address and
  direct route to the VM host. The original values are recorded in
  `C:\\Users\\Martin\\wpad-route-before-fix-20261028.txt`.
- After the change, SSH port 22 on `192.168.122.66` remained reachable; the
  active DNS settings were `.103 -> 192.168.1.79` and
  `.66 -> 192.168.122.1`. The default route through `192.168.1.254` is now
  preferred over the NAT gateway route. The user confirmed the profile flyout
  was fast after the DNS correction.
- A separate proxy probe for the intentionally nonexistent host
  `nosuchhost.lab.thessley.test` still took 11.2 seconds to fail. That is not
  the profile-flyout test and should not be reported as a remaining account
  button delay. The temporary WPAD probe task/process has completed; the
  machine currently has `WinHttp\\DisableWpad=1` and policy
  `ProxySettingsPerUser=0` from its A/B test.

### Clone1 network settings and recovery

Keep both NICs on the disposable client: the LAN NIC reaches the domain
controller and the NAT NIC provides the libvirt host's SSH/debug path. Do not
point the NAT NIC at the DC for DNS; the DC is not routable through that NIC.

| Adapter | Address | Gateway | DNS | IPv4 interface metric | Purpose |
|---|---|---|---|---:|---|
| `Ethernet` (index 15) | `192.168.1.103/24` | `192.168.1.254` | `192.168.1.79` | 25 | LAN, AD/DNS, phone reachability |
| `Ethernet 2` (index 9) | `192.168.122.66/24` | `192.168.122.1` | `192.168.122.1` | 500 | Libvirt NAT and host SSH/debug access |

The original adapter values are saved on the VM at
`C:\\Users\\Martin\\wpad-route-before-fix-20261028.txt`. Inspect the live
configuration from elevated PowerShell with:

```powershell
Get-NetIPConfiguration -InterfaceAlias 'Ethernet','Ethernet 2'
Get-DnsClientServerAddress -AddressFamily IPv4
Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceMetric | Format-Table InterfaceAlias,InterfaceIndex,AutomaticMetric,InterfaceMetric
Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Format-Table InterfaceAlias,NextHop,RouteMetric
```

The resulting route preference must keep `Ethernet` ahead of `Ethernet 2`.
If the NAT NIC is accidentally pointed back at the DC, restore only its DNS
and route preference (leave its DHCP address and gateway intact):

```powershell
Set-DnsClientServerAddress -InterfaceIndex 9 -ServerAddresses 192.168.122.1
Set-NetIPInterface -InterfaceIndex 9 -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 500
```

The `.103` and `.79` LAN addresses were DHCP leases during this test. Reserve
them on the router before treating them as permanent; the `.122.66` address
belongs to the libvirt NAT network and should remain dynamically assigned.

## AD QR provider missing on the generic “Other user” tile (2026-10-28)

- The current request is to use Thessley QR sign-in after selecting Windows'
  generic **Other user** tile, including when entering `THESSLEYLAB\\martin`.
  The current provider is registered as
  `{2678765D-9F74-4BDE-A4DA-2B53234BE053}` and loads
  `C:\\ProgramData\\ThessleyPamWin\\ad-credential-provider\\ThessleyADCredentialProvider-diag-next.dll`.
- The prototype currently creates credentials from the Windows
  `ICredentialProviderUserArray` and rejects all SIDs except the single lab
  SID in `windows-logon-provider/ad_lab_vsc_config.h`. It does not yet have a
  generic username-entry credential for Windows' **Other user** identity.
- Temporary local/connected-user enumeration values were set, then removed
  after LogonUI passed three non-target users to this SID-restricted provider
  (`AdLabSidCheck=0`, `CredentialInitialize=0x80070005`,
  `GetCredentialCount=0x8000000A`). The VM was rebooted afterward. Those two
  policy values are currently absent; the local accounts are no longer shown
  in the left list.
- Current screenshot: `THESSLEYLAB\\martin` and **Other user** appear at the
  lower left, with **Other user** selected. Its standard username/password
  form and Windows key/smart-card sign-in options are visible; no Thessley QR
  option appears on that generic tile.
- The LogonUI values currently remember Martin's domain identity and the
  Thessley provider: `LastLoggedOnUser=THESSLEYLAB\\martin`,
  `LastLoggedOnSAMUser=THESSLEYLAB\\martin`,
  `LastLoggedOnUserSID=SelectedUserSID=S-1-5-21-1719900462-4250469598-2954734011-1101`,
  and `LastLoggedOnProvider={2678765D-9F74-4BDE-A4DA-2B53234BE053}`. The
  values were exported to
  `C:\\ProgramData\\ThessleyPamWin\\backups\\LogonUI-before-qr-restore-20261028-current.reg`
  (that export was made after `LastLoggedOnUser` had already been changed).
- After the last LogonUI reload, provider diagnostics showed a successful
  one-user enumeration and matching SID (`SetUserArray count=1`,
  `AdLabSidCheck count=1`, `CredentialInitialize hr=0`,
  `GetCredentialCount count=1`). `ADApprovalStart` returned `S_OK`, then the
  worker ended with `0x80004004`; the log alone does not establish whether the
  QR viewer appeared or why the worker ended. The UI was subsequently left on
  **Other user**, so generic-tile behavior remains unverified and QR sign-in
  from that tile remains unavailable.
- Next investigation must be read-only: compare provider diagnostics when
  selecting Martin's account tile versus **Other user**, and inspect the
  credential-provider/LogonUI state. Do not modify registry values, policy,
  provider files, accounts, or network settings during diagnosis. A proper
  product solution likely needs a separate generic AD credential that accepts
  a qualified username, resolves it to a SID, and obtains server-side policy
  authorization before a phone approval can begin; never infer authorization
  from the typed username alone.

## Separate phone-key certificate-template experiment (2026-10-28)

- SSH maintenance uses the domain-qualified account form
  `Administrator@lab.thessley.test@192.168.122.66`; the unqualified local
  `Administrator@192.168.122.66` is not the same login.
- The test VM reports `MARTIN-WM`, is joined to `lab.thessley.test`, and has a
  ready TPM plus the `ThessleyADTest` virtual smart-card reader.
- The existing `ThessleyVscLogon` / “Thessley TPM Virtual Smart Card Logon”
  template remains unchanged. It uses the Microsoft Base Smart Card Crypto
  Provider, RSA 2048, and its existing restricted enrollment ACL. Its TPM
  virtual-smart-card certificate sign-in is the proven baseline; it does not
  make an Android-held key available to Windows.
- Only the unpublished duplicate `Copy 2 of Smartcard Logon` was changed for
  the Android P-256 certificate experiment: CNG syntax, ECDSA P-256, SHA-256,
  signing-only key usage, 256-bit minimum, and template minor revision 3. Its
  ACL, EKUs, OID, and name settings were preserved. The CA issuance list was
  checked before the update; the duplicate remains unpublished.
- A rollback copy of the duplicate's prior attributes is on the test VM at
  `%TEMP%\thessley-copy2-before-update.clixml`. No CA publication, Windows
  sign-in provider, or existing VSC setting was changed.
- This is only certificate-template preparation. The phone-key smart-card
  signing bridge and an end-to-end AD sign-in are still required.

## Configurable AD sign-in method policy (source implementation)

- `infra/thessley_ad_service/login_policy.py` stores a domain default, priority
  rules keyed by AD group SID, and overrides keyed by paired machine ID in the
  protected AD state database. Resolution is machine override → highest-priority
  matching nested group → domain default; ambiguous matching rules fail closed.
- The Windows AD admin service now mounts `/admin/policy` and lets a domain
  administrator configure those rules. The API returns the selected method and
  policy source; the Windows agent/provider accepts only `tpm_smartcard` for
  the existing TPM-backed approval tile. `windows_native` disables that QR
  route while leaving Windows password/Hello recovery available.
- The phone-issued ephemeral-certificate method is deliberately not selectable:
  its AD CS/KDC proof is incomplete. Per-user effective-policy reporting and
  client capability advertisement are still follow-up work.
- This is source-only and has not been deployed to either lab VM. Before any
  rollout, review the diff, build the Windows package, and verify both methods
  plus group/machine precedence on a disposable snapshot.

## Safe implementation order

1. (Complete for the TPM VSC baseline) The disposable Windows client is joined
   and its secure channel, DNS, time, and interactive domain-user sign-in are
   verified. A TPM virtual smart card has a SmartcardLogon certificate with the
   correct account mapping and a non-exportable key. Windows sign-in succeeded;
   the DC recorded PKINIT pre-authentication type 16 and the matching thumbprint.
   This proves the AD CS/KDC path, not phone-held key signing.
2. (Complete for the lab control plane) The standalone AD service and Windows
   agent authenticate the machine, resolve the selected SID and nested AD
   security groups, and create a short-lived request bound to the machine,
   SID hash, domain authority, context, and nonce. Keep this API separate from
   Drupal and local-account login.
3. (Complete for the approval path) Enroll one phone key for Martin, approve a
   live login request, and receive the one-use result on the initiating client.
   Still exercise denial, expiry, revocation, and cross-machine result refusal.
4. Prototype a distinct `Thessley AD Passkey` Credential Provider with its own
   CLSID and a generic qualified-AD-username tile for **Other user**. Keep the
   current QR password tile, existing TPM smart-card path, and built-in Windows
   PIN/password recovery intact. Never route AD users into the Drupal client
   code.
5. Keep these bridge milestones separate:

   - **Near-term lab bridge: phone approval + TPM virtual smart card.** The
     user approves the SID-bound request on the phone, then supplies the VSC
     PIN. The new provider submits a Kerberos certificate-logon serialization
     for the existing TPM VSC certificate. This demonstrates an AD-domain QR
     approval gate without sending or storing the AD password. The private
     key stays in the computer TPM; this is not phone-key PKINIT and must be
     labeled accordingly.
   - **Target lab bridge: phone authorization + ephemeral, strongly mapped
     certificate.** Validate the Enrollment Agent controls, actual KDC
     authentication, and guaranteed cleanup before connecting it to LogonUI.
     Do not claim the phone key itself performs PKINIT; it authorizes one
     short-lived certificate for one account and machine.

   The VSC bridge is opt-in and does not replace or silently change the
   phone-held-key design. Stop before installation if it requires weakening
   Windows recovery or changing the existing VSC template.
6. First validate provider serialization and the TPM certificate on the
   disposable VM without registering a provider or touching LogonUI. Install
   only with automatic rollback and a tested recovery route. Then test
   interactive sign-in, lock/unlock, denied and expired requests, network
   loss, phone revocation, machine revocation, and fallback.

## Windows cryptographic bridge choice

The existing `ThessleyVscLogon` path proves AD smart-card sign-in: Windows asks
the TPM virtual smart card to use its local, non-exportable RSA key and the KDC
validates its certificate. It is an important baseline, but it does not expose
the Android key or make the phone the PKINIT signer. Keep its template and card
unchanged.

Windows also defines a certificate credential serialization containing the
domain, selected user, smart-card PIN, and smart-card provider data. That makes
the VSC path a plausible isolated bridge experiment: a new Thessley AD provider
could require a fresh phone approval and then submit the existing VSC
certificate credential. It must obtain the certificate/container metadata
from the actual card and must never substitute a password tile. This adds
phone approval to a computer-held TPM credential; the VSC PIN and TPM
requirements remain, and the phone's private key is not used for PKINIT. It is
a stepping stone, not the phone-held-key end state.

The domain certificate is in Martin's domain-user certificate context, not the
separate local SSH maintenance account's `CurrentUser` store. A remote metadata
inspection under the maintenance account therefore returns no certificate and
must not be treated as evidence that the VSC enrollment is missing. Inspect it
from an interactive `THESSLEYLAB\martin` session or a narrowly scoped task
running as that identity. Do not issue, remove, or replace certificates as part
of this inspection.

`inspect-vsc-user-certificate.ps1` is a read-only helper for that interactive
domain session. It reports certificate and provider/container metadata without
exporting the key or requesting a signature. It deliberately refuses to run
under the local SSH maintenance identity.

The separate `ad-prototype/credential-serialization/` spike now builds a
standalone Kerberos smart-card serialization object. It requires a
CredProtect-protected PIN, takes card metadata and the Kerberos auth package
from a future provider, and does not call LSA or register a provider. Martin's
VSC certificate reports CNG `dwProvType = 0`, `dwKeySpec = 0`. That certificate
metadata is distinct from `KERB_SMARTCARD_CSP_INFO.KeySpec`, which Microsoft
documents as `AT_KEYEXCHANGE` (1) or `AT_SIGNATURE` (2). `certutil -key -csp SC`
identifies the actual VSC container as `AT_KEYEXCHANGE`, so the provider uses
1. Serialization with zero caused `STATUS_SMARTCARD_SUBSYSTEM_FAILURE`
(`0xC0000321`); serialization with 2 caused `STATUS_SMARTCARD_NO_KEY_CONTAINER`
(`0xC0000384`). The provider now matches the key spec reported by the actual
container. The failure persisted after matching the key spec and supplying the
PnP reader label. Local System's `certutil -scinfo -sid 22` reports the actual
reader as `Microsoft Virtual Smart Card 0`, card profile `Identity Device
(Microsoft Generic Profile)`, and a legacy `Microsoft Base Smart Card Crypto
Provider` container with `AT_KEYEXCHANGE`. The provider now serializes that
exact CSP/reader/card/key-spec combination and logs nonsecret stage results plus
numeric auth statuses, never the PIN or account identity. On 2026-10-28 the
AD lab VM completed sign-in: serialization returned success (584 bytes) and
LogonUI reported `STATUS_SUCCESS`. Automatic rollback was stopped after this
verified result. This confirms the isolated TPM VSC path only; direct phone-key
PKINIT remains unimplemented. See the credential-serialization README for
the diagnostic event list and limits. The
Microsoft structures and layout are documented at [KERB_CERTIFICATE_LOGON](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon)
and [KERB_SMARTCARD_CSP_INFO](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info),
and CNG key metadata at [CRYPT_KEY_PROV_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info).

For direct phone-key AD sign-in, prefer the Windows smart-card Base CSP/KSP
plus a card minidriver if the prototype can expose the phone key through a
supported PC/SC reader path. The minidriver is the card-specific interface
Windows already uses for smart-card cryptographic operations, including ECC.
This does **not** make a Windows Credential Provider alone sufficient: a usable
reader/card interface and the exact smart-card logon serialization path still
need to be demonstrated. Do not silently substitute the TPM VSC's local key
for the phone's enrolled key; that would change the design to phone-approved
use of a computer-held credential.

A custom CNG KSP is an alternate route, not a small wrapper around the existing
credential provider. It needs Microsoft's Cryptographic Provider Development
Kit and must implement key discovery, properties, signing, error handling, and
provider registration. Microsoft documents that third-party KSPs are not
loaded in the CNG key isolation service, so do not assume a custom KSP can
perform the LSA/PKINIT operation; prove that call path before investing in it.
The minidriver route also has a signing gate: a driver loaded into protected
LSA must satisfy Microsoft's driver-signing requirements. Do not enable test
signing on the joined client. The existing `ThessleyCredential.cpp` remains an
approval-gated password provider and must not be changed into a password cache.

References: [Smart-card architecture](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture),
[smart-card minidriver overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview),
and [CNG provider development](https://learn.microsoft.com/en-us/windows/win32/seccng).

### Existing virtual-reader project: useful reference, unsafe default installer

The upstream [`vsmartcard`](https://github.com/frankmorgner/vsmartcard)
project's Windows virtual reader (`vpcd`) and remote virtual-card endpoint
(`vpicc`) are useful architecture references. Its Android Remote Smart Card
Reader is different: it relays the phone's NFC reader to a physical
contactless card and does not expose Thessley's Android Keystore key.

Do **not** install the upstream `virtualsmartcard-0.11` Windows package on the
joined lab client. Its installer requires Windows `testsigning` mode, installs
the project's test certificate into the machine Root and Trusted Publisher
stores, and its MSI opens TCP 35963 inbound on all firewall profiles and
addresses. The remote-card TCP protocol is also unencrypted. These settings
would weaken the test machine and expose the smart-card channel. A future
isolated VM experiment would need its own snapshot, time-limited test-signing
window, firewall scope restricted before the listener starts, and verified
cleanup. Do not copy GPL-licensed code into Thessley without a deliberate
license review. This project is research only, not a passwordless-login
implementation. Microsoft's [CNG key-storage documentation](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval)
notes that third-party KSPs are not loaded into the key isolation service;
the [minidriver documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview)
describes the Microsoft-signing requirement for drivers loaded into protected
LSA.

The Windows lab client currently has only the Microsoft TPM reader
(`ThessleyADTest`, `tpmvsc.inf`); testsigning is off and no vpcd listener or
firewall rule is present. Leave that state as-is. Do not switch this joined
client into test-signing mode to try the upstream driver.

## Required trust checks

- Identify the account by the SID selected by LogonUI, then resolve that SID
  against AD. Never use a typed username alone to choose an AD principal.
- Bind every challenge to a random request ID, nonce, machine ID, SID hash,
  domain authority, context (`interactive` or `unlock`), and short expiry.
- Authenticate the Windows machine to the standalone service with a distinct
  machine credential. A phone approval must be returned only to the machine
  that initiated the challenge.
- Read group authorization from AD over authenticated LDAPS. Ignore any
  client-provided group names. If AD or the approval service is unavailable,
  refuse Thessley sign-in and leave Windows recovery providers available.
- Never store or release a domain password in the standalone AD path.

## Phone-held Administrator CSR proof (2026-10-30)

- Clone 1 was reachable over the existing SSH key as `THESSLEYLAB\martin`;
  the current token includes local Administrators. The installed
  `thessley-ad-test.cmd` was zero bytes, so it was backed up and regenerated
  from the checked-in launcher contract. The launcher now runs the installed
  AD CLI and its `--help` import check succeeds. The backup is beside the
  launcher with suffix `.before-repair-20261030010301`.
- The phone's active `THESSLEYLAB\Administrator` key is `verified_tee` in the
  DC registry. The Android app exported a public PKCS#10 CSR using that key.
  Its ECDSA self-signature verified, and its SPKI SHA-256 exactly matches the
  active DC key record. The private key remained in Android Keystore.
- The CSR was 223 bytes DER with `CN=Thessley AD Logon Key`. The source had
  incorrectly required at least 256 bytes and the Windows pilot's randomized
  subject, so it rejected the valid phone request. The local source now accepts
  this EC profile and checks its SPKI hash against an active AD logon key for
  the approved SID before CSR upload, issuer claim, and certificate acceptance.
  The HTTP base64 lower bound and issuer CLI size checks now admit this valid
  request size.
- Focused CSR/challenge tests pass. The full service test suite still has
  unrelated environment failures: sandbox socket creation is denied in HTTPS
  tests, and existing untracked directory/enrollment tests have expectation
  mismatches. The service change has not been deployed.
- The live DC config has `certificate_template: null`; the certificate method
  remains disabled and no certificate was issued. The published template list
  does not include the existing duplicate Smart Card Logon template; its
  current configuration has auto-enrollment enabled and broad ACLs, so do not
  publish it as-is. The next CA step is a dedicated duplicate with automatic
  enrollment off and narrowly scoped enrollment rights, followed by a
  restricted Enrollment Agent path. Windows sign-in still requires a supported
  phone-backed Kerberos signing bridge and must not be marked active before a
  real interactive PKINIT test.

