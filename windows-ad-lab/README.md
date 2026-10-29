# Thessley passwordless AD lab

This is a disposable Windows Server 2025 evaluation lab for validating QR-mediated, certificate-based Windows domain sign-in. It is not a production AD design.

For the proposed school setup—central phone enrollments, one-time workstation pairing, separate student/staff and IT groups, and what the prototype still lacks—see [SCHOOL-ROLLOUT-MODEL.md](SCHOOL-ROLLOUT-MODEL.md).

For the generic AD **Other user** sign-in target, its current blocker, and the proof gates before changing Windows logon, see [OTHER-USER-AD-TILE.md](OTHER-USER-AD-TILE.md).

## Lab layout

For a concise map of the current management addresses, SSH commands, phone
approval route, firewall scope, and remote access limitations, see
[`ACCESS.md`](ACCESS.md).

- Forest: `lab.thessley.test` (`THESSLEYLAB` NetBIOS name)
- Server: `THESSLEY-DC1`, primary NIC attached to the `192.168.1.x` LAN; a second libvirt NAT NIC provides host-only management
- Server roles: AD DS, DNS, and an Enterprise Root CA on the same VM for lab use only
- Test account: `martin` (ordinary domain user)
- Input layout: Swedish (`sv-SE`)
- Evaluation media: Windows Server 2025 Standard Evaluation Core

The DC VM uses a fixed virtual MAC. Its direct LAN address is now statically
configured as `192.168.1.79/24` with gateway `192.168.1.254` and itself as DNS;
the libvirt management address is
`192.168.122.98`. The Windows client is also directly on the LAN at
`192.168.1.103`, as well as its management address `192.168.122.66`. The
phone reached the DC's LDAPS and Thessley API ports from Wi-Fi and reached the
client over TCP. The DC's static address was previously its DHCP lease; reserve
or exclude it on the router (`192.168.1.254`) to prevent a later duplicate.
SSH on the management NIC is allowed only from the hypervisor gateway
`192.168.122.1`.

## Access and credentials

From the Ubuntu hypervisor, connect to the lab machines over their management
addresses with the local debug key:

```bash
ssh -i ~/.ssh/thessley-vm-debug Administrator@192.168.122.98
ssh -F /dev/null -l 'martin@lab.thessley.test' 192.168.122.66
```

The first command reaches the domain controller; the second reaches the Windows
client. The client SSH session uses the domain account `THESSLEYLAB\martin`.
The host accepts the hypervisor's existing SSH key; private keys remain on the
hypervisor and are not included in this repository. `-F /dev/null` bypasses
local SSH aliases and keeps this command explicit. SSH may request a Thessley
phone approval; approve that request before continuing.

### Group based AD SSH and workstation administrators

The AD API and managed workstation gate now use
`THESSLEYLAB\ThessleyQRWorkstationAdmins` (SID
`S-1-5-21-1719900462-4250469598-2954734011-1107`). It contains `Domain Admins`
and the explicitly selected user `martin`. It intentionally does not include
the disposable `startmenutest` account. On clone1, this group is mapped into
local `Administrators`, so its authorized members retain local administrator
rights. The SSH gate invokes the AD QR approval for members of this group.

`martin` must start a fresh domain SSH session after group changes so Windows
builds a new logon token. The login still requires a valid SSH key/password;
the phone approval adds a second factor and does not replace the Windows
credential. Each user must enroll their phone for that computer. To apply the
same policy to another managed workstation, install/pair the AD agent, copy
`enable-group-ad-ssh-qr.ps1` from this directory to the host, and run it from
elevated PowerShell. It arms a verified rollback before changing `sshd_config`
and local Administrators membership; keep the maintenance session open and
confirm only after a new QR-gated SSH login succeeds. Do not run it on the DC.

The `THESSLEYLAB\Administrator` maintenance SSH path is also behind the group
QR gate. Keep the automatic rollback armed until the fresh phone-approved
domain SSH login is verified; if it is not confirmed, the timer restores the
prior `sshd_config`. The local-account Thessley gate and Windows sign-in tiles
remain separate.

The group-based SSH session should have an enabled Administrators SID and a
High Mandatory Level token. Verify before making machine-level changes:

```powershell
whoami /user
whoami /groups
[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

This elevation applies only to the disposable `MARTIN-WM` client. SSH is
firewalled to the hypervisor management gateway (`192.168.122.1`); it does not
open SSH to the physical LAN. Do not store the user's password or SSH private
key in this repository. This admin mapping is for lab administration and does
not make `martin` a Domain Admin.

Lab passwords and account SIDs are kept only in the ignored local file
`LOCAL-CREDENTIALS.txt` beside this README. It has mode `0600`; it is excluded
from Git and must not be copied into commits, release packages, or public
documentation. It records the DC's local/Domain Administrator and DSRM
credentials, the ordinary domain user `martin`, and the Windows client's local
administrator credential. Use the domain Administrator credential only for
joining or administering this disposable lab; use `THESSLEYLAB\martin` for
ordinary domain sign-in tests.

## Current lab state

- Forest and DNS: `lab.thessley.test` / `THESSLEYLAB`; AD DS, DNS, KDC, Netlogon, ADWS, and Certificate Services are running.
- The two active Windows VMs are `MARTIN-WM` (`192.168.122.66`, Windows 11 Pro client) and `THESSLEY-DC1` (`192.168.122.98` management address; `192.168.1.79` LAN address). The client has 8 GiB assigned; the DC has 4 GiB. Both were running during the 2026-10-27 session. The client SSH service is running and `Test-ComputerSecureChannel` succeeds against `lab.thessley.test`.
- The separate AD API is running on the DC as the `ThessleyADApi` LocalSystem startup task at `https://192.168.1.79:47810`. Its firewall rule allows TCP 47810 only from `192.168.1.0/24`. Its protected `service.json` allowlist now contains only `ThessleyQRWorkstationAdmins`. The client’s signed API check and group authorization check succeeded after this change. The existing standalone local-login service, the Thessley QR tile, and the TPM virtual smart-card template/card were left unchanged.
- The Windows client is paired to the AD API with its own machine key. `authorization-check --user THESSLEYLAB\martin` confirmed the dedicated AD group policy allows that account. Martin’s phone is enrolled for this machine, and an AD QR approval test succeeded on 2026-10-28. This verifies phone approval only; the AD passwordless Credential Provider/PKINIT bridge is not installed.
- A separate AD-account SSH QR gate is configured for the workstation administrator group on clone1. See [AD-SSH-QR-PROTOTYPE.md](AD-SSH-QR-PROTOTYPE.md) for the request flow, group policy, firewall restriction, and rollback process.
- The source tree now has a configurable AD sign-in method policy at
  `infra/thessley_ad_service/admin_web.py` and `login_policy.py`; it supports
  domain, AD-group, and paired-workstation rules for the TPM-backed QR tile or
  disabling Thessley QR in favor of Windows-native sign-in. This update is not
  deployed to the lab. The phone-issued certificate option remains locked until
  its KDC path is proven.
- DC time: timezone `Romance Standard Time` (Paris); Windows Time uses `time.windows.com` and advertises the DC as reliable. The DC had been eight hours ahead on its local CMOS clock; correct and verify time before any future domain join.
- Enterprise root CA: `THESSLEY-LAB-CA`.
- CA templates enabled: `KerberosAuthentication` and `SmartcardLogon`.
- A machine certificate with the KDC Authentication EKU has been issued to the DC.
- Test user: `martin` (`martin@lab.thessley.test`), not a Domain Admin. The local-only credential file records lab passwords and the user's SID.
- `martin` belongs to the global security group `ThessleyQRWorkstationAdmins`, alongside the nested `Domain Admins` group. It grants the selected members workstation administrator access; it does not change their Domain Admin status.
- On `MARTIN-WM`, `ThessleyQRWorkstationAdmins` is a member of local `Administrators`. Other domain-joined PCs need the same group-to-local-Administrators mapping and the group SSH gate before this policy applies there.
- The AD service allowlists only the `ThessleyQRWorkstationAdmins` SID. Do not widen it to `Domain Users`.
- The CA's `SmartcardLogon` Enroll right is granted only to `THESSLEYLAB\martin` for this lab.
- Windows client `MARTIN-WM` is joined to the forest. DNS discovery, DC ports 53/88/389/445, machine secure channel, and time source all pass the read-only verifier.
- Four SmartcardLogon certificates were issued during enrollment troubleshooting. They are now in the interactive domain user's `CurrentUser\My` store; all pass checks for the Smart Card Logon and Client Authentication EKUs, UPN, matching strong SID extension, private key, and validity. The private keys are non-exportable software keys. The VSC baseline sign-in has now succeeded; leave these certificates in place until the VSC test is repeated after a reboot, then revoke unused certificates.
- A separate `ThessleyVscLogon` template is registered with a forest-unique enterprise OID and published by the CA. Its Enroll ACL is limited to Martin and domain administrators. A TPM virtual smart card was created, and a fifth certificate was issued through the `Microsoft Smart Card Key Storage Provider`; Windows reports its private key as non-exportable. The card's lab PIN is stored only in the ignored `LOCAL-CREDENTIALS.txt`. Certificate-based domain sign-in is verified: the KDC recorded pre-authentication type 16 with the VSC certificate thumbprint `12693C9F323CC1F4C54616237F10ECC2ABA7CBF1` at 18:00 on 2026-10-27. Password recovery remains available. The existing software certificates have not been revoked.
- The temporary local batch-logon grant and scheduled enrollment tasks have been removed. The VSC test validates AD CS/KDC certificate sign-in only; none of these keys is the phone's protected signing key.

## Initial setup

1. Install Windows Server 2025 Standard Evaluation Core on the isolated libvirt VM.
2. Connect the primary NIC to the physical `enp1s0` LAN with macvtap/bridge mode. Add the libvirt default NAT NIC only for host management; its Windows Firewall SSH rule must stay limited to `192.168.122.1`.
3. Attach `configure-domain-controller.ps1` to the VM as a read-only CD and run it in elevated PowerShell.
4. The script sets Swedish input, renames the server, installs AD DS, promotes the forest, configures AD CS, and creates the ordinary `martin` test account. Run it again after the rename and forest-promotion restarts. If the first post-promotion boot has not started NTDS yet, the script performs one recovery restart rather than starting a second promotion.
5. The DC Kerberos Authentication certificate has been issued and its KDC Authentication EKU verified. The Windows client is joined and its secure channel is verified. `martin` has SmartcardLogon certificates in the persistent user store and the SID/EKU/private-key verifier passes. The TPM VSC certificate has also completed a Windows sign-in and produced certificate pre-authentication at the KDC. Do not treat the template or lab setup as production-ready.

## Joining the disposable client

1. Confirm the DC is running and retains its static LAN address (`192.168.1.79`). Verify that address is excluded/reserved on the router so another DHCP client cannot claim it. Do not start the client if host memory is low; shut down unrelated VMs first.
2. Log in to the client with its existing local administrator account, open elevated PowerShell, and run `join-domain-client.ps1` from the `THESSLEYJOIN` CD. It sets active adapter DNS resolvers to the DC's LAN address, disables DNS registration on non-LAN adapters, checks the AD SRV record, synchronizes time from the DC, and prompts for the domain Administrator password in the console before joining. If setup fails, it restores prior DNS resolver and registration settings.
3. After the restart, sign in as `THESSLEYLAB\martin` with the lab test-account password. This interactive sign-in creates the persistent domain user profile needed for user certificate enrollment.
4. Run `verify-domain-client.ps1` from PowerShell to check domain membership, LAN DNS, DC ports, secure channel, time, account SID, and any enrolled SmartcardLogon certificate. It is read-only and exits with a nonzero status if a required check fails.
5. From a `THESSLEYLAB\martin` interactive session, run `enroll-smartcard-certificate.ps1`. It requests the certificate explicitly into `Cert:\CurrentUser\My`, then runs `verify-smartcard-certificate.ps1` to check the EKUs, UPN, private key, expiry, and SID mapping. This lab certificate does not implement phone-backed private-key signing.
6. For the TPM virtual smart-card experiment, run `enable-vsc-logon-template.ps1` on the DC, then run `create-vsc-system-task.ps1` elevated on the client. In the signed-in domain user's interactive session, use `start-vsc-enrollment-task.ps1` with `request-vsc-certificate.cmd`. Use `verify-vsc-certificate.cmd` to inspect the issued certificate and provider; `inspect-vsc-reader.cmd` runs `certutil -scinfo` without changing the card. These scripts do not modify Windows sign-in providers. Keep the password recovery path available.

## Thessley AD sign-in group mapping

The lab user's AD group membership and the client-local administrator grant are
separate steps. On the DC, run `create-test-admin-group.ps1` elevated; it is
idempotent and creates the dedicated group and adds `martin`. On the disposable
client, run `map-test-admin-group.ps1` elevated; it maps only that group to the
client's local Administrators group. New group membership is reflected in a
domain user's logon token after signing in again. Do not add `martin` to Domain
Admins. The service's allowed group SID must match the dedicated group's SID.

There are two distinct Windows sign-in paths. The existing Thessley QR tile
gates a **local Windows account** and remains the supported path for Windows
Home. The AD prototype is a separate domain-account path for domain-joined
Windows Pro or higher; it must not replace or alter the local tile. Microsoft
lists Active Directory domain join for Pro and higher editions, not Home. Keep
the normal PIN/password providers available for recovery. See Microsoft's
[Credential Providers guidance](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
and [Windows edition requirements](https://learn.microsoft.com/en-us/windows/security/licensing-and-edition-requirements).

The script prompts for the DSRM and test-user passwords. Local-only credentials are recorded in the ignored `LOCAL-CREDENTIALS.txt`; never commit or distribute that file. The local/domain Administrator password is managed separately.

The DC setup script binds DNS to the LAN IPv4 address and removes the controller's NAT and IPv6 addresses from its host, zone-apex, and Global Catalog A/AAAA records. Before changing DNS, it saves the previous listener, client resolver settings, and affected records under `C:\ProgramData\Thessley\ADLab\DnsBackup`. Reserve the LAN address on the router so this binding remains valid.

### Optional host-only SSH management

`enable-client-ssh.cmd` starts the PowerShell setup with a UAC prompt. The script installs the Windows OpenSSH Server capability, installs a supplied Ed25519 public key for the selected local user and administrator accounts, and opens TCP 22 only from the libvirt management gateway (`192.168.122.1` by default). The matching `.pub` file must be beside the script and is not part of the repository. It disables the broad inbox OpenSSH firewall rule, does not change password or Windows sign-in policy, and leaves all other firewall rules intact.

## Why the lab uses certificates

The phone key must authorize a Windows credential that the domain controller can validate through Kerberos PKINIT. A QR approval by itself is not an AD credential. The next client-side work is a Windows credential-provider and remote signing bridge for the phone key, plus account/SID enrollment and revocation in Thessley.

## Standalone Thessley AD sign-in direction

The AD QR sign-in path must not depend on the Drupal server or Drupal user roles.
Active Directory is the authority for account SIDs, domain groups, and computer
authorization. AD CS issues the test logon certificates. Use a standalone
Thessley approval service for phone enrollment and approval; it can run beside
the existing Thessley PAM service, but it must read authorization directly from
AD over a protected LDAP connection. Its AD identity should be read-only except
for narrowly scoped certificate or enrollment operations that are explicitly
required. Do not install this service on a domain controller for a production
deployment.

The AD flow should be a separate Windows sign-in tile beside the existing
Thessley tile. The current tile gates the selected account's existing password;
it is not passwordless AD sign-in. Keep that tile and Windows PIN/password
recovery unchanged. The AD tile must identify the selected account by its SID and domain,
request a fresh approval from the standalone Thessley service, and then allow
Windows to authenticate to the KDC using that account's certificate. It must
not cache or release the account password as a substitute for certificate
authentication. Approval-only 2FA and passwordless certificate logon are
separate milestones: the former gates an existing credential; the latter needs
Windows to perform PKINIT with the phone-protected private key.

### Next milestones

1. (Complete) Join the disposable Windows client, validate DNS, time,
   connectivity, its secure channel, and an interactive domain-user sign-in.
2. (Complete for the TPM VSC baseline) Martin's SmartcardLogon certificate has
   the expected EKUs, UPN, strong SID mapping, and non-exportable private keys
   in the user store. A separate certificate was issued to the TPM virtual smart
   card; Windows sign-in succeeded, and the KDC audit log recorded certificate
   pre-authentication type 16 with the matching thumbprint. This validates the
   AD CS/KDC baseline independently of phone integration.
3. Define the standalone service API for pairing a Windows account SID, phone
   key, and machine key; querying AD group membership; starting and polling a
   signed phone approval; and revoking either key. Drupal is not in this flow.
4. Connect the Windows credential provider to that service and prove the
   phone-held key can complete the certificate signature needed for PKINIT.
   A custom credential provider alone does not make an Android TEE key appear
   as a Windows smart card. A supported smart-card/KSP bridge or equivalent
   signing provider is needed.
5. Use AD security groups and domain policy to grant logon rights and local
   administrator membership. Keep PIN/password recovery available until the
   phone-backed certificate flow is proven through reboot and lock/unlock.

The current phone-authorized ephemeral-certificate route is still unproven.
The live DC inspection on 2026-10-29 found that `Copy 2 of Smartcard Logon`
is unpublished but has no required Enrollment Agent signature (`RA-Signature
is unpublished but has no required Enrollment Agent signature (`msPKI-RA-Signature=0`)
and grants Martin the Certificate-Enrollment extended right. Do not
publish that template. The exact checkpoint and the CSR-bound phone approval
contract are documented in
[`OTHER-USER-AD-TILE.md`](OTHER-USER-AD-TILE.md#live-certificate-issuance-checkpoint-2026-10-29).

The detailed standalone service boundary and API plan is in
[`STANDALONE-THESSLEY-SERVICE.md`](STANDALONE-THESSLEY-SERVICE.md).
The current code boundaries and safe implementation order are mapped in
[`IMPLEMENTATION-MAP.md`](IMPLEMENTATION-MAP.md).

Microsoft references: [smart-card sign-in flow and certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration), [certificate credential serialization](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon), [strong certificate mappings](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/95c6f0e3-3565-41d7-80ed-2333c4c5e107), and [smart-card minidriver architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview).

Microsoft’s current requirements and flows:

- [Windows smart-card sign-in and certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [Windows credential providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [AD CS Certification Authority installation](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority)
