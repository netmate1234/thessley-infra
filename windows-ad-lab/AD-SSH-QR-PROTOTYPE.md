# AD account SSH QR approval prototype

This is a development path for one domain account on the disposable Windows
client. It is separate from the existing local-account SSH QR gate and the
experimental Windows sign-in tile. It does not modify the tile, its rollback,
or an existing `sshd_config` until an administrator explicitly runs the
opt-in script below.

## Request flow

1. Windows OpenSSH authenticates the domain account using its existing SSH
   method (normally a public key). A scoped `ForceCommand` starts
   `ad-ssh-gate.cmd` for that one account.
2. The gate reads the account SID from its Windows process token and connects
   only to the local Thessley SYSTEM service on `127.0.0.1:47800`.
3. The SYSTEM service verifies the loopback peer process token has that exact
   SID and is a domain user. It then uses the machine-protected AD service key
   to start an `ssh` approval request. The API checks that SID against the
   computer's allowed AD group.
4. The PC prints a Thessley QR link. The Android phone connects to the
   **Thessley AD API** and signs the SID-bound request with its enrolled key.
   The PC polls the API over certificate-pinned HTTPS. An approval permits the
   already-authenticated SSH session to continue; it does not replace the SSH
   key/password factor or create an AD credential.

When the Windows service's global SSH grace duration is greater than zero, a
successful AD approval creates a pass for that domain SID and configured IP
scope. Reuse still checks the SID's current AD authorization and that the
approving phone key remains active. Passes are separate from same-named local
Windows accounts, expire at a fixed time, and are not extended by reuse. Set
the duration to zero to require phone approval on every SSH connection.

The phone does **not** connect to the Windows PC or talk to the domain
controller directly. It talks to the AD approval API. The API, in turn, checks
AD authorization. For this lab the API is hosted on the DC, but that is a lab
topology choice, not a requirement of the protocol.

## Network access and VPN

The API uses **TCP 47810** for machine requests and phone responses. It is the
only inbound port needed for this QR approval exchange. Restrict it to the
VPN client subnet and the Windows client address (or client VPN subnet) that
must reach the API. Do not expose TCP 47810 to the public internet.

On the current lab, the DC API firewall rule is named
`Thessley AD API TCP 47810 (LAN)`. From elevated PowerShell on the DC, an
example for VPN clients in `10.8.0.0/24` and the Windows client at
`192.168.1.103` is:

```powershell
$rule = Get-NetFirewallRule -DisplayName 'Thessley AD API TCP 47810 (LAN)' -ErrorAction Stop
$addressFilter = $rule | Get-NetFirewallAddressFilter
$addressFilter | Set-NetFirewallAddressFilter -RemoteAddress @('10.8.0.0/24', '192.168.1.103/32')
($rule | Get-NetFirewallAddressFilter).RemoteAddress
```

For a fresh AD API installation, the installer accepts the same restriction
directly; omitting this parameter preserves an existing rule's source list:

```powershell
& '.\install-windows-service.ps1' -AllowedRemoteAddresses '10.8.0.0/24','192.168.1.103/32'
```

Use the actual VPN pool and Windows client IPs in your deployment. The phone
must have a route through the VPN to the API's configured address. If the
Windows client also reaches the API through that VPN, allow its VPN source
instead of its LAN address. The VPN gateway must route/forward only the
required traffic to the API host and port; a VPN client address alone does not
create that route. Keep the VPN server's own listener (for example, its
OpenVPN UDP port) open only on the VPN gateway as needed.

This firewall restriction is for **phone approvals and Windows-to-API HTTPS**.
It does not provide the Windows client with domain connectivity. Domain SSH
authentication and normal domain account use still need the required DNS,
Kerberos, LDAP, SMB, and other AD traffic to the domain controller, according
to the domain/network design. Keep those rules separate from the one-port
Thessley approval rule.

## Enable for a workstation administrator group

For the lab's multi-admin setup, the API allowlist and workstation SSH gate use
the AD security group `THESSLEYLAB\ThessleyQRWorkstationAdmins` (SID
`S-1-5-21-1719900462-4250469598-2954734011-1107`). It contains `Domain Admins`
and explicitly selected workstation administrators. The disposable
`startmenutest` account is intentionally excluded. Keep group membership as the
central access control: add or remove a user in AD instead of editing each
PC's `sshd_config`.

The group is mapped into local `Administrators` on each managed workstation,
so an authorized member retains administrator rights after SSH authentication.
The AD QR approval remains a second factor; members still need a valid
Windows SSH authentication method and a phone enrolled for their SID on each
PC. A Windows domain account is distinct from a same-named local account.

On each domain-joined Windows Pro workstation with the AD agent and its
approval service installed, copy this directory's `enable-group-ad-ssh-qr.ps1`
to the workstation, then run it from elevated PowerShell in that directory.
It backs up `sshd_config`, arms and verifies a 15-minute SYSTEM rollback,
maps the AD group to local Administrators, replaces the prototype's exact
per-user AD gate block with a group `Match`, validates `sshd_config`, and
restarts `sshd`. Members of this group are sent through the AD gate; other
accounts retain their existing SSH policy. Keep a maintenance SSH session
open. Then test a second
interactive connection using a group member whose phone is enrolled:

```powershell
& '.\enable-group-ad-ssh-qr.ps1' `
  -Domain 'THESSLEYLAB' `
  -GroupSamAccountName 'ThessleyQRWorkstationAdmins' `
  -RollbackMinutes 15
```

The reusable source is `enable-group-ad-ssh-qr.ps1` in this directory. The
installer reports its backup and rollback task. Only stop that task after a
new QR-gated SSH login succeeds. If the test fails, the task restores the
previous SSH config and removes the local admin mapping it added. Repeat the
installer on every workstation where this access policy should apply; never
link it to or run it on the domain controller.

The AD API must allow this group's SID in its protected `service.json`
`allowed_group_sids` list. After changing that policy, restart the API and
verify that the client listener remains available. Adding a different group
to a machine's local `Administrators` group alone does **not** make it
eligible for QR approval; both the API allowlist and the workstation gate must
use the intended group.

## Enable for one test account (legacy prototype)

The package installer places `ad-ssh-gate.cmd` but does not change SSH policy.
From an elevated PowerShell in the extracted Windows package source folder,
first ensure the Windows client is paired to the AD API, the phone is enrolled
for that client and domain SID, and AD group authorization passes. Keep an
existing administrator SSH session open. From elevated PowerShell on the test
client, run the opt-in installer with the domain's NetBIOS name and exact
account name:

```powershell
& '.\install\enable-ad-ssh-qr.ps1' -Domain 'THESSLEYLAB' -UserName 'martin' -RollbackMinutes 15
```

The legacy script backs up `sshd_config`, arms a separate scheduled rollback
first, adds an exact `Match User thessleylab\martin` rule, validates the config and
effective ForceCommand, then restarts `sshd`. It leaves the account's current
SSH authentication methods in effect. Test a **new second** connection. The
first SSH factor must still succeed, then the approval QR should appear and
the session should continue only after phone approval. If it works, stop only
this SSH-config rollback from elevated PowerShell:

```powershell
& '.\install\confirm-ad-ssh-qr.ps1' -Domain 'THESSLEYLAB' -UserName 'martin'
```

Otherwise wait for the timer to restore the exact original SSH config. Do not
use the Windows sign-in tile's rollback/confirmation command for this timer.

This gate is for shell and remote-command SSH sessions. SFTP subsystem
sessions are not supported yet. Keep the test to one account and retain an
out-of-band or already-open administrator session until separately testing
recovery. Do not widen it to all domain users based on this prototype.

## Current development boundary

The AD service's `/requests` route, machine signature, SID-bound phone
signature, Android `ssh` context label, Windows SYSTEM-side approval request,
and isolated ForceCommand gate are implemented in source. The per-user script
is retained for the original one-account prototype. The group-based installer
is the current lab path and is applied separately to each intended workstation.
The API approval is a second factor around SSH, not passwordless AD logon.
