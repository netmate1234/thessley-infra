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

## Enable for one test account

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

The script backs up `sshd_config`, arms a separate scheduled rollback first,
adds an exact `Match User thessleylab\martin` rule, validates the config and
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
and isolated ForceCommand gate are implemented in source. The new config
script is opt-in and source-only. It has not been run on the VM or validated
against the live domain SSH username representation; verify with `sshd -T`
before relying on the rule. The API approval is a second factor around SSH,
not passwordless AD logon.
