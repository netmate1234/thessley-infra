# Windows phone approval and password sign-in

## Current Clone 1 deployment

The experimental Thessley AD credential provider is installed on the disposable
Windows 11 Pro Clone 1 VM. Known domain accounts have a named Thessley AD tile;
the **Other user** credential handles domain accounts not listed on the PC.
Both resolve the account through the paired AD service, request phone approval,
and only then expose the Windows password field. The password is not saved.

The generic credential is associated with Windows' **Other user** entry, so it
does not create another named user in the left-side account list. Select Other
user and choose the Thessley AD Passkey sign-in method for accounts that have
never appeared in the list. For a named domain account, select that account and
use its Thessley AD Passkey tile.

Named domain tiles do not require per-PC Thessley enrollment. The client sends
the selected account SID to the paired AD service, which must authorize the
account and confirm an enrolled phone before issuing an approval request.
Unlisted or new domain accounts use the username-first Other user flow. The
separate local provider checks the local SAM SID and does not show its local
recovery tile for domain accounts.

On Clone 1, the unused local Thessley chip tile, Windows Smartcard tile, and
isolated AD ticket-test tile are hidden by the machine-wide
`ExcludedCredentialProviders` policy. The Thessley AD Passkey tile is retained.
The local chip and ticket-test providers are also removed from the active
Credential Provider registration; their registry keys are backed up for
restoration. The Smartcard provider remains registered with Windows but is
excluded by policy. An AD tile does not open a QR just because LogonUI selects
it; the user must explicitly click **Request phone approval**.
The filter is reversible and preserves the existing password-provider
exclusion. To inspect or restore it, run elevated PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "C:\Users\Public\Documents\configure-unused-ad-lab-tiles.ps1" -Mode Status

powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "C:\Users\Public\Documents\configure-unused-ad-lab-tiles.ps1" -Mode Restore
```

Restoring re-enables the local chip and Smartcard credential providers on this
Clone 1. It does not remove their binaries or the virtual reader devices.
To restore the local chip and ticket-test registrations, first run
`remove-unused-ad-lab-providers.ps1 -Mode Restore`, then run the tile filter's
`-Mode Restore` command above.

Clone 1 has the built-in Windows Password credential provider excluded by the
`ExcludedCredentialProviders` machine policy. The policy is confirmed, and the
deployment rollback task was stopped after the phone-approved sign-in succeeded.
The enable/rollback/confirm script is `phone-2fa-policy.ps1`.

## Account requirements

- The AD service must authorize the account and a phone key must already be
  enrolled before sign-in. Unknown, unauthorized, or unenrolled accounts fail
  closed.
- This supports existing domain accounts such as
  `THESSLEYLAB\Administrator` and newly created domain accounts that have never
  signed in to this PC, provided they are authorized and enrolled first.
- The workstation must reach both its domain controller and the paired Thessley
  approval service. No internet connection is inherently required if those
  services are reachable on the local network.

## Scope and remaining bypasses

`ExcludedCredentialProviders` is a machine-wide Windows policy. Excluding the
built-in Password provider also affects local password sign-in, RDP, and Run As.
Local users need a working Thessley local credential path for recovery.

This deployment excludes the Password provider only. It does **not** disable
Windows Hello PIN, smart-card, security-key, or any other credential provider
that may be enabled on the machine. Therefore it blocks the ordinary
password-only tile, but it does not prove that phone approval is the only
possible sign-in method. Review and test every enabled provider before treating
the machine as enforcing phone approval exclusively.

## Rollback and confirmation

The deployment script arms a scheduled rollback before changing the provider
registration or Windows policy. To inspect, confirm, or roll back, run elevated
PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "C:\ProgramData\ThessleyPamWin\ad-credential-provider\phone-2fa-policy.ps1" -Mode Status

powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "C:\ProgramData\ThessleyPamWin\ad-credential-provider\phone-2fa-policy.ps1" -Mode Confirm

powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  "C:\ProgramData\ThessleyPamWin\ad-credential-provider\phone-2fa-policy.ps1" -Mode Rollback
```

Confirm only after a successful phone-approved sign-in. Rollback restores the
previous provider DLL and Password-provider exclusion list.
