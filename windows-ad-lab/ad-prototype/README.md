# Isolated Windows AD prototype

This directory is the VM install source for `thessley-ad-test.cmd`. It is kept
separate from the installed local-account Thessley app and its credential
provider. It does not add or replace a Windows sign-in tile.

The current prototype supports pairing the computer, requesting phone-key
enrollment for an authorized AD account, and testing phone approval. It does
not yet perform Windows AD sign-in. Passwordless AD sign-in needs a separate
PKINIT-compatible credential bridge; the local QR tile remains the path for
local accounts, including Windows Home.

The package imports Python modules from `thessley_pam_win/` in this directory
and cryptography/qrcode dependencies from the existing private vendor folder
at `C:\ProgramData\ThessleyPamWin\app\vendor`.

Run from an elevated PowerShell window to pair the machine:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' pair-machine --server 'https://AD-SERVICE-HOST:47810' --tls-sha256 'CERTIFICATE-SHA256'
```

For ordinary self-enrollment, sign in to the domain account and launch
**Thessley → Add phone for Windows sign-in** from the Windows Start menu. The
shortcut requests elevation through Windows and then uses `pythonw.exe`, so it
shows the normal UAC approval prompt without opening a PowerShell or console
window. Elevation is needed to use the protected machine signing key. The GUI
resolves the current Windows SID, displays a scannable QR and pairing code, and
refuses a local-account session. To start it manually, run:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-enroll.cmd'
```

Scan the fresh QR with Thessley Passkey, approve Add phone, then confirm on the
PC only if the phone and PC show the same pairing code. The request is short
lived; keep the window open until it completes. An SSH maintenance session
under a local account is a different identity and cannot use self-enrollment.
The service checks the account's AD group membership. Admin-assisted
enrollment for another authorized domain account remains available.

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' enroll-current-user
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' enroll-phone --user 'THESSLEYLAB\martin'
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' approval-test --user 'THESSLEYLAB\martin'
```

`activate.ps1` stages and validates a replacement before moving it into place,
then installs the all-users Start menu shortcut and Thessley icon. The current
local-account sign-in remains available throughout.
