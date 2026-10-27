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

Then enroll a domain account's phone and test approval:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' enroll-phone --user 'THESSLEYLAB\martin'
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' approval-test --user 'THESSLEYLAB\martin'
```

`activate.ps1` stages and validates a replacement before moving it into place;
the current prototype remains available for local sign-in throughout.
