# Isolated Windows AD prototype

This directory is the VM install source for `thessley-ad-test.cmd`. It is kept
separate from the installed local-account Thessley app and its credential
provider. It does not add or replace a Windows sign-in tile.

The current prototype supports pairing the computer, requesting phone-key
enrollment for an authorized AD account, and testing phone approval. A
separate, build-only Credential Provider clone now connects those approvals to
a lab TPM virtual smart-card certificate. It is hard-limited to the inspected
`THESSLEYLAB\\martin` SID and VSC container on the disposable Pro VM. It is not
registered or installed by the prototype setup scripts. The working local QR
tile remains unchanged and continues to cover local accounts, including
Windows Home.

Two quiet JSON commands are available as the native AD tile's service
adapter: `approval-start --sid SID --context interactive|unlock` returns a
validated one-use request ID, phone link, and QR matrix; `approval-poll
--request-id ID --timeout 175` waits for the machine-bound result. They do not
log in to Windows. The isolated AD Credential Provider uses them to request
approval, then uses the existing TPM VSC certificate to build a Kerberos
certificate-logon serialization. On first use, enter the card PIN and
explicitly check the remember option. After a successful logon, the PIN is
stored in a separate SID-scoped DPAPI LocalMachine vault, with access limited
to SYSTEM and Administrators. Later logons require phone approval but no PC
PIN entry. This convenience reduces the protection provided by the card PIN
against a compromised local administrator; phone approval remains mandatory
for each sign-in attempt. The private key remains in the TPM virtual smart
card. The tile does not serialize or save an account password. The existing
local provider, TPM sign-in, and PIN/password recovery tiles remain separate.

Build the isolated AD tile and QR viewer for review only:

```bash
bash infra/windows-ad-lab/ad-prototype/windows-logon-provider/build.sh
```

The output goes to `/tmp/thessley-ad-provider-build` by default. This only
compiles files; it does not register the provider, deploy it to the VM, or
change any sign-in setting. The provider embeds the lab SID and VSC container
from `windows-logon-provider/ad_lab_vsc_config.h`; do not treat this artifact
as a general installer. A later deployment must first have a tested rollback
path and a separate non-network recovery login.

The isolated provider directory also contains an opt-in lab installer and two
recovery scripts. The installer arms and verifies a SYSTEM scheduled rollback
before writing either Credential Provider registry key. The default rollback
is 10 minutes; a successful domain sign-in must be confirmed with the separate
`keep-ad-lab-provider.ps1` command. Running the rollback removes only this
provider's unique registration and leaves the existing local, PIN, password,
and VSC tiles alone. These scripts have not been run against a VM.

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
