# Isolated Windows AD prototype

This directory is the VM install source for `thessley-ad-test.cmd`. It is kept
separate from the installed local-account Thessley app and its credential
provider. It does not add or replace a Windows sign-in tile.

The current prototype supports pairing the computer, requesting phone-key
enrollment for an authorized AD account, and testing phone approval. A
separate, build-only Credential Provider clone is a legacy proof tied to one
lab TPM virtual smart-card certificate. It is not the phone-issued certificate
path and is not registered or installed by the prototype setup scripts. The
working local QR tile remains unchanged and continues to cover local accounts,
including Windows Home.

The phone-approved certificate path is a separate, disabled proof of concept.
Its isolated CSR, approval-binding, and certificate-validation stages are
documented in `certificate-pilot/README.md`; the actual phone-held-key logon
requirements are in `certificate-pilot/PHONE-HELD-KEY-DESIGN.md`. The current
pilot's private key is generated on the PC, so it is not phone-held. The
issuer-side EOBO helper is
source-only, restricted to a domain controller, and does not submit requests;
no Enrollment Agent key or helper belongs on workstation clients. No AD QR
sign-in currently uses this certificate path.

Two quiet JSON commands are available as the native AD tile's service
adapter: `approval-start --sid SID --context interactive|unlock` returns a
validated one-use request ID, phone link, and QR matrix; `approval-poll
--request-id ID --timeout 175` waits for the machine-bound result. They do not
log in to Windows. The isolated AD Credential Provider uses them to request
approval, then uses the lab TPM VSC certificate to build a Kerberos
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
change any sign-in setting. The provider embeds one lab SID and VSC container
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
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' enroll-phone --user 'DOMAIN\account'
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' approval-test --user 'DOMAIN\account'
```

## Phone-approved certificate pilot

The isolated service and Android protocol support a separate v3 approval whose
phone signature binds one exact CSR SHA-256 digest, the configured AD CS
template, the machine, domain SID, and request expiry. The generic agent
exposes `certificate-approval-start --sid SID --csr-file PATH` (or an already
computed `--csr-sha256 DIGEST`) and
`certificate-approval-poll --request-id ID --csr-sha256 DIGEST --template NAME --csr-file PATH`.
The file option accepts a bounded PEM or DER PKCS#10 request, verifies its
self-signature, canonicalizes it to DER, and sends only the digest to the
service at request start. The start command validates the service's complete
v3 link before returning QR data. After approval, the poll command sends the
same CSR over a machine-signed request; the service checks the approved digest
and CSR profile, then accepts it once for that machine and challenge. The
service now has a machine-authenticated certificate-result route, but it only
returns a certificate after the internal issuance validator has accepted and
stored it. The claim, CA-response validation, and storage operations are not
exposed through an issuer worker or HTTP endpoint. The Windows admin CLI now
supports a manual, one-use claim and validated certificate import on the DC;
the separate PowerShell proof can build and manually submit CMC/EOBO. Neither
path has been run against a CA. The `certificate-fetch` command retrieves only
a service-validated result, checks that its public key matches the retained
CSR, and writes a new DER file without overwriting an existing file. The
separate `accept-validated-certificate.ps1` helper can link that certificate
to the request's non-exportable machine Software KSP key and install it in the
machine certificate store. This is still a PC-held key, not a phone-held key;
the helper does not perform PKINIT. The policy store still refuses to enable
this method, so do not register a login tile from this scaffold. The v3 request
does not embed a user, SID, machine, or template; the service resolves the user
and reads the template from protected configuration.

`activate.ps1` stages and validates a replacement before moving it into place,
then installs the all-users Start menu shortcut and Thessley icon. The current
local-account sign-in remains available throughout.
