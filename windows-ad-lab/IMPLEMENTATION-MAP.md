# AD QR sign-in implementation map

This is a map from the disposable AD lab to the existing Thessley source. It
keeps the AD experiment separate from the current Drupal-backed distributed
Windows login feature.

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
   CLSID and AD-only account handling. Keep the current QR password tile,
   existing TPM smart-card path, and built-in Windows PIN/password recovery
   intact. Never route AD users into the Drupal client code.
5. Keep these bridge milestones separate:

   - **Near-term lab bridge: phone approval + TPM virtual smart card.** The
     user approves the SID-bound request on the phone, then supplies the VSC
     PIN. The new provider submits a Kerberos certificate-logon serialization
     for the existing TPM VSC certificate. This demonstrates an AD-domain QR
     approval gate without sending or storing the AD password. The private
     key stays in the computer TPM; this is not phone-key PKINIT and must be
     labeled accordingly.
   - **Target bridge: phone-held key + PKINIT.** Only call this passwordless
     phone-key sign-in after a supported Windows smart-card/KSP bridge can
     pass the actual fresh PKINIT signing operation to the Android Keystore
     key and the KDC accepts it. A Thessley approval signature is not a
     substitute for that KDC signature.

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
VSC certificate reports CNG `dwProvType = 0`, `dwKeySpec = 0`; Microsoft
documents that zero is passed to `NCryptOpenKey` for a CNG provider. The helper
accepts it only with the exact Microsoft Smart Card KSP name. This resolves the
key-spec mismatch, but the resulting serialization still needs an isolated
LogonUI sign-in test before the helper can be connected to a tile. The
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

