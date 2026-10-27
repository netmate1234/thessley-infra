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

## Safe implementation order

1. (Complete for the TPM VSC baseline) The disposable Windows client is joined
   and its secure channel, DNS, time, and interactive domain-user sign-in are
   verified. A TPM virtual smart card has a SmartcardLogon certificate with the
   correct account mapping and a non-exportable key. Windows sign-in succeeded;
   the DC recorded PKINIT pre-authentication type 16 and the matching thumbprint.
   This proves the AD CS/KDC path, not phone-held key signing.
2. Add a new standalone Thessley AD service component, separate from
   `drupal_agent.py` and Drupal APIs. Put its persistent data in a dedicated
   store, not the generic per-Windows-user PAM device database.
3. Add per-machine authentication to the Windows agent and pair each phone
   key to a domain SID plus an explicit machine or AD-group scope. Keep
   enrollment authorization separate from an ordinary login approval.
4. Build a distinct `Thessley AD Passkey` Windows Credential Provider with a
   separate CLSID and AD-only account handling. Connect it to this service
   through a new agent interface. Keep the existing QR password tile and
   built-in Windows PIN/password recovery intact; never route AD users into
   the existing Drupal client code.
5. Replace password serialization only after a Windows certificate provider
   can sign a live KDC PKINIT request with the enrolled phone key. A QR
   approval response by itself cannot complete that step.
6. Test enrollment, interactive sign-in, lock/unlock, denied and expired
   requests, network loss, phone revocation, machine revocation, and fallback.
   Keep this on the disposable VM until each path is repeatable.

## Windows cryptographic bridge choice

Prefer the Windows smart-card Base CSP/KSP plus a card minidriver if the
prototype can expose the phone key through a supported PC/SC reader path. The
minidriver is the card-specific interface Windows already uses for smart-card
cryptographic operations, including ECC. This does **not** make a Windows
Credential Provider alone sufficient: a usable reader/card interface and the
exact smart-card logon serialization path still need to be demonstrated.

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

