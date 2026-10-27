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

1. (AD foundation complete) The disposable Windows client is joined and its
   secure channel, DNS, time, and test user SID are verified. A SmartcardLogon
   certificate was issued with the matching SID security extension; verify its
   private-key presence in the domain user's certificate store next.
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

