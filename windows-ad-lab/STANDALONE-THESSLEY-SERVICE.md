# Standalone Thessley service for AD QR sign-in

This prototype has no Drupal dependency. Drupal URLs, Drupal accounts, Drupal
roles, and the Drupal Windows Access module must not be used by the AD sign-in
path.

## Responsibilities

- **Active Directory** is authoritative for domain users, SIDs, security groups,
  computer accounts, and Windows logon rights.
- **AD CS** issues the lab logon certificate after the user identity and SID
  mapping are verified.
- **Thessley service on the existing Linux host** handles phone enrollment,
  signed approval requests, revocation, and audit. It is a separate service
  from Drupal, even if both happen to run on the same physical Orange Pi.
- **Windows client agent and credential provider** identify the selected
  principal by SID, consult the Thessley service, and invoke a Windows
  certificate provider for the KDC logon. They do not send or cache the
  account password.
- **Android app** remains the phone authenticator. The app signs an
  origin-pinned Thessley PAM request; the private phone key stays in Android
  Keystore/TEE.

## Windows sign-in options

The AD integration is a separate `Thessley AD Passkey` credential-provider
tile with its own CLSID. Keep the existing Thessley QR tile unchanged: it
approves and then submits an account password. Keep Windows PIN/password
recovery available during the experiment. The new AD tile resolves a domain
account SID and must not serialize, cache, or release a domain password.

## Request and enrollment flow

1. The Windows agent resolves the selected account to its SID and domain,
   creates a short-lived, one-use request, and authenticates its machine
   connection to the standalone Thessley service with a per-machine key.
2. The service verifies the machine, account enrollment, request freshness,
   and current AD authorization. It returns a Thessley Passkey link pinned to
   the service TLS certificate. The link contains the machine ID, SID hash,
   authority, account name, logon context, request ID, and nonce.
3. The phone displays the Windows sign-in or unlock context. After biometric
   approval, it signs the versioned Windows PAM challenge. The service checks
   the enrolled phone public key, signature, timestamp, nonce, and one-use
   request state, then returns the result to the Windows agent.
4. For actual passwordless logon, Windows obtains a certificate credential
   whose public key matches the phone-held signing key, and the Windows key
   provider asks the phone to sign the KDC's PKINIT challenge. Approval of a
   QR request alone is not a Windows credential.
5. AD group membership and computer policy decide whether the account may
   sign in and which local groups it receives. Thessley does not replace AD
   policy with a separate role database.

The preferred Windows crypto integration to investigate is the built-in
smart-card Base CSP/KSP with a Thessley card minidriver. Windows documents the
minidriver as the card-specific interface used by the Base CSP/KSP and as the
normal route for smart-card ECC. This still requires a PC/SC reader/card path
that can carry requests between the Windows logon environment and the phone;
the Android app does not appear to Windows as a reader today. A custom CNG KSP
is a separate, larger provider-development effort using Microsoft's CNG
Provider Development Kit. Microsoft documents that third-party KSPs are not
loaded into the CNG key-isolation service, so a custom KSP must first prove it
can be called in the LSA/PKINIT signing path. A minidriver loaded into
protected LSA has a Microsoft driver-signing requirement. Prototype both
execution and signing constraints before committing to either implementation.
Keep the current password-based tile separate throughout.

Pairing must bind the phone public key to the exact domain SID and the
authorized computer/group scope. A local account with the same spelling is a
different identity. Enrollment, approval, and revocation are separate,
audited operations. A host must fail closed if the service is unreachable or
the identity, signature, or policy cannot be checked; PIN/password recovery
remains a Windows-managed fallback until passwordless login is validated.

## Reuse versus new work

The Thessley Passkey Android app already parses version-2 Windows PAM links
and signs a challenge covering SID hash, principal type, authority, username,
logon context, nonce, and action (`thessley_win_pam_v2`). The Linux Thessley
PAM service already has a certificate-pinned HTTPS listener on port 47810,
temporary request routes, a Unix-socket registration mechanism, and phone
key verification. Reuse those protocol and listener pieces where they fit.

The existing Windows Drupal agent (`drupal_agent.py`) and its `/thessley-windows`
API are not the backend for this project. Replace that integration with a
Windows agent that speaks to the standalone Thessley service. The Linux
listener currently exposes temporary PAM approval routes to local privileged
components; it does not yet provide the persistent, machine-authenticated AD
account registry or AD policy lookup required here. Add those as a separate
service/package and storage boundary rather than putting AD logic in Drupal or
silently expanding the generic PAM database.

## API boundary to implement

Use a versioned API on the standalone Thessley host, with TLS certificate
pinning and a unique machine credential for every Windows computer:

- `POST /thessley-ad/v1/machines/enroll` — pair a machine key to a short-lived
  administrator-authorized enrollment code.
- `POST /thessley-ad/v1/principals/resolve` — submit the domain and SID hash;
  return canonical identity and current group/computer authorization from
  protected LDAP/AD queries.
- `POST /thessley-ad/v1/phones/pair` — bind an Android public key to a domain
  SID and permitted group/computer scope after matching one-time codes.
- `POST /thessley-ad/v1/requests` — create a one-use interactive-login or
  unlock challenge, returning the standard Thessley PAM v2 link fields.
- `POST /thessley-ad/v1/requests/{id}/result` — machine-authenticated poll or
  response endpoint; approval is returned only to the machine that created
  the request.
- `DELETE /thessley-ad/v1/phones/{id}` and `DELETE
  /thessley-ad/v1/machines/{id}` — revoke credentials and expire pending
  requests.

The phone callback can use the existing pinned PAM listener and its compatible
v2 signature format. The machine API must use mutual TLS or equivalent
machine-key proof, authorize every request against AD, enforce strict body and
rate limits, and never accept a client-supplied group list as authority. Keep
the service identity read-only in AD unless a narrowly scoped certificate
enrollment operation is separately required.

The first standalone code component is `infra/thessley_ad_service/protocol.py`.
It validates SID-derived principal IDs and reproduces the Android
`thessley_win_pam_v2` canonical message and P-256 signature checks. It is only
the cryptographic protocol layer: it does not yet provide network routes,
machine authentication, persistent enrollment storage, or AD policy queries.

## Technical gate before passwordless claims

The current C credential provider submits a password credential after
approval. That is approval-gated password sign-in, not passwordless AD
authentication. Do not adapt it to release a cached password. First validate
the phone-key certificate and strong SID mapping with AD CS, then implement a
Windows-supported smart-card minidriver bridge (preferred) or a separate CNG
KSP that can obtain a phone signature for a live PKINIT challenge. Test
interactive sign-in, workstation unlock, revocation, offline behavior, and
recovery separately.

### Android phone-key constraints

The Android app's current computer key is a P-256 ECDSA Android Keystore key.
It is non-exportable and each signing operation is gated by a fresh strong
biometric. StrongBox is preferred; the app now falls back to the TEE path only
when Android specifically reports that StrongBox is unavailable. Other key
generation errors fail instead of silently lowering protection. The service
must verify the attestation chain, nonce, public-key match, and security level
itself; client-side assurance is not a server trust decision.

The current Windows v2 signature is only an approval over the Thessley
canonical request. It is not the PKINIT signature. The smart-card minidriver
must pass the actual, fresh PKINIT signing operation to the phone, and the app
must show the account, domain, machine, and sign-in/unlock context before
biometric confirmation. The phone's PKINIT signature must cover the exact DER
AuthPack that the KDC verifies. Separately bind the response envelope to its
AuthPack hash, certificate key, request ID, SID hash, machine ID, and short
expiry. Do not append Thessley metadata to the PKINIT AuthPack or accept a
generic approval signature as a substitute for the KDC signature.

There is also a signing API boundary to settle before wiring the phone into the
Windows provider. `KeystoreManager.signWithBiometric` currently uses Java
`SHA256withECDSA` and returns a DER-encoded ECDSA signature. Windows
[`NCryptSignHash`](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash)
accepts a precomputed hash for ECDSA; a bridge must not send
that digest to the current Android method and accidentally hash it a second
time. Define whether the phone receives the exact AuthPack bytes or a digest
and use matching algorithms at both ends. Windows exposes more than one ECC
signature representation: for example,
[`CERT_ECC_SIGNATURE`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_ecc_signature)
stores `r` and `s` as little-endian blobs. That structure alone does not
establish the minidriver's required output encoding, so implement and verify
an explicit adapter against the precise Smart Card KSP/minidriver entry point.
Never pass the app's approval-envelope signature through as if it were a
PKINIT result.

The phone's EC certificate path needs its own Windows test before building the
minidriver: Windows requires ECC smart-card logon to be enabled by policy, and
cached/offline sign-in with an ECDSA key needs its associated ECDH key. First
issue a test certificate for the P-256 public key and verify online PKINIT on
the lab domain. If offline logon is required, design and test the paired ECDH
key explicitly; do not export or copy the phone's private signing key to
Windows. The current TPM-VSC test proves the AD/KDC baseline only.

### Lab certificate-template inspection (read-only, 2026-10-27)

The two current templates were inspected through AD and left unchanged:

| Template | Schema version | Provider | Key spec | Purpose |
|---|---:|---|---:|---|
| `SmartcardLogon` | 1 | no explicit provider list | 1 (signature) | Built-in legacy template |
| `ThessleyVscLogon` | 1 | Microsoft Base Smart Card Crypto Provider | 1 (signature) | Existing RSA TPM-VSC baseline |

These are not the phone ECC template. Do not edit either one to experiment.
Create a separately named template by duplicating an appropriate template in
Certificate Templates MMC, set compatibility high enough to expose CNG, and on
the Cryptography tab choose **Key Storage Provider**, ECDSA P-256, and only the
required smart-card logon/client-authentication usages. Keep enrollment ACLs
limited to the lab user and domain admins; publish the new template only on
the lab CA. Microsoft documents the KSP and ECC settings in its [CNG template
guidance](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/network/cng-certificates-overview)
and the ECC logon switch in [Smart Card Group Policy](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-group-policy-and-registry-settings).
Do not hand-edit template LDAP attributes to simulate the GUI settings.

The first test should be online sign-in only. An ECDSA certificate may satisfy
the logon signature requirement, but Microsoft documents that offline sign-in
also needs an associated ECDH key. Do not enable a broad domain policy or claim
offline support until both keys and the actual credential-provider path have
been tested. The VSC success remains the recovery baseline.

### ECC provider gate (read-only, 2026-10-27)

Microsoft documents ECDSA P-256/P-384/P-521 support in the **Microsoft Smart
Card Key Storage Provider**, and separately documents the policy needed for
ECC smart-card logon. This establishes Windows API support; it does not
establish that the current TPM virtual smart card and its legacy Base CSP
template can create and use an ECC key. The `Tpmvscmgr` overview does not
specify its supported key algorithms.

Read-only inspection of the joined client found:

- The only smart-card reader remains `ThessleyADTest` (the Microsoft TPM
  virtual reader).
- `certutil -csplist` lists the legacy Microsoft Base Smart Card Crypto
  Provider and the Microsoft Smart Card KSP, but returns `E_NOTIMPL` while
  enumerating KSP details. Provider presence alone is not a capability test.
- The `EnumerateECCCerts` policy value is absent. Do not set it domain-wide
  merely to test whether the TPM virtual card can enroll ECC.
- The current-user software `My` certificate store is empty. The previously
  verified RSA VSC/PKINIT baseline remains recorded by the KDC audit; this
  store query did not inspect the card's private-key operations.

The next ECC gate therefore remains an isolated capability test: use a
separately named ECC template and a disposable virtual smart card, enroll an
ECDSA P-256 certificate, and prove online PKINIT against the lab KDC. Keep the
existing RSA card, its certificate, the current template, and all sign-in
providers unchanged. Do not enable ECC logon policy until the certificate is
actually issued and its key can complete a KDC-backed logon. If the TPM virtual
card rejects ECC, stop this branch and use a separately isolated PC/SC bridge
prototype; do not change the joined client's driver-signing state.

### Certificate-template MMC prerequisite (2026-10-27)

The Windows 11 Pro lab client is build 26300.9711 and does not have
`certtmpl.msc` or the `Rsat.CertificateServices.Tools` capability installed.
`DISM /Online /Add-Capability` returned `0x80070005` without installing the
capability or requesting a reboot. Windows Update services were running, no
Windows Update policy key was configured, and the read-only component-store
scan reported no corruption. The mounted `ESD-ISO` is Windows installation
media, not a Features-on-Demand source. Do not repair ACLs or alter AD CS
templates to work around this. The supported GUI path remains gated on a
matching Features-on-Demand source or a separately diagnosed servicing fix.
Retrying the capability install as `SYSTEM` through a temporary scheduled task
also stalled in CBS finalization; the task was stopped and deleted, the
diagnostic log was removed, and the capability remains `Not Present`.

Microsoft references: [Smart Card KSP algorithm support](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers),
[TPM virtual smart-card requirements and tool](https://learn.microsoft.com/en-us/windows/security/identity-protection/virtual-smart-cards/virtual-smart-card-use-virtual-smart-cards),
and [ECC smart-card logon policy](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-group-policy-and-registry-settings).

References: [Windows ECC smart-card policy](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-group-policy-and-registry-settings), [Windows smart-card sign-in certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration), [Smart Card Minidriver overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview), and [RFC 4556 PKINIT](https://www.rfc-editor.org/rfc/rfc4556.html).

