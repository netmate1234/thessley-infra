# Thessley AD tile for Windows “Other user”

## Goal

Let an enrolled AD account sign in on a paired Windows workstation by entering
its qualified account name at the generic **Other user** tile, approving a
fresh QR request with its centrally enrolled phone, and completing Windows
Kerberos authentication without typing or storing the AD password and without
creating a long-lived per-user key on every workstation.

The phone's private key remains in Android Keystore. The AD service stores the
phone's public key and the AD account's SID. Each approval is bound to the
account SID, workstation identity, logon context, nonce, and one-use request.
The workstation must not treat a typed username or a phone's “approved” result
alone as a Windows logon credential.

## Why the current tile cannot do this

The isolated provider currently enumerates Windows user tiles and accepts only
Martin's lab SID. Its successful certificate-logon serialization references
Martin's TPM virtual smart-card key container. That demonstrates the AD/KDC
path, but it cannot authenticate another account or the generic **Other user**
entry. Adding more SIDs would still require a separate PC-held smart-card
credential for each account and would not meet the central enrollment model.

Windows does provide a supported way to associate a Credential Provider V2
credential with **Other user**: `ICredentialProviderCredential2::GetUserSid`
returns `S_FALSE` and a null SID. The current provider does not implement that
anonymous-user credential path. This solves tile placement only; it does not
turn a QR approval into a Kerberos credential. See Microsoft's
[`GetUserSid` documentation](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nf-credentialprovider-icredentialprovidercredential2-getusersid).

A Credential Provider is only the sign-in UI and credential serializer. LSASS,
Kerberos, and the KDC still need a credential Windows recognizes. The phone's
signature is an approval for the attempt, not the KDC's PKINIT signature.

## Target flow to prove in the disposable lab

1. The generic Thessley tile accepts a qualified domain name. It sends that
   name through the paired machine API; the DC resolves it to one canonical SID
   and checks account state, configured sign-in groups, and an active phone
   enrollment. The tile never decides authorization from the typed name.
2. The workstation creates a fresh, per-attempt key pair and CSR. The private
   key is non-exportable and usable only by the sign-in service for this
   request. The machine asks the AD service to bind the CSR hash, account SID,
   machine ID, logon context, and request nonce to a phone challenge.
3. The phone displays the account and workstation and signs the challenge
   using the user's enrolled key. The service verifies the signature and
   rechecks current AD authorization before any certificate is issued.
4. A narrowly scoped AD CS Enrollment Agent issues a very short-lived
   smart-card-logon certificate for that CSR, strongly mapped to the exact AD
   SID. The agent may issue only from one dedicated template and only for the
   explicitly configured sign-in population. It must not have general CA
   administration rights.
5. The Credential Provider submits `KERB_CERTIFICATE_LOGON` using the
   one-attempt key and certificate. The KDC must validate the strong SID
   mapping and the certificate's smart-card-logon usage. Password, Windows
   Hello, and the existing local-account tile remain available as recovery.
6. The client removes the temporary certificate and key after success,
   rejection, cancellation, and timeout. A short certificate lifetime and a
   separate cleanup mechanism cover process crashes and power loss. Issuance,
   sign-in result, revocation, and cleanup are auditable without logging QR
   contents, private material, or passwords.

This is **phone-authorized ephemeral-certificate logon**. The phone does not
perform PKINIT itself; its approval authorizes one tightly scoped certificate
for one account and one workstation.

## Configurable method policy

Store policy centrally on the AD service and show it in the AD administration
site. Resolve the effective policy in
this order:

1. An explicit override for the paired workstation.
2. The highest-priority matching AD group rule for the user's current nested
   group membership. Reject conflicting rules at the same priority.
3. The domain-wide default.

The current policy UI exposes only methods with an implemented client path:

- `tpm_smartcard`: phone approval authorizes use of the user's already-issued
  TPM virtual smart-card credential on that PC. This remains a per-user,
  per-PC setup and is best treated as a compatibility method.
- `windows_native`: disable Thessley QR for the selected domain/group/PC; leave
  the Windows password and Hello providers available.
- `phone_ephemeral_certificate`: after phone approval, issue and use the
  one-attempt, strongly SID-mapped certificate described above. This is the
  intended school rollout method, but remains unavailable until all proof
  gates pass.

Windows password and Windows Hello recovery stay available locally and are
not switched off by the Thessley policy. They are recovery paths, not silent
fallbacks for a failed QR request. If the selected Thessley method is missing,
unsupported by the workstation, or cannot reach the DC, report the reason and
stop that Thessley attempt; do not downgrade it to another Thessley method.
Only an administrator can change the central policy. Record the actor, target
group or machine, old and new method, and timestamp. Return the effective
method in every signed AD authorization response so the Windows tile can
enforce the same selection.

The policy page documents precedence and lists saved group and workstation
rules. Per-user effective-method reporting and client capability advertisement
are follow-up work. A method remains unselectable until its corresponding
client and KDC proof is complete.

## Proof gates — do these before changing LogonUI

1. Use a disposable AD account and a throwaway key. Exercise Enrollment Agent
   issuance without registering or installing a Credential Provider.
2. Inspect the issued certificate: expected public key, Smart Card Logon EKU,
   short validity, and the strong SID security extension for the exact target
   account. Reject a certificate mapped only by UPN or subject name.
3. Perform an actual fresh KDC certificate logon using the ephemeral key and
   confirm the resulting AD identity and PKINIT audit event. A successful CA
   request, QR approval, or certificate serialization alone is insufficient.
4. Prove that another SID, machine, CSR, nonce, or reused approval cannot use
   the certificate. Exercise denial, expiry, cancellation, revocation, and
   cleanup after a simulated client crash.
5. Only then build a separate generic **Other user** Credential Provider. Add
   an automatic rollback task and verify password/Hello recovery before
   registering it on Clone 1. Do not change the existing local tile or the
   Martin VSC baseline.

## Live certificate-issuance checkpoint (2026-10-29)

Read-only inspection of `THESSLEY-DC1` found the following state:

- The CA is reachable. Its published list includes `ThessleyVscLogon` and the
  built-in `SmartcardLogon` template; `Copy 2 of Smartcard Logon` is **not**
  published.
- `Copy 2 of Smartcard Logon` exists in AD as schema version 4. It has the
  Smart Card Logon and Client Authentication EKUs, a 256-bit minimum key, and
  `msPKI-RA-Signature = 0`. It therefore does **not** require an Enrollment
  Agent signature and is not safe to publish for the phone-issued path.
- The unpublished template has a direct Certificate-Enrollment ACE for
  `THESSLEYLAB\martin` (extended-right GUID
  `0e10c968-78fb-11d2-90d4-00c04f79dc55`). That right is inert while the
  template is unpublished, but would let Martin enroll directly if this
  template were published. Do not publish this copy or use it as the pilot.
- No Enrollment Agent certificate was found in the DC's LocalMachine\My store
  during the read-only check.
- The CA service is running. Its default policy `EditFlags` did not include
  `EDITF_ATTRIBUTESUBJECTALTNAME2`, and `DisableExtensionList` was empty. This
  is a useful baseline, not proof that a future issued certificate will carry
  the correct SID extension; inspect the actual pilot certificate.

The read-only inventory is repeatable from an elevated PowerShell on the DC:

```powershell
.\inspect-phone-certificate-readiness.ps1
```

It reports the selected template, publication state, RA-signature count,
enrollment ACEs, EKUs, CA policy flags, and agent certificates in the current
user and machine stores. It deliberately does not edit AD CS or inspect the
CA's Enrollment Agent Restrictions; verify those in the Certification
Authority console before any publication.

Therefore the next lab step is to create a **new, separate, unpublished** pilot
template and a dedicated Enrollment Agent identity, then configure CA
Enrollment Agent Restrictions before publishing anything. The restriction
must constrain both the one pilot template and a disposable AD test-account
group. The agent key must be accessible only to the issuance broker identity;
do not use a Domain Admin or the DC's general-purpose Administrator as the
broker. Keep `Copy 2 of Smartcard Logon` untouched and unpublished until its
ACL and RA-signature requirements are corrected or the object is retired.

### Phone approval must bind the exact certificate request

The current Windows v2 phone signature does not bind a CSR. It must not
authorize certificate issuance. A certificate pilot needs a separate,
versioned approval message that signs all of these fields in a fixed canonical
encoding:

```text
protocol-domain | request-id | machine-id | account-SID-hash | authority |
username | logon-context | nonce | expiry | SHA256(DER-CSR) | action
```

The client creates a fresh key for one attempt and sends the DER CSR to the
broker over the machine-authenticated channel. The phone displays the
canonical AD account, workstation, and sign-in context, then signs the CSR
digest along with the request identity. The broker re-resolves the SID and
current group policy, verifies that the CSR contains the exact approved public
key, and only then submits the on-behalf request. Before returning a
certificate, the broker must verify its public key against the approved CSR,
Smart Card Logon EKU, exact strong SID mapping, template, issuer, and very short
validity. The client must also validate those fields before attempting PKINIT.

The phone's approval signature remains separate from the KDC's PKINIT proof.
Do not reuse the v2 signature, accept a UPN-only mapping, or make the
certificate method selectable until a fresh KDC sign-in and crash-safe key
cleanup have both passed.

For the generic credential, add a qualified-username edit field and bind the
approval request to the canonical SID returned by the AD service, never to the
unverified text. Keep logon and unlock separate until each has its own verified
identity and credential flow. Microsoft notes that Credential Providers
collect and serialize credentials; LSA and the authentication package enforce
the logon. See [Credential Providers in
Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows).

If the lab cannot prove these gates, keep the current working Windows
credentials and the existing approval-gated TPM experiment. Do not silently
fall back to per-user PC keys, serialize the AD password, or claim that phone
approval alone performs Windows logon.

## Current project status

- Central AD phone enrollment, machine pairing, SID/group authorization, and
  one-use phone approval are implemented and have been exercised separately.
- The existing TPM VSC certificate sign-in works for the one lab identity.
- Generic **Other user** account selection and a passwordless logon credential
  for arbitrary enrolled AD users are not implemented.
- The deployed AD service still has only a global allowed-group list. The
  source tree now includes domain/group/workstation method rules, but that
  policy update has not yet been deployed to the lab.
- No workstation logon configuration was changed as part of this design work.
