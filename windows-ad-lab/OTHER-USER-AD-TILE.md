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
