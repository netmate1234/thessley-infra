# Single-biometric phone approval for Windows PIV sign-in

## Goal

One fresh phone biometric must both approve one named Windows sign-in and
authorize the PIV operation that proves the enrolled AD key. The AD private
key remains non-exportable in Android Keystore/TEE or StrongBox. Do not add a
biometric reuse window and do not relax per-operation key authentication.

## Why the current flow asks twice

The phone currently signs two different operations:

1. The enrolled computer key signs the general approval request.
2. The separate AD logon key signs the exact digest requested by Windows.

Both Android Keystore keys require per-operation biometric authorization, so
Android correctly presents two prompts. Hiding the second prompt or changing
the key authorization timeout would weaken the existing protection.

## Proposed protocol

The exact Windows PIV digest becomes the approval itself:

1. Windows starts a short-lived, machine-authenticated AD login challenge and
   displays its QR. The challenge binds the machine, AD principal, account,
   interactive login context and expiry.
2. The phone displays the account and computer. When the user taps **Approve**,
   it waits for the matching PIV digest from that machine. It does not sign the
   generic computer-approval message first.
3. Windows requests one signature for its Kerberos/PIV operation. The server
   stores that exact digest under the same challenge and active AD key.
4. Android shows one biometric prompt for the AD key after Windows requests
   the signature. The prompt names the account and computer; the key signs only
   the exact pending digest.
5. The server verifies the signature, active key, machine, account, challenge,
   digest, expiry and one-use state in one transaction. It then marks the
   challenge approved and makes the same signature available only to the
   originating authenticated machine.
6. The Windows reader returns that signature to the Windows smart-card/Kerberos
   path. The sign-in succeeds only if Windows also accepts it.

## Required fail-closed checks

- A pending PIV digest is available only for an unexpired, interactive
  challenge explicitly marked for phone PIV signing.
- The machine endpoint authenticates the registered machine and binds the
  challenge ID, AD key hash and exact digest. It cannot replace a digest after
  creation.
- The phone endpoint checks the enrolled approval credential and active AD key
  for the same principal. The app independently checks the account, authority,
  host and expected digest format before prompting.
- The phone response is accepted once. Approval state and stored signature are
  committed atomically; denial, cancellation, revocation or expiry cannot
  leave an approved challenge behind.
- Before the phone signature arrives, Windows can only reach the PIV signing
  operation for the same live request ID. The server does not release a usable
  signature until it verifies the exact digest and atomically approves that
  challenge. A Windows password/PIN provider remains a separate recovery path
  unless policy disables it.
- The machine can retrieve only the signature for its own challenge. Signature
  bytes, digest bytes, passwords and QR contents are never written to logs.
- Old clients may continue the existing two-prompt flow until the one-prompt
  protocol is explicitly enabled and verified end to end.

## Important distinction

The successful password-plus-phone experiment is a separate comparison path.
It demonstrates that a normal password-based Windows logon avoids the slow
account flyout for `startmenutest`; it does not demonstrate passwordless PIV
sign-in, and the ordinary Windows password provider remains an alternate path.
Do not describe that experiment as enforced two-factor authentication.

## Verification sequence

Use a disposable lab account and Clone 1. Confirm exactly one biometric prompt,
the server rejects a modified or replayed digest, revoked/expired keys fail,
and the phone signature reaches the Windows PIV reader and is accepted by the
KDC. Then measure the Start account flyout after a fresh sign-in and after a
lock/unlock cycle. Keep the normal Windows recovery option until these checks
pass.
