# Android key protection for AD logon keys

The app creates each dedicated AD logon key in Android Keystore with
StrongBox requested first. If StrongBox is unavailable, it retries without
that request so Android can use its TEE-backed Keystore. The app reads
`KeyInfo` after generation. A software-only or unknown result produces a
confirmation warning before it submits the enrollment; the user may continue.

The AD service verifies the submitted attestation off the phone. It checks the
Google Android attestation roots (including the CA1 root introduced for new
chains in 2026), the certificate signatures and validity rules, Google's
revocation status, the attested public key, the request ID challenge, and the
attestation/keymaster security levels. Old factory chains with Google's
`f92009e853b6b045` root serial retain Google's documented expiration
exception; they are still checked against the revocation list.

Attestation is descriptive rather than a login gate under the current policy:
TEE, StrongBox, software-backed, and unverifiable keys can all be registered
after the normal phone approval and proof-of-possession checks. Software or
unverifiable keys are visibly marked as less protected. If Google roots,
revocation data, or the chain cannot be verified, the service reports
`unverified`; it does not claim TEE protection. The software-key warning does
not mean Windows sign-in is complete: the Windows credential-provider bridge
is still a separate prototype step.

The Google revocation list is fetched over HTTPS with a short timeout and
cached in process memory according to its `Cache-Control` max age (capped at
24 hours). If it cannot be reached after the cache expires, attestation is
reported as unverified and the user can continue with the warning. The app's
local `KeyInfo` report is useful feedback, but the service-side attestation is
what distinguishes verified hardware protection from a local software claim.

Sources: [Android key attestation verification guidance](https://developer.android.com/privacy-and-security/security-key-attestation),
[AOSP attestation data schema](https://source.android.com/docs/security/features/keystore/attestation),
[Android `KeyInfo.getSecurityLevel()`](https://developer.android.com/reference/android/security/keystore/KeyInfo).
