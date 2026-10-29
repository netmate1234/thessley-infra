# Central AD login and DC management site

## Current state

The domain controller runs a small Python HTTPS login API on TCP 47810 and a
separate HTTPS administration site on TCP 47820. The login API on 47810 is
reserved for phone approvals and signed workstation requests; browser
administration is on 47820 only. The service
uses Windows LDAP/SSPI to read AD and stores machine registrations, login
challenges, and phone public keys in the protected
`C:\ProgramData\ThessleyAD\state.sqlite3` database. The new source hosts
`/admin/` on its own port and supports SID-wide AD enrollments. The signed
Android 0.1.22 release recognizes account-wide keys. The split-port service
update is installed on the disposable DC: the admin listener returns `200 OK`
on TCP 47820, while TCP 47810 remains API-only. The DC admin page now offers QR
phone sign-in alongside password sign-in. The updated service was deployed
with a pre-update state backup; interactive QR approval and rights-display
verification remain outstanding.

No Clone 1 client update is needed for central key scope: it keeps using its
existing machine-paired signed API on TCP 47810. SID-wide key lookup is handled
by the DC service, and the phone app already understands the central enrollment
scope. The Clone 1 machine still must be paired and able to reach the DC API.

The local Thessley Windows sign-in provider is a separate path. Keep its local
account keys and offline behavior unchanged.

## Intended design

## Sign-in method policy

The AD service now stores sign-in method rules in the protected state database
and exposes them under **Admin → Sign-in method policy**. Administrators can
choose a domain default, add AD-group overrides with priorities, and set an
override for a paired workstation. The effective rule order is workstation,
then highest-priority matching nested AD group, then domain default. Equal
priority group rules selecting different methods are rejected. Each rule stores
the last administrator SID and timestamp; administrator actions are also
written to the Windows service log with the target and new method.

The available choices are `tpm_smartcard` (phone approval gates use of the
existing per-user TPM virtual smart-card credential on that PC) and
`windows_native` (the Thessley QR method is refused; Windows password/Hello
remain available). The API returns the effective method and source with signed
principal resolution and phone-request responses. The Windows agent checks
those fields and fails closed if the response is missing, malformed, or asks
the current TPM tile to use another method.

`phone_ephemeral_certificate` remains intentionally unavailable. It is still
blocked on proving strongly SID-mapped AD CS issuance and KDC logon. Windows
password and Hello remain local recovery options outside the Thessley policy.
An unavailable selected method must never silently downgrade to another
credential path.

The Python management website is hosted by the DC at
`https://192.168.1.79:47820/admin/`, separate from the phone/workstation API at
`https://192.168.1.79:47810`. The DC is the authority for AD-account
enrollment, phone-key status, and the group policy used by AD QR sign-in.

The site lets an authorized administrator:

- Search/browse enabled AD users and show whether the configured sign-in group
  authorizes workstation QR sign-in, and whether they are members of the DC's
  built-in Administrators group. These are separate rights.
- Start phone enrollment for a selected AD user, display the Thessley QR and
  matching short pairing code, and confirm the code after scanning.
- List the enrolled phone labels and enrollment dates for that AD user.
- Revoke an AD user's phone credential centrally. Revocation must take effect
  on the next approval attempt from any enrolled workstation.
- Show the currently configured Thessley sign-in group. Mapping AD groups to
  workstation administrator rights remains a separate AD/GPO task.
- Configure the Thessley credential method by domain default, AD group, and
  paired workstation. A workstation override wins; otherwise the highest-
  priority matching nested AD group rule wins; otherwise use the domain
  default. Conflicting rules at the same priority must be rejected.
- See stored rules and their precedence. Per-user effective-method reporting
  for arbitrary user/workstation pairs is not yet shown in this UI. Keep
  Windows password/Hello recovery available regardless of the Thessley method.
  A failed phone approval or unavailable selected method must not silently
  switch to a different credential.

AD user and group creation/membership changes remain in Active Directory's
normal management tools. The Thessley site manages Thessley enrollment and
policy; it must not silently edit directory accounts or group membership.

## Login flow

1. A domain-joined Windows client authenticates to the DC API using its
   enrolled machine signing key and sends the interactive or unlock request,
   the user's SID, and the local computer identity.
2. The DC resolves the SID in AD, checks that the account is enabled and is in
   an allowed sign-in group, and creates a one-use challenge bound to that
   machine, user SID, login context, and expiry.
3. The phone signs the challenge with its locally held Thessley key. The phone
   key is registered centrally against the AD SID, not against an individual
   workstation. The request remains bound to the requesting workstation, so
   an approval cannot be replayed on another PC.
4. The DC validates the signature and returns the one-use result only to the
   machine that created the challenge. The Windows provider continues its
   existing credential submission path.
5. If the DC or network is unavailable, AD QR sign-in fails with a useful
   message. The existing local-account QR, PIN, and password options remain
   available for offline recovery.

Phone private keys stay on the phone. The DC stores public keys only. Revoking
a key at the DC blocks it for all PCs without visiting each PC.

## Admin site security requirements

- Authenticate administrators with their domain identity; do not add a shared
  admin password or trust a username supplied by the browser.
- Both password and QR sign-in require an enabled domain account in the DC's
  built-in Administrators group. QR sign-in additionally requires an active,
  centrally enrolled phone key for that exact AD SID. The workstation QR
  sign-in group does not grant web-admin access. Phone enrollment is available
  to users in either the configured workstation sign-in group or the DC's
  built-in Administrators group. This lets an administrator enroll their own
  AD account without changing workstation sign-in eligibility.
- Serve HTTPS with the DC service certificate and restrict the management
  listener in Windows Firewall to approved management networks.
- Use short idle sessions, secure/HTTP-only cookies, CSRF protection, output
  escaping, request-size limits, and no-store caching for enrollment pages.
- Audit administrator, target SID, action, timestamp, and result. Never log
  passwords, QR challenge secrets, phone signatures, or private key material.
- Keep the signed machine API on TCP 47810 compatible. Serve the admin UI on
  its own TLS listener at TCP 47820 with an independently scoped firewall
  rule; both listeners use the same DC certificate.

## Implementation sequence

1. Source now supports a SID-scoped central phone-key binding while preserving
   machine-scoped records. Central keys are accepted only for that SID; every
   approval remains bound to its requesting machine.
2. Source now adds a DC admin page for enabled-user listing, centrally scoped
   phone enrollment with QR/pairing confirmation, key listing, and revocation.
   Password login validates a domain account with Windows `LogonUser`; the
   password is not stored. An alternative QR flow creates a short-lived,
   single-use challenge for an exact AD username, signs it with that SID's
   centrally enrolled phone key, and rechecks current DC Administrators-group
   membership before creating the same short admin session. Password login
   remains available as recovery.
3. The Android 0.1.22 source recognizes central AD keys across paired PCs and
   labels their scope. It was built with the existing release signing setup
   and installed on the connected phone without clearing app data.
4. The updated service is deployed to the disposable lab with separate API
   (47810) and admin (47820) listeners. Verify password and QR administrator
   login, enrollment, cross-PC approval, revocation, offline behavior, and
   recovery before deploying to other PCs.

Do not install these changes on production PCs until the web login, enrollment,
cross-PC approval, revocation, and local-account recovery paths are verified
together in the disposable lab.
