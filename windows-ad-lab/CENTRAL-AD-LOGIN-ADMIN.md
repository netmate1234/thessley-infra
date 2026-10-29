# Central AD login and DC management site

## Current state

The domain controller already runs a small Python HTTPS API on TCP 47810. It
uses Windows LDAP/SSPI to read AD and stores machine registrations, login
challenges, and phone public keys in the protected
`C:\ProgramData\ThessleyAD\state.sqlite3` database. The API is not an admin
website. Today, phone credentials are scoped to both a Windows machine and an
AD SID, so an enrollment on one PC does not authorize the same account on
another PC.

The local Thessley Windows sign-in provider is a separate path. Keep its local
account keys and offline behavior unchanged.

## Intended design

Add a small Python management website hosted by the DC, separate from the
machine API routes. The DC is the authority for AD-account enrollment, phone
key status, and the group policy used by AD QR sign-in.

The site should let an authorized administrator:

- Search/browse enabled AD users and show their relevant group memberships.
- Start phone enrollment for a selected AD user, display the Thessley QR and
  matching short pairing code, and confirm the code after scanning.
- List the enrolled phone labels and enrollment dates for that AD user.
- Revoke an AD user's phone credential centrally. Revocation must take effect
  on the next approval attempt from any enrolled workstation.
- View which AD groups grant QR sign-in and workstation administrator rights.

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
- Require membership in a separately configured AD management group. Do not
  assume that the workstation QR sign-in group is also allowed to administer
  the DC service.
- Serve HTTPS with the DC service certificate and restrict the management
  listener in Windows Firewall to approved management networks.
- Use short idle sessions, secure/HTTP-only cookies, CSRF protection, output
  escaping, request-size limits, and no-store caching for enrollment pages.
- Audit administrator, target SID, action, timestamp, and result. Never log
  passwords, QR challenge secrets, phone signatures, or private key material.
- Keep the existing signed machine API on TCP 47810 compatible while the admin
  UI is added. Use a distinct listener/route and explicit firewall rule for
  browser management.

## Implementation sequence

1. Add a SID-scoped central phone-key registry with a migration that preserves
   existing machine-scoped records. Verify lookup precedence and revocation
   behavior before enabling it for sign-in.
2. Add DC-initiated enrollment routes using the existing Thessley phone
   enrollment signature format and pairing-code confirmation. Keep enrollment
   short-lived, single-use, and tied to the selected AD SID.
3. Add the authenticated Python admin site for directory browsing, enrollment,
   key listing/revocation, and group-policy visibility.
4. Update the Windows AD tile client to request and poll the DC centrally;
   leave the local account provider untouched.
5. Test migration, approval, cross-PC use, revocation, offline behavior, and
   rollback on the disposable Windows lab before deploying to other PCs.

Do not switch existing AD sign-in to global keys until the central enrollment
and authorization paths are implemented and verified together.
