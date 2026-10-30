# Thessley AD login for a school

## Goal

One phone enrollment per AD account and phone should work on every approved
school workstation. Users should not need a separate key for every PC. Regular
users get ordinary Windows user rights; a separate IT group gets local admin
rights on workstations. Servers are outside the workstation policy.

## The short version

**Enroll each person's phone once in the AD service. Pair each PC once with
the AD service. Do not enroll a person's phone separately on every PC.** The
phone proves the person's identity; AD group membership decides where the
person may sign in and whether they receive workstation administrator rights.

```text
Phone private key ──signs approval──▶ Central AD service
                                           ▲
                                           │ signed request
Windows PC ──its own machine key, once────┘
     │
     └── Windows gets standard/admin rights from AD groups and policy
```

The PC stores its own machine credential. It does not receive each user's
phone key. The central service stores each phone's public key under the user's
AD SID, so the same enrollment can be recognized from every paired PC.

## What works today versus the school target

The lab currently demonstrates central AD account lookup, central phone-key
enrollment/revocation, workstation pairing, group authorization, and the AD QR
approval gate for SSH. It does **not** yet provide a finished QR Credential
Provider for Windows desktop sign-in across a fleet. The central key design
does not require per-PC phone enrollment, but the desktop sign-in bridge still
needs implementation and lab validation before this can be rolled out to
students and staff.

## What is registered

| Item | Registered once | Stored centrally | Stored on the device |
| --- | --- | --- | --- |
| User phone | Per phone and AD account | Public key, AD SID binding, label, active/revoked status | Private signing key in the phone's Android Keystore |
| Windows workstation | Per PC | Machine public key, machine name, registration and revocation status | Machine private key protected for the local service |

The DC does not need a copy of the phone's private key. A workstation does not
need a copy of each user's key. The phone key remains tied to the AD SID, so a
same-named local Windows account is a different identity.

For example, 300 users and 100 PCs mean up to 300 phone registrations (more if
users have multiple phones) and 100 machine registrations—not 30,000
user-to-PC keys.

## Suggested AD groups and computer layout

Use AD as the source of truth for membership and Windows rights:

- `School-Workstation-Users`: students and staff allowed to sign in to normal
  school PCs. Membership grants standard-user access only.
- `School-Workstation-Admins`: IT staff who receive local Administrators
  membership on managed school PCs through Group Policy.
- `School-Server-Admins`: administrators for servers, controlled by server
  policy. It does not grant access to the Thessley workstation login policy.
- Put managed PCs in a `Workstations` OU and servers in a separate `Servers`
  OU. Link workstation logon and local-group policies only to the workstation
  OU; do not pair server machines as Thessley workstations.

At each workstation sign-in, the AD service should make two independent
decisions:

1. Is this an enabled AD user in `School-Workstation-Users` or
   `School-Workstation-Admins`?
2. Is the requesting machine an enrolled workstation in the permitted machine
   scope?

Phone approval answers whether the enrolled phone approves this exact,
short-lived request. It must not grant local administrator rights. Windows
rights come from the user's AD groups and workstation Group Policy. Remote
Desktop access should have its own policy and group.

## Simple IT workflow

1. Join and place each classroom or staff PC in the `Workstations` OU. A
   managed deployment task registers that PC once and marks its role as
   `workstation`.
2. Add a student or staff member to `School-Workstation-Users` using the
   school's normal identity-management process.
3. Enroll that person's phone once against their AD account. The first
   enrollment uses a displayed QR and pairing-code confirmation. Further
   enrollments and revocations are managed centrally by authorized IT staff.
4. The user can then use that account on any enrolled workstation covered by
   the policy. Group removal blocks future logins; revoking a phone blocks
   approvals from that phone across all workstations.
5. Add a technician to `School-Workstation-Admins` only when they need local
   admin rights on workstations. Keep server administration in its separate
   group and OU.

In daily use, IT should normally change AD membership, not reconfigure every
PC:

| Request | IT action | Effect on managed workstations |
| --- | --- | --- |
| New student or staff member | Add the account to `School-Workstation-Users`; enroll their phone once | Sign-in is approved as a standard user |
| Technician needs workstation admin | Add the account to `School-Workstation-Admins` | Sign-in is allowed and workstation policy grants local admin rights |
| Remove access | Disable the account or remove its access-group membership | New sign-ins are denied centrally |
| Lost phone | Revoke that phone's public key centrally, then enroll a replacement | The lost phone can no longer approve on paired PCs |

PC setup is a one-time device task: join it to AD, place it in the workstation
OU, pair it with the service, and apply workstation sign-in and local-admin
policies. A new user does not require another PC installation.

The Thessley admin page should have searchable, paged user and workstation
lists. A user card should show account status, workstation sign-in eligibility,
workstation-admin membership, and that account's phone keys. A workstation card
should show its name, assigned role, and pairing status. Enrollment and phone
revocation stay central. AD group membership remains authoritative. If the UI
later edits group membership, it should use a narrowly delegated identity and
audit every change; the login service should not receive broad domain-admin
write privileges merely to approve logins.

## Authentication and availability

The AD service is the central authority for phone public keys, revocation,
machine pairing, and group checks. It should be deployed on a dedicated,
managed service host in a production school, using LDAPS and a read-only AD
identity, rather than relying on the lab's LocalSystem-on-DC setup. Keep the
phone approval API separate from the admin website and limit each firewall
rule to the required school networks.

QR approval requires the workstation, phone, and approval service to have a
working route to each other. Keep a supported recovery method for a phone,
network, or service outage. A password or Windows Hello fallback can use
cached domain credentials where configured; QR approval itself cannot work
while the phone cannot reach the service.

## Current prototype gaps

- The AD service already stores central phone public keys bound to AD SIDs,
  checks enabled users and configured sign-in groups, and pairs workstation
  machine keys. Phone private keys remain on the phone.
- `service.json` currently has one `allowed_group_sids` allowlist. For a
  school, it can include both the standard workstation sign-in group and the
  workstation-admin group. Local admin rights still come from workstation
  policy, not phone approval. A separate admin-group indicator in the UI would
  make that distinction easier to see.
- The current admin account list is a single enabled-user listing capped at
  1,000 entries; a school deployment needs server-side search and pagination
  instead of loading the entire directory for each page view.
- A paired machine is currently identified by its registered machine key and
  name. The production policy still needs a protected workstation role or AD
  computer-group check so an accidentally paired server cannot use the
  workstation policy.
- The current QR flow is phone approval. It does not yet produce a native
  passwordless AD logon credential. A Windows-to-AD credential bridge must be
  implemented and lab-tested before claiming passwordless school sign-in.

These gaps should be closed in the lab first. Keep ordinary AD password or
Windows Hello recovery available while testing the new credential provider;
never disable the existing recovery tile across the fleet as part of the
initial deployment.
