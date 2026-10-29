# AD lab access guide

This guide records the current ways to reach the disposable Thessley AD lab.
It contains no passwords or private key material. Addresses can change if the
VM network or router configuration changes; verify them before relying on them.

## Machines and addresses

| Machine/service | Address | Port | Purpose |
| --- | --- | ---: | --- |
| `THESSLEY-DC1` management NIC | `192.168.122.98` | TCP 22 | SSH administration from the Ubuntu hypervisor using the local debug key |
| `THESSLEY-DC1` LAN NIC | `192.168.1.79` | TCP 47810 | Thessley AD approval API over HTTPS; phone and paired clients use this endpoint |
| `THESSLEY-DC1` LAN NIC | `192.168.1.79` | TCP 47820 | Separate HTTPS admin page for central AD phone enrollment and revocation |
| `MARTIN-WM` management NIC | `192.168.122.66` | TCP 22 | SSH to the Windows 11 Pro domain client from the Ubuntu hypervisor; Thessley AD approval is required |
| `MARTIN-WM` LAN NIC | `192.168.1.103` | TCP 22 | Client SSH from the LAN; this address is documented from the lab setup and should be checked after VM/network changes |

The `.122.x` addresses are the libvirt management network. They are for
hypervisor-to-VM administration; they are not the phone-facing AD API address.
The `.1.x` addresses are on the LAN and are used for phone/client connectivity.
The AD approval API listens at `https://192.168.1.79:47810`; the separate
admin page is at `https://192.168.1.79:47820/admin/`. Each has its own Windows
Firewall rule scoped to the LAN subnet `192.168.1.0/24` by default. Do not
expose either port to the public internet.

## SSH from the Ubuntu hypervisor

The debug private key is held locally at `~/.ssh/thessley-vm-debug`. Keep that
private key on the hypervisor; only its public key should be installed on a
VM. These commands are run in the Ubuntu hypervisor terminal.

### Domain controller

```bash
ssh -F /dev/null -i ~/.ssh/thessley-vm-debug Administrator@192.168.122.98
```

This reaches the DC management interface as its Windows `Administrator`
account. It is separate from the AD API, which listens on `.79:47810`.

### Windows client, domain account

```bash
ssh -tt -F /dev/null -o ConnectTimeout=8 -i ~/.ssh/thessley-vm-debug -l 'martin@lab.thessley.test' 192.168.122.66
```

Use the fully qualified AD identity `martin@lab.thessley.test`; the local
Windows account `MARTIN-WM\martin` is a different identity. The SSH key
authenticates the SSH account, then the Thessley AD SSH gate requests a
separate phone approval. `-tt` allocates a terminal so the link and QR can be
shown and Ctrl+C can cancel a waiting request. Approve the current request in
Thessley Passkey; an earlier approval or a chat message alone does not approve
a newly generated request.

### What happened in the latest access check

On 2026-10-29, the command above reached `MARTIN-WM`, authenticated far enough
to start the AD SSH gate, and displayed a fresh phone approval link and QR.
No phone approval arrived during that attempt, so the waiting session was
canceled with Ctrl+C. This confirms network reachability and SSH-key
authentication, but not a completed interactive SSH login.

## Phone and client access to the AD approval API

- API origin: `https://192.168.1.79:47810` (`THESSLEY-DC1` LAN interface).
- API TLS SHA-256 pin: `49a95d5ab0710aa9c6d822d0263a753e195e717aa2947377784c3a8a7f37bc99`.
- The phone follows a Thessley `thessleypam://login?...&api=ad` approval link
  and connects to the AD API. It does not connect directly to `MARTIN-WM`.
- The Windows client uses its paired machine identity to request/poll approval;
  the API checks the user SID against `THESSLEYLAB\ThessleyQRWorkstationAdmins`.
- The current firewall rule permits TCP 47810 from `192.168.1.0/24`. A phone
  on a different network needs an authorized route/VPN and a matching
  restricted firewall source range; changing the URL alone does not create
  that route.
- The browser admin page uses separate TCP 47820; it does not share the
  phone/workstation listener. Its firewall source range is configured
  independently by the DC service installer.

The Ubuntu hypervisor has `192.168.1.111` on `enp1s0`, while the DC's LAN
adapter MAC (`52-54-00-B4-8C-15`) is attached through `macvtap0` on that same
physical NIC. In this layout, the hypervisor host cannot directly reach the
macvtap guest at `192.168.1.79`; its packets get `Destination Host
Unreachable` at ARP. Other LAN devices can use the address. A temporary SSH
tunnel is available from the Ubuntu host:

```bash
ssh -NT -F /dev/null -i ~/.ssh/thessley-vm-debug \
  -L 127.0.0.1:14780:192.168.1.79:47820 \
  Administrator@192.168.122.98
```

With the tunnel running, browse to `https://127.0.0.1:14780/admin/`. The
browser will warn because the DC's certificate is self-signed and names
`192.168.1.79`, not localhost. The tunnel was verified to return HTTP 200.
From a phone or another LAN device, use `https://192.168.1.79:47820/admin/`
directly.

The AD API and the standalone local-account Thessley service are separate
services. Do not use the local-account service's port or enrollment records as
proof that an AD phone enrollment or AD API request is working.

## Other Windows remote access paths

The last connectivity check from the DC to `MARTIN-WM` found TCP 5985/5986
(WinRM), 445 (SMB), 135 (RPC), and 3389 (RDP) unreachable. Do not assume these
are usable for remote installation. The verified maintenance route is SSH to
`.66`, but it is currently gated by the AD phone approval described above.

For interactive console work, use the VM console. Domain sign-in and the
experimental Windows QR credential tile are separate from SSH and from the
AD API; retain the PIN/password recovery method when testing the tile.

## Authorization boundaries

- `THESSLEYLAB\ThessleyQRWorkstationAdmins` is the allowlisted AD group for
  workstation authorization and the AD approval API. Its current SID is
  `S-1-5-21-1719900462-4250469598-2954734011-1107`.
- On `MARTIN-WM`, that group is mapped into local `Administrators`; membership
  grants workstation admin rights there, not Domain Admin rights.
- SSH uses the domain account and a registered SSH key plus phone approval.
  Local and AD SSH accounts share the configurable grace duration and IP scope.
  AD passes are keyed by the domain SID hash (separate from a same-named local
  account), and each reuse rechecks current AD group authorization plus the
  approving phone key's active status. A pass expires at its original deadline
  and is not extended by reuse.
- The phone key and AD API machine key are distinct. The API holds metadata
  for enrolled phone keys and does not return their private key material.
- Passwords and private keys are never documented here. Lab credentials are
  maintained outside Git in the ignored local credential store; do not copy
  that file into commits or shared artifacts.

## Current deployment status

On 2026-10-29, the AD API was upgraded with server-side Android key
attestation verification. The installer retained the existing `service.json`,
TLS identity, firewall scope, and SQLite enrollment/key database, and saved a
pre-update snapshot at
`C:\ProgramData\ThessleyAD\backups\pre-update-20261029-224220`. The API
task is running and both `192.168.1.79:47810` and `:47820` are listening. The
TLS pin remains
`49a95d5ab0710aa9c6d822d0263a753e195e717aa2947377784c3a8a7f37bc99`.
The installed verifier hash matches the source package. The Android app
`0.1.25` was installed on the Samsung A52s with the same signing certificate
as the prior build, preserving its app data and Keystore entries. It now
requests StrongBox first, falls back to TEE, and warns before registering a
software-backed or unverified AD logon key. No new AD logon key has yet been
created to confirm this phone's hardware attestation. Use **Add AD logon key**
in the app; the server records and displays the verified protection level.
This key enrollment is still a prototype and does not yet enable Windows
passwordless sign-in.

At 22:50, the admin page was redeployed to label key status as TEE verified,
StrongBox verified, software-backed, or not verified. The service installer
created another state snapshot at
`C:\ProgramData\ThessleyAD\backups\pre-update-20261029-225016`. The task is
running and both listeners remain active; the TLS pin and firewall scopes are
unchanged.

On 2026-10-29, the central AD service was updated on `THESSLEY-DC1` using the
rollback-capable installer. The existing `service.json`, allow-group SID,
TLS certificate, firewall scope, and SQLite database were retained. State
snapshots are under `C:\ProgramData\ThessleyAD\backups`, including
`pre-update-20261029-154949` and the later split-port update snapshot. The API
listens on TCP 47810; the separate admin site listens on TCP 47820. From the
DC, `/admin/` returned HTTP 200 on 47820 and the same path returned 405 on
47810. Both firewall rules are scoped to `192.168.1.0/24`. Administrator
authentication, phone enrollment, cross-PC use, and revocation remain to be
verified interactively.

On 2026-10-29, the AD API and Windows service were both updated for AD SSH
grace-pass support. The DC task `ThessleyADApi` is running and listening on
`192.168.1.79:47810`; its existing `service.json`, AD allow group, and firewall
scope were retained. On `MARTIN-WM`, the approval task is running, local health
check on port 47800 passed, and the existing SSH/firewall settings were
preserved. The installed Windows package SHA-256 is
`ce9e93fdeb3955547a49a8957bd205be90f31d7e2fc28d73744990d9ed25293f`.

A live AD SSH check succeeded: the first login required phone approval and
created a four-hour pass for source IP `192.168.122.1`; a second login from the
same IP entered without another QR and reported 3 h 59 min remaining. The pass
is SID-scoped and remains subject to current AD group authorization and active
approver-key checks.

For lab topology, AD service behavior, and the implementation map, see
[`README.md`](README.md), [`STANDALONE-THESSLEY-SERVICE.md`](STANDALONE-THESSLEY-SERVICE.md),
and [`IMPLEMENTATION-MAP.md`](IMPLEMENTATION-MAP.md).
