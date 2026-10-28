# AD lab access guide

This guide records the current ways to reach the disposable Thessley AD lab.
It contains no passwords or private key material. Addresses can change if the
VM network or router configuration changes; verify them before relying on them.

## Machines and addresses

| Machine/service | Address | Port | Purpose |
| --- | --- | ---: | --- |
| `THESSLEY-DC1` management NIC | `192.168.122.98` | TCP 22 | SSH administration from the Ubuntu hypervisor using the local debug key |
| `THESSLEY-DC1` LAN NIC | `192.168.1.79` | TCP 47810 | Thessley AD approval API over HTTPS; phone and paired clients use this endpoint |
| `MARTIN-WM` management NIC | `192.168.122.66` | TCP 22 | SSH to the Windows 11 Pro domain client from the Ubuntu hypervisor; Thessley AD approval is required |
| `MARTIN-WM` LAN NIC | `192.168.1.103` | TCP 22 | Client SSH from the LAN; this address is documented from the lab setup and should be checked after VM/network changes |

The `.122.x` addresses are the libvirt management network. They are for
hypervisor-to-VM administration; they are not the phone-facing AD API address.
The `.1.x` addresses are on the LAN and are used for phone/client connectivity.
The AD API listens at `https://192.168.1.79:47810` and its Windows Firewall
rule is scoped to the LAN subnet `192.168.1.0/24`. Do not expose it to the
public internet.

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
  The normal Windows Thessley SSH gate has a configurable grace-pass feature
  (typically four hours, scoped to the same client IP). **The AD SSH prototype
  does not yet use that pass store**: `ad-ssh-gate` starts a new SID-bound
  phone approval for every SSH connection. That is a current feature gap, not
  a setting you can change in Admin today.
- The phone key and AD API machine key are distinct. The API holds metadata
  for enrolled phone keys and does not return their private key material.
- Passwords and private keys are never documented here. Lab credentials are
  maintained outside Git in the ignored local credential store; do not copy
  that file into commits or shared artifacts.

## Current deployment status

The AD API service on `THESSLEY-DC1` was updated and its scheduled task was
verified running on 2026-10-29. The source includes the AD-user key inventory,
enrollment, and revocation admin feature, but the corresponding Windows web
GUI package has not yet been installed on `MARTIN-WM`. The latest interactive
SSH request was reachable, but its phone response did not reach the AD API;
the request remained `pending` in the API state database. It expired without
opening a shell. AD SSH grace-pass reuse is also not implemented yet.

For lab topology, AD service behavior, and the implementation map, see
[`README.md`](README.md), [`STANDALONE-THESSLEY-SERVICE.md`](STANDALONE-THESSLEY-SERVICE.md),
and [`IMPLEMENTATION-MAP.md`](IMPLEMENTATION-MAP.md).
