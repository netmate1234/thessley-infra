# AD certificate serialization spike

This directory contains isolated helpers for the future AD-only Credential
Provider. The certificate helper builds `KERB_CERTIFICATE_LOGON` or
`KERB_CERTIFICATE_UNLOCK_LOGON`; the ticket helper builds `KERB_TICKET_LOGON`
for the built-in Kerberos package. The probe separately calls
`LsaLogonUser` in an isolated lab; none of these helpers performs PKINIT,
talks to the approval service, registers a provider, or alters a Windows
sign-in path.

`ad_approval_client.cpp` is the separate native adapter for the AD agent. It
starts the existing Python agent with a SID and logon context, captures its
bounded JSON response without a shell or visible console, and polls the
machine-bound one-use decision. Cancellation terminates only the local polling
process; the server request expires naturally. The caller must close the QR
viewer and securely clear the response after use. It is not yet called by a
Credential Provider.

The PIN parameter must already be protected with `CredProtect`. The helper
checks that property and refuses an unprotected PIN. The caller supplies the
Kerberos authentication-package ID, provider CLSID, and card metadata. Optional
card and reader names are serialized as empty strings; the container name is
required. The returned buffer must be securely freed with
`FreeKerbCertificateSerialization` if it is not handed to LogonUI. After
handoff, LogonUI owns it.

## Certificate-pilot boundary

The separate `certificate-pilot` currently generates the private key in the
PC's Software KSP. Installing the CA response with `certreq -accept` does not
make that key a phone key, and this serializer is not a generic interface for
any certificate in `LocalMachine\My`. `KERB_CERTIFICATE_LOGON` is the Kerberos
smart-card logon structure; its `CspData` carries
`KERB_SMARTCARD_CSP_INFO` metadata for a smart-card provider, key container,
and optional card/reader ([KERB_CERTIFICATE_LOGON](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon),
[KERB_SMARTCARD_CSP_INFO](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info)).
Windows' smart-card subsystem routes key operations through the Base CSP/KSP
and a card minidriver ([Smart Card Architecture](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-architecture),
[Smart Card Minidriver Overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview)).

Therefore the current Software KSP certificate is not wired into this tested
VSC serializer. The new ticket serializer supports a different candidate:
Android performs PKINIT with its TEE-held key, requests the exact computer
host ticket, then delivers that KDC-issued ticket and a forwarded TGT for
`KERB_TICKET_LOGON`. This avoids asking Windows to call a remote private-key
provider. Microsoft describes `KERB_TICKET_LOGON` as a *network logon*; the
documentation does not promise that this serialization produces a usable
interactive desktop through a third-party Credential Provider. An isolated
LSA probe did return a primary token for an `Interactive` logon using a cached
host ticket, but it did not exercise Winlogon or a Credential Provider. Treat
the route as a feasibility experiment only. The existing TPM VSC path remains
the only proven end-to-end interactive sign-in path. End-to-end requirements
are in
[`certificate-pilot/PHONE-HELD-KEY-DESIGN.md`](../certificate-pilot/PHONE-HELD-KEY-DESIGN.md).

## Current lab blocker

The existing Martin certificate is present in the domain user's store, uses
`Microsoft Smart Card Key Storage Provider`, and has this TPM VSC container:
`te-ThessleyVscLogon-0ef1969d-38db-09390`. Its certificate metadata reports
`dwProvType = 0` and `dwKeySpec = 0`, identifying the CNG KSP path. That
certificate metadata value is not the same as `KERB_SMARTCARD_CSP_INFO.KeySpec`:
Microsoft documents the serialization field as `AT_KEYEXCHANGE` (1) or
`AT_SIGNATURE` (2). On the test VM, `certutil -key -csp SC` identifies this VSC
container as `AT_KEYEXCHANGE`, so the provider must serialize 1 while keeping
the exact Microsoft Smart Card KSP and container names. Passing zero first
caused `STATUS_SMARTCARD_SUBSYSTEM_FAILURE` (`0xC0000321`); passing 2 then
caused `STATUS_SMARTCARD_NO_KEY_CONTAINER` (`0xC0000384`). The provider uses the
key spec reported by the actual container. The latter status persisted with
the correct key spec and reader name. Local System's `certutil -scinfo -sid 22`
shows this VSC on reader `Microsoft Virtual Smart Card 0`; the Calais
registration names its card `Identity Device (Microsoft Generic Profile)`.
The same output exposes a legacy `Microsoft Base Smart Card Crypto Provider`
view of the container with `AT_KEYEXCHANGE`, alongside the CNG KSP view. The
Kerberos CSP serialization uses that legacy provider, exact reader, card
profile, and key spec. On 2026-10-28 the isolated VM completed an AD sign-in:
`BuildADCertificateLogon` returned success with a 584-byte serialization and
`ReportResult` returned `STATUS_SUCCESS` after LogonUI submitted it. This only
verifies the lab's TPM virtual smart-card path; it does not establish direct
phone-key PKINIT.

The provider writes a bounded diagnostic trace to
`C:\ProgramData\ThessleyPamWin\ad-credential-provider\provider.log`. AD
serialization events record HRESULTs, lengths, auth-package ID, and fixed
nonsecret VSC metadata. They must never include a PIN, account name/SID, QR
payload, or phone-approval response. The trace distinguishes PIN protection,
qualified-name parsing, Kerberos package lookup, buffer construction, and the
final LSA status/substatus. When changing the provider DLL, verify its SHA-256
against the build output and reload LogonUI (a VM reboot was used for this
test) before interpreting the trace.

The direct phone-key target is PKINIT in Android followed by Kerberos ticket
logon in Windows. The phone key performs the KDC authentication signature; the
Windows machine receives only the short-lived KDC-issued ticket material. The
ticket serializer is not yet connected to the Credential Provider, and this
flow has not yet passed an interactive logon test. The existing TPM VSC path
remains available as recovery.

## Build

From the repository root on Linux with MinGW-w64 installed:

```sh
bash infra/windows-ad-lab/ad-prototype/credential-serialization/build.sh
```

The script writes three object files and the self-contained lab probe
`/tmp/thessley-ad-ticket-logon-probe.exe`; it does not produce or install a
Credential Provider DLL. The probe must run as LocalSystem on a disposable
lab machine. It accepts a cached logon LUID and host SPN, reads the ticket into
memory, calls LSA, reports only status/token metadata, and wipes the ticket
buffer. It does not write ticket data to disk. Example:

```text
ticket_logon_probe.exe 0x18d8d0 HOST/COMPUTER.example.test interactive
```

Do not use this probe to capture or export tickets from production sessions.

References: Microsoft's [`CRYPT_KEY_PROV_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info)
documentation describes `dwProvType = 0` as CNG and passes `dwKeySpec` to
`NCryptOpenKey`; the [`KERB_SMARTCARD_CSP_INFO`](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info)
documentation defines the credential serialization fields.

### Clone 1 ticket handoff investigation (2026-10-30)

The broker successfully returned a 1435-byte HOST ticket for the explicitly
configured test account. Direct `LsaLogonUser(Interactive)` probes succeeded
with both Kerberos and Negotiate, returning a primary token. Negotiate's
package ID on this machine is **0**, which is valid; serializers must not
reject zero as an invalid package ID. The probe now accepts an optional
`negotiate` argument to reproduce this without another phone approval.

Other defects corrected during this investigation: SID validation now checks
the `S-` prefix correctly; automatic submission uses the ticket path without a
saved password; and the broker captures again on workstation lock. The ticket
serializer now selects the Kerberos package and uses the correct
`KERB_TICKET_LOGON` or `KERB_TICKET_UNLOCK_LOGON` structure for the active
scenario. Its temporary ticket lifetime remains three minutes. Restarting the
broker clears its in-memory cache.

Direct LSA success does **not** prove the LogonUI handoff works. Clone 1's
first screen attempt reached ReportResult with `STATUS_LOGON_FAILURE` /
`STATUS_INTERNAL_ERROR` after the broker successfully delivered the ticket.
The provider was using Negotiate and an unlock-sized header for a fresh logon.
The current correction switches to Kerberos and chooses the structure based on
the active logon/unlock scenario. End-to-end screen login with that correction
remains to be verified. Broker and provider diagnostics record stage, SID, and
status codes, never ticket bytes or passwords.
