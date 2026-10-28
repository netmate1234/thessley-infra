# AD certificate serialization spike

This directory contains a small, isolated helper for the future AD-only
Credential Provider. It builds a `KERB_CERTIFICATE_LOGON` or
`KERB_CERTIFICATE_UNLOCK_LOGON` buffer for LogonUI; it does not call
`LsaLogonUser`, talk to the approval service, register a provider, or alter a
Windows sign-in path.

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

The eventual near-term flow is phone approval followed by this TPM VSC
certificate logon. The private key remains on the PC. This is not the
phone-held-key PKINIT target.

## Build

From the repository root on Linux with MinGW-w64 installed:

```sh
bash infra/windows-ad-lab/ad-prototype/credential-serialization/build.sh
```

The script writes two object files under `/tmp`; it does not produce or install
a Credential Provider DLL.

References: Microsoft's [`CRYPT_KEY_PROV_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info)
documentation describes `dwProvType = 0` as CNG and passes `dwKeySpec` to
`NCryptOpenKey`; the [`KERB_SMARTCARD_CSP_INFO`](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info)
documentation defines the credential serialization fields.
