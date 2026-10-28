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
`AT_SIGNATURE` (2). This certificate is used for PKINIT signing, so the provider
must serialize `AT_SIGNATURE` (2) while keeping the exact Microsoft Smart Card
KSP and container names. Passing zero into the serialization field caused
Windows to report `STATUS_SMARTCARD_SUBSYSTEM_FAILURE` (`0xC0000321`). The
corrected value still needs a fresh isolated LogonUI sign-in test.

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
