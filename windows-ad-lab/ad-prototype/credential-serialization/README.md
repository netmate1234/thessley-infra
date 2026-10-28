# AD certificate serialization spike

This directory contains a small, isolated helper for the future AD-only
Credential Provider. It builds a `KERB_CERTIFICATE_LOGON` or
`KERB_CERTIFICATE_UNLOCK_LOGON` buffer for LogonUI; it does not call
`LsaLogonUser`, talk to the approval service, register a provider, or alter a
Windows sign-in path.

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
`dwKeySpec = 0` (CNG), while the Kerberos smart-card serialization's `KeySpec`
uses `AT_KEYEXCHANGE` (1) or `AT_SIGNATURE` (2). The certificate has RSA-2048
and both KeyEncipherment and DigitalSignature usages. The correct serialization
KeySpec still needs to be established from the working Windows smart-card
provider/card behavior; do not guess it in a sign-in attempt. This is why the
helper requires the caller to pass an explicit valid value and is not yet
connected to a credential tile.

The eventual near-term flow is phone approval followed by this TPM VSC
certificate logon. The private key remains on the PC. This is not the
phone-held-key PKINIT target.

## Build

From the repository root on Linux with MinGW-w64 installed:

```sh
bash infra/windows-ad-lab/ad-prototype/credential-serialization/build.sh
```

The script writes an object file under `/tmp`; it does not produce or install a
Credential Provider DLL.
