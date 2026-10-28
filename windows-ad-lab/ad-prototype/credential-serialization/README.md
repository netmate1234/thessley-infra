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
`dwProvType = 0` and `dwKeySpec = 0`, identifying the CNG KSP path. Microsoft
documents that a zero legacy key spec is passed to `NCryptOpenKey` for a CNG
provider. The serialization helper accepts zero only with the exact Microsoft
Smart Card KSP name; legacy CSPs must use `AT_KEYEXCHANGE` (1) or
`AT_SIGNATURE` (2). The certificate has RSA-2048 and both KeyEncipherment and
DigitalSignature usages. This resolves the key-spec mismatch, but does not yet
prove that LogonUI accepts the resulting serialization for this TPM VSC.

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

References: Microsoft's [`CRYPT_KEY_PROV_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info)
documentation describes `dwProvType = 0` as CNG and passes `dwKeySpec` to
`NCryptOpenKey`; the [`KERB_SMARTCARD_CSP_INFO`](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerb-smartcard-csp-info)
documentation defines the credential serialization fields.
