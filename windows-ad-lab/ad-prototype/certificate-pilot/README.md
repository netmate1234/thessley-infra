# Isolated AD certificate sign-in pilot

This folder contains an unintegrated proof step for a generic, phone-approved
AD certificate login. It does not register a Windows Credential Provider,
change a sign-in policy, contact a CA, or perform PKINIT.

## Fresh local key and CSR

`new-ephemeral-csr.ps1` uses the Windows Certificate Enrollment API to create a
new RSA-3072 key in the machine `Microsoft Software Key Storage Provider`.
The key is non-exportable and its key ACL is limited to SYSTEM and local
Administrators. Each attempt gets a random container prefix and random subject;
the account, domain name, and certificate template are not compiled or written
into the request. The script writes DER PKCS#10 and a protected JSON manifest
under `%ProgramData%\ThessleyPamWin\ad-agent\certificate-requests`.

The manifest expires after five minutes. To remove a cancelled attempt by its
ID, run elevated:

```powershell
& '.\cleanup-ephemeral-csr.ps1' -RequestId 'REQUEST-GUID' -Reason Cancelled
```

To reap only expired requests:

```powershell
& '.\cleanup-ephemeral-csr.ps1' -SweepExpired
```

The cleanup script validates the manifest and generated container prefix,
removes only the matching machine key and matching temporary request-store
record, then deletes the CSR and manifest. It retains the manifest if key
deletion fails. Automatic cleanup after successful sign-in and a scheduled
expiry sweep are not yet integrated.

The returned CSR digest can be passed to the existing isolated client:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' certificate-approval-start --sid 'DOMAIN-SID' --csr-file 'CSR-PATH'
```

The command will refuse because the certificate method is intentionally absent
from selectable policy. This keeps the proof path inert until the CA and KDC
gates below are implemented.

## Broker-side request validation

`infra/thessley_ad_service/certificate_requests.py` contains a pure validation
helper for the future broker boundary. Before any CA operation is added, callers
must pass the exact DER bytes and the digest bound into phone approval to
`validate_approved_csr`. It enforces the size bound, digest equality, valid
PKCS#10 signature, RSA-3072/SHA-256 profile, one random temporary CN, and no
requested extensions. It returns only request fingerprints and metadata; it
does not contact AD CS, authorize a SID, consume approval, or issue a
certificate. It is not yet wired to an HTTP route, by design.

## Still required

- A CNG-backed Credential Provider path that can use the issued key for
  Kerberos certificate logon.
- A broker-side, tightly restricted Enrollment Agent identity and signed CMC
  Enrollment-on-Behalf-of request.
- A CSR upload route that verifies the challenge is still approved and
  unexpired, binds the uploaded DER bytes to the approved digest, and invokes
  the strict CSR helper above before any CA operation.
- Issued-certificate, EKU, template, issuer, validity, and strong SID mapping
  checks on both broker and workstation.
- One-use delivery of the certificate to the originating machine, followed by
  PKINIT validation in a disposable domain-joined VM.
- Cleanup after success, denial, timeout, crash, and reboot; recovery must not
  delete unrelated machine keys or certificates.

No CA template should be published and no login tile should be installed from
this proof until those gates have passed. The helper uses the Windows software
KSP; it does not claim TPM/TEE key protection.

The implementation follows Microsoft's documented `IX509PrivateKey` and
`IX509Enrollment` APIs and `certutil -delkey` semantics:
[Certificate request creation](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializefromprivatekey),
[DER request encoding](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-createrequest),
[machine-key context](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1),
[key deletion](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).
