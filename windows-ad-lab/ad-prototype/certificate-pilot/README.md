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

Start the isolated approval using the CSR file so the local client computes the
digest from canonical DER:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' certificate-approval-start --sid 'DOMAIN-SID' --csr-file 'CSR-PATH'
```

After the phone approves, submit the same request file while polling:

```powershell
& 'C:\ProgramData\ThessleyPamWin\ad-prototype\thessley-ad-test.cmd' certificate-approval-poll --request-id 'REQUEST-ID' --csr-sha256 'APPROVED-DER-SHA256' --template 'CONFIGURED-TEMPLATE' --csr-file 'CSR-PATH'
```

The paired machine signs the upload. The service accepts it only once, for the
matching machine and approved challenge, revalidates the exact DER request, and
stores it once with the challenge record. An exact retry returns the same
verification receipt; a different CSR is rejected. The CSR is public material, but
the service database remains service-owned and ACL-protected. No endpoint can
retrieve it or submit it to AD CS yet; this upload currently ends with a
validation receipt.
Certificate issuance and Windows logon remain unavailable.

## Broker-side request validation

`infra/thessley_ad_service/certificate_requests.py` contains the broker's strict
CSR validation helper, called by the upload route. It enforces the size bound,
digest equality, valid
PKCS#10 signature, RSA-3072/SHA-256 profile, one random temporary CN, and no
requested extensions. It returns only request fingerprints and metadata; it
does not contact AD CS, authorize a SID, consume approval, or issue a
certificate. The upload route stores the public CSR once against its approved
challenge. It has no retrieval endpoint and cannot issue certificates.

## Still required

- A CNG-backed Credential Provider path that can use the issued key for
  Kerberos certificate logon.
- A broker-side, tightly restricted Enrollment Agent identity and signed CMC
  Enrollment-on-Behalf-of request.
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
