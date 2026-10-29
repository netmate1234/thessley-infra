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
validation receipt. Both service runtimes purge expired challenge and CSR rows
at startup and every 60 seconds.
Certificate issuance and Windows logon remain unavailable.

## CMC/EOBO request construction (source-only)

`build-eobo-cmc.ps1` is an isolated issuer-side primitive. It is restricted to a
domain controller, requires an explicitly configured Enrollment Agent
thumbprint and certificate template name, validates that the CSR digest matches
the phone-approved digest supplied by its caller, verifies the Enrollment Agent
certificate chain and revocation status, and creates a signed CMC/EOBO request.
It does **not** submit the request, install a certificate, or export the
Enrollment Agent private key. Its JSON output contains the signed CMC request;
handle it as an enrollment artifact and keep it out of shared logs.

The surrounding broker is not wired to call this helper yet. Before integration,
the broker must itself prove the approval is still valid, bind the exact CSR
digest to the approved account SID and `DOMAIN\user` RequesterName, enforce a
single-use issuance transaction, and allow only an explicitly configured
template. The helper's parameters are not an authorization mechanism. Never
distribute the Enrollment Agent certificate or this helper to workstation
clients.

EOBO changes the subject semantics: the CA uses the CMC `RequesterName` value
to construct the issued certificate subject. Because this pilot's PKCS#10 CSR
uses a randomized temporary subject, the issued-certificate validator therefore
binds the certificate to the CSR by public key and to the approved account by
the AD SID extension; it does not compare the resulting subject to the temporary
CSR subject. The requester name is not treated as the strong identity binding.
See [Microsoft's EOBO request format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92a48c37-2928-4800-9e91-40aad6a9bc3b),
[the CertEnroll EOBO sample](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/enrolleobocmc),
and [the `ISignerCertificate.Initialize` parameters](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-isignercertificate-initialize).

## Broker-side request validation

`infra/thessley_ad_service/certificate_requests.py` contains the broker's strict
CSR validation helper, called by the upload route. It enforces the size bound,
digest equality, valid
PKCS#10 signature, RSA-3072/SHA-256 profile, one random temporary CN, and no
requested extensions. It returns only request fingerprints and metadata; it
does not contact AD CS, authorize a SID, consume approval, or issue a
certificate. The upload route stores the public CSR once against its approved
challenge. It has no retrieval endpoint and cannot issue certificates.

`infra/thessley_ad_service/issued_certificates.py` is the next pure gate. Given
an issued DER certificate, the approved CSR and SID, configured template OID,
and pinned issuer certificate, it checks the certificate signature, time
validity, subject and public-key match, template OID, Smart Card Logon EKU, and
the AD SID security extension. It supports direct RSA/SHA-256 issuance by the
pinned CA certificate only. It is not connected to issuance or Windows logon;
it does not perform revocation checking or general certificate-chain building.
The SID extension's DER form is defined in
[MS-WCCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71),
and SID matching is required for a strong KDC mapping under
[MS-PKCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/e8fd2c1d-50d3-493a-9b58-5e453850c567).

## Still required

- A CNG-backed Credential Provider path that can use the issued key for
  Kerberos certificate logon.
- A broker-side, tightly restricted Enrollment Agent identity and signed CMC
  Enrollment-on-Behalf-of request. Microsoft’s protocol requires the signed
  CMS/CMC envelope to carry exactly one PKCS#10 request and the required
  requester-name attribute; the signer certificate must have the Certificate
  Request Agent EKU. See [Microsoft's EOBO request format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/2d1cf183-2507-4026-bc05-7b6b65dfced9)
  and [EOBO processing rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/6becda04-e17f-46df-825a-cec64ed0a203).
- Wire the issued-certificate validator into the future broker after CA
  response, then independently validate the certificate on the workstation.
- Define revocation handling, trust-chain rules, and fail-closed recovery for
  issuance that succeeds after the client times out or reboots.
- One-use delivery of the certificate to the originating machine, followed by
  PKINIT validation in a disposable domain-joined VM.
- Cleanup after success, denial, timeout, crash, and reboot; recovery must not
  delete unrelated machine keys or certificates.

No CA template should be published and no login tile should be installed from
this proof until those gates have passed. The helper uses the Windows software
KSP; it does not claim TPM/TEE key protection.

The KDC must resolve the issued certificate through a strong mapping. A name in
the subject or UPN alone is not sufficient; the pilot is intended to use the
AD SID security extension and verify that it matches the approved account. See
[Microsoft's KDC mapping-strength rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/95c6f0e3-3565-41d7-80ed-2333c4c5e107).

The implementation follows Microsoft's documented `IX509PrivateKey` and
`IX509Enrollment` APIs and `certutil -delkey` semantics:
[Certificate request creation](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializefromprivatekey),
[DER request encoding](https://learn.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509enrollment-createrequest),
[machine-key context](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1),
[key deletion](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).
