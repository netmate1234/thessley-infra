# Thessley passwordless AD lab

This is a disposable Windows Server 2025 evaluation lab for validating QR-mediated, certificate-based Windows domain sign-in. It is not a production AD design.

## Lab layout

- Forest: `lab.thessley.test` (`THESSLEYLAB` NetBIOS name)
- Server: `THESSLEY-DC1`, primary NIC attached to the `192.168.1.x` LAN; a second libvirt NAT NIC provides host-only management
- Server roles: AD DS, DNS, and an Enterprise Root CA on the same VM for lab use only
- Test account: `martin` (ordinary domain user)
- Input layout: Swedish (`sv-SE`)
- Evaluation media: Windows Server 2025 Standard Evaluation Core

The DC VM uses fixed virtual MACs and DHCP. The router-assigned LAN address was `192.168.1.79` during setup; the libvirt management address is `192.168.122.98`. A router DHCP reservation is preferred so the LAN address remains stable across long shutdowns. SSH on the management NIC is allowed only from the hypervisor gateway `192.168.122.1`.

## Current lab state

- Forest and DNS: `lab.thessley.test` / `THESSLEYLAB`; AD DS, DNS, KDC, Netlogon, ADWS, and Certificate Services are running.
- Enterprise root CA: `THESSLEY-LAB-CA`.
- CA templates enabled: `KerberosAuthentication` and `SmartcardLogon`.
- A machine certificate with the KDC Authentication EKU has been issued to the DC.
- Test user: `martin` (`martin@lab.thessley.test`), ordinary domain user. The local-only credential file records the lab passwords and current SID.
- The CA's `SmartcardLogon` Enroll right is granted only to `THESSLEYLAB\martin` for this lab.
- The Windows client is still separate and has not yet been joined to this forest.

## Initial setup

1. Install Windows Server 2025 Standard Evaluation Core on the isolated libvirt VM.
2. Connect the primary NIC to the physical `enp1s0` LAN with macvtap/bridge mode. Add the libvirt default NAT NIC only for host management; its Windows Firewall SSH rule must stay limited to `192.168.122.1`.
3. Attach `configure-domain-controller.ps1` to the VM as a read-only CD and run it in elevated PowerShell.
4. The script sets Swedish input, renames the server, installs AD DS, promotes the forest, configures AD CS, and creates the ordinary `martin` test account. Run it again after the rename and forest-promotion restarts. If the first post-promotion boot has not started NTDS yet, the script performs one recovery restart rather than starting a second promotion.
5. The DC Kerberos Authentication certificate has been issued and its KDC Authentication EKU verified. Next, join the client, enroll a `SmartcardLogon` user certificate for `martin`, and verify that the issued certificate has a strong SID mapping before testing logon. Do not treat the template as production-ready.

## Joining the disposable client

1. Confirm the DC is running and still has its reserved LAN address (`192.168.1.79` at last check). Do not start the client if host memory is low; shut down unrelated VMs first.
2. Log in to the client with its existing local administrator account, open elevated PowerShell, and run `join-domain-client.ps1` from the `THESSLEYJOIN` CD. It sets active adapter DNS resolvers to the DC's LAN address, disables DNS registration on non-LAN adapters, checks the AD SRV record, synchronizes time from the DC, and prompts for the domain Administrator password in the console before joining. If setup fails, it restores prior DNS resolver and registration settings.
3. After the restart, sign in as `THESSLEYLAB\martin` with the lab test-account password.
4. From Martin's session, request the test certificate with `certreq.exe -enroll -user -q SmartcardLogon`. This is a lab certificate to validate AD CS and strong mapping; it does not yet implement phone-backed private-key signing.

The script prompts for the DSRM and test-user passwords. Local-only credentials are recorded in the ignored `LOCAL-CREDENTIALS.txt`; never commit or distribute that file. The local/domain Administrator password is managed separately.

The DC setup script binds DNS to the LAN IPv4 address and removes the controller's NAT and IPv6 addresses from its host, zone-apex, and Global Catalog A/AAAA records. Before changing DNS, it saves the previous listener, client resolver settings, and affected records under `C:\ProgramData\Thessley\ADLab\DnsBackup`. Reserve the LAN address on the router so this binding remains valid.

### Optional host-only SSH management

`enable-client-ssh.cmd` starts the PowerShell setup with a UAC prompt. The script installs the Windows OpenSSH Server capability, installs a supplied Ed25519 public key for the selected local user and administrator accounts, and opens TCP 22 only from the libvirt management gateway (`192.168.122.1` by default). The matching `.pub` file must be beside the script and is not part of the repository. It disables the broad inbox OpenSSH firewall rule, does not change password or Windows sign-in policy, and leaves all other firewall rules intact.

## Why the lab uses certificates

The phone key must authorize a Windows credential that the domain controller can validate through Kerberos PKINIT. A QR approval by itself is not an AD credential. The next client-side work is a Windows credential-provider and remote signing bridge for the phone key, plus account/SID enrollment and revocation in Thessley.

## Standalone Thessley AD sign-in direction

The AD QR sign-in path must not depend on the Drupal server or Drupal user roles.
Active Directory is the authority for account SIDs, domain groups, and computer
authorization. AD CS issues the test logon certificates. Use a standalone
Thessley approval service for phone enrollment and approval; it can run beside
the existing Thessley PAM service, but it must read authorization directly from
AD over a protected LDAP connection. Its AD identity should be read-only except
for narrowly scoped certificate or enrollment operations that are explicitly
required. Do not install this service on a domain controller for a production
deployment.

The Windows tile should identify the selected account by its SID and domain,
request a fresh approval from the standalone Thessley service, and then allow
Windows to authenticate to the KDC using that account's certificate. It must
not cache or release the account password as a substitute for certificate
authentication. Approval-only 2FA and passwordless certificate logon are
separate milestones: the former gates an existing credential; the latter needs
Windows to perform PKINIT with the phone-protected private key.

### Next milestones

1. Join the disposable Windows client and validate DNS, time, AD group lookup,
   and ordinary domain logon.
2. Issue Martin a SmartcardLogon certificate with a strong SID mapping and
   validate certificate logon using a Windows-supported key provider. This
   isolates AD CS/KDC configuration from Thessley phone integration.
3. Define the standalone service API for pairing a Windows account SID, phone
   key, and machine key; querying AD group membership; starting and polling a
   signed phone approval; and revoking either key. Drupal is not in this flow.
4. Connect the Windows credential provider to that service and prove the
   phone-held key can complete the certificate signature needed for PKINIT.
   A custom credential provider alone does not make an Android TEE key appear
   as a Windows smart card. A supported smart-card/KSP bridge or equivalent
   signing provider is needed.
5. Use AD security groups and domain policy to grant logon rights and local
   administrator membership. Keep PIN/password recovery available until the
   phone-backed certificate flow is proven through reboot and lock/unlock.

Microsoft references: [smart-card sign-in flow and certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration), [certificate credential serialization](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_certificate_logon), [strong certificate mappings](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/95c6f0e3-3565-41d7-80ed-2333c4c5e107), and [smart-card minidriver architecture](https://learn.microsoft.com/en-us/windows-hardware/drivers/smartcard/smart-card-minidriver-overview).

Microsoft’s current requirements and flows:

- [Windows smart-card sign-in and certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [Windows credential providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [AD CS Certification Authority installation](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority)
