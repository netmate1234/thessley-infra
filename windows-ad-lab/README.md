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
2. Log in to the client with its existing local administrator account, open elevated PowerShell, and run `join-domain-client.ps1`. It sets active adapter DNS resolvers to the DC's LAN address, disables DNS registration on non-LAN adapters, checks the AD SRV record, synchronizes time from the DC, and prompts for the domain Administrator password before joining. If setup fails, it restores prior DNS resolver and registration settings.
3. After the restart, sign in as `THESSLEYLAB\martin` with the lab test-account password.
4. From Martin's session, request the test certificate with `certreq.exe -enroll -user -q SmartcardLogon`. This is a lab certificate to validate AD CS and strong mapping; it does not yet implement phone-backed private-key signing.

The script prompts for the DSRM and test-user passwords. Local-only credentials are recorded in the ignored `LOCAL-CREDENTIALS.txt`; never commit or distribute that file. The local/domain Administrator password is managed separately.

The DC setup script binds DNS to the LAN IPv4 address and removes the controller's NAT and IPv6 addresses from its host, zone-apex, and Global Catalog A/AAAA records. Before changing DNS, it saves the previous listener, client resolver settings, and affected records under `C:\ProgramData\Thessley\ADLab\DnsBackup`. Reserve the LAN address on the router so this binding remains valid.

## Why the lab uses certificates

The phone key must authorize a Windows credential that the domain controller can validate through Kerberos PKINIT. A QR approval by itself is not an AD credential. The next client-side work is a Windows credential-provider and remote signing bridge for the phone key, plus account/SID enrollment and revocation in Thessley.

Microsoft’s current requirements and flows:

- [Windows smart-card sign-in and certificate requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [Windows credential providers](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [AD CS Certification Authority installation](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority)
