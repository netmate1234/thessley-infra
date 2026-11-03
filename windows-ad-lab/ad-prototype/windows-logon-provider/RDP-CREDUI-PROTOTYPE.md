# Thessley RDP Credential UI prototype

The AD credential provider now has an experimental `CPUS_CREDUI` path for
remote credential prompts such as `mstsc`. It presents one **Thessley RDP
Sign-In** tile with separate **Username** and **Domain** fields, a phone approval link, and Windows
password field. The user requests approval first; only after approval does the
provider serialize the entered password through Windows' normal Negotiate
credential path. It does not persist or log the password.

The incoming CredUI serialization is intentionally ignored. This means a
saved username/password may not prefill the Thessley tile; enter the account
again in the separate fields. The default domain can be configured with
`configure-ad-default-domain.ps1 -Domain THESSLEYLAB`. The QR viewer is launched on the calling
user's interactive desktop, while the existing `CPUS_LOGON` and unlock paths
continue to use the Winlogon desktop.

## Lab test

1. On the Windows client, open Remote Desktop Connection (`mstsc.exe`) and
   connect to a Windows host that already accepts RDP.
2. At its credential prompt, choose **More choices** and select **Thessley RDP
   Sign-In**.
3. Enter `startmenutest` as **Username** and `THESSLEYLAB` as **Domain**, choose
   **Request phone approval**, approve the QR on the enrolled phone, then enter
   the Windows account password and submit.
4. Check `C:\ProgramData\ThessleyPamWin\logs\provider.log` for
   `SetUsageScenario` with scenario `CPUS_CREDUI`, followed by approval and
   serialization events. Logs intentionally omit credentials and QR payloads.

This is a client-side CredUI option, not server-side RDP policy enforcement.
Other credential providers, saved credentials, or a different RDP client can
bypass this tile. A deployment that must enforce phone approval needs an
RDP-side authentication control, such as an RD Gateway/NPS policy or an
equivalent server-side MFA integration. Clone 1's own `TermService` was stopped
when this prototype was deployed; it has since been enabled for the lab test.

## Clone 1 test server

Clone 1 accepts RDP with Network Level Authentication required. Its inbound
TCP 3389 rules are limited to the Domain profile from `192.168.1.0/24` and the
Public profile from the VM host bridge address `192.168.122.1` only. Use
`192.168.122.66` from the Ubuntu VM host; `192.168.1.103` is the LAN address.
The provider tile must be installed on the Windows machine running the RDP
client; installing it on Clone 1 affects only RDP client prompts opened on
Clone 1 itself.

The provider update is side-by-side: its prior DLL remains in
`C:\ProgramData\ThessleyPamWin\ad-credential-provider`, and no rollback
task or other sign-in provider registration is changed by the binary updater.
