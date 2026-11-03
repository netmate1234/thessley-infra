# Start menu account flyout delay

## Current symptom

On Clone 1 (`Martin-wm`), the Start menu account flyout sometimes takes about 20–40 seconds to open. The observations now distinguish several cases: a clean password sign-in is faster than doing QR sign-in, pressing Win+L, then signing in with a password; after password sign-in, the first flyout opening can still take roughly 20–25 seconds while a later opening is quick; after QR sign-in or QR unlock, the flyout has repeatedly been slow. The user also reports the power button opens promptly. These reports do not support a QR-only explanation: QR may leave additional session state, while a first-use shell delay also occurs after password sign-in.

The account flyout is implemented by Windows shell components. Thessley’s credential provider is not called when the already-signed-in user opens this flyout, so adding more provider-side logging would not capture the wait itself. The investigation uses Windows ETW instead.

## Evidence collected (31 October 2026)

- `nltest /sc_query:lab.thessley.test` completed in about **0.10 seconds** and returned `NERR_Success`; DC DNS resolution returned `192.168.1.79`. This rules out a generally slow secure-channel check at the time of the test.
- The earlier GeneralProfile trace showed StartMenuExperienceHost `TermSrvApi` RPC calls returning `0xC0000034` in a burst lasting about 149 ms. They occur after the reported wait and are not the delay.
- In that earlier trace, the account’s WinINET `AutoDetect` setting was `0`; WinHTTP was direct. Earlier WPAD timeouts are therefore not currently explained by proxy autodetection.
- A Shell-Core/User Profiles ETW capture found account-picture file lookups completing in under a millisecond and no User Profile service events during the captured interval.
- A WPR `XAMLAppResponsiveness` capture ran from about **12:45:07 to 12:46:33 UTC**, with zero lost events. It recorded XAML activity in StartMenuExperienceHost PID 6472 from about 12:45:31 to 12:45:40. The longest matched XAML Start/Stop operation was about **1.83 seconds**. The user’s click time was not separately marked, so this trace does not prove the exact click-to-open duration.
- A later WPR capture included a `ACCOUNT_FLYOUT_CLICK_START` marker at **12:57:59.428 UTC**. In StartMenuExperienceHost PID 6472, the main XAML thread (TID `0xE30`) emitted a `PointerLeave` event at **12:58:12.635**, then no more XAML events for **70.487 seconds**; events resumed at **12:59:23.122**. The render thread’s `RenderThreadWaitForWork` interval spanned **70.707 seconds**, which is consistent with it waiting while the UI thread was not producing work. This matches the reported long delay and locates it before the flyout is drawn.
- The same QR session has an important Kerberos difference: its primary interactive logon LUID `0x1cd4304` has no cached tickets, while linked LUID `0x1ccdfb1` has a TGT and LDAP ticket. A previous password sign-in had tickets in its primary LUID. A `klist get` in the QR primary LUID failed with `0xC0000321` (smart-card subsystem); it did not add a ticket.
- RAM and CPU were not under pressure during a later check: about 1.7 GB free of 3.9 GB, with total CPU below 8% over five samples. The domain secure-channel check remained about 0.10 seconds.
- In a same-session comparison after the QR sign-in, the user reported the first account-flyout opening after an unlock was still a little slow, while the second opening was fast. This is consistent with one-time shell initialization/cache warm-up, but does not identify what initialized or prove the QR path is the cause.
- The unlock trace `thessley-password-unlock.etl` (StartMenuExperienceHost PID 6860, 71 seconds, zero lost events) has a 29.95-second `RenderThreadWaitForWork` interval on TID 2968 and two gaps (6.01s and 23.95s) in XAML events on TID 2508. Without a timestamped marker for the first and second clicks, these gaps cannot be attributed to the account flyout. The trace is not sufficient to claim that the flyout is fixed or to time its click-to-open latency.
- After the password unlock, the active session 13 primary LUID `0x284c1f0` contained four Kerberos tickets (TGT, HOST and LDAP); the linked LUID `0x28459a6` contained none. Earlier in the QR-only state the observation was the reverse. This confirms that the credential cache state changed across the unlock, but does not establish that the account flyout waits on Kerberos.
- A follow-up `Win+L` using the Thessley QR unlock kept session 13 and its LUIDs, but the user reported the flyout was slow again on repeated openings. Immediately afterward, both primary LUID `0x284c1f0` and linked LUID `0x28459a6` had zero cached tickets. A password unlock of that same session restored four tickets to the primary LUID, and the user reported the flyout was fast. This is a stronger within-session correlation between QR unlock, an empty Kerberos cache, and the delay; it still does not prove which shell call is blocked.
- A read-only token query of `StartMenuExperienceHost.exe` PID 6860 returned AuthenticationId `0x0:0x284c1f0`, matching the primary interactive logon LUID. After the password unlock, this LUID held the TGT, HOST, and LDAP tickets. Thus the shell process runs under the same LUID whose ticket cache changes between the slow QR state and fast password state.
- Provider log review shows the 13:23Z attempt ended with `ADApprovalStart 0x800704C7` (cancelled), so it was not a successful QR authentication. Its `SetUsageScenario` value was 1 (`CPUS_LOGON`). This value alone does not tell whether the user was at initial sign-in or unlocking: Microsoft's credential-provider documentation says `CPUS_LOGON` can be used for workstation logon or unlock, while Windows may request `CPUS_UNLOCK_WORKSTATION` in some configurations. Correlate provider events with Security events 4800/4801 and session IDs before assigning a test to one scenario.
- A combined GeneralProfile + XAML ETL was saved on Clone 1 as `C:\Users\Public\Documents\qr-unlock-flyout.etl` (about 454 MB, zero dropped events). The first XML export attempt was cancelled because filtering the large trace was taking too long. Keep the ETL for a focused follow-up; do not copy the full trace off the VM.
- The latest successful QR attempt logged `SetUsageScenario count=1`, `BuildADCertificateLogon` using the Kerberos package, and `ReportResult hr=0`. `klist` then showed zero tickets in both session-13 LUIDs. The log records the `CPUS_LOGON` provider scenario, but that is compatible with an unlock flow as well as initial sign-in. The UI's current primary LUID was empty, and `klist get ldap/THESSLEY-DC1.lab.thessley.test -li 0x284c1f0` stalled until interrupted.
- `Microsoft-Windows-Kerberos/Operational` had been disabled and contained no events. It is now enabled on Clone 1 for the next reproduction. Querying the DC Security log remotely from Clone 1 failed with RPC unavailable, so there is not yet DC-side 4768 evidence for this authentication.
- After enabling that channel, a targeted `klist get ldap/THESSLEY-DC1.lab.thessley.test -li 0x284c1f0` again stalled for over 30 seconds and was interrupted. No Kerberos Operational events were emitted. The DC Security log is still unavailable through remote Event Log RPC; direct SSH from the Codex host to the DC returned a closed session without command output.
- The user repeated the QR sign-in and again reported the flyout slow. Provider log at 13:28Z showed `SetUsageScenario count=1`, successful certificate serialization, and `ReportResult hr=0`; both primary and linked ticket caches were empty afterward. A second targeted LDAP ticket request also stalled for over 30 seconds. The VM clock is not the cause: `w32tm /stripchart` against DC `192.168.1.79` measured only 10–15 ms offset.
- A direct SSH query to the DC's Security log now confirms a successful PKINIT TGT request for `startmenutest` from Clone 1 at **13:40:53Z** (`4768`, result `0x0`, pre-auth type `16`, certificate thumbprint `DBD58F69D13F4227C20120104C0FA87A0EC5F596`). The earlier statement that DC-side 4768 evidence was unavailable is superseded.
- The matching Clone 1 provider log shows `SetUsageScenario count=1` (`CPUS_LOGON`), QR approval at 13:40:45Z, `BuildADCertificateLogon` success at 13:40:48Z, and `ReportResult hr=0` at 13:41:06Z. The user was testing QR sign-in around Win+L. Because `CPUS_LOGON` can also be used for unlock, this log does not establish whether the attempt was initial sign-in or unlock; the earlier interpretation that count 1 excludes unlock was incorrect.
- In the resulting Session 14, the interactive primary LUID is `0x3d7ac7a`; its Kerberos cache is empty. The linked LUID `0x3d73cf3` holds two tickets: the TGT (issued at 14:40:53 local time, matching the DC event) and an LDAP service ticket (14:41:06). `StartMenuExperienceHost.exe` PID 9508 runs with AuthenticationId `0x3d7ac7a`, the empty primary cache. This is the clearest current correlation: the DC issued the TGT, but it is present in the linked cache while the shell process uses the empty primary LUID.
- The user reports the account flyout remains slow after QR sign-in and opens quickly after a password unlock. This supports a credential/session-state cause over a general network outage, but it does not yet prove why Windows placed the QR TGT in the linked LUID or whether the shell's slow call is Kerberos-related.
- After the user reported that starting `NlaSvc` did not improve the flyout, the live session was checked again over SSH. Clone 1 is Windows 11 26H2 build **26300.9711** (`UBR 9711`); both `NlaSvc` and `netprofm` are running. The current console session is `THESSLEYLAB\startmenutest`, session 17. `klist sessions` reports primary LUID `0x47ae214` and linked LUID `0x47a820e`. The primary LUID has **zero tickets**; the linked LUID has the TGT and LDAP ticket issued at 16:57 local. The provider log for this sign-in says `ADUnlockContextCheck ... not a matching locked console; certificate-logon serialization`, then `BuildADCertificateLogon ... message_type=13` and `ReportResult hr=0`. This sign-in did not exercise the new unlock-aware serialization. Combined with the user's report that the flyout is still delayed, this is a strong current correlation: the active desktop's primary logon cache is empty while the QR-issued tickets sit in the linked logon context. It still does not prove that this cache placement is the exact wait inside Start.
- On that same active primary LUID, `klist get ldap/THESSLEY-DC1.lab.thessley.test -li 0x47ae214` was run as a direct cache-repair probe. It blocked for about 20 seconds, then failed with `0xC0000321` and `LsaCallAuthenticationPackage` substatus `0x4f0`: “The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.” It did not add a ticket. This independently confirms that the shell's primary logon context cannot obtain a service ticket through the current smart-card state; the delay is in that path, not in NLA startup. It is strongly consistent with the account flyout's slow authentication/cloud lookup, though the exact Start call remains unproven.
- The trace for the latest timestamped click also found a 17.49-second RPC from `netprofm.exe` to the Network Store Interface around the click and recurring 5–6.5-second LSASS RPCs, plus AAD Operational errors for cloud account fallback. Starting `NlaSvc` did not change the symptom. These remain secondary/correlated signals; the ticket-cache placement is the stronger actionable lead.
- The user then tried QR unlock and could not sign in. Four provider attempts matched the locked console and selected `certificate-unlock message_type=15`; each returned `ReportResult 0xC000006D`, substatus `0xC00000E5`. The PIV relay log records one approved request id consumed and a verified phone signature at 16:33:11–16:33:22Z, but the repeated attempts overlap, so that signature cannot yet be assigned to a particular failed logon. The unlock conversion is therefore a regression and is not retained as the active provider. The provider source was changed back to use the previously working `KERB_CERTIFICATE_LOGON` type 13 for `CPUS_LOGON`; explicit `CPUS_UNLOCK_WORKSTATION` still uses type 15. The rebuilt DLL SHA-256 is `72D426C200D07ED9FBDF8F2D275539AC16598480A02E2B8DF145EF4E6F926CAC`. It is staged at `C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider-restored-logon.dll`, and the provider CLSID now points there. The previous registration is exported to `C:\Users\Public\Documents\provider-registration-before-restored-logon.reg`. This restoration is not yet verified at a fresh lock-screen enumeration or QR unlock.
- A live module query confirmed LogonUI PID 6928 still has the old `ThessleyADCredentialProvider-bcsp-test.dll` mapped, even though the registry now points to the restored-logon DLL. Therefore the new path cannot take effect until the current LogonUI instance exits and a new one enumerates providers. Do not kill LogonUI remotely; unlock with the Windows password, then press Win+L to create the next test screen.
- Microsoft's Windows Insider Flight Hub lists Release Preview build **26300.9807** (16 October 2026), later than this VM's 26300.9711. The current VM is on the 26H2 servicing line. No release note found so far identifies this exact account-flyout delay, so updating may be a useful OS-control test but is not yet a confirmed fix.
- The user's latest comparison refines that pattern: a clean password sign-in is faster than QR sign-in followed by Win+L and password sign-in. Separately, the first account-flyout opening after a clean password sign-in can take about 20–25 seconds, and the second opening is fast. Therefore a QR-related session-state effect remains plausible, but a cold-start or one-time initialization delay also occurs without QR. The prior conclusion that password unlock makes the flyout simply “fast” was too broad.
- The user now reports a repeatable additional sequence: password sign-in, Win+L, then QR unlock makes the account flyout slow. This confirms QR unlock can trigger the delay in the same session, but it does not establish that QR is the only cause.
- The matching event records now identify that sequence more precisely. Session 16 was created at local **14:54:42** with `startmenutest` LogonType 11 (`Negotiate`, cached interactive), LUIDs `0x4001d9e` and `0x4001d27`. The provider then began a successful QR request at 13:55:19Z (14:55:19 local) with scenario value 1 (`CPUS_LOGON`), completed serialization, and reported success at 13:56:01Z (14:56:01 local). At that same local time, Security event 4624 recorded a Kerberos LogonType 2 by `UserManager` (PID `0x7f0`) with new LUIDs `0x40c6ce7` and `0x40bcafb`. Those new LUIDs no longer existed when queried later. The active shell stayed in session 16, and a token query confirmed StartMenuExperienceHost PID 2656 still used the original `0x4001d9e` LUID; both original LUIDs had zero Kerberos tickets. This is a direct correlation between QR authentication and a separate Kerberos logon context while the shell remains in its prior ticketless context. It strongly supports the session-context explanation for the later TokenBroker/SSPI waits, but does not alone prove the Start flyout's exact blocking call.
- Windows' account-notifications policy test was removed after checking the user-side GPO report: no GPO manages it, and Microsoft's policy description covers MSA and local account notifications rather than this domain account. The value is now absent for `startmenutest`; this branch is closed as a poor-fit mitigation.
- The AD provider was changed to check whether `CPUS_LOGON` is being submitted for the same locked active console account. In that case it now serializes a `KERB_CERTIFICATE_UNLOCK_LOGON`; explicit `CPUS_UNLOCK_WORKSTATION` continues to use the unlock structure. The provider also logs the named usage scenario, flags, console session ID, lock state, account-match result, and chosen serialization type without writing credentials or QR content. Microsoft documents that Winlogon fills in the unlock LUID. The updated DLL built successfully with MinGW and was installed on Clone 1 after backing up the previous DLL. Installed SHA-256: `4C6D38AA30A5A9E1286284BB23503604CAE1F9A067B2CC5AAB6EDBF63369D5A5`; backup: `C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider.dll.preunlockfix-20261031-153911`. The new path has not yet been exercised at the sign-in screen.
- A focused export of `qr-unlock-flyout.etl` contains **3,897,362 events with zero lost events** over about 290 seconds. In the trace, StartMenuExperienceHost PID `0x1ACC` made a **70.434-second RPC call to the TokenBroker service** (server PID 4888), and separate calls on the SSPI RPC interface lasted up to **50.826 seconds**. The trace shows the shell stall, but it was not correlated to a particular provider scenario or a precise click marker, so it cannot by itself prove that the waits were caused by QR unlock.
- At local time 14:17:49, Windows AAD Operational event 1097 recorded `GetFallbackDomain` failing to obtain domain registration data (`0x80070005`), followed by `UseWindowsIntegratedAuth` reporting “Account type is unknown” (`0xCAA9004D`) for Windows Shell requesting `https://officeapps.live.com`. `dsregcmd /status` showed the VM is domain joined but neither Entra joined nor workplace joined. This aligns in time with the TokenBroker stall and makes the Windows shell’s cloud-account lookup a strong candidate for the account-flyout delay. It is an evidence-backed inference, not proof that the Thessley QR provider caused the lookup.
- To test that candidate, the Windows 11 local `AccountNotifications.admx` was inspected. It maps **Turn off account notifications in Start** to `HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\AccountNotifications\DisableAccountNotifications` (`DWORD 1`). That value is now set only for the loaded `THESSLEYLAB\startmenutest` profile, and StartMenuExperienceHost was restarted for that account. The initial check for a pre-existing value used a malformed registry path, so the prior state was not conclusively captured; record that before cleanup. The user has not yet reported a post-change flyout timing, so this is an unverified mitigation, not a fix.

## Conclusion so far

The captured data does not show a slow DC secure-channel check, profile load, or account-picture read. The marked trace shows a long gap in StartMenuExperienceHost's UI activity that matches a reported delay. Password sign-in puts Kerberos tickets in the shell's primary LUID; the latest QR sign-in again leaves that primary cache empty while the TGT and LDAP ticket appear under the linked LUID. A direct `klist get` in that primary LUID stalls and fails with the smart-card-subsystem status `0xC0000321`. A different trace showed StartMenuExperienceHost waiting about 70 seconds on TokenBroker while Windows Shell's AAD fallback failed. Together, these observations make ticket/session placement and smart-card ticket acquisition the strongest current cause of the QR-triggered delay; the NLA restart did not help. The experimental automatic conversion to certificate-unlock message type 15 made QR unlock fail with `0xC000006D/0xC00000E5`, so the registered provider is now pointed to a rebuilt DLL that keeps `CPUS_LOGON` on the original message type 13. That rollback needs an interactive QR verification. The account-notifications policy experiment was removed.

## Trace files on Clone 1

The detailed ETL files are in `C:\Users\Public\Documents`:

- `qr-flyout-clean.etl` and `qr-flyout-clean-summary.txt`
- `thessley-account-menu-shell.etl`
- `thessley-account-menu-profile.etl`
- `thessley-xaml-response.etl` and `thessley-xaml-response-summary.txt`
- `thessley-flyout-marked.etl`

The CSV exports and temporary filtered text files are derived analysis artifacts; they can be regenerated from the ETLs with `tracerpt` if needed.

## Next diagnostic step

The next validation is one QR unlock of the already signed-in `startmenutest` account, followed by one Start account-flyout click. Confirm the provider log contains `ADUnlockContextCheck ... unlock_serialization=1`, `BuildADCertificateLogon ... message_type=15`, and `ReportResult hr=0`; then compare the active shell LUID's Kerberos cache and time the flyout. If the login fails, use the password tile and restore the DLL from the backup path above. Windows documents `CPUS_LOGON` for both logon and unlock; the new runtime check distinguishes a matching locked console session.

### Renewed phone certificate and unlock-aware provider installed (2026-10-31)

The user performed a password unlock of the existing `startmenutest` console
session. The primary session LUID then held a fresh TGT and LDAP tickets. The
existing interactive CA task issued request 62 from the new CSR signed by the
same enrolled RSA-2048 phone key. The certificate has the expected
`startmenutest@lab.thessley.test` SAN, the account SID security extension, the
Smart Card Logon and Client Authentication EKUs, and a four-hour validity
(local `NotBefore` 16:16, `NotAfter` 20:16). Its public-key identifier is still
`ea2cab773cfd86ee1fa0eda42fe2f1f7fd987f2c48e44e948fff18168ff8e4fee`; the
phone private key was not rotated.

The renewed certificate replaced the expired `piv-phone-logon.cer`; the old
file is preserved as `piv-phone-logon.cer.expired-20261031`. The
`Thessley-AD-PIV-Phone-Reader` SYSTEM task was restarted and verified Running.
The unlock-aware provider DLL was copied to Clone 1 after preserving the
previous DLL as
`ThessleyADCredentialProvider.dll.beforeunlockfix-20261031-2`. The active
provider hash is `4c6d38aa30a5a9e1286284bb23503604cae1f9a067b2cc5aab6edbf63369d5a5`.
No reboot is required for the test; the next Win+L QR submission should load
the updated provider. Its result and the following account-flyout latency have
not yet been observed.

The first attempt after the certificate renewal still failed before the phone
signature. The provider's prior `ReportResult` substatus `0xC0000384` is
`STATUS_SMARTCARD_NO_KEY_CONTAINER`. A SYSTEM `certutil -scinfo` run showed the
renewed certificate and successful public-key matching on reader `Virtual
Smart Card Architecture Virtual PCD 0`, under container
`b8c0485f-c856-1e51-ad5d-25278c5fc105`. The provider mapping still named the
old container `4dd9a5c7-73d5-3954-a819-1e92345fc105`; the phone's RSA
key identifier is unchanged, so this was a stale card-container mapping, not a
phone-key mismatch. The old mapping was exported to
`C:\Users\Public\Documents\startmenutest-piv-config-before-container-refresh.reg`
and only `PivContainerName` was updated to the newly enumerated container. The
temporary SYSTEM diagnostic task and output file were removed. The next QR
approval and PIV signing attempt is required to verify the correction.

The `same thing` attempt at 16:37:08 local is not a valid check of the new
mapping: its credential object was initialized at 16:36:24, three seconds
before the registry update at 16:36:27, and it returned the expected old
`STATUS_SMARTCARD_NO_KEY_CONTAINER`. LogonUI enumerated the provider again at
16:37:45. The next QR approval worker ended with `E_ABORT` at 16:40:07; no
serialization or PIV signing APDU followed, so that fresh mapping has still
not been exercised. A completed approval followed by PIN submission is needed
before comparing the sign-in result or flyout timing.

### QR sign-in leaves the shell without Kerberos tickets (2026-10-31)

The latest successful attempt built 590 bytes of certificate-logon
serialization and logged `ReportResult hr=0` at 15:42:06 UTC. The active
console session remained present, but `klist` showed no tickets in either its
primary LUID (`0x4001d9e`) or linked LUID (`0x4001d27`). The reader then saw
GENERAL AUTHENTICATE APDUs at 15:42:43, 15:42:50, and 15:42:56 UTC, after the
provider had cleared `PivPhoneRequestId`; each was refused without contacting
the phone. This is direct evidence that the approved phone signature never
reached the Windows Kerberos path in that attempt.

The provider now retains the request ID through `ReportResult`. The local
reader consumes and deletes it only when Windows sends the first valid
GENERAL AUTHENTICATE digest, before relaying that exact digest to the AD
service. The service independently limits the approval to the same machine,
account, enrolled key, exact digest, and short login window. A new QR approval
is needed if that one signature operation fails. This change is not yet
validated on Clone 1; the next check must confirm the reader log says it
consumed the ID and returned a verified phone signature, then check the active
shell LUID for a TGT and time the account flyout.

The first retry exposed a deployment-path mistake: the Credential Provider
registration points to
`C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider-bcsp-test.dll`,
not `ThessleyADCredentialProvider.dll`. The initial copy updated an
unregistered DLL, so the 15:50–15:52 QR attempts still ran the old provider.
The actual registered file has now been replaced with the request-ID-lifecycle
build (`d90fa40471679a6e3298103a8d8c287eeaaa94ff255141d30d4aed9db26a188b`),
with the previous registered DLL preserved as
`ThessleyADCredentialProvider-bcsp-test.dll.before-request-id-fix-20261031-165415`.
The reader helper was updated and hash-verified as well. No new sign-in has yet
exercised this correctly registered binary.

In the latest user-reported successful QR unlock, the reader log recorded a
verified phone signature at 15:52:15 UTC and the old provider reported success
at 15:52:28 UTC. The existing console session remains the one logged on at
14:54; its shell LUID `0x4001d9e` still has zero tickets. Querying that cache
over SSH took about ten seconds to return `Cached Tickets: (0)`, close to the
observed flyout delay. This strengthens the missing-ticket correlation but
does not prove the shell is blocked on `klist` or Kerberos. A full sign-out and
fresh QR logon using the corrected registered DLL is the next needed check;
unlocking the old session cannot establish whether a newly created shell LUID
gets a TGT.

The first test of the session-LUID build ran at 17:54 local. It established
that the Credential Provider executes in a context without `SeTcbPrivilege`:
`WTSQueryUserToken` returned `ERROR_PRIVILEGE_NOT_HELD` (`0x80070522`), so the
provider correctly fell back to message type 13. That attempt therefore did
not test certificate-unlock serialization. Do not grant `SeTcbPrivilege` to
LogonUI or the Credential Provider to work around this.

The replacement build obtains the `AuthenticationId` from the existing
`StartMenuExperienceHost.exe` (or, if unavailable, `explorer.exe`) token in the
active console session. It opens only query handles, verifies the process
token SID against the selected account SID, and requires a locked-session
match for the `CPUS_LOGON` unlock case. This build passed MinGW compilation and
is installed at the registered path with SHA-256
`5DF5D22AFD1695382A82D56C5836FCF768889571F05BF82DE4D5F7050279F193`. Its
rollback copy is
`ThessleyADCredentialProvider-restored-logon.dll.before-session-luid-v2-20261031-175908`.
It has not yet been loaded by a new LogonUI process or exercised by a QR
unlock. The next log must show `ADUnlockContextCheck` success, a nonzero
`logon_luid`, and `message_type=15`; then verify that the shell's primary LUID
has a TGT and compare the account-flyout timing.

### Real-LUID unlock serialization rejected; fallback restored (2026-10-31)

The next LogonUI process did load the v2 build. Its log showed
`ADUnlockContextCheck hr=0`, `session=17`, `logon_luid=0:0x047ae214`, and
`console_user_match=1`; it built the 598-byte `KERB_CERTIFICATE_UNLOCK_LOGON`
(message type 15). LSA still returned `STATUS_LOGON_FAILURE` with substatus
`0xC00000E5`, and the user could not QR-unlock. Thus the failure was not a
stale binary or zero LUID. The type-15 approach is rejected by this Windows
credential-provider path even with the real shell LUID; do not leave it
registered for normal testing.

The known-good type-13 fallback (`5BC4E5BDC399AFC90E81600052101F4DEE551829C2E3698471F6B6B16C3FF180`)
is now copied to
`C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider-session-luid-v1.dll`
and the Credential Provider CLSID registration points to that exact file.
The type-15 DLL remains preserved as
`ThessleyADCredentialProvider-restored-logon.dll.failed-unlock-luid-20261031-...`.
The previous binary could not be overwritten because the active LogonUI still
had it mapped. A password sign-in followed by a fresh lock screen is required
to load the fallback path. The registered fallback has not yet been tested
after this rollback, and the account flyout remains slow.

### Password plus phone approval comparison mode (2026-10-31)

The user chose a password-plus-QR comparison to see whether the flyout delay
depends on the passwordless certificate path. A per-account test switch
(`PasswordPlusPhoneTest=1`) now makes the allowlisted AD tile request phone
approval, then submit the typed Windows password through the normal
`KERB_INTERACTIVE_UNLOCK_LOGON` / Negotiate path. The password field is
explicitly labeled, the checkbox and QR setup link are hidden, and the password
is cleared from the provider field after serialization. The test mode does not
save the password. Other accounts keep their existing provider mode.

This mode is enabled only for `startmenutest` SID
`S-1-5-21-1719900462-4250469598-2954734011-1106`. The first build assumed VSC
metadata; a read-only check showed this account has PIV metadata only. Before
testing, that build was replaced with one that keeps the PIV enrollment as the
allowlist while disabling PIV signing only for this mode. The corrected
provider is registered at
`C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider-password-plus-phone-test-v2.dll`
with SHA-256
`0B3767A07261B6D52FF138DD7AFA28B08DF5FDDE9F47671BF3C8E16531CCC66B`. The
first test DLL remains beside it. The
previous type-13 provider remains at
`ThessleyADCredentialProvider-session-luid-v1.dll`. This test build has not
yet been loaded by a fresh LogonUI process. To test, use the built-in password
tile once, then Win+L, choose the Thessley AD Password + Phone Test tile,
approve on the phone, enter the Windows password, and compare the account
flyout timing. If the test fails, restore the previous provider registration
and remove the per-account test value.

### Certificate-unlock test with the existing console LUID (2026-10-31)

After the latest QR session, both active `startmenutest` LUIDs (`0x47ae214` and
`0x47a820e`) were queried from the elevated SSH session and had zero tickets.
`klist get krbtgt/lab.thessley.test -li 0x47ae214` failed with
`0xC0000321` / substatus `0x4F0` (smart-card subsystem); it could not repair the
cache because the current context had no usable smart-card operation.

The provider's previous experimental unlock conversion used an all-zero LUID.
This did not test the documented same-session unlock layout correctly. The
provider now reads the active console session token with `WTSQueryUserToken`,
checks its SID against the selected AD account, and uses that token's real
`AuthenticationId` only when the target is the same locked console session
(or for an explicit `CPUS_UNLOCK_WORKSTATION` scenario). Non-matching or
unavailable console sessions keep the normal certificate-logon path. The
provider does not duplicate or impersonate the user token. Diagnostics record
the selected session ID, LUID, and match result, not credentials.

The rebuilt provider passed the MinGW build and was installed at the exact
registered path
`C:\ProgramData\ThessleyPamWin\ad-credential-provider\ThessleyADCredentialProvider-restored-logon.dll`
with SHA-256
`5BC4E5BDC399AFC90E81600052101F4DEE551829C2E3698471F6B6B16C3FF180`. The
previous DLL is backed up beside it as
`ThessleyADCredentialProvider-restored-logon.dll.before-session-luid-20261031-175248`.
The new path has not yet been exercised at a fresh lock-screen submission. The
next test is Win+L, QR approval and PIN submission, then check the provider
events for `ADUnlockContextCheck` and message type 15, query the active shell
LUID's ticket cache, and time one account-flyout opening. If the matching
session lookup fails or sign-in fails, use the password tile and restore the
backup DLL.

### Password-plus-phone comparison result (2026-10-31)

The password-plus-phone test provider was loaded by a fresh LogonUI process for
`startmenutest`. Provider events show the tile was selected, the phone approval
QR was completed, `ADPasswordPlusPhoneReady` built the normal Negotiate
interactive credential, and `ReportResult` returned success. The user reported
that Start > account opened quickly. A second password-plus-phone sign-in
produced the same successful provider events; after that fresh sign-in, the user
again reported the account flyout was fast. The elevated SSH session showed
`startmenutest` active in console session 17.

This is a repeatable comparison result for this account: the slow flyout is
avoided when Windows receives its normal password-based interactive logon
credential after phone approval. It does not prove that the passwordless
certificate/PIV path is fixed. It also is not enforced two-factor
authentication yet: the separate built-in Windows password credential
provider remains available and can authenticate without this phone gate.

The current password-plus-phone implementation requests one phone signature,
so it shows one biometric prompt. The PIV phone-key path currently shows two:
the app first signs the machine's general approval request with its computer
enrollment key, then signs the exact Windows smart-card digest with the separate
AD logon key. Both Android Keystore keys require per-operation biometric
authorization. Hiding the second prompt or adding a reusable authentication
window would weaken that property. A proper one-prompt PIV design should bind
the approval itself to the exact Windows digest and let one AD-key signature
both approve the login and satisfy the smart-card operation; the Windows
provider and service handshake must then be reordered so the digest exists
before the phone asks for approval.
