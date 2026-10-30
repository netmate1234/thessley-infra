# Clone 1 ticket-logon handoff experiment

This package tests whether the Windows Credential Provider to LogonUI path can
submit the already validated `KERB_TICKET_LOGON` serialization. It is a lab
feasibility experiment only. It does **not** implement Android PKINIT and does
not prove a phone key can obtain tickets or log into Windows.

The test broker runs as LocalSystem on Clone 1. After an interactive domain
session obtains a `HOST/<computer>` service ticket, the broker holds one copy in
volatile memory for at most three minutes, bound to that session's SID. After a
fresh phone approval, only `LogonUI.exe` can consume the ticket through the
local named pipe; the broker deletes it after one attempt. Ticket bytes are
never written to disk or included in logs. The broker returns a service ticket
without a TGT, so the experiment can only create a local-machine logon and does
not provide domain SSO. Treat the in-memory ticket as a short-lived credential
and run this only on the disposable Clone 1 VM.

The ticket tile uses a separate Credential Provider GUID and separate DLL. It
does not replace the existing TPM/VSC tile. The ordinary Windows password and
PIN sign-in providers are not modified. A SYSTEM scheduled rollback removes
only the experimental ticket provider and broker service.

## Diagnostics

The broker writes `C:\ProgramData\ThessleyPamWin\ad-ticket-logon-test\broker.log`.
It records session capture attempts, the HOST-ticket lookup result, ticket-cache
misses/expiry, and one-use delivery status. The provider's
`provider.log` records the HRESULT returned while consuming and serializing the
ticket. For the ticket experiment, `ADTicketSerializationReady` and
`ReportResult` now write separate hexadecimal `status` and `substatus` fields,
plus the credential-provider scenario, authentication-package ID, and
serialized byte count. The broker log includes the test account SID. Neither
log includes ticket contents, passwords, PINs, or key material.

`Windows ticket preparation failed (0x80070490)` means the broker had no
unexpired ticket cached for that account SID when LogonUI requested it. Check
`broker.log` for `CaptureTicketStored` versus `CaptureHostTicketFailed` or
`TicketCacheMiss`. This test captures a ticket from an already authenticated
interactive session. To run this **one Clone 1 harness test**, sign in once as
the disposable test user, wait until `CaptureTicketStored` appears, then sign
out and try the ticket tile within the broker's three-minute cache window. A
cold sign-in with no existing session cannot manufacture its own Kerberos
ticket. This setup step is a harness limitation, not an acceptable product
requirement: the intended phone-PKINIT flow must obtain fresh tickets from the
phone without first logging that user into every PC.

`Phone approved, but Windows rejected the ticket (0xC000006D / 0xC00000E5)`
means the broker delivered the ticket but Winlogon/LSA rejected the handoff.
`0xC00000E5` is `STATUS_INTERNAL_ERROR`; inspect the provider's
`RetrieveAdTicketKerberosPackage`, `BuildADTicketLogon`, and `ReportResult`
events alongside the broker's `TicketDelivered` event. The provider now uses
the Kerberos authentication package and emits the correct `KERB_TICKET_LOGON`
or `KERB_TICKET_UNLOCK_LOGON` layout for the active scenario.

## Current state

- The direct LSA probe accepted the ticket when its embedded pointer was a
  native address into the input buffer and returned a primary token on Clone
  1. It rejected the same bytes with an offset in that field; this is not an
  end-to-end Credential Provider sign-in.
- The provider now has a per-SID, opt-in ticket mode and calls a local broker
  only after phone approval.
- The 12:14 UTC failure used DLL build `458c6a61`: the trace says
  `CPUS_LOGON` but reports 1,475 serialized bytes for a 1,435-byte ticket.
  That implies a 40-byte unlock header, inconsistent with both the scenario
  and the committed source's expected 32-byte logon header (1,467 bytes). It
  was an intermediate/unmatched DLL and is not a valid baseline for the current
  source.
- DLL build `ae1c970a` is the corrected provider currently registered on Clone
  1. The 12:45 and 12:46 attempts stopped earlier: its broker had restarted at
  12:40, clearing the volatile cache, and logged `TicketCacheMiss` for the
  `startmenutest` SID. The provider returned `0x80070490` before serialization
  or LSA. Those attempts did not test the corrected header or Winlogon handoff.
- The 12:56–12:58 UTC run did reach the corrected provider. The broker logged
  `CaptureTicketStored` for `startmenutest` at 12:56:57Z and delivered the
  1,435-byte ticket at 12:58:29Z. The provider built the expected 1,467-byte
  `CPUS_LOGON` serialization (`scenario=1`, Kerberos package ID 22), then
  Winlogon reported `0xC000000D` (`STATUS_INVALID_PARAMETER`), with substatus
  zero. This is the first current-build end-to-end rejection; it is not a
  cache miss and does not prove a successful desktop logon.
- At 14:20 CEST (13:20 UTC), while `THESSLEYLAB\startmenutest` was signed in at console
  session 3, the SYSTEM-only pointer probe used that session's LUID
  `00000000:005678DC` and the `HOST/MARTIN-WM.lab.thessley.test` ticket. With
  Kerberos package ID 2 and `Interactive` logon, the native-pointer buffer
  returned `STATUS_SUCCESS`, profile type 2, and a primary token. The same
  ticket and header with the serialized `ServiceTicket` value left as offset
  `0x20` returned `STATUS_INVALID_PARAMETER` (`0xC000000D`). This isolates a
  concrete difference at the direct `LsaLogonUser` boundary: LSA accepts the
  in-buffer native pointer and rejects the bare offset. It does not yet prove
  whether Winlogon rebases pointer fields for Credential Provider
  serializations; the current provider's offset form still fails in the actual
  sign-in path. No ticket bytes were logged, and the one-shot SYSTEM task was
  removed after the probe.
- The direct pointer comparison is complete. A separate ticket-provider build
  now passes the native in-buffer pointer form. It is registered at
  `C:\ProgramData\ThessleyPamWin\ad-ticket-logon-test\ThessleyADTicketTestCredentialProvider-73002320d8b9511d.dll`
  with SHA-256
  `73002320d8b9511de099cc19d575db2713c3f5477a08de96125bdafffb9c24bc`.
  The prior offset-based DLL remains at
  `C:\ProgramData\ThessleyPamWin\ad-ticket-logon-test\ThessleyADTicketTestCredentialProvider-ae1c970a52a898b4.dll`
  with SHA-256
  `ae1c970a52a898b4e76112eb8be7a439290571ae3f777dfc3b620a859096af73`.
  SYSTEM rollback task `Thessley-Ticket-Native-Pointer-Rollback` was verified
  and is due at 14:40 CEST on 2026-10-30. No sign-in attempt has been made with
  the native-pointer provider yet. The existing TPM/VSC provider and Windows
  password/PIN options remain registered. After a fresh password sign-in
  captures a ticket, sign out and immediately test the experimental QR tile.
  Success would prove this pointer representation works in the actual
  Credential Provider handoff; failure would rule out this ticket
  serialization route and return focus to the supported certificate/PKINIT
  approach.
- Tie future logs to the registered DLL's full SHA-256, not only the shortened
  filename suffix. The local source now logs the message type, flags, ticket
  lengths, and pointer-field values at serialization time, without logging
  ticket bytes. The local broker source also records the session LUID with
  `CaptureTicketStored`. The new broker, direct probe, native-pointer provider,
  and rollback script are staged on Clone 1. The broker is running
  with SHA-256
  `abcba3fa1e3344b215b6c1ec9d33222fa06e493877d3c607e1358dbaa28c31a2`; its
  previous executable is backed up as
  `C:\ProgramData\ThessleyPamWin\ad-ticket-logon-test\ThessleyADTicketBroker.before-20261030-141710.exe`.
  The probe SHA-256 is
  `93a751534b17deefdb69bcf68d22be16ec5dc00e1b1ece3c4dff47085dcfdfa8`.
  The ordinary `startmenutest` session is currently active; its password sign-in
  was only needed to seed this diagnostic ticket. This is not a product
  sign-in requirement. Do not repeat the password-seeded test after a cache
  miss unless the broker log first confirms a fresh `CaptureTicketStored`
  event.
- The local `ticket_logon_probe.cpp` parser already accepts the Kerberos
  package and pointer mode independently, in either optional-argument order.
  For clarity, use the explicit form
  `ticket_logon_probe.exe <luid-low-hex> <host-spn> interactive kerberos raw-offsets`
  to test raw offsets with Kerberos, and replace `raw-offsets` with
  `native-pointers` for the comparison. The earlier claim that this source
  required Negotiate for raw offsets does not match the checked-in parser.
- The next test must use a disposable, low-privilege AD account with its own
  phone approval. Do not use `Administrator` or the everyday `martin` account.
- A successful sign-in would only prove the Clone 1 Winlogon handoff. It would
  not validate Android PKINIT or the eventual physical-PC flow.

## Build

From the repository root:

```sh
bash infra/windows-ad-lab/ad-prototype/credential-serialization/build.sh
bash infra/windows-ad-lab/ad-prototype/windows-logon-provider/build.sh
```

Outputs are written under `/tmp/thessley-ad-*.exe` and
`/tmp/thessley-ad-provider-build/`. Builds do not install or register anything.

## Before testing

1. Create a disposable, non-admin domain user and enroll a phone for it through
   the existing AD enrollment flow.
2. Enable `TicketLogonTest=1` only for that account SID using
   `configure-ad-lab-ticket-test-user.ps1` from elevated PowerShell.
3. Install the separate ticket test provider with its timed rollback.
4. On the Clone 1 sign-in screen, use the normal Windows password/PIN once for
   the test user. The broker then requests that user's `HOST/<computer>` ticket
   and keeps it in memory for at most three minutes.
5. Sign out and select the experimental Thessley ticket tile promptly. Scan
   its QR and approve. The existing TPM/VSC, password, and PIN options remain
   available throughout. If the broker has no ticket, the tile reports that
   and the normal sign-in option remains available.
6. After the attempt, let the 15-minute rollback remove the experimental
   provider and broker, or run the rollback script elevated. Do not move this
   package to a physical PC.

The installer and rollback scripts are newly prepared but have not been
PowerShell-parsed or exercised on Clone 1. Do not run them until that check is
complete. Do not run the existing `install-ad-lab-provider.ps1` for the ticket
experiment.
