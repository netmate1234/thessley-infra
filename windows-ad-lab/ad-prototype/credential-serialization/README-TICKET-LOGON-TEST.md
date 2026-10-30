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

- LSA accepted the exact ticket serialization and returned a primary token on
  Clone 1.
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
- The next diagnostic must isolate the serialization representation. The
  direct `ticket_logon_probe` can submit the same structure with native
  pointers or with the packed offsets unchanged. The checked-in CLI accepts
  `kerberos raw-offsets` and `kerberos native-pointers`; use both against the
  same freshly captured ticket if possible. Native success plus raw-offset
  failure would implicate LogonUI/Winlogon's pointer relocation for this
  package-specific structure. If both modes fail, investigate the ticket
  semantics and the `KERB_TICKET_LOGON`/interactive-logon combination instead.
  No ticket bytes should be logged or persisted.
- Tie future logs to the registered DLL's full SHA-256, not only the shortened
  filename suffix. Do not repeat the password-seeded test after a cache miss
  unless the broker log first confirms a fresh `CaptureTicketStored` event.
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
