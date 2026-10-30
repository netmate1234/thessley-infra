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
ticket. Both logs include timestamps, status codes, and the test account SID;
neither log includes ticket contents, passwords, PINs, or key material.

`Windows ticket preparation failed (0x80070490)` means the broker had no
unexpired ticket cached for that account SID when LogonUI requested it. Check
`broker.log` for `CaptureTicketStored` versus `CaptureHostTicketFailed` or
`TicketCacheMiss`. This test captures a ticket from an already authenticated
interactive session. The normal password/PIN login must therefore happen first;
then sign out and try the ticket tile within the broker's three-minute cache
window. A cold sign-in with no existing session cannot manufacture its own
Kerberos ticket.

## Current state

- LSA accepted the exact ticket serialization and returned a primary token on
  Clone 1.
- The provider now has a per-SID, opt-in ticket mode and calls a local broker
  only after phone approval.
- The volatile broker and the separate ticket-test DLL compile on Linux with
  MinGW. Clone 1 reached the ticket tile, but the first attempt failed because
  no cached ticket was available (`ERROR_NOT_FOUND`, 0x80070490). The broker now
  records the capture/delivery path so the next attempt shows where it failed.
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
