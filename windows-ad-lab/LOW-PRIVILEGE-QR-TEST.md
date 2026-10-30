# Low-privilege AD QR test account

`ThessleyQRWorkstationAdmins` is not suitable for an ordinary-user test: on
`MARTIN-WM` it maps to the local `Administrators` group. Use the separate
`ThessleyQRWorkstationUsers` Global security group for a normal domain user.
The group grants only Thessley workstation QR authorization; it does not add
members to local Administrators or Domain Admins.

## Prepare the account on the DC

Copy `create-test-workstation-users-group.ps1` and
`infra/thessley_ad_service/add-authorized-group-sid.ps1` to a working folder on
the domain controller. From an elevated PowerShell window there:

```powershell
.\create-test-workstation-users-group.ps1 -TestUser startmenutest
```

The script refuses to proceed if the test account already belongs to a
privileged group. It creates the group if needed and adds only the named test
account. Record the `GroupSID` from its output.

Add that SID to the service's allowlist, preserving the existing admin group.
The updater uses a real temporary backup path for Windows PowerShell/.NET
Framework compatibility and confirms that the API listener returns:

```powershell
.\add-authorized-group-sid.ps1 -GroupSid 'GROUP-SID-FROM-OUTPUT'
```

The script backs up the protected `service.json`, appends the Global security
group SID, restarts the `ThessleyADApi` task if it was running, and verifies
that TCP 47810 is listening again. On failure it restores the original config
and restarts the prior service. It does not change firewall rules or local
Administrators membership.

Refresh the AD Accounts page until the user displays `Workstation QR: allowed`
and `DC admin: no`. Then enroll that account's phone approval key in the AD
Accounts GUI. AD logon keys are a separate credential and remain disabled until
the Windows signing bridge and attestation are validated. Do not add the user
to `ThessleyQRWorkstationAdmins` to make the badge change.

## Clone 1 ticket handoff experiment

Only after the group and phone key are ready should the separate ticket-test
provider be configured for the user's SID and installed on disposable Clone 1.
The existing VSC provider and password/PIN sign-in remain recovery paths. The
test ticket comes from a prior normal password/PIN sign-in and is only a local
machine ticket; this experiment does not yet test phone PKINIT or physical PCs.
