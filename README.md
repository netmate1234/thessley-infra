# Thessley infrastructure

Lab and service infrastructure behind the Thessley projects.

- **`thessley_ad_service/`** — the Active Directory side: phone-key registry, admin web console, AD logon-key enrolment and the DC pairing flow.
- **`windows-ad-lab/`** — the Windows/AD lab: domain controller notes, the credential-provider prototype, certificate pilot and the SSH gate.
- **`thessley_passkey/`** — shared server pieces used by the lab service.
- **`unwantedip_api/`** — the small API the reputation tracker exposes to the hardening plugin.
- **`crawler-nets-updater.php`** — keeps the crawler network list current on the WordPress hosts.

Lab credentials are **not** in this repository: `windows-ad-lab/LOCAL-CREDENTIALS.txt` is ignored and stays on the machines that need it.

Project family: [Thessley](https://github.com/netmate1234/Thessley) · deck: [overview](https://netmate1234.github.io/Thessley/).
