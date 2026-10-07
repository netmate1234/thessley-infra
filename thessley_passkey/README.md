# Thessley Passkey Login for Drupal

Sign in to Drupal with the **Thessley Passkey Android app** (scan a QR code or
tap a link) instead of, or on top of, a password. This is the server half of
the same protocol the *Thessley Security Hardening* WordPress plugin speaks
(`includes/modules/passkey-login`), so the **existing app works unchanged**:
same endpoints, request/response fields, error codes and signed string.

Requires Drupal 10.3+ / 11, PHP 8.1+ with OpenSSL. Tested on Drupal 11.4.8,
PHP 8.4, SQLite and MySQL.

## Install

```
cp -r thessley_passkey  <drupal>/web/modules/custom/
drush en thessley_passkey
```

Then:

1. Give the role that may use the app the **Use Thessley Passkey** permission
   (`drush role:perm:add <role> 'use thessley passkey'`). Nobody has it by
   default; `administer thessley passkey` is for administrators.
2. Open **Configuration → People → Thessley Passkey Login**
   (`/admin/config/people/thessley-passkey`) and pick a method.
3. Each person adds a phone from the **Passkey devices** tab of their account
   (`/user/{uid}/passkey`).
4. Behind a proxy / with `$base_url` set, put the public address in the
   *Public site URL* field (or leave it empty if `trusted_host_patterns` is set
   and the request carries the real scheme). That exact value is what the app
   signs, so it must match what people enrolled with.

## Login methods (site-wide)

| Mode | Behaviour |
|---|---|
| `optional` — Password or the app | Password form and QR shown together. |
| `2fa` — Password, then app | Password first, then a "confirm with the app" page. |
| `required` — App only | QR only; the password form is hidden. |

*Username prompt* (`identify`, for `optional`/`required`): step 1 is a username
box, step 2 the QR for that account (plus the password form in `optional`).
Only that account's own devices can approve it; an unknown username looks
identical to a real one.

An account with **no device** always falls back to its password: there is
nothing to require without one. An account that loses the *Use Thessley
Passkey* permission falls back too.

Everything is enforced on the server, not just by the screen: an anonymous
QR approval can never finish a login for an account in `2fa` mode, a request
bound to a username can only be approved by that account, requests are
single-use, and the session is only handed to the browser that started the
request (login-CSRF guard).

## If you get locked out

```
drush config:set thessley_passkey.settings mode optional
drush uli            # one-time login link
```

In `required` mode `/user/login?thessley_password=1` shows the password form
(accounts that already have a device are still refused a password login there).

## What it does *not* cover

Only the web login form and core's JSON login (`/user/login?_format=json`,
closed while the mode is not `optional`) are gated. Other ways in stay as
they are: the emailed one-time password-reset link, `drush uli`, and any
contributed authentication provider (basic_auth, OAuth, SSO…). Disable those
if "app only" must mean app only.

## Wire format

Same as the WordPress plugin. The app calls
`{origin}/?rest_route=/thessley/v1/passkey/...`; a path processor maps that
(only that exact prefix) onto the real routes `/thessley/v1/passkey/...`,
which also work directly.

| Route | Who |
|---|---|
| `POST login/start` | anyone (rate limited, 20 / 10 min / IP) |
| `GET login/{id}/status`, `POST login/{id}/respond` | browser / app |
| `POST enroll/start`, `GET enroll/{id}/status` | logged in, CSRF token header |
| `POST enroll/{id}/respond` | open: proof of possession of the new key is the auth |
| `GET devices`, `POST devices/{id}/revoke` | owner (or administrator) |

Signed string: `thessley_passkey_v1|type|request_id|origin|nonce|timestamp|action`
(ECDSA P-256 / SHA-256, ±60 s). The origin is always the site's own, never
client-supplied. Enrolment also records the Android Keystore attestation level
(shown on the devices tab) but never rejects on it.

## Differences from the WordPress plugin

* Events go to the Drupal log (`admin/reports/dblog`, type `thessley_passkey`)
  instead of the Thessley event log; nothing is reported to unwantedip.
* No country label in the app link.
* Enrolling a device emails the account owner.
* Expired/consumed handshake rows are pruned by cron.

## Tests

`tests/drupal-passkey-checks.php` (repo root) drives the module over real HTTP
with real EC signatures, the app's exact `?rest_route=` request shape, real
cookies and the real login form. **Run it against a sandbox, never a live
site**: it creates and deletes users, a role and devices and flips the mode.

```
BASE=http://127.0.0.1:10190 SSH_HOST=<host> DRUPAL_DIR=~/drupal-sandbox php tests/drupal-passkey-checks.php
```
