# Android AD key enrollment

The domain controller admin page remains the enrollment authority. An administrator selects an authorized AD account and starts **Add AD logon key** there. The page displays a one-time QR for Thessley Passkey; the phone creates its separate RSA logon key in Android Keystore, proves possession of both the existing account phone key and the new key, then submits the public key and attestation directly to the DC. The admin page's matching-code confirmation activates it. Private keys never leave the phone.

## Separate HTTPS listeners

- `47810`: AD sign-in and phone-approval API, plus the existing enrollment endpoints.
- `47811`: narrowly scoped Android AD logon-key enrollment and status API.
- `47820`: browser admin page. It starts enrollments and confirms the phone's matching code.

All three use the same DC TLS certificate and fingerprint. The admin page's QR keeps the pinned sign-in service at `p=47810` and includes `ep=47811` for the phone's key upload. The Android app accepts that extra port only on an AD logon-key enrollment QR. The Windows service binds the new listener to the configured DC address. The installer opens TCP 47811 only to the same source range used by the AD API, unless an existing rule already defines its scope.

## Operator flow

1. Open the DC admin page and sign in as a DC administrator.
2. Select an authorized AD account and choose **Add AD logon key**.
3. Scan the displayed QR in Thessley Passkey and confirm both phone-key prompts.
4. Compare the short code shown by the phone and the admin page, then confirm on the admin page.
5. The phone reports the active key and its server-verified attestation level. Windows sign-in still requires the separate provider integration to be enabled.

No public key, private key, password, or CSR needs to be copied by hand. Enrollment requests expire; an expired request is restarted from the admin page.
