# GoDark app, account and publication TODO

## Android account and consent UI
- [x] Add an optional account/settings page for registration, sign-in, profile display, sign-out, data export and account deletion; local offline messaging continues to work without an account.
- [x] Add separate diagnostics and usage-analytics consent controls, both disabled by default and changeable later; keep them separate from location sharing and all message/group settings.
- [x] Store native session tokens only in Android protected storage, and call only the dedicated account API when the user is signed in and a consent is enabled.

## iPhone account and consent UI
- [x] Add the same optional account/settings page and data controls; keep account identity separate from mesh identity and local offline messaging account-free.
- [x] Store native session tokens in Keychain; add diagnostics and usage-analytics controls disabled by default, with opt-out available at any time.
- [x] Update the iOS privacy manifest to declare the actual account and consented telemetry data, without declaring tracking or ad SDKs.

## Data boundary and app disclosures
- [x] Limit the account/API code to approved account fields, opt-in diagnostics (app/device model, OS/app version and crash details; 90 days), opt-in feature-name/event-time analytics (12 months), and sign-in/security metadata; never upload messages, group codes/keys, contacts, check-ins or precise location.
- [x] Keep telemetry payloads strictly allowlisted and separate from the mesh/relay network; opting out stops future collection and removes previously collected optional records.
- [x] Account deletion clears account sessions and server-linked account/telemetry data, but does not silently delete local messages, group keys, other phones' copies or relay copies.
- [x] Update README, PRIVACY.md, TERMS.md and native help text to describe optional accounts and the planned data policy accurately.

## Launch and publication gates
- [x] Keep the native API base URL blank; no temporary Preview URL is embedded and the app sends no account/telemetry requests in this source snapshot.
- [x] Keep legacy package/bundle IDs, wire/encryption identifiers, radio-discovery strings and invite schemes unchanged to preserve compatibility with existing installs and groups.
- [ ] Before enabling account signup or telemetry, configure a permanent HTTPS API origin, publish the daily retention cleanup, verify the provider's backup-retention window (90 days or less), and complete the required security/legal review.
- [ ] Before announcing a public app launch, obtain an independent legal/privacy review of `TERMS.md` and `PRIVACY.md` and provide a publicly reachable policy/support URL; the user chose a downloadable website ZIP, so no live policy URL is configured. No legal protection from lawsuits is promised.
- [x] Build and verify Android v0.5 as a non-debug direct-install APK signed with the selected Liashaven release certificate. Version code 5 is higher than the prior Liashaven v0.4 build (code 4); signing fingerprint `ac785c88258f161d4fda963e5ac66137db66b2ae0539d9858f8fba3441022fef`. This is not a Play Store listing or public GitHub Release; no iOS build is in this delivery.
- [x] Publish the app source/docs to the public GitHub repository `frnsy210-commits/godark` on `main`; commit `01862bb4941679fe6ef6c4e40e7bcdc120300553`. No APK is included.
- [x] Account-service GitHub Actions passed. Android CI passed on commit `274bd54710925cad7b3cfd048a00fe9e4d2c3fe0` (run `44411996078`); local Android tests and `assembleDebug` also pass.
- [x] Keep the informational website as a downloadable static ZIP; the user chose not to use Cloudflare or another live hosting service. There is no live website URL.
- [x] Add a direct Home shortcut to Places → Map and its existing offline-area download controls.
- [x] Make the Android Ask assistant a fixed built-in feature; first use prepares the Gemma 4 E2B model over Wi-Fi only, keeps conversations on-device, and removes the in-app model picker/delete control.
- [x] Run `testDebugUnitTest assembleRelease` successfully after the Android changes; verified the release APK signature, matching Liashaven certificate, package/version metadata, alignment and non-debuggable status locally.
- [ ] Do not attempt Cloudflare/GitHub Pages publishing unless the user changes the hosting choice; keep the Node/MySQL backend, signup and telemetry unpublished.
