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
- [ ] Create a production-signed Android release with an owner-controlled signing key. The current 55 MB v0.4 APK is a verified debug/test build, not a store release; no iOS build is in this delivery.
- [x] Publish the app source/docs to the public GitHub repository `frnsy210-commits/godark` on `main`; commit `01862bb4941679fe6ef6c4e40e7bcdc120300553`. No APK is included.
- [x] Account-service GitHub Actions passed. Android CI is currently blocked during `setup-android` (`sdkmanager` exited 1) before the app build runs; the local Android build and tests had passed previously.
- [x] Keep the informational website as a downloadable static ZIP; the user chose not to use Cloudflare or another live hosting service. There is no live website URL.
- [x] Add a direct Home shortcut to Places → Map and its existing offline-area download controls.
- [x] Make the Android Ask assistant a fixed built-in feature; first use prepares the Gemma 4 E2B model over Wi-Fi only, keeps conversations on-device, and removes the in-app model picker/delete control.
- [x] Run `testDebugUnitTest assembleDebug` successfully after the Android changes; verified the resulting APK signature and package metadata locally.
- [ ] Do not attempt Cloudflare/GitHub Pages publishing unless the user changes the hosting choice; keep the Node/MySQL backend, signup and telemetry unpublished.
