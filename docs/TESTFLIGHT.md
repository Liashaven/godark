# GoDark TestFlight checklist — not ready to submit

This document is a future release checklist, not an announcement of a TestFlight build. There is no public GoDark domain, App Store listing or TestFlight invitation configured. The mobile account API origin is intentionally blank, and the privacy/terms drafts and operator details need review before a public release.

## Before any submission

1. Complete legal review of `PRIVACY.md` and `TERMS.md`, configure the operator/support details, and publish a stable privacy-policy URL on the authorized GoDark domain.
2. Decide and verify the App Store Connect privacy labels from the actual release behavior. Do not select “Data Not Collected” without reviewing the app's relays, map/model downloads, account and optional telemetry behavior; the privacy manifest and App Store Connect answers are separate disclosures.
3. Configure the real HTTPS account API only after the scheduled retention cleanup is registered and verified and the provider's backup-retention limit is confirmed. Until then, account and telemetry collection stays disabled.
4. Join the Apple Developer Program at https://developer.apple.com/programs/ and sign in to Xcode → Settings → Accounts.
5. Open the existing iOS Xcode project and select the Apple team under Signing & Capabilities. The project still has an internal legacy target and bundle identifier. Do not change the bundle identifier as a casual rebrand: changing it creates a different iPhone app and can prevent updates to existing installations.
6. Create the App Store Connect record only when the user explicitly authorizes a release. Use **GoDark** as the displayed app name if available. Keep the existing bundle identifier unless a deliberate migration plan is approved.

## Build and upload (future)

1. Run `ios/Vendor/fetch-llama.sh` once per checkout to retrieve the pinned llama.cpp dependency.
2. In Xcode, select **Any iOS Device** and choose Product → Archive.
3. In Organizer, choose Distribute App → TestFlight & App Store only after the privacy, account, domain and signing prerequisites above are complete.
4. Increment `CURRENT_PROJECT_VERSION` for each new upload.

## TestFlight review notes

Describe only features verified in the exact submitted build. State clearly that GoDark is not an emergency service and that messages may fail to send or arrive. Do not promise an account service, public support channel, App Store privacy status, or TestFlight availability before each is actually configured and verified.

## Tester instructions

Tell testers to download any on-device AI model while internet is available, to practise only with people who understand the limits, and to retain ordinary communication options. GoDark cannot guarantee delivery or replace emergency services.
