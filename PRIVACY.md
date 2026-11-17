# GoDark privacy policy — DRAFT

Last updated: November 16, 2026. This draft requires qualified legal review before public launch. The account API origin is intentionally blank in this source snapshot, so this build cannot register, sign in, export or delete accounts and sends no account or telemetry requests. Some earlier internal labels and protocol identifiers remain pending compatibility review; the visible product name is GoDark.

The optional account service is separate from offline messaging, mesh forwarding and third-party message relays. An account is not required for offline messaging. If the account service is later enabled, it may receive only the information described below. It must never receive message contents, group codes or keys, contacts, check-in contents or precise location.

## Account data

The account record is limited to the account identifier, email address, chosen display name, password hash, account creation date and last-login date. A password is used to authenticate a registration or sign-in request over HTTPS; the service must store a password hash and must not retain the raw password. The service also records the applicable Terms and Privacy Policy versions, consent choices and the times those choices were made or changed. Account data is retained while the account exists. A confirmed account-deletion request must be completed within 30 days, including removal of account-linked optional telemetry. Deleting an account does not delete local messages, group keys, or copies held by other phones or independent relays.

The service may keep the IP address and sign-in/security events for 30 days. Those records are limited to account security and are not used for advertising or cross-service tracking.

The service provider may make backups. Backup expiration within 90 days is an intended limit, but **has not been verified and is a launch blocker**. This draft does not claim that backups expire within 90 days; provider behavior and contractual commitments must be verified before launch.

## Optional analytics and diagnostics

Usage analytics and diagnostics are separate, optional choices. Both checkboxes are off by default; neither is required for an account or messaging. Each choice can be changed later. When a choice is turned off, the service must stop future collection and remove previously collected data covered by that choice.

- **Usage analytics** (only with explicit opt-in): allowlisted feature names and event timestamps only, retained for no more than 12 months. No message contents are included.
- **Diagnostics** (only with explicit opt-in): app version, device model, operating-system version, an allowlisted incident type and a hash of that incident category only, retained for no more than 90 days. No crash stack, raw crash report, message, location, contact or group data is inspected or uploaded.

Account and telemetry requests use a dedicated HTTPS API and are not routed through mesh, message or relay handling. No optional telemetry is sent while the API origin is blank, while signed out, before the account's server-side consent has been read, or when the relevant consent is off.

## Data the account service must never collect

The account service and its telemetry endpoints must never receive message contents, group codes or keys, contact lists, check-in contents or precise location. They must not ingest mesh packets, chat text, photos, AI conversations, check-in needs/status, location coordinates, invite links or relay payloads. The name a user chooses to display with a mesh message is a separate local/mesh feature and is not an account field unless the user separately supplies an account display name.

## Messages, mesh and public relays

GoDark messaging continues to work without an account. Messages can travel directly over Bluetooth, local Wi-Fi and compatible LoRa radios, or through public third-party Nostr relays when internet connectivity is available and Internet is enabled. Those relays are operated independently of the account service. Group messages are encrypted for group members; public Everyone messages and places are readable by anyone. Relays and network providers may see connection metadata such as IP address, timing and packet size. Tor can hide the device's network address from a relay, but does not change what Tor infrastructure can observe.

Nearby phones may store and forward packets. On-device message retention and deletion follow the app's local storage behavior and wire protocol, not the account service. Deleting an account does not recall or erase messages already delivered to other phones or independent relays. Treat the Everyone channel and anything shared through another app as public or visible to the selected third party.

The app can also access third-party internet services when a user requests features such as AI model or map downloads. Those service operators may see ordinary network metadata under their own policies. AI conversations are processed on the device by the included on-device models.

## On-device information and permissions

Group codes and keys, messages, local group membership, AI conversations, radio settings, blocked users and reports are handled on the device for their local functions. iOS stores the account access token in Keychain; Android encrypts it using an Android Keystore AES-GCM key. Account-consent choices are stored locally to support the interface, but telemetry remains blocked until consent has been synchronized from the account service for the current session.

Bluetooth and nearby-device access support mesh/radio connections. Camera/photo selection supports user-requested photos or invite QR scanning. Notifications are generated on the phone. Location permission is used for location features chosen by the user and can be included in a message to a group or an Everyone place if the user explicitly chooses that feature; location is never sent to the account or telemetry service. Review current app permission prompts and local controls before enabling optional capabilities.

## Children's use

The app and optional account are not intended for children under 13. The Everyone channel is public to app users.

## iOS privacy manifest and store labels

The iOS `PrivacyInfo.xcprivacy` manifest declares Name, Email Address and User ID for account functionality, Product Interaction for opt-in analytics, and Other Diagnostic Data for opt-in diagnostics. It does not declare raw crash reports or crash-stack data. The manifest declares no tracking and no tracking domains. **App Store Connect privacy labels are separate from the iOS privacy manifest and must be completed and checked independently before submission.**

## Launch readiness and contact

This policy is a draft, not launch approval. Public launch requires legal review, selection and authorization of the real public HTTPS API origin, production security review, and verification of provider backup-retention behavior. The account service, operator identity and support contact are **not configured** in this source snapshot. Do not rely on an unconfigured account or support channel for emergencies or incident response.

If this policy changes, the published policy must be updated with its effective date and a real, operator-controlled contact before accounts are made available.
