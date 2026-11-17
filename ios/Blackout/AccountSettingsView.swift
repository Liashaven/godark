import SwiftUI

struct AccountSettingsPage: View {
    @StateObject private var service = AccountService.shared
    @State private var registering = false
    @State private var email = ""
    @State private var displayName = ""
    @State private var password = ""
    @State private var termsAccepted = false
    @State private var privacyAcknowledged = false
    @State private var showingDelete = false
    @State private var deletePassword = ""
    @State private var exportText: String?
    @State private var incident = "app_crash"

    private var configured: Bool { service.configured }
    var body: some View {
        SettingsPage(title: "GoDark account") {
            Card {
                Text("Optional account").scaledFont(18, .bold).foregroundStyle(Theme.text)
                Text("Offline messaging works without sign-in. Account and telemetry requests use a separate HTTPS API and never use mesh, message or relay handling.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                if !configured {
                    Text("Accounts are not available in this build: the public API origin has not been configured. Nothing is sent.")
                        .scaledFont(15, .semibold).foregroundStyle(Theme.help).fixedSize(horizontal: false, vertical: true)
                }
            }
            if let account = service.account {
                Card {
                    Text(account.displayName).scaledFont(21, .bold).foregroundStyle(Theme.text)
                    Text(account.email).scaledFont(16).foregroundStyle(Theme.dim)
                    Text("Account ID: \(account.id)").scaledFont(13).foregroundStyle(Theme.dim)
                    if let created = account.createdAt { Text("Created: \(created)").scaledFont(13).foregroundStyle(Theme.dim) }
                    if let lastLogin = account.lastLoginAt { Text("Last sign-in: \(lastLogin)").scaledFont(13).foregroundStyle(Theme.dim) }
                }
                Card {
                    Text("Privacy choices").scaledFont(18, .bold).foregroundStyle(Theme.text)
                    Toggle("Optional usage analytics: feature names and event timestamps only; no message contents. Off by default; deletion within 12 months.", isOn: Binding(
                        get: { service.analyticsOptIn }, set: { value in Task { await service.updateConsent(analytics: value, diagnostics: service.diagnosticsOptIn) } }))
                        .tint(Theme.safe)
                    Toggle("Optional diagnostics: app/device model, OS/app version, incident type and category hash only. Off by default; deletion within 90 days.", isOn: Binding(
                        get: { service.diagnosticsOptIn }, set: { value in Task { await service.updateConsent(analytics: service.analyticsOptIn, diagnostics: value) } }))
                        .tint(Theme.safe)
                    Text("Turning a choice off asks the service to remove previously collected optional data. Until the API is configured, preferences cannot be saved to an account service.")
                        .scaledFont(14).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                }
                Card {
                    Text("Manual diagnostics").scaledFont(18, .bold).foregroundStyle(Theme.text)
                    Text("Only an approved incident type and local category hash, app/device model, OS version and app version are submitted. No stack trace, message, location, contact or group data is inspected or uploaded.")
                        .scaledFont(14).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                    Picker("Incident category", selection: $incident) {
                        Text("App crash").tag("app_crash")
                        Text("Startup failure").tag("startup_failure")
                        Text("Freeze").tag("freeze")
                        Text("Other").tag("other")
                    }.tint(Theme.text)
                    Button("Submit diagnostic") { Task { await service.submitDiagnostic(kind: incident) } }
                        .buttonStyle(GhostButton()).disabled(!configured || !service.diagnosticsOptIn || service.busy)
                }
                if let exportText {
                    ShareLink(item: exportText) { Label("Share account export", systemImage: "square.and.arrow.up") }
                        .buttonStyle(GhostButton())
                }
                HStack(spacing: 10) {
                    Button("Access / export account data") { Task { exportText = await service.exportAccount() } }
                        .buttonStyle(GhostButton()).disabled(!configured || service.busy)
                    Button("Delete account", role: .destructive) { showingDelete = true }
                        .buttonStyle(GhostButton()).disabled(!configured || service.busy)
                }
                Button("Sign out") { Task { await service.logout() } }.buttonStyle(GhostButton()).disabled(!configured || service.busy)
            } else {
                HStack(spacing: 12) {
                    Button(registering ? "Create account" : "Sign in") { registering.toggle(); service.message = "" }
                        .buttonStyle(GhostButton()).disabled(!configured)
                    Button(registering ? "Sign in instead" : "Register") { registering.toggle(); service.message = "" }
                        .buttonStyle(GhostButton()).disabled(!configured)
                }
                InputField(label: "Email", hint: "name@example.com") {
                    TextField("", text: $email).textContentType(.emailAddress).keyboardType(.emailAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                if registering {
                    InputField(label: "Display name", hint: "Your chosen name") {
                        TextField("", text: $displayName).textContentType(.name)
                    }
                }
                InputField(label: "Password", hint: "") {
                    SecureField("", text: $password).textContentType(registering ? .newPassword : .password)
                }
                if registering {
                    Toggle("I accept the draft Terms of Service.", isOn: $termsAccepted).tint(Theme.safe)
                    Toggle("I have read and acknowledge the draft Privacy Policy.", isOn: $privacyAcknowledged).tint(Theme.safe)
                    Toggle("Optional usage analytics: feature names and event timestamps only; no message contents. Off by default; deletion within 12 months.", isOn: $service.analyticsOptIn).tint(Theme.safe)
                    Toggle("Optional diagnostics: app/device model, OS/app version, incident type and category hash only. Off by default; deletion within 90 days.", isOn: $service.diagnosticsOptIn).tint(Theme.safe)
                    Text("Terms and privacy acknowledgment are required only to create an account. Analytics and diagnostics are separate optional choices and start off.")
                        .scaledFont(14).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                }
                Button(service.busy ? "Working…" : registering ? "Create account" : "Sign in") {
                    Task {
                        if registering { await service.register(email: email.trimmingCharacters(in: .whitespacesAndNewlines), displayName: displayName.trimmingCharacters(in: .whitespacesAndNewlines), password: password, terms: termsAccepted, privacy: privacyAcknowledged) }
                        else { await service.login(email: email.trimmingCharacters(in: .whitespacesAndNewlines), password: password) }
                        password = ""
                    }
                }.buttonStyle(PrimaryButton()).disabled(!configured || service.busy || email.isEmpty || password.isEmpty || (registering && (displayName.isEmpty || !termsAccepted || !privacyAcknowledged)))
            }
            if !service.message.isEmpty { Text(service.message).scaledFont(14).foregroundStyle(Theme.dim).textSelection(.enabled) }
            Text("Account-service retention is not active in this unconfigured build. The draft policy describes intended limits, not a promise until provider backup retention has been verified.")
                .scaledFont(13).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
        }
        .task { await service.refresh() }
        .sheet(isPresented: $showingDelete) {
            NavigationStack {
                VStack(alignment: .leading, spacing: 18) {
                    Text("This requests deletion of the account and linked optional telemetry. Local messages, group keys, other phones’ copies and relay copies are not deleted.")
                        .scaledFont(16).foregroundStyle(Theme.dim)
                    SecureField("Confirm password", text: $deletePassword).textContentType(.password)
                    Button("Delete account", role: .destructive) { Task { await service.deleteAccount(password: deletePassword); showingDelete = false; deletePassword = "" } }
                        .buttonStyle(DangerButton()).disabled(deletePassword.isEmpty || service.busy)
                    Spacer()
                }.padding(24).background(Theme.bg.ignoresSafeArea()).navigationTitle("Delete account")
                    .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showingDelete = false; deletePassword = "" } } }
            }.presentationDetents([.medium])
        }
    }
}
