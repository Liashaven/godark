import Foundation
import CryptoKit
import Security
import UIKit

/// Account and optional telemetry APIs are isolated from mesh, message, and relay traffic.
@MainActor
final class AccountService: ObservableObject {
    static let shared = AccountService()
    /// Intentionally blank until publication is authorized and the real HTTPS origin is selected.
    static let apiBaseURL = ""
    private let tokenKey = "it.darkproof.godark.account.access-token"
    private var consentSessionReady = false
    private let diagnosticKinds: Set<String> = ["app_crash", "startup_failure", "freeze", "other"]
    // The backend's usage-event enum list is not present in this repository; reject until it is verified.
    private let allowedUsageFeatures: Set<String> = []

    struct Account: Codable, Equatable {
        let id: String
        let email: String
        let displayName: String
        let createdAt: String?
        let lastLoginAt: String?
    }
    private struct AccountConsents: Decodable { let analyticsOptIn: Bool; let diagnosticsOptIn: Bool }
    private struct AccountEnvelope: Decodable { let account: Account; let consents: AccountConsents }
    private struct SessionEnvelope: Decodable { let account: Account; let accessToken: String }

    @Published private(set) var account: Account?
    @Published private(set) var busy = false
    @Published var message = ""
    @Published var analyticsOptIn = false
    @Published var diagnosticsOptIn = false
    var configured: Bool { Self.apiBaseURL.hasPrefix("https://") }
    var signedIn: Bool { keychainToken() != nil }

    private init() {}

    func refresh() async {
        guard configured, let token = keychainToken() else {
            account = nil
            resetConsent()
            return
        }
        consentSessionReady = false
        analyticsOptIn = false; diagnosticsOptIn = false
        busy = true; defer { busy = false }
        do { try await hydrateAccount(token: token) }
        catch {
            resetConsent()
            message = error.localizedDescription
        }
    }

    func register(email: String, displayName: String, password: String, terms: Bool, privacy: Bool) async {
        guard configured, terms, privacy else { return }
        busy = true; defer { busy = false }
        do {
            let body: [String: Any] = ["email": email, "displayName": displayName, "password": password,
                "termsAccepted": true, "privacyAcknowledged": true, "analyticsOptIn": analyticsOptIn,
                "diagnosticsOptIn": diagnosticsOptIn, "client": "native"]
            let session = try JSONDecoder().decode(SessionEnvelope.self, from: await request("POST", "/api/auth/register", body: body))
            try setKeychainToken(session.accessToken)
            account = session.account
            consentSessionReady = false; resetConsent()
            do { try await hydrateAccount(token: session.accessToken); message = "Account created" }
            catch { message = "Account created, but privacy choices could not be refreshed. Optional telemetry is paused." }
        } catch { message = error.localizedDescription }
    }

    func login(email: String, password: String) async {
        guard configured else { return }
        busy = true; defer { busy = false }
        do {
            let session = try JSONDecoder().decode(SessionEnvelope.self, from: await request("POST", "/api/auth/login", body: ["email": email, "password": password, "client": "native"]))
            try setKeychainToken(session.accessToken)
            account = session.account
            consentSessionReady = false; resetConsent()
            do { try await hydrateAccount(token: session.accessToken); message = "Signed in" }
            catch { message = "Signed in, but privacy choices could not be refreshed. Optional telemetry is paused." }
        } catch { message = error.localizedDescription }
    }

    func logout() async {
        guard configured, let token = keychainToken() else { clearSession(); return }
        busy = true; defer { busy = false }
        do { _ = try await request("POST", "/api/auth/logout", body: [:], token: token); clearSession(); message = "Signed out" }
        catch { clearSession(); message = "Signed out on this device; service sign-out could not be confirmed." }
    }

    func exportAccount() async -> String? {
        guard configured, let token = keychainToken() else { return nil }
        busy = true; defer { busy = false }
        do { return String(data: try await request("GET", "/api/account/export", token: token), encoding: .utf8) }
        catch { message = error.localizedDescription; return nil }
    }

    func deleteAccount(password: String) async {
        guard configured, let token = keychainToken() else { return }
        busy = true; defer { busy = false }
        do { _ = try await request("DELETE", "/api/account", body: ["password": password], token: token); clearSession(); message = "Account deleted" }
        catch { message = error.localizedDescription }
    }

    func updateConsent(analytics: Bool, diagnostics: Bool) async {
        guard configured, consentSessionReady, let token = keychainToken() else { return }
        busy = true; defer { busy = false }
        do {
            _ = try await request("PATCH", "/api/account/consent", body: ["analyticsOptIn": analytics, "diagnosticsOptIn": diagnostics], token: token)
            saveConsent(analytics: analytics, diagnostics: diagnostics)
            analyticsOptIn = analytics; diagnosticsOptIn = diagnostics
        } catch { message = error.localizedDescription }
    }

    /// Manual enum-only diagnostics; no raw crash stack or application content is read.
    func submitDiagnostic(kind: String) async {
        guard diagnosticKinds.contains(kind), configured, consentSessionReady, diagnosticsOptIn, let token = keychainToken() else { return }
        let appVersion = normalizedAppVersion(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String)
        let osVersion = "iOS-\(normalizedNumericVersion(UIDevice.current.systemVersion))"
        let deviceModel = normalizedDeviceModel(UIDevice.current.model)
        let signature = SHA256.hash(data: Data("manual-diagnostic:\(kind)".utf8)).map { String(format: "%02x", $0) }.joined()
        busy = true; defer { busy = false }
        do {
            _ = try await request("POST", "/api/telemetry/diagnostics", body: ["platform": "ios", "appVersion": appVersion,
                "deviceModel": deviceModel, "osVersion": osVersion, "crashKind": kind, "signatureHash": signature], token: token)
            message = "Diagnostic submitted"
        } catch { message = error.localizedDescription }
    }

    /// Only allowlisted feature identifiers and timestamps can be sent; refuse unverified server enums.
    func recordUsage(feature: String, eventTime: Date = Date()) async {
        guard allowedUsageFeatures.contains(feature), configured, consentSessionReady, analyticsOptIn, let token = keychainToken() else { return }
        busy = true; defer { busy = false }
        do {
            _ = try await request("POST", "/api/telemetry/usage", body: ["feature": feature, "eventTime": ISO8601DateFormatter().string(from: eventTime)], token: token)
        } catch { message = error.localizedDescription }
    }

    private func hydrateAccount(token: String) async throws {
        let envelope = try JSONDecoder().decode(AccountEnvelope.self, from: await request("GET", "/api/account", token: token))
        account = envelope.account
        saveConsent(analytics: envelope.consents.analyticsOptIn, diagnostics: envelope.consents.diagnosticsOptIn)
        analyticsOptIn = envelope.consents.analyticsOptIn
        diagnosticsOptIn = envelope.consents.diagnosticsOptIn
        consentSessionReady = true
    }

    private func normalizedAppVersion(_ raw: String?) -> String {
        let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard value.range(of: #"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$"#, options: .regularExpression) != nil else { return "0.0.0" }
        return value.split(separator: ".").count == 2 ? value + ".0" : value
    }

    private func normalizedNumericVersion(_ raw: String) -> String {
        raw.range(of: #"^[0-9]+(?:\.[0-9]+)*$"#, options: .regularExpression) != nil ? raw : "0"
    }

    private func normalizedDeviceModel(_ raw: String) -> String {
        let value = raw.replacingOccurrences(of: #"\s+"#, with: "-", options: .regularExpression)
            .replacingOccurrences(of: #"[^A-Za-z0-9.,_-]"#, with: "", options: .regularExpression)
        return String(value.prefix(80)).isEmpty ? "unknown" : String(value.prefix(80))
    }

    private func resetConsent() {
        consentSessionReady = false
        analyticsOptIn = false; diagnosticsOptIn = false
        UserDefaults.standard.set(false, forKey: "accountAnalyticsOptIn")
        UserDefaults.standard.set(false, forKey: "accountDiagnosticsOptIn")
    }

    private func request(_ method: String, _ path: String, body: [String: Any]? = nil, token: String? = nil) async throws -> Data {
        guard configured, let base = URL(string: Self.apiBaseURL), base.scheme == "https" else { throw ServiceError.notConfigured }
        guard let url = URL(string: path, relativeTo: base) else { throw ServiceError.badURL }
        var request = URLRequest(url: url); request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body { request.setValue("application/json", forHTTPHeaderField: "Content-Type"); request.httpBody = try JSONSerialization.data(withJSONObject: body) }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw ServiceError.server(detail ?? "Account request failed")
        }
        return data
    }

    private enum ServiceError: LocalizedError {
        case notConfigured, badURL, server(String)
        var errorDescription: String? {
            switch self { case .notConfigured: return "Accounts are not available in this build; the public API origin is not configured."; case .badURL: return "Invalid account API URL."; case .server(let text): return text }
        }
    }

    private func keychainToken() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: tokenKey,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var value: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &value) == errSecSuccess, let data = value as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    private func setKeychainToken(_ token: String) throws {
        let data = Data(token.utf8)
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: tokenKey]
        SecItemDelete(query as CFDictionary)
        var attributes = query; attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw ServiceError.server("Could not securely store the sign-in token.") }
    }
    private func clearSession() {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: tokenKey]
        SecItemDelete(q as CFDictionary)
        account = nil
        resetConsent()
    }
    private func saveConsent(analytics: Bool, diagnostics: Bool) {
        UserDefaults.standard.set(analytics, forKey: "accountAnalyticsOptIn")
        UserDefaults.standard.set(diagnostics, forKey: "accountDiagnosticsOptIn")
    }
}
