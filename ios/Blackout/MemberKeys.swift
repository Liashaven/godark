import Foundation
import Combine
import CryptoKit
import Security
import BlackoutCore

/// This phone's signing key in each group (spec/FORMAT.md, "Member ids"). Where the phone has a Secure Enclave the private
/// key is made inside it and can't be copied off the phone; only a wrapped reference to it is saved. It works after the
/// first unlock (Bluetooth can wake the app in the background). `tag` names the group without revealing its key.
enum MemberKeys {
    struct SigningKey: @unchecked Sendable {
        let publicKey: P256.Signing.PublicKey, inChip: Bool
        /// Returns r ‖ s.
        let sign: (Data) throws -> Data
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var cache: [String: SigningKey] = [:] // guarded by lock
    private static let service = "darkproof-member"

    static func forGroup(_ tag: String) -> SigningKey {
        lock.lock(); defer { lock.unlock() }
        if let k = cache[tag] { return k }
        let k = saved(tag) ?? make(tag)
        cache[tag] = k
        return k
    }

    private static func software(_ k: P256.Signing.PrivateKey) -> SigningKey {
        SigningKey(publicKey: k.publicKey, inChip: false) { try MemberKey.sign(k, $0) }
    }
    private static func chip(_ k: SecureEnclave.P256.Signing.PrivateKey) -> SigningKey {
        SigningKey(publicKey: k.publicKey, inChip: true) { try k.signature(for: $0).rawRepresentation }
    }

    /// A key made earlier. One outside the chip stays as it is: a new key would make this phone a new person in that group.
    private static func saved(_ tag: String) -> SigningKey? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: tag, kSecReturnData as String: true]
        var out: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let d = out as? Data,
           let k = try? P256.Signing.PrivateKey(rawRepresentation: d) { return software(k) }
        return Vault.get("chip.sign.\(tag)").flatMap { try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: $0) }.map(chip)
    }

    private static func make(_ tag: String) -> SigningKey {
        if SecureEnclave.isAvailable, let access = Vault.chipAccess, let k = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: access) {
            Vault.put("chip.sign.\(tag)", k.dataRepresentation)
            return chip(k)
        }
        let k = P256.Signing.PrivateKey() // the Simulator has no Secure Enclave
        let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                  kSecAttrAccount as String: tag, kSecValueData as String: k.rawRepresentation,
                                  kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        SecItemAdd(add as CFDictionary, nil)
        return software(k)
    }
}

/// Small secrets on this phone (epoch secrets, encryption keys: spec/DESIGN-v0.6-groups.md, "Keys"), in the Keychain,
/// only on this phone and readable after the first unlock.
enum Vault {
    private static let service = "darkproof-vault"

    static func put(_ name: String, _ data: Data?) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: name]
        SecItemDelete(q as CFDictionary)
        guard let data else { return }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }

    static func get(_ name: String) -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: name, kSecReturnData as String: true]
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    /// The Keychain outlives the app and UserDefaults doesn't: on the first start after an install, nothing of an earlier
    /// install stays. Does nothing, and tries again next time, while the phone hasn't been unlocked yet.
    static func wipeAfterReinstall() {
        let d = UserDefaults.standard
        guard d.string(forKey: "device") == nil, !d.bool(forKey: "keychainFresh") else { return }
        var ok = true
        for s in [service, "darkproof-member"] {
            let status = SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: s] as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound { ok = false }
        }
        if ok { d.set(true, forKey: "keychainFresh") }
    }

    /// What a Secure Enclave key may do: be used by this app, on this phone, once it has been unlocked after starting.
    static var chipAccess: SecAccessControl? { SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil) }

    struct EncryptionKey: @unchecked Sendable {
        let publicKey: P256.KeyAgreement.PublicKey, inChip: Bool
        let agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret
    }

    private static func software(_ k: P256.KeyAgreement.PrivateKey) -> EncryptionKey {
        EncryptionKey(publicKey: k.publicKey, inChip: false) { try k.sharedSecretFromKeyAgreement(with: $0) }
    }
    private static func chip(_ k: SecureEnclave.P256.KeyAgreement.PrivateKey) -> EncryptionKey {
        EncryptionKey(publicKey: k.publicKey, inChip: true) { try k.sharedSecretFromKeyAgreement(with: $0) }
    }

    /// This phone's encryption key in group `groupId` (HPKE recipient key), made the first time, in the Secure Enclave
    /// where there is one. A key made earlier outside it stays: other members have sealed new keys to it.
    static func encryptionKey(_ groupId: String) -> EncryptionKey {
        if let d = get("enc.\(groupId)"), let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: d) { return software(k) }
        if let d = get("chip.enc.\(groupId)"), let k = try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: d) { return chip(k) }
        if SecureEnclave.isAvailable, let access = chipAccess, let k = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access) {
            put("chip.enc.\(groupId)", k.dataRepresentation)
            return chip(k)
        }
        let k = P256.KeyAgreement.PrivateKey() // the Simulator has no Secure Enclave
        put("enc.\(groupId)", k.rawRepresentation)
        return software(k)
    }

    /// Deletes an encryption key for good: what was sealed to it can't be opened any more, on this phone or by anyone who takes it.
    static func forgetEncryptionKey(_ groupId: String) {
        put("enc.\(groupId)", nil)
        put("chip.enc.\(groupId)", nil)
    }
}

/// This phone's encryption keys in one group (spec "Sealing for one member"): the newest goes in its introductions, and
/// every key still kept can open what was sealed to it. EncSchedule says when one changes. Any thread.
final class EncKeys: @unchecked Sendable { // guarded by lock
    private let groupId: String, lock = NSLock()
    private var list: [EncSchedule.Entry]
    private var keys: [Int: Vault.EncryptionKey] = [:]
    private var pqKeys: [Int: (pub: Data, seed: Data)] = [:] // ML-KEM halves

    private func pq(_ n: Int) -> (pub: Data, seed: Data)? {
        if let k = pqKeys[n] { return k }
        if let seed = Vault.get("mlkem.\(name(n))"), let pub = MlKem.publicKey(seed: seed) { pqKeys[n] = (pub, seed); return (pub, seed) }
        guard let k = MlKem.newKey() else { return nil }
        Vault.put("mlkem.\(name(n))", k.seed)
        pqKeys[n] = k
        return k
    }

    init(_ groupId: String) {
        self.groupId = groupId
        let saved = EncSchedule.parse(UserDefaults.standard.string(forKey: "encs.\(groupId)") ?? "")
        list = saved.isEmpty ? [.init(n: 0, made: Int64(Date().timeIntervalSince1970 * 1000))] : saved
        if saved.isEmpty { save() }
    }

    private func save() { UserDefaults.standard.set(EncSchedule.save(list), forKey: "encs.\(groupId)") }
    private func name(_ n: Int) -> String { n == 0 ? groupId : "\(groupId).\(n)" } // the first key keeps the name older builds gave it
    private func key(_ n: Int) -> Vault.EncryptionKey {
        if let k = keys[n] { return k }
        let k = Vault.encryptionKey(name(n))
        keys[n] = k
        return k
    }

    /// The newest key, as it goes in an introduction.
    var currentPub: Data { lock.withLock { key(list.last!.n).publicKey.x963Representation } }
    /// The newest key's ML-KEM half, as it goes in an introduction.
    var currentPq: Data? { lock.withLock { pq(list.last!.n)?.pub } }
    var inChip: Bool { lock.withLock { key(list.last!.n).inChip } }

    /// Deletes keys that were replaced long enough ago, and makes a new one when the current one is a week old. True if it did.
    func rotateIfDue(now: Int64) -> Bool {
        lock.withLock {
            let gone = EncSchedule.expired(list, now: now)
            if !gone.isEmpty {
                for e in gone { Vault.forgetEncryptionKey(name(e.n)); Vault.put("mlkem.\(name(e.n))", nil); keys[e.n] = nil; pqKeys[e.n] = nil }
                list.removeAll { gone.contains($0) }
                save()
            }
            guard EncSchedule.due(list, now: now) else { return false }
            list = EncSchedule.rotated(list, now: now)
            _ = key(list.last!.n)
            save()
            #if DEBUG
            DebugLog.write("new encryption key \(list.last!.n)")
            #endif
            return true
        }
    }

    /// What was sealed to any key still kept, newest first; nil if none opens it.
    func open(_ box: Data, info: Data, aad: Data) -> Data? {
        lock.withLock {
            for e in list.reversed() {
                let k = key(e.n)
                if let d = Hybrid.open(box, to: k.publicKey, agree: k.agree, seed: pq(e.n)?.seed, info: info, aad: aad) { return d }
            }
            return nil
        }
    }
}

/// Group codes on this phone, in the Keychain: a code is what lets someone ask to join, and UserDefaults goes into
/// backups. Read once, then from memory; codes saved by older builds move here. Any thread.
final class GroupSecrets: ObservableObject, @unchecked Sendable { // guarded by lock
    static let shared = GroupSecrets()
    private struct Saved: Codable { var code = ""; var groups: [SavedGroups.Entry] = []; var found: [String] = []; var pins: [String: String]? } // optional: saved data from older builds has none
    private static let item = "groups"
    private let lock = NSLock()
    private var saved = Saved()

    private init() {
        if readKeychain() { return }
        let d = UserDefaults.standard
        var s = Saved()
        s.code = d.string(forKey: "code") ?? ""
        if let data = d.data(forKey: "savedGroups"), let list = try? JSONDecoder().decode([SavedGroups.Entry].self, from: data) { s.groups = list }
        s.found = d.stringArray(forKey: "found") ?? []
        guard !(s.code.isEmpty && s.groups.isEmpty && s.found.isEmpty) else { return }
        saved = s
        Vault.put(Self.item, try? JSONEncoder().encode(s))
        if Vault.get(Self.item) != nil { for key in ["code", "savedGroups", "found"] { d.removeObject(forKey: key) } }
    }

    private func readKeychain() -> Bool {
        guard let raw = Vault.get(Self.item), let s = try? JSONDecoder().decode(Saved.self, from: raw) else { return false }
        saved = s
        return true
    }

    /// Before the phone's first unlock the Keychain can't be read: tries again while nothing is known. Hold the lock.
    private func read<T>(_ f: (Saved) -> T) -> T {
        lock.withLock {
            if saved.code.isEmpty && saved.groups.isEmpty && saved.found.isEmpty { _ = readKeychain() }
            return f(saved)
        }
    }

    private func change(_ f: (inout Saved) -> Void) {
        lock.withLock { f(&saved); Vault.put(Self.item, try? JSONEncoder().encode(saved)) }
        if Thread.isMainThread { objectWillChange.send() } else { DispatchQueue.main.async { self.objectWillChange.send() } }
    }

    /// The code of the group in use; empty before setup.
    var code: String { read(\.code) }
    /// The same, nil before setup.
    var current: String? { let c = code; return c.isEmpty ? nil : c }
    var groups: [SavedGroups.Entry] { read(\.groups) }
    /// Groups made on this phone, or saved before v0.6, that have no first epoch yet (spec "Making the first epoch").
    var found: [String] { read(\.found) }
    /// The admins the invite for `code` named ("" if none): only they can let this phone in (spec "Invites").
    func pins(_ code: String) -> String { read { $0.pins?[code] ?? "" } }
    /// The user chose to join `code`, or to show it: if this phone doesn't have that code yet, the admins its invite
    /// names are kept from now on (`Invite.joinPins`). Nothing else writes them. Call before the group is saved.
    func joining(_ code: String, pins: String) {
        change { s in s.pins = Invite.joinPins(s.pins ?? [:], groups: s.groups.map(\.code) + [s.code], code: code, pins: pins) }
    }

    func setCode(_ c: String) {
        change { $0.code = c }
        #if DEBUG
        noteForTests()
        #endif
    }
    func setGroups(_ list: [SavedGroups.Entry]) { change { $0.groups = list } }
    func setFound(_ codes: [String]) { change { $0.found = codes } }

    #if DEBUG
    /// For tests that compare phones' codes: the start of its hash, never the code.
    func noteForTests() { DebugLog.write("code now " + SHA256.hash(data: Data(code.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()) }
    #endif
}
