import Foundation
import CryptoKit
import CoreBluetooth
import UIKit
import UserNotifications
import BlackoutCore

/// Owns the one Engine. It starts as soon as the app process starts, if a group is set up, so it also runs when iOS
/// relaunches GoDark in the background for Bluetooth (BleLink's restore identifiers), with no screen at all.
final class Mesh: ObservableObject {
    static let shared = Mesh()
    @Published private(set) var engine: Engine?

    /// Starts the mesh for the saved group, if there is one. Safe to call more than once.
    func startIfSetUp() {
        let d = UserDefaults.standard
        guard engine == nil, let code = GroupSecrets.shared.current, !code.isEmpty else { return }
        engine = Engine(name: d.string(forKey: "name") ?? "", code: code)
    }

    /// Starts the mesh right after setup. Bluetooth starts first; the Wi-Fi links (which ask for Local Network)
    /// only once the Bluetooth question is answered, so iOS asks one thing at a time.
    func start(name: String, code: String) {
        if engine == nil { engine = Engine(name: name, code: code, askInOrder: true) }
    }
}

/// State shared between the transports and the UI, like the Android MeshEngine.
final class Engine: ObservableObject {
    static let maxTtl = MeshRouter.maxTtl
    private static let handedOffMax = 2_000  // "Sent" labels remembered across restarts
    private static let maxPublic = 2_000     // Public messages kept on the phone; older ones are removed
    private static let week: Int64 = 7 * 24 * 3_600_000
    /// This group's messages and the Public channel's, oldest first, without blocked people and reported messages.
    @Published private(set) var messages: [Message] = []
    /// Every saved group's messages and the Public channel's, likewise; `Message.group` tells which group.
    @Published private(set) var allMessages: [Message] = []
    @Published private(set) var status: [String: String] = [:] // transport -> status line
    @Published private(set) var phones = 0        // other devices linked directly, each counted once
    @Published private(set) var bluetoothLinks = 0
    @Published private(set) var wifiLinks = 0
    @Published private(set) var wifiNetworkLinks = 0 // phones linked over a Wi-Fi network (WifiLink)
    @Published private(set) var radioLinked = false
    @Published private(set) var meshcoreLinked = false
    @Published private(set) var relaysLinked = 0     // internet relays connected right now (NostrLink)
    @Published private(set) var throughTor: Bool?    // "Connect through Tor": true when checked, false while waiting
    @Published private(set) var linkedNodes: Set<String> = [] // node ids linked directly right now
    @Published private(set) var name: String
    @Published private(set) var deliveries = Deliveries()  // who confirmed which message (spec/FORMAT.md, "Delivery receipts")
    @Published private(set) var handedOff: Set<String> = [] // ids of my messages given to a phone, radio or the relays
    /// A check-in waiting for its GPS fix (up to 10 s): the buttons show "Sending…" and stay disabled meanwhile.
    @Published private(set) var checkInSending: CheckIn?
    @Published private(set) var bluetooth = CBManagerState.unknown  // this phone's Bluetooth: off, not allowed…
    @Published private(set) var localNetworkDenied = false          // Local Network refused: no Wi-Fi links
    @Published private(set) var networkStarted = false              // the Wi-Fi links started (after the Bluetooth question)
    @Published private(set) var torSlow = false                     // "Connect through Tor" found no way out for 2 minutes
    private var torWaitingSince: Date?
    /// Marks this phone's own messages on this phone only (`Message.sender`); never sent: packets carry member ids.
    let deviceId: String
    /// The node id other phones see when they link (spec/FORMAT.md, "Link ids"): random, new at every app start,
    /// unrelated to member ids, so a phone seen over the air can't be matched to a person or followed across restarts.
    let linkId: String = {
        var b = [UInt8](repeating: 0, count: 6)
        _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        return b.map { String(format: "%02x", $0) }.joined()
    }()
    let startedAt = Int64(Date().timeIntervalSince1970 * 1000)

    /// What a group's code opens (spec/DESIGN-v0.6-groups.md, "Keys"): introductions, new keys, and messages from phones not in yet.
    final class Door: @unchecked Sendable {
        let code: String, crypto: GroupCrypto, receipts: GroupCrypto, intros: GroupCrypto, rekeys: GroupCrypto, id: String
        init(_ code: String) {
            self.code = code; crypto = GroupCrypto(code: code); receipts = crypto.receipts(); intros = crypto.intros(); rekeys = crypto.rekeys()
            id = crypto.groupId()
        }
    }

    /// A saved group's keys (spec/FORMAT.md, "Encryption", "Delivery receipts", "Introductions"), this phone's member
    /// key there (Keychain), and the members' public keys this phone knows (`known`, guarded by `lock`).
    final class Keys: @unchecked Sendable {
        private var doors: (now: Door, old: [Door]) // lock
        private var state: (removedAt: (number: Int64, rank: Int)?, removedBy: String?, closed: Bool, rejoiningSince: Int64, leftOut: LeftOut?) = (nil, nil, false, 0, nil) // lock
        /// The door in use. It changes when someone is removed; the old ones stay a week, for removals that crossed.
        var door: Door { lock.withLock { doors.now } }
        var oldDoors: [Door] { lock.withLock { doors.old } }
        func setDoors(_ now: Door, old: [Door]) { lock.withLock { doors = (now, old) } }
        var code: String { door.code }
        var intros: GroupCrypto { door.intros }
        var rekeys: GroupCrypto { door.rekeys }
        /// This phone was removed from the group: that removal's epoch number and its maker's rank, and `removedBy` its maker.
        var removedAt: (number: Int64, rank: Int)? { get { lock.withLock { state.removedAt } } set { lock.withLock { state.removedAt = newValue } } }
        var removedBy: String? { get { lock.withLock { state.removedBy } } set { lock.withLock { state.removedBy = newValue } } }
        /// A new key that lists this phone but gave it no part it can open (`Keyring.Taken.leftOut`): its number and rank, and
        /// how many keys this phone has made to get back in.
        typealias LeftOut = (number: Int64, rank: Int, tries: Int)
        var leftOut: LeftOut? { get { lock.withLock { state.leftOut } } set { lock.withLock { state.leftOut = newValue } } }
        var removed: Bool { removedAt != nil }
        /// This phone had been away past the weekly key and asked to come back (its new key is the request): since when, or 0.
        var rejoiningSince: Int64 { get { lock.withLock { state.rejoiningSince } } set { lock.withLock { state.rejoiningSince = newValue } } }
        var rejoining: Bool { rejoiningSince > 0 }
        /// How long after the week is up this phone makes the new key.
        let weeklyDelay = Int64.random(in: 0..<Keyring.maxDelayMs)
        /// Still joining or rejoining, and a removal came through this door: this invite no longer works.
        var closed: Bool { get { lock.withLock { state.closed } } set { lock.withLock { state.closed = newValue } } }
        /// Never changes for the group, even when its code does: member keys hang off it.
        let id: String
        /// The group's random epoch secrets. Empty while this phone is joining.
        let ring = Keyring()
        var joined: Bool { ring.currentOrNil != nil }
        /// Written with: the current epoch's keys, or the door's while joining.
        var group: GroupCrypto { ring.currentOrNil?.group ?? door.crypto }
        var receipts: GroupCrypto { ring.currentOrNil?.receipts ?? door.receipts }
        var members: [String] { ring.currentOrNil?.members ?? [] }
        let key: MemberKeys.SigningKey, pub: Data, me: String
        /// The HPKE keys other members seal new epoch secrets to: a new one every week.
        let encs: EncKeys
        var encPub: Data { encs.currentPub }
        var isPublic: Bool { code == GroupCrypto.publicCode }
        let lock = NSLock(), moveLock = NSLock()
        var known: [String: Known] = [:] // member id -> their keys and name
        let mine: MemberKey.Checker
        init(code: String) {
            let d = Door(code)
            doors = (d, [])
            id = Vault.get("origin.\(d.id)").flatMap { String(data: $0, encoding: .utf8) } ?? d.id
            key = MemberKeys.forGroup(id); pub = key.publicKey.compressedRepresentation; me = MemberKey.id(pub)
            encs = EncKeys(id)
            mine = MemberKey.Checker(pub)!
            #if DEBUG
            DebugLog.write("member keys: signing \(key.inChip ? "in the Secure Enclave" : "in the Keychain"), encryption \(encs.inChip ? "in the Secure Enclave" : "in the Keychain")")
            #endif
        }
        func sign(_ msg: Data) throws -> Data { try key.sign(msg) }
        func checker(_ id: String) -> MemberKey.Checker? { id == me ? mine : lock.withLock { known[id]?.checker } }
    }

    /// A member's public keys, from their introduction.
    /// Group id -> what was written before an admin let this phone in. Main thread.
    private var waitingToJoin: [String: [(text: String, photo: Data?)]] = [:]

    struct Known { let checker: MemberKey.Checker; let enc: Data?; let name: String; var encAt: Int64 = 0; var pq: Data? = nil; var seen: Int64 = 0 } // seen: when it last changed here

    /// A packet opened with one of `Keys`: not shown before its signature is checked (spec "Signatures").
    private enum Seen {
        case msg(Message, Keys, GroupCrypto.Opened, Bool) // the last: from this phone's copy
        case receipt(Message, Keys, GroupCrypto.Opened)
        case intro(Keys, String, MemberKey.Checker, Data, String, Int64, Data?) // keys, member id, its key, encryption key, name, when, ML-KEM key
        case newKey(Keys, GroupCrypto.Opened, Rekey, String, Door) // keys, opened packet, rekey, packet id, the door it came through
        case forged                                       // an introduction that doesn't hold up
    }

    /// A message or receipt from a member whose public key isn't known yet; checked when the introduction comes.
    private struct Pending { let k: Keys; let o: GroupCrypto.Opened; let receipt: Message? }
    /// What waits for a key, each group and the Public channel apart (`KeyWait`). Main thread.
    private var unchecked = KeyWait<ObjectIdentifier, Pending>()
    private static let maxKnown = 500, introEvery: Int64 = 3 * 24 * 3_600_000
    private let keyLock = NSLock()
    private let knownLock = NSLock()
    private var knownDirty: [String: Keys] = [:] // group id -> keys whose saved key list is behind memory; knownLock
    private var knownUnread: Set<String> = [] // group ids whose key-list file is there but couldn't be read (phone not unlocked yet): never written over; knownLock
    private let rescanLock = NSLock(), rescanFlag = Flag() // new keys arriving together: one reading of the store
    private final class Flag { var on = false }
    private var keyCache: [String: Keys] = [:] // code -> keys: each derivation takes 32 MiB of scrypt, so only once
    private let cryptoLock = NSLock()          // guards the three below: read from the router's thread
    private var _active: Keys?                 // the group on screen
    private var _others: [Keys] = []           // the other saved groups: read, alerted and confirmed too
    private var _public: Keys?                 // the Public channel's
    private var keySet: (active: Keys?, others: [Keys], pub: Keys?) { cryptoLock.withLock { (_active, _others, _public) } }
    private var activeCode: String             // main thread: the group on screen, even while its keys are derived

    private let idsLock = NSLock()
    private var mine = Set<String>()       // ids of messages written on this phone; guarded by idsLock
    private var myReceipts = Set<String>() // ids of receipts written on this phone (they go up to the relays first); idsLock
    private var sentIds: RecentIds         // my messages already handed off, saved on the phone; idsLock
    private var receiptIds = RecentIds(max: 20_000) // receipt packets this phone can open, kept off LoRa; guarded by idsLock
    private var shownAs: [String: String] = [:] // what was signed (`GroupCrypto.Opened.mark`) -> the row that shows it; idsLock

    private let storeLock = NSLock()
    private var index: [String: StoreCap.Entry] = [:] // every stored packet, for the store cap; guarded by storeLock
    private var indexBytes = 0                        // storeLock
    private var doorCount = 0, doorBytes = 0          // what the index holds of `StoreCap.Kind.door`; storeLock
    private var joinAlertAt: [String: Int64] = [:]    // group id -> when this phone last alerted "asks to join" there; storeLock
    private var allKeys = false                       // every saved group's key was tried on the whole store; storeLock
    private var compacting = false                    // storeLock
    private var raisedTtl: [String: Int] = [:]        // stored packets whose ttl a later copy raised (MeshRouter.key → ttl), until written; storeLock
    private let work = DispatchQueue(label: "engine", qos: .userInitiated) // loading, keys and compaction, in order

    private var raw: [Message] = []          // main thread: every readable message, before moderation
    private var rawIds = Set<String>()       // main thread
    private var pendingAcks: [(id: String, key: Keys)] = [] // main thread: messages to confirm, with their group's keys
    private var firstAck: Int64 = 0, lastAck: Int64 = 0            // main thread

    private let store = PacketStore()
    /// Packets that arrived under an id another packet had already taken: each goes by its key (`StoreCap.name`).
    private let more = PacketStore(file: "more.bin", naming: .key)
    private let history = PacketStore(file: "history.bin")
    private(set) var router: MeshRouter!
    private var ble: BleLink!
    private var mc: MultipeerLink!
    private(set) var lora: LoraLink!
    private(set) var meshcore: MeshCoreLink!
    private(set) var wifi: WifiLink!
    private(set) var nostr: NostrLink!
    /// Packets a relay brought first: they never go back up, after a restart either (spec "Publish"). Saved by the relay links.
    private let fromRelays = FromRelays(UserDefaults.standard.string(forKey: FromRelays.pref) ?? "")

    /// Starts the transports at once; keys and stored messages are read in the background (no scrypt key
    /// derivation or store reading on the main thread), then published.
    init(name: String, code: String, askInOrder: Bool = false) {
        let d = UserDefaults.standard
        let upgrade = d.string(forKey: "device") != nil // this phone ran GoDark before (a device id exists from then)
        if let id = d.string(forKey: "device") { deviceId = id } else {
            deviceId = String(UUID().uuidString.lowercased().prefix(12)) // same shape as Android ids, e.g. 7c0d995b-2c4
            d.set(deviceId, forKey: "device")
        }
        self.name = name
        activeCode = code
        if !d.bool(forKey: "v06") { // groups saved before v0.6 count as founded here (spec "Making the first epoch")
            let saved = upgrade ? Set(SavedGroups.all().map(\.code) + (GroupSecrets.shared.current.map { [$0] } ?? [])) : []
            GroupSecrets.shared.setFound(Array(Set(GroupSecrets.shared.found).union(saved)))
            d.set(true, forKey: "v06")
            for key in d.dictionaryRepresentation().keys where key.hasPrefix("introAt.") { d.removeObject(forKey: key) } // introductions now carry the encryption key
        }
        sentIds = RecentIds(max: Self.handedOffMax, d.stringArray(forKey: "handedOff") ?? [])
        handedOff = Set(sentIds.list)
        router = MeshRouter(send: { [weak self] peer, p in self?.route(peer, p) },
                            deliver: { [weak self] p in self?.onDeliver(p) },
                            minCipher: MeshRouter.minSealed, maxPerMinute: MeshRouter.linkPerMinute, unlimited: { $0 == NostrLink.peer },
                            raised: { [weak self] p in self?.onRaised(p) })
        mc = MultipeerLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("1-mc", s) }
        ble = BleLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("2-ble", s) }
        lora = LoraLink(router: router) { [weak self] s in self?.setStatus("3-lora", s) }
        meshcore = MeshCoreLink(router: router) { [weak self] s in self?.setStatus("3b-meshcore", s) }
        wifi = WifiLink(nodeId: linkId, router: router) { [weak self] s in self?.setStatus("4-wifi", s) }
        nostr = NostrLink(router: router, viaTor: TorSetting.isOn(d), scopes: { [weak self] in self?.relayScopes() ?? [] },
                          packetKey: { [weak self] id in self?.packetKey(id) }, fromRelays: fromRelays,
                          onRelays: { [weak self] id in self?.markHandedOff(id) }) { [weak self] s in
            self?.setStatus("5-internet", s)
        }
        nostr.setSaver(Self.saver)
        if d.object(forKey: "internet") as? Bool ?? true { nostr.start() }
        #if DEBUG
        DebugLog.start()
        GroupSecrets.shared.noteForTests()
        BleLink.restoredHook = { DebugLog.write("bluetooth " + $0) }
        #endif
        ble.start()
        lora.start()
        meshcore.start()
        if askInOrder && CBManager.authorization == .notDetermined {
            afterBluetoothAnswer(tries: 240) { [weak self] in self?.startNetwork() }
        } else {
            startNetwork()
        }
        work.async { self.startUp(code) }
    }

    /// Apple peer-to-peer and Wi-Fi networks: both make iOS ask for Local Network.
    private func startNetwork() {
        mc.start()
        if wifiWanted { wifi.start() }
        networkStarted = true
    }

    /// Waits (at most `tries` × 0.5 s) until the user has answered the Bluetooth question. Main thread.
    private func afterBluetoothAnswer(tries: Int, _ then: @escaping () -> Void) {
        if CBManager.authorization != .notDetermined || tries <= 0 { return then() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.afterBluetoothAnswer(tries: tries - 1, then) }
    }

    /// "Battery saver" (Connections): no Wi-Fi network links and fewer relay requests. Bluetooth keeps running.
    static var saver: Bool { UserDefaults.standard.bool(forKey: "saver") }
    private var wifiWanted: Bool { (UserDefaults.standard.object(forKey: "wifiNetwork") as? Bool ?? true) && !Self.saver }

    func setSaver(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "saver")
        if wifiWanted { wifi.start() } else { wifi.stop() }
        nostr.setSaver(on)
    }

    var statusLines: [String] { status.keys.sorted().compactMap { status[$0] } }

    /// Turns linking over Wi-Fi networks on or off (Connections screen), and remembers it.
    func setWifi(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "wifiNetwork")
        if wifiWanted { wifi.start() } else { wifi.stop() }
    }

    /// Turns the internet relays on or off (Connections screen), and remembers it.
    func setInternet(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "internet")
        if on { nostr.start() } else { nostr.stop() }
    }

    /// Turns "Connect through Tor" on or off (Connections screen), and remembers it.
    func setTor(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: "tor")
        nostr.setTor(on)
        OfflineMap.shared.applyNetwork()
    }

    /// The very packet a message is shown from (`MeshRouter.key`), or nil: what a report of that message is about.
    /// `id` is the name the packet goes by in the store (`StoreCap.name`): the packet stored first under an id goes by
    /// that id, any other by its key. Reads the whole store (once per reported message); any thread.
    private func packetKey(_ id: String) -> String? {
        if id.count > 16 { return id }
        var key: String?
        store.forEachNamed { p, name in if name == id { key = MeshRouter.key(p) } }
        return key
    }

    /// This phone's relay mailboxes (spec/FORMAT.md, "Mailboxes"): its group's, the other saved groups', the Public
    /// channel's last. Any thread.
    private func relayScopes() -> [NostrLink.Scope] {
        let set = keySet
        let groups: [NostrLink.Scope] = ([set.active].compactMap { $0 } + set.others).filter { !$0.isPublic }.map { k in
            var boxes: [UInt16] = []
            for m in k.ring.all.map(\.group.mailbox) + ([k.door] + k.oldDoors).map(\.crypto.mailbox) where !boxes.contains(m) { boxes.append(m) }
            return NostrLink.Scope(id: k.id, mailboxes: boxes)
        }
        return groups + [NostrLink.Scope(id: "", mailboxes: [Nostr.publicMailbox])]
    }

    /// The cached keys of `code`, derived the first time (32 MiB of scrypt). Any thread; never holds a lock while
    /// deriving, so the main thread never waits for another group's key. A code its group has moved on from (an old
    /// invite, an alert from before a removal) gives the keys that group has under its new code, if it is saved here: a
    /// second holder would put the old door on the group's current keyring and save over it.
    private func keys(_ code: String, follow: Bool = true) -> Keys {
        if let k = keyLock.withLock({ keyCache[code] }) { return k }
        let k = Keys(code: code)
        if follow, let now = movedTo(k) { return keys(now, follow: false) }
        loadKnown(k)
        loadRing(k)
        return keyLock.withLock { if let other = keyCache[code] { return other }; keyCache[code] = k; return k }
    }

    /// The code `k`'s group has now, if `k` was made from another one and the group is saved on this phone under it (`moveDoor` notes it).
    private func movedTo(_ k: Keys) -> String? {
        guard let now = Vault.get("door.\(k.id)").flatMap({ String(data: $0, encoding: .utf8) }), now != k.code,
              SavedGroups.all().contains(where: { $0.code == now }) else { return nil }
        return now
    }

    // MARK: - Member keys (spec/FORMAT.md, "Signatures", "Introductions")

    /// The public keys saved for `k`'s group: member id -> ["s": seen ms, "p": signing key hex, "e": encryption key hex, "a": when it was introduced, "q": ML-KEM key hex, "n": name].
    /// The list is kept in a file left out of backups ("known.<group id>.plist"): UserDefaults goes into them, and the
    /// list holds names. A list an earlier version kept in UserDefaults is read from there and moved at the next save.
    private func loadKnown(_ k: Keys) {
        let url = Self.knownURL(k.id), d = UserDefaults.standard
        let file = (try? Data(contentsOf: url)).flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) } as? [String: [String: String]]
        if file == nil && FileManager.default.fileExists(atPath: url.path) { knownLock.withLock { _ = knownUnread.insert(k.id) } }
        if file != nil { d.removeObject(forKey: "known.\(k.id)") } // moved already
        let old = file == nil ? d.dictionary(forKey: "known.\(k.id)") as? [String: [String: String]] : nil
        let saved = file ?? old ?? [:]
        var out: [String: Known] = [:]
        for (id, v) in saved {
            guard let p = v["p"], let c = MemberKey.Checker(Self.unhex(p)) else { continue }
            out[id] = Known(checker: c, enc: v["e"].map(Self.unhex), name: v["n"] ?? "", encAt: Int64(v["a"] ?? "") ?? 0, pq: v["q"].map(Self.unhex), seen: Int64(v["s"] ?? "") ?? 0)
        }
        k.lock.withLock { k.known = out }
        if old != nil { saveKnownSoon(k) } // into the file, out of UserDefaults
    }

    private static func knownURL(_ id: String) -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("known.\(id).plist")
    }

    /// A member's public keys from a checked introduction: kept (the 500 most recently changed per group stay), and saved
    /// soon after. True if new. Someone who isn't in the group and isn't known here yet is kept only while there is room
    /// among those asking to join (`Joining`).
    @discardableResult private func learn(_ k: Keys, _ id: String, _ c: MemberKey.Checker, enc: Data? = nil, encAt: Int64 = 0, pq: Data? = nil, name who: String = "") -> Bool {
        if !k.isPublic, id != k.me, k.lock.withLock({ k.known[id] == nil }), !Joining.keeps(id, asking: asking(k), listed: k.ring.everyone(), me: k.me) { return false }
        let members = Set(k.members)
        let (fresh, changed): (Bool, Bool) = k.lock.withLock {
            let had = k.known[id]
            let newer = enc != nil && EncSchedule.isNewer(known: had?.encAt ?? 0, ts: encAt)
            let name = who.isEmpty ? had?.name ?? "" : who
            let changed = had == nil || newer || had?.checker.pub != c.pub || had?.name != name
            k.known[id] = Known(checker: c, enc: newer ? enc : had?.enc, name: name, encAt: newer ? encAt : had?.encAt ?? 0, pq: newer ? pq : had?.pq,
                                seen: changed ? Self.nowMs() : had?.seen ?? 0)
            if k.known.count > Self.maxKnown {
                // The least recently changed go, but never someone in the group, or new keys for them couldn't be sealed.
                let old = k.known.filter { !members.contains($0.key) && $0.key != id }.sorted { $0.value.seen < $1.value.seen }
                for (gone, _) in old.prefix(k.known.count - Self.maxKnown) { k.known[gone] = nil } // a flood of made-up members can't fill the memory
            }
            return (had == nil, changed)
        }
        // An introduction that brings nothing new (one read again from the store, or played back) writes nothing.
        if changed { saveKnownSoon(k) }
        return fresh
    }

    /// Saves `k`'s key list 2 s from now, with whatever else changes until then: the whole list is written once, not once
    /// for every introduction that arrives. What isn't saved when the app ends is learned again from the stored packets.
    private func saveKnownSoon(_ k: Keys) {
        let first = knownLock.withLock { () -> Bool in let was = knownDirty.isEmpty; knownDirty[k.id] = k; return was }
        guard first else { return }
        work.asyncAfter(deadline: .now() + 2) { self.saveKnown() }
    }

    /// Writes the key lists that changed: member id -> ["s": when it last changed here, ms, "p": signing key hex, "e":
    /// encryption key hex, "a": when it was introduced, "q": ML-KEM key hex, "n": name]. On `work`.
    private func saveKnown() {
        let all = knownLock.withLock { () -> [Keys] in let a = Array(knownDirty.values); knownDirty = [:]; return a }
        for k in all {
            var saved: [String: [String: String]] = [:]
            for (id, w) in k.lock.withLock({ k.known }) {
                var v = ["s": String(w.seen), "p": Self.hex(w.checker.pub)]
                if let e = w.enc { v["e"] = Self.hex(e); v["a"] = String(w.encAt); v["q"] = w.pq.map(Self.hex) }
                if !w.name.isEmpty { v["n"] = w.name }
                saved[id] = v
            }
            guard !knownLock.withLock({ knownUnread.contains(k.id) }) else { continue } // the file there would be lost
            let url = Self.knownURL(k.id)
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            guard let data = try? PropertyListSerialization.data(fromPropertyList: saved, format: .binary, options: 0),
                  (try? data.write(to: url, options: .atomic)) != nil else { continue } // UserDefaults keeps it meanwhile
            var u = url, v = URLResourceValues(); v.isExcludedFromBackup = true; try? u.setResourceValues(v)
            UserDefaults.standard.removeObject(forKey: "known.\(k.id)")
        }
    }

    /// `k`'s epoch secrets from the Keychain. A group this phone founded (created here, or saved before v0.6) and that
    /// has none gets epoch 1 now, with this phone as its only member and admin (spec "Making the first epoch").
    private func loadRing(_ k: Keys) {
        guard !k.isPublic else { return }
        if let raw = Vault.get("epochs.\(k.id)"), let list = try? JSONSerialization.jsonObject(with: raw) as? [[String: Any]] {
            for o in list {
                guard let n = (o["n"] as? NSNumber)?.int64Value, let made = (o["made"] as? NSNumber)?.int64Value, let s = o["s"] as? String else { continue }
                func text(_ n: String) -> String? { (o[n] as? String).flatMap { $0.isEmpty ? nil : $0 } }
                k.ring.add(.init(number: n, made: made, secret: Self.unhex(s), members: o["m"] as? [String] ?? [], admins: o["a"] as? [String] ?? [],
                                 code: text("c"), via: text("v"), removes: text("r"), by: text("b"), rank: (o["k"] as? NSNumber)?.intValue ?? .max,
                                 taken: (o["t"] as? NSNumber)?.int64Value)) // saved before "t": its date
            }
        }
        if let raw = Vault.get("mkeys.\(k.id)") {
            let b = [UInt8](raw); var i = 0
            while i + 68 <= b.count {
                let hash = String(decoding: b[i..<(i + 64)], as: UTF8.self), n = b[(i + 64)..<(i + 68)].reduce(0) { $0 << 8 | Int($1) }
                i += 68
                guard i + n <= b.count else { break }
                // By the epoch's id: two epochs can share a secret. By its hash for keys saved before epochs had an id.
                let all = k.ring.all
                if let e = all.first(where: { $0.id == hash }) ?? all.first(where: { $0.hash == hash }) { e.messageKeys = MessageKeys.decode(Data(b[i..<(i + n)])) }
                i += n
            }
        }
        // The parts it opened, only together with the epochs they brought: without those, the stored new keys are read again.
        if k.joined, let raw = Vault.get("parts.\(k.id)") { k.ring.restoreParts(String(decoding: raw, as: UTF8.self).split(separator: ",").map(String.init)) }
        var via: [String] = []
        for c in k.ring.all.compactMap(\.via) where c != k.code && !via.contains(c) { via.append(c) }
        k.setDoors(k.door, old: via.map(Door.init))
        if k.ring.lastMove?.code == k.code, Vault.get("door.\(k.id)") == nil { Vault.put("door.\(k.id)", Data(k.code.utf8)) } // moved before this was noted
        let d = UserDefaults.standard
        k.rejoiningSince = Int64(d.double(forKey: "rejoining.\(k.id)"))
        if let p = d.string(forKey: "removedAt.\(k.id)")?.split(separator: ":"), p.count >= 2, let n = Int64(p[0]), let r = Int(p[1]) {
            k.removedAt = (n, r); k.removedBy = p.count > 2 ? String(p[2]) : nil
        }
        if d.bool(forKey: "closed.\(k.id)") { k.closed = true; k.ring.closed = true }
        var found = Set(GroupSecrets.shared.found)
        if !k.joined && found.contains(k.code) {
            var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
            k.ring.add(.fresh(number: 1, made: Self.nowMs(), secret: Data(b), members: [k.me], admins: [k.me]))
            saveRing(k)
            found.remove(k.code); GroupSecrets.shared.setFound(Array(found))
            #if DEBUG
            DebugLog.write("epoch 1 made for a group founded here")
            #endif
        }
    }

    private func saveRing(_ k: Keys) {
        saveMessageKeys(k)
        let hex: (Data) -> String = { $0.map { String(format: "%02x", $0) }.joined() }
        let list: [[String: Any]] = k.ring.all.map { ["n": $0.number, "made": $0.made, "s": hex($0.secret), "m": $0.members, "a": $0.admins,
                                                  "c": $0.code ?? "", "v": $0.via ?? "", "r": $0.removes ?? "", "b": $0.by ?? "", "k": $0.rank, "t": $0.taken] }
        Vault.put("epochs.\(k.id)", try? JSONSerialization.data(withJSONObject: list))
        saveParts(k)
    }

    /// The sealed parts `k`'s keyring has opened (`Keyring.openedParts`): saved after the epochs they brought, never before.
    private func saveParts(_ k: Keys) {
        _ = k.ring.partsToSave()
        Vault.put("parts.\(k.id)", Data(k.ring.openedParts.joined(separator: ",").utf8))
    }

    /// Marks `code` as founded on this phone (a new group): its first epoch is made here.
    static func found(_ code: String) {
        let d = UserDefaults.standard
        GroupSecrets.shared.setFound(Array(Set(GroupSecrets.shared.found).union([code])))
    }

    /// True while this phone has the code of `code`'s group but no epoch yet: it is asking to join.
    func joining(_ code: String?) -> Bool {
        guard let code, let k = keyLock.withLock({ keyCache[code] }) else { return false }
        return !k.isPublic && !k.joined
    }

    private func held(_ code: String?) -> Keys? { guard let code else { return nil }; return keyLock.withLock { keyCache[code] } }
    private func memberId(_ k: Keys, _ id: String) -> String { id == deviceId ? k.me : id.hasPrefix("web-") ? String(id.dropFirst(4)) : id }

    /// True if this phone was removed from `code`'s group.
    func removed(_ code: String?) -> Bool { held(code)?.removed ?? false }
    /// True if `code` is an invite this phone is trying to join with and the group has moved on from it.
    func inviteClosed(_ code: String?) -> Bool { held(code).map { $0.closed && (!$0.joined || $0.rejoining) } ?? false }
    /// True while this phone, back after more than a week, waits for someone in `code`'s group to answer.
    func rejoining(_ code: String?) -> Bool { held(code)?.rejoining ?? false }

    /// Makes the weekly new key of every saved group that is due. On `work`.
    func weeklyCheck() { let s = keySet; for k in [s.active].compactMap({ $0 }) + s.others { rekeyIfDue(k); finishRemovals(k); answerLeftOut(k) } }

    private func hourly() {
        work.asyncAfter(deadline: .now() + .seconds(Int(Keyring.hourMs / 1000))) { [weak self] in
            guard let self else { return }
            self.weeklyCheck(); self.compact(); self.hourly()
        }
    }

    /// A new key when the current one is a week old (spec "Keys"), after this phone's random delay so that the group's
    /// phones don't all do it at once; the first to do it settles it for the rest. Well past that delay this phone has
    /// missed the group's new keys, or the whole group was quiet: its new key is then also how it asks to come back.
    private func rekeyIfDue(_ k: Keys) {
        // Counted from when this phone got the key, if that was after its date: a member's key dated long ago isn't due at once.
        guard let cur = k.ring.currentOrNil, !k.isPublic, !k.removed, Keyring.weeklyDue(made: cur.since, now: Self.clock(), delay: k.weeklyDelay) else { return }
        let away = Keyring.overdue(made: cur.since, now: Self.clock())
        if makeRekey(k, add: [], answers: nil) && away { setRejoining(k, Self.nowMs()) }
    }

    /// The time, for deciding when a key is due; tests can move it forward.
    private static func clock() -> Int64 {
        #if DEBUG
        return nowMs() + ahead
        #else
        return nowMs()
        #endif
    }
    #if DEBUG
    /// Moves the clock that decides when a key is due: launch argument `ahead 8` (days).
    static var ahead: Int64 = 0
    #endif

    private func setRejoining(_ k: Keys, _ since: Int64) {
        guard k.rejoiningSince != since else { return }
        k.rejoiningSince = since
        UserDefaults.standard.set(Double(since), forKey: "rejoining.\(k.id)")
        DispatchQueue.main.async { self.refresh() }
    }

    /// The rekey really is from who it says: its key matches the sender's id, and it signed the packet.
    private func signed(_ o: GroupCrypto.Opened, _ r: Rekey) -> Bool {
        guard MemberKey.id(r.maker) == o.message.sender, let c = MemberKey.Checker(r.maker) else { return false }
        return c.verify(digest: o.digest, signature: o.signature)
    }

    /// A member's phone missed our keys: a new epoch, sealed to everyone, brings it back (spec "Away for a while"). Not if
    /// another member answered first, or this phone made a key in the last hour (a flood of these must not cost more than that).
    /// `at`: this phone's current epoch when that member's key came. Another one since then is the answer, whatever date
    /// the key carried: its maker writes the date, and one a few minutes ahead would have every phone answer.
    private func answerBehind(_ k: Keys, made: Int64, at: Keyring.Epoch?) {
        guard let cur = k.ring.currentOrNil, !k.removed, cur === at, cur.made < made, !k.ring.tooSoon(k.me, made: Self.clock()) else { return }
        makeRekey(k, add: [], answers: nil)
    }

    /// A new key listed this phone but its part didn't open (`Keyring.Taken.leftOut`): the others may have moved on to it,
    /// and can't tell. Like a phone that was away, this one makes a key of its own, sealed to everyone, and shows that it is
    /// rejoining. That key has the same number as the one it couldn't open if that was the next one, so it can lose to it:
    /// an hour later this phone makes one more, numbered above both. Not once a key that settles it got here: a
    /// higher-numbered one, or one of the same number that comes before the one it couldn't open whatever the hashes.
    private func answerLeftOut(_ k: Keys) {
        guard let t = k.leftOut, let cur = k.ring.currentOrNil else { return }
        if k.removed || cur.number > t.number || (cur.number == t.number && (cur.code != nil || cur.rank < t.rank)) { k.leftOut = nil; return }
        if k.ring.tooSoon(k.me, made: Self.clock()) { return } // the hourly check tries again
        guard makeRekey(k, add: [], answers: nil) else { return }
        setRejoining(k, Self.nowMs())
        k.leftOut = t.tries == 0 ? (t.number, t.rank, 1) : nil
    }
    /// The admins an invite to `code`'s group names (spec "Invites"), first listed first, or nil until its keys are loaded.
    func invitePins(_ code: String) -> String? {
        guard let k = held(code) else { return nil }
        let pubs = (k.ring.currentOrNil?.admins ?? []).compactMap { $0 == k.me ? k.pub : k.checker($0)?.pub }
        return pubs.prefix(Invite.maxPins).map(Invite.pin).joined()
    }

    func isAdmin(_ code: String?, _ id: String) -> Bool { held(code).map { $0.ring.currentOrNil?.admins.contains(memberId($0, id)) ?? false } ?? false }
    func inGroup(_ code: String?, _ id: String) -> Bool { held(code).map { $0.members.contains(memberId($0, id)) } ?? false }

    /// Gives `id` the admin role, with a new key. `done` says on the main thread if it worked.
    func makeAdmin(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        adminChange(code, id, done) { k, m, cur in !cur.admins.contains(m) && self.makeRekey(k, add: [], answers: nil, admins: cur.admins + [m]) }
    }

    /// Removes `id`: a new key and a new code for everyone else (spec "Removing and the code").
    func remove(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        adminChange(code, id, done) { k, m, _ in m != k.me && self.makeRekey(k, add: [], answers: nil, remove: m) }
    }

    private func adminChange(_ code: String?, _ id: String, _ done: @escaping (Bool) -> Void, _ act: @escaping (Keys, String, Keyring.Epoch) -> Bool) {
        work.async {
            var ok = false
            if let k = self.held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me) {
                let m = self.memberId(k, id)
                ok = cur.members.contains(m) && act(k, m, cur)
            }
            DispatchQueue.main.async { done(ok); self.refresh() }
        }
    }

    /// What happened in `code`'s group, by name and when: "Marco joined", "Anna removed Marco", "Anna made Ben an admin".
    func groupLines(_ code: String?) -> [GroupEvent] {
        guard let k = held(code) else { return [] }
        let eps = k.ring.all.filter { k.ring.won($0) }.sorted { $0.number < $1.number }
        guard eps.count > 1 else { return [] }
        func name(_ id: String?) -> String { let n = id.flatMap { i in k.lock.withLock { k.known[i]?.name } } ?? ""; return n.isEmpty ? "Someone" : n }
        func subject(_ id: String?) -> String { id == k.me ? "You" : name(id) }
        func object(_ id: String?) -> String { id == k.me ? "you" : name(id) }
        var out: [GroupEvent] = []
        for (a, b) in zip(eps, eps.dropFirst()) {
            for id in b.members where !a.members.contains(id) && id != k.me { out.append(GroupEvent(ts: b.made, text: "\(name(id)) joined")) }
            for id in b.admins where !a.admins.contains(id) { out.append(GroupEvent(ts: b.made, text: "\(subject(b.by)) made \(object(id)) an admin")) }
            if let id = b.removes { out.append(GroupEvent(ts: b.made, text: "\(subject(b.by)) removed \(object(id))")) }
        }
        return out
    }

    /// A new epoch from a rekey (spec "New key"): signed by its maker, allowed by `Keyring.admit`, with a part this
    /// phone can open. A removal also moves the group to its new code. True if it was new.
    private func acceptRekey(_ k: Keys, _ o: GroupCrypto.Opened, _ r: Rekey, _ packetId: String, _ door: Door) -> Bool {
        let maker = o.message.sender
        guard signed(o, r) else { return false }
        let pins = GroupSecrets.shared.pins(k.code)
        let pinned = Invite.allows(pins, maker: r.maker) // only read while this phone has no epoch
        #if DEBUG
        if !pinned && !k.joined { DebugLog.write("new key from someone this invite doesn't name: ignored") }
        #endif
        // The group may have moved on while this phone was away. Only on an admin's word: anyone who has the code can sign a removal.
        if r.removal && k.rejoining && maker != k.me && door === k.door && k.ring.movedOn(r, maker: maker) { k.closed = true }
        defer { if k.ring.partsToSave() { saveParts(k) } } // a part opened for an epoch this phone holds already: not opened again either
        switch k.ring.take(r, maker: maker, me: k.me, door: door.code, oldDoor: door !== k.door, removedAt: k.removedAt, pinned: pinned, removedBy: k.removedBy, named: Invite.names(pins, maker: r.maker), inUse: otherCodes(k), open: { k.encs.open($0, info: Rekey.info(door.id), aad: Rekey.aad(packetId, k.me)) }) {
        case .ignored:
            return false
        case .leftOut(let number, let rank):
            // The others may have taken this key and be writing with it; this phone can't. It asks its way back with a key of its own.
            #if DEBUG
            DebugLog.write("epoch \(number) lists this phone, but its part doesn't open")
            #endif
            if (k.leftOut?.number ?? 0) < number { k.leftOut = (number, rank, 0) } // read again from the store: the count stays
            work.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0..<3_000))) { self.answerLeftOut(k) }
            return false
        case .closed:
            k.closed = true
            UserDefaults.standard.set(true, forKey: "closed.\(k.id)") // saved: the keyring takes no key through this code from now on
            DispatchQueue.main.async { self.refresh() }
            return false
        case .removed(let number, let rank, let by):
            k.removedAt = (number, rank); k.removedBy = by
            UserDefaults.standard.set("\(number):\(rank):\(by)", forKey: "removedAt.\(k.id)")
            #if DEBUG
            DebugLog.write("removed from a group")
            #endif
            DispatchQueue.main.async { self.refresh() }
            return false
        case .added(let e, let moveTo, let back):
            if back { k.removedAt = nil; k.removedBy = nil; UserDefaults.standard.removeObject(forKey: "removedAt.\(k.id)") }
            if moveTo != nil { moveDoor(k) }
            saveRing(k)
            if k.ring.current === e && maker != k.me { setRejoining(k, 0) }
            DispatchQueue.main.async { if let held = self.waitingToJoin.removeValue(forKey: k.id) { for w in held { self.send(w.text, photo: w.photo, group: k.code) } } }
            #if DEBUG
            DebugLog.write("epoch \(r.epoch): \(r.members.count) member(s)\(r.removal ? ", after a removal" : "")")
            #endif
            return true
        }
    }

    /// The codes of the other groups on this phone, saved or held: a removal can't move `k`'s group onto one of them.
    private func otherCodes(_ k: Keys) -> [String] {
        let held = keyLock.withLock { keyCache.filter { $0.value !== k }.map(\.key) }
        return (SavedGroups.all().map(\.code) + [GroupSecrets.shared.code] + held).filter { !$0.isEmpty && $0 != k.code }
    }

    /// Two admins removed different people at once: only one removal won, so the other person is still in the current
    /// epoch. An admin's phone finishes it, after 0-3 s unless another admin did (spec "Two new keys at the same time").
    private func finishRemovals(_ k: Keys) {
        guard !k.removed, k.ring.currentOrNil?.admins.contains(k.me) == true else { return }
        for m in k.ring.stillToRemove() where m != k.me { if !makeRekey(k, add: [], answers: nil, remove: m) { return } }
    }

    /// The group follows the code of its newest removal (`Keyring.lastMove`): same group id, member keys and messages, a
    /// new door and a new invite. Taken from the keyring, so a removal made here and one arriving at the same moment end
    /// up on the same code.
    private func moveDoor(_ k: Keys) {
        k.moveLock.lock(); defer { k.moveLock.unlock() }
        guard let code = k.ring.lastMove?.code else { return }
        let old = k.door
        guard old.code != code else { return }
        let next = Door(code)
        Vault.put("origin.\(next.id)", Data(k.id.utf8))
        k.setDoors(next, old: [old] + k.oldDoors.filter { $0.code != code })
        k.closed = false // that was about the code it left
        keyLock.withLock { keyCache.removeValue(forKey: old.code); keyCache[code] = k }
        Vault.put("door.\(k.id)", Data(code.utf8)) // where the group is now: its old codes lead here (`keys`)
        SavedGroups.replaceCode(old.code, code)
        GroupTag.moved(from: old.code, to: code) // alerts already showing still answer this group
        let d = UserDefaults.standard
        d.removeObject(forKey: "introAt.\(k.id)") // introduce ourselves through the new door
        #if DEBUG
        DebugLog.write("the group moved to a new code")
        #endif
        DispatchQueue.main.async {
            if GroupSecrets.shared.current == old.code { GroupSecrets.shared.setCode(code) } // on the main thread: the screens watch it
            if self.activeCode == old.code { self.activeCode = code }
            Unread.shared.rename(old.code, code)
            for i in self.raw.indices where self.raw[i].group == old.code { self.raw[i].group = code }
            self.refresh()
        }
    }

    private func declined(_ k: Keys) -> Set<String> { Set(UserDefaults.standard.stringArray(forKey: "declined.\(k.id)") ?? []) }

    /// People asking to join `code`'s group, for this phone to answer if it is an admin: they introduced themselves through
    /// the door in the last week and aren't in the group, weren't removed and weren't turned down.
    func joinRequests(_ code: String?) -> [JoinRequest] {
        guard let k = held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me) else { return [] }
        let gone = Set(k.ring.all.compactMap(\.removes)), ids = asking(k).filter { !gone.contains($0) }
        return k.lock.withLock {
            ids.compactMap { id in k.known[id].map { JoinRequest(id: id, name: $0.name.isEmpty ? "Someone" : $0.name, pub: $0.checker.pub) } }
        }.sorted { $0.id < $1.id }
    }

    /// Who is asking to join `k`'s group (`Joining.asking`): they introduced themselves through the door in the last week,
    /// aren't in the group and weren't turned down. At most `Joining.maxAsking`: anyone with the code can make up keys.
    private func asking(_ k: Keys) -> [String] {
        let at = k.lock.withLock { k.known.filter { $0.value.pq != nil }.mapValues(\.encAt) }
        return Joining.asking(at, members: Set(k.members), declined: declined(k), me: k.me, now: Self.nowMs())
    }

    /// The class of a packet `k`'s door opened (`StoreCap.door`): the group's own only if someone in the group wrote it,
    /// or this phone. `signed`: the packet names `by` and their signature checks. The door opens with the code alone, so
    /// anything else gets the small room of people who aren't in (`StoreCap.Kind.door`) and can't push a message out.
    private func doorKind(_ k: Keys, _ by: String, signed: Bool) -> StoreCap.Kind {
        StoreCap.door(mine: signed && by == k.me, member: signed && k.ring.inGroup(by))
    }

    /// An admin lets `id` in: a new epoch for everyone, them included (spec "Joining"). `done` says on the main thread if it worked.
    func approveJoin(_ code: String?, _ id: String, done: @escaping (Bool) -> Void) {
        work.async {
            var ok = false
            if let k = self.held(code), let cur = k.ring.currentOrNil, !k.removed, cur.admins.contains(k.me), !cur.members.contains(id) {
                ok = self.makeRekey(k, add: [id], answers: id)
            }
            DispatchQueue.main.async { done(ok); self.refresh() }
        }
    }

    /// An admin turns `id` down. They can ask again only with a new key, that is by reinstalling.
    func declineJoin(_ code: String?, _ id: String) {
        guard let k = held(code) else { return }
        UserDefaults.standard.set(Array(declined(k).union([id])), forKey: "declined.\(k.id)")
        DispatchQueue.main.async { self.refresh() }
    }

    /// Makes and sends a new epoch for the current members plus `add`, sealed to each member's encryption key. `admins`:
    /// a new admin list. `remove`: who leaves; everyone else also gets a new code. False if a member's encryption key
    /// hasn't reached this phone yet: leaving them out would quietly remove them.
    @discardableResult private func makeRekey(_ k: Keys, add: [String], answers: String?, admins: [String]? = nil, remove: String? = nil) -> Bool {
        guard let cur = k.ring.currentOrNil else { return false }
        var members = cur.members.filter { $0 != remove }
        for m in [k.me] + add where !members.contains(m) { members.append(m) }
        guard members.count <= Keyring.maxMembers else {
            #if DEBUG
            DebugLog.write("rekey: the group is full")
            #endif
            return false
        }
        let door = k.door, code = remove == nil ? nil : Invite.newCode(), now = Self.nowMs()
        var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
        let secret = Data(b), plain = Rekey.box(secret, code: code)
        // An admin's rekey also keeps every admin added by a rekey of the same number that didn't win.
        var list: [String] = []
        for a in (admins ?? cur.admins) + (cur.admins.contains(k.me) ? k.ring.rivalAdmins() : []) where members.contains(a) && !list.contains(a) { list.append(a) }
        let who = DispatchQueue.main.sync { name }
        // A big group's key goes in several packets, each with the whole member list and some members' parts.
        var packets: [Packet] = [], made: Rekey?
        for some in Rekey.split(members) {
            let pid = Packet.newId(mailbox: door.rekeys.mailbox)
            var parts: [(id: String, box: Data)] = []
            for m in some {
                let known = m == k.me ? nil : k.lock.withLock { k.known[m] }
                let enc = m == k.me ? k.encPub : known?.enc, pq = m == k.me ? k.encs.currentPq : known?.pq
                guard let enc, let pq, let pk = try? P256.KeyAgreement.PublicKey(x963Representation: enc),
                      let box = try? Hybrid.seal(plain, to: pk, pq: pq, info: Rekey.info(door.id), aad: Rekey.aad(pid, m)) else {
                    #if DEBUG
                    DebugLog.write("rekey: no encryption key for a member yet")
                    #endif
                    return false
                }
                parts.append((m, box))
            }
            let one = Rekey(epoch: cur.number + 1, made: now, maker: k.pub, admins: list, answers: remove ?? answers, parts: parts, removal: remove != nil, members: members)
            guard let c = try? door.rekeys.seal(id: pid, ts: now, sender: k.me, name: who, text: "", extra: one.encode(), pad: .full, sign: { try k.sign($0) }) else { return false } // always the largest size: its length would count the members
            packets.append(Packet(id: pid, ts: door.rekeys.hideTime(now, c), ttl: Self.maxTtl, cipher: c))
            made = one
        }
        guard let rk = made else { return false }
        k.ring.add(.fresh(number: rk.epoch, made: now, secret: secret, members: members, admins: list, code: code, via: remove == nil ? nil : door.code, removes: remove, by: k.me,
                         rank: k.ring.standing(rk, maker: k.me)))
        if code != nil { moveDoor(k) }
        saveRing(k)
        for p in packets {
            idsLock.withLock { _ = myReceipts.insert(p.id) }
            store.append(p)
            indexed(p, .group)
            router.publish(p)
        }
        if code != nil { introIfDue(k) }
        nostr.resubscribe()
        #if DEBUG
        DebugLog.write("epoch \(rk.epoch) made: \(members.count) member(s) in \(packets.count) packet(s)" + (answers == nil ? "" : ", answering a join") + (remove == nil ? "" : ", removing a member"))
        #endif
        DispatchQueue.main.async { self.refresh() }
        return true
    }

    /// true: signed by that member; false: not (forged or broken), or its sender isn't in the group or was removed; nil:
    /// the member's public key isn't known yet. `had`: this phone accepted the packet before, so it is read from its own
    /// copy or was waiting for its sender's key. Only then does a removed member's date count (`Keyring.shutOut`).
    private func check(_ k: Keys, _ o: GroupCrypto.Opened, had: Bool = false) -> Bool? {
        let id = o.message.sender.hasPrefix("web-") ? String(o.message.sender.dropFirst(4)) : o.message.sender
        if k.ring.shutOut(id, at: o.message.ts, had: had) { return false } // not in the group; or removed, and seen only now or dated after the removal
        guard let c = k.checker(id) else { return nil }
        return c.verify(digest: o.digest, signature: o.signature)
    }

    /// Messages and receipts of `id` in `k`'s group that waited for its key: shown as checked, or dropped. Main thread.
    private func resolve(_ k: Keys, _ id: String) {
        guard k.checker(id) != nil else { return } // its key wasn't kept (`Joining`): nothing can be checked
        let waited = unchecked.take(channel: ObjectIdentifier(k), sender: id)
        guard !waited.isEmpty else { return }
        for e in waited {
            let w = e.item
            let ok = check(k, w.o, had: true) == true
            if let r = w.receipt { if ok { deliveries.add(group: k.id, r) }; continue }
            // Only a packet that is the one shown under its id waits (`KeyWait.message`), so this row is that packet's.
            guard let row = e.row, let i = raw.firstIndex(where: { $0.id == row }), !raw[i].verified else { continue }
            if ok { raw[i].verified = true; w.o.leaf?.forget(); saveMessageKeys(w.k) } else { rawIds.remove(raw[i].id); idsLock.withLock { shownAs[w.o.mark] = nil }; raw.remove(at: i) }
        }
        refresh()
    }

    /// Sends this phone's introduction to `k`'s group when the last one there is more than 3 days old (or there was
    /// none), so members' introductions are always among the packets of the last 7 days. Any thread.
    private func introIfDue(_ k: Keys, writing: Bool = false) {
        guard !k.removed else { return }
        let d = UserDefaults.standard, key = "introAt.\(k.id)", now = Self.nowMs()
        // The Public channel: only when the user writes there, then while a post of theirs is still shown. A phone
        // whose user never posts on Everyone doesn't announce itself there.
        if k.isPublic && !writing {
            let last = DispatchQueue.main.sync { raw.filter { $0.isPublic && $0.sender == deviceId }.map(\.ts).max() }
            guard PublicIntro.wanted(writing: false, lastOwnPost: last, now: now) else { return }
        }
        let rotated = !k.isPublic && k.encs.rotateIfDue(now: Self.clock()) // a new encryption key has to be introduced at once
        guard rotated || now - Int64(d.double(forKey: key)) >= Self.introEvery else { return }
        let id = Packet.newId(mailbox: k.intros.mailbox), who = DispatchQueue.main.sync { name }
        let pq = k.isPublic ? nil : k.encs.currentPq // the Public channel has no new keys to seal
        // No name on the Public channel: nothing reads it there, and a post carries its sender's name itself.
        guard let c = try? k.intros.seal(id: id, ts: now, sender: k.me, name: k.isPublic ? "" : who, text: "", extra: pq.map { Data([3]) + k.pub + k.encPub + $0 } ?? Data([2]) + k.pub + k.encPub, sign: { try k.sign($0) })
        else { return }
        let p = Packet(id: id, ts: k.intros.hideTime(now, c), ttl: Self.maxTtl, cipher: c)
        idsLock.withLock { _ = myReceipts.insert(id) } // written here: goes up to the relays first, like receipts
        store.append(p)
        indexed(p, k.isPublic ? .isPublic : .group)
        d.set(Double(now), forKey: key)
        router.publish(p)
        #if DEBUG
        DebugLog.write("introduction sent to \(k.isPublic ? "Everyone" : "a group")")
        #endif
    }

    // People whose emoji the user compared (spec "Person emoji"): "<group tag>|<member id>|<name key>".
    private func tagOf(_ code: String?) -> String? { keyLock.withLock { keyCache[code ?? GroupCrypto.publicCode] }?.id }
    private var checkedList: [String] { UserDefaults.standard.stringArray(forKey: "checked") ?? [] }

    func isChecked(_ code: String?, _ id: String) -> Bool {
        guard let t = tagOf(code) else { return false }
        return checkedList.contains { $0.hasPrefix("\(t)|\(id)|") }
    }

    /// The user compared `id`'s emoji and they matched: this key is that person's from now on (an older one for the name goes).
    func markChecked(_ code: String?, _ id: String, _ name: String) {
        guard let t = tagOf(code) else { return }
        UserDefaults.standard.set(Checked.marked(checkedList, group: t, id: id, name: name), forKey: "checked")
        objectWillChange.send()
    }

    /// True if `name` belongs to a checked person but `id` is another key: a reinstall, or someone using their name.
    func newKeyFor(_ code: String?, _ id: String, _ name: String) -> Bool {
        guard id != deviceId, let t = tagOf(code) else { return false }
        let checked = checkedList
        return !checked.isEmpty && Checked.newKey(checked, group: t, id: id, name: name)
    }

    /// The id of the group whose code is or was `code` (`Message.group`): it stays when the code changes, so blocks hang
    /// off it (`Blocks`). The door a group has just left still counts, for a message read a moment before the move.
    private func groupId(_ code: String?) -> String? {
        guard let code else { return nil }
        if let k = keyLock.withLock({ keyCache[code] }) { return k.id }
        let all = keyLock.withLock { Array(keyCache.values) }
        return all.first { k in k.oldDoors.contains { $0.code == code } }?.id
    }

    /// The channel a message's sender is blocked in (`Blocks`): Everyone, or its group's id.
    private func channel(of m: Message) -> String? { m.isPublic ? Blocks.everyone : groupId(m.group) }

    /// Blocks the sender of `m` in the channel `m` came in, and shows the messages again. False, and nothing saved, if
    /// that sender can't be blocked: `m` is this phone's own, or its signature wasn't checked (`Blocks.canBlock`). Main thread.
    @discardableResult func block(_ m: Message) -> Bool {
        guard Blocks.canBlock(m, me: deviceId), let c = channel(of: m) else { return false }
        Moderation.block(Blocks.key(channel: c, sender: m.sender), name: m.name)
        refresh()
        return true
    }

    /// False for a message hidden on this phone: reported or hidden itself, or from someone blocked in its channel. Main thread.
    private func visible(_ m: Message) -> Bool {
        if Moderation.hidden.contains(m.id) { return false }
        let blocked = Moderation.blocked
        return blocked.isEmpty || !Blocks.hides(Set(blocked.keys), channel: channel(of: m), sender: m.sender)
    }

    /// This phone's public key in `code`'s group ("your emoji"), or nil if its keys aren't ready.
    func myPublicKey(_ code: String?) -> Data? { keyLock.withLock { keyCache[code ?? GroupCrypto.publicCode] }?.pub }

    /// The public key of member `id` in `code`'s group, if an introduction brought it.
    func publicKey(of id: String, in code: String?) -> Data? {
        guard let k = keyLock.withLock({ keyCache[code ?? GroupCrypto.publicCode] }) else { return nil }
        return k.checker(id.hasPrefix("web-") ? String(id.dropFirst(4)) : id)?.pub
    }

    /// Switches to another group (or just another name) without restarting the radios: every phone relays every
    /// group anyway, and saved groups' messages are already read. Only the name changed: nothing else happens. A new
    /// group's key is derived in the background. Call on the main thread.
    func rejoin(name: String, code: String) {
        self.name = name
        guard code != activeCode else { return }
        flushAcks() // confirmations owed so far go out first
        activeCode = code
        refresh() // a saved group's messages show at once
        work.async { self.savedGroupsChanged(code) }
    }

    /// After blocking, unblocking or reporting: shows the messages again with the new rules. Main thread; no reading.
    func moderationChanged() { refresh() }

    // MARK: - Loading (background, on `work`)

    /// Passes stored packets on right away (no keys needed), then reads them with this group's and the Public key, then
    /// with the other saved groups' keys, then trims the store.
    private func startUp(_ code: String) {
        let now = Self.nowMs(), cut = now - Self.week
        var recent: [Packet] = [], seen = Set<String>()
        for s in [store, more] {
            s.forEach { p in
                guard p.ts >= cut, !MeshRouter.inFuture(p.ts, now: now) else { return }
                seen.insert(MeshRouter.key(p)); recent.append(p)
                if recent.count >= 2_000 { recent.sort { $0.ts > $1.ts }; recent.removeLast(recent.count - 500) }
            }
        }
        // The router keeps the newest 500. What the relays brought before the restart doesn't go back to them.
        router.restore(recent, seenIds: seen, from: { [fromRelays] key in fromRelays.contains(key) ? NostrLink.peer : "" })
        let a = keys(code), pub = keys(GroupCrypto.publicCode)
        cryptoLock.withLock { _active = a; _public = pub }
        load()
        nostr.resubscribe()
        savedGroupsChanged(code)
        hourly()
    }

    /// `code` is the group on screen and the saved list may have changed: derives the keys not seen before, reads the
    /// store again only if there are any, then trims the store.
    private func savedGroupsChanged(_ code: String) {
        let known = keyLock.withLock { Set(keyCache.keys) }
        let a = keys(code)
        if a.code != code { // an old code of a group saved here: that group is shown, not a second one
            let now = a.code
            DispatchQueue.main.async { SavedGroups.follow(code, now); if self.activeCode == code { self.activeCode = now }; self.refresh() }
            return savedGroupsChanged(now)
        }
        var codes: [String] = [], o: [Keys] = []
        for c in SavedGroups.all().map(\.code) where c != code && !codes.contains(c) {
            let k = keys(c)
            if k.code != c { SavedGroups.follow(c, k.code) } else { codes.append(c) } // an old code among the saved ones isn't kept: its group is saved too
            if k !== a && !o.contains(where: { $0 === k }) { o.append(k) }
        }
        cryptoLock.withLock { _active = a; _others = o }
        if !(codes + [code]).allSatisfy(known.contains) { load() }
        storeLock.withLock { allKeys = true }
        for k in [a] + o + [keySet.pub].compactMap({ $0 }) { introIfDue(k) }
        for k in [a] + o { rekeyIfDue(k) }
        compact()
        nostr.resubscribe() // the relays now send every saved group's mailbox
    }

    /// Reads every stored packet with every key known so far: messages, receipts, my own ids and the store index.
    /// Packets dated more than 10 minutes ahead are removed. Publishes on the main thread.
    private func load() {
        let k = keySet, now = Self.nowMs()
        var msgs: [(Message, String)] = [], recs: [(group: String, receipt: Message)] = [], own = Set<String>(), ownR = Set<String>(), rIds = Set<String>() // msgs: with what was signed (`mark`)
        var sent: [(group: String, id: String)] = [] // this phone's own group messages, with their group's id (`Deliveries.sent`)
        var idx: [String: StoreCap.Entry] = [:], future = Set<String>()
        var opened: [(Message, Keys, GroupCrypto.Opened, Bool, Bool, Bool)] = [] // checked once every introduction is known; the last: another packet had its id first
        var copies: [String: Data] = [:]
        history.forEach { copies[$0.id] = $0.cipher }
        // `name`: what the packet goes by (`StoreCap.name`): its id, or its key if another packet had that id first.
        // `extra`: it comes from the file of those other packets.
        func read(_ stored: Packet, _ name: String, _ extra: Bool) {
            let p = MeshRouter.clamp(stored)
            if MeshRouter.inFuture(p.ts, now: now) { future.insert(name); return }
            // This phone's copy is kept under the packet's name. In "packets.bin" a later record under an id (written by
            // an older version: a readable packet after junk) may still have its copy under that id.
            let underId = extra ? nil : copies[p.id]
            let sealed = underId == nil ? name : p.id, copy = underId ?? copies[Self.copyId(name)]
            // Introductions are learned at once; messages and receipts are checked after the loop, when every
            // introduction in the store is known, whatever their order. This phone's own introductions and new keys
            // count as written here, like its receipts: after a restart too they go up on their group's relay links,
            // not with the packets it passes on (Nostr.scope).
            // What came through a group's door is the group's own only from someone in it (`doorKind`).
            let kind: StoreCap.Kind
            switch copy.flatMap({ fromHistory(sealed, $0, k) }) ?? see(p, k) {
            case .intro(let keys, let id, let c, let enc, let who, let ts, let pq)?:
                if id == keys.me { ownR.insert(p.id) }
                learn(keys, id, c, enc: enc, encAt: ts, pq: pq, name: who); kind = keys.isPublic ? .isPublic : doorKind(keys, id, signed: true)
            case .newKey(let keys, let o, let r, let pid, let d)?:
                let ok = signed(o, r)
                if o.message.sender == keys.me, ok { ownR.insert(p.id) }
                _ = acceptRekey(keys, o, r, pid, d); kind = doorKind(keys, o.message.sender, signed: ok)
            case .msg(let m, let keys, let o, let copy)?: opened.append((m.id == name ? m : m.withId(name), keys, o, false, copy, name != p.id)); kind = m.isPublic ? .isPublic : .group
            case .receipt(let r, let keys, let o)?: opened.append((r, keys, o, true, false, false)); rIds.insert(p.id); kind = .group
            default: kind = .unreadable
            }
            idx[name] = StoreCap.Entry(id: name, ts: p.ts, size: Packet.headerSize + p.cipher.count, kind: kind)
        }
        store.forEachNamed { read($0, $1, false) }
        more.forEachNamed { read($0, $1, true) }
        var waiting: [Pending] = [], spent: [Keys] = []
        for (m, keys, o, receipt, copy, other) in opened {
            if other, !receipt, m.sender == deviceId { continue } // another packet under an id that was taken, naming this phone as its sender: never a row of its own
            switch check(keys, o, had: copy) {
            case true?:
                if receipt { recs.append((keys.id, m)); if m.sender == deviceId { ownR.insert(m.id) } }
                else {
                    msgs.append((m, o.mark))
                    if m.sender == deviceId { own.insert(m.id); if !m.isPublic { sent.append((keys.id, m.id)) } }
                    if !copy { remember(m.id, keys, o) }
                    if let l = o.leaf { l.forget(); if !spent.contains(where: { $0 === keys }) { spent.append(keys) } }
                }
            case nil:
                if receipt { waiting.append(Pending(k: keys, o: o, receipt: m)) }
                else { var u = m; u.verified = false; msgs.append((u, o.mark)); waiting.append(Pending(k: keys, o: o, receipt: nil)); if !copy { remember(m.id, keys, o) } }
            case false?:
                if let e = idx[m.id] { idx[m.id] = StoreCap.Entry(id: e.id, ts: e.ts, size: e.size, kind: .unreadable) }
            }
        }
        spent.forEach(saveMessageKeys)
        if !future.isEmpty {
            store.remove(future); more.remove(future)
            history.remove(Set(future.map(Self.copyId)))
            #if DEBUG
            DebugLog.write("store: removed \(future.count) packets dated in the future")
            #endif
        }
        idsLock.withLock { mine.formUnion(own); myReceipts.formUnion(ownR); rIds.forEach { receiptIds.add($0) } }
        storeLock.withLock {
            for (id, e) in index where idx[id] == nil { idx[id] = e } // stored while reading
            index = idx; indexBytes = idx.values.reduce(0) { $0 + $1.size }
            let door = idx.values.filter { $0.kind == .door }
            doorCount = door.count; doorBytes = door.reduce(0) { $0 + $1.size }
        }
        // Who confirmed what, worked out here and not on the main thread. A receipt counts only for a message written
        // on this phone, in the group whose receipt key opened it; the receipts themselves aren't kept in memory.
        var found = Deliveries()
        for (group, id) in sent { found.sent(group: group, id) }
        for (group, r) in recs { found.add(group: group, r) }
        let confirmed = found
        DispatchQueue.main.async {
            var added = Set<String>()
            for (m, mark) in msgs {
                // Another packet already shows this very message: it is one row, whatever packets bring it.
                let free = self.idsLock.withLock { () -> Bool in if let row = self.shownAs[mark], row != m.id { return false }; return true }
                guard free else { continue }
                if self.rawIds.insert(m.id).inserted { self.raw.append(m); added.insert(m.id) }
                self.idsLock.withLock { self.shownAs[mark] = m.id }
            }
            self.raw.sort { $0.ts < $1.ts }
            self.deliveries.merge(confirmed)
            // A message waits only if its row was made just now from the stored packet: a row that was there already
            // may show another packet with that id.
            for w in waiting {
                let channel = ObjectIdentifier(w.k), sender = w.o.message.sender
                if w.receipt != nil { self.unchecked.receipt(w.o.key, channel: channel, sender: sender, w) }
                else { self.unchecked.message(w.o.key, channel: channel, sender: sender, id: w.o.message.id, shown: added.contains(w.o.message.id), w) }
            }
            self.refresh()
        }
    }

    /// Keeps the store small, once every saved group's key has been tried: packets older than 7 days that no saved
    /// group can read go (phones stop passing them on after 7 days anyway), and so do those that came through a group's
    /// door from someone who isn't in it; Public packets beyond 2,000 go (no sender more than its share:
    /// StoreCap.everyone), and then the store cap (StoreCap: about 40 MB and 20,000 packets, unreadable packets first,
    /// and the door's own small room). Same rules as the Android app (MeshEngine.compact).
    private func compact() {
        let now = Self.nowMs()
        var expired: [String: (gone: [Keyring.Epoch], held: [Keyring.Epoch])] = [:] // group id -> the epochs deleted now, and those still held
        for k in keyLock.withLock({ Array(keyCache.values) }) {
            // A removed phone still deletes its replaced encryption keys on time (spec "Changing keys"); it only stops introducing itself.
            if k.removed && !k.isPublic { _ = k.encs.rotateIfDue(now: Self.clock()) }
            let gone = k.ring.expire(now: now)
            guard !gone.isEmpty else { continue } // keys replaced more than 7 days ago go (v0.6), from the Keychain too
            saveRing(k)
            k.setDoors(k.door, old: k.oldDoors.filter { d in k.ring.all.contains { $0.via == d.code } })
            expired[k.id] = (gone, k.ring.all)
        }
        let stale = copies(of: expired)
        // Nor is an alert kept past a week, whatever happens to its message (Android: a timeout from the message's date).
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { ns in
            let old = ns.filter { Date().timeIntervalSince($0.date) > 7 * 86_400 }.map(\.request.identifier)
            if !old.isEmpty { center.removeDeliveredNotifications(withIdentifiers: old) }
        }
        // Over the Everyone channel's cap, not simply the oldest go: one sender can't push everyone else's messages and
        // places out (StoreCap.everyone). Who sent what is read before the store lock is taken: the main thread may be
        // waiting for that lock.
        let many = storeLock.withLock { allKeys && index.values.filter { $0.kind == .isPublic }.count > Self.maxPublic }
        var shown: [String: (sender: String, verified: Bool)] = [:]
        if many { shown = DispatchQueue.main.sync { everyoneSenders() } }
        let written: Set<String> = many ? idsLock.withLock { myReceipts } : []
        let drop: Set<String> = storeLock.withLock {
            compacting = false
            guard allKeys else { return [] }
            let cut = Self.nowMs() - Self.week
            var drop = Set(index.values.filter { ($0.kind == .unreadable || $0.kind == .door) && $0.ts < cut }.map(\.id))
            drop.formUnion(stale) // the messages of an epoch deleted now: their packets no longer open either
            let pub = index.values.filter { $0.kind == .isPublic }
            if many, pub.count > Self.maxPublic {
                // A Public packet that isn't a message is an introduction; this phone's own are the ones it wrote.
                let held = pub.map { e -> StoreCap.Held in
                    guard let m = shown[e.id] else { return StoreCap.Held(id: e.id, ts: e.ts, holder: "introductions", own: written.contains(e.id)) }
                    let sender = m.sender.hasPrefix("web-") ? String(m.sender.dropFirst(4)) : m.sender
                    return StoreCap.Held(id: e.id, ts: e.ts, holder: m.verified ? sender : "not verified", own: m.sender == deviceId)
                }
                drop.formUnion(StoreCap.everyone(held, max: Self.maxPublic))
            }
            drop.formUnion(StoreCap.overflow(index.values.filter { !drop.contains($0.id) }))
            for id in drop { if let e = index.removeValue(forKey: id) { indexBytes -= e.size; if e.kind == .door { doorCount -= 1; doorBytes -= e.size } } }
            return drop
        }
        guard !drop.isEmpty else { return }
        store.remove(drop); more.remove(drop)
        history.remove(Set(drop.map(Self.copyId)))
        // An alert is posted under its message's id: it must not keep showing the text of a message that is gone.
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: Array(drop))
        #if DEBUG
        DebugLog.write("store: removed \(drop.count) packets")
        #endif
        DispatchQueue.main.async {
            self.raw.removeAll { drop.contains($0.id) }; self.rawIds.subtract(drop)
            self.idsLock.withLock { self.shownAs = self.shownAs.filter { !drop.contains($0.value) } }
            self.unchecked.forget(drop); self.deliveries.forget(drop) // nothing waits for, or confirms, a message that is gone
            self.refresh()
        }
    }

    /// The Everyone messages by id: who sent each, and whether that was checked. Main thread.
    private func everyoneSenders() -> [String: (sender: String, verified: Bool)] {
        var out: [String: (sender: String, verified: Bool)] = [:]
        for m in raw where m.isPublic { out[m.id] = (sender: m.sender, verified: m.verified) }
        return out
    }

    /// The store grew well past its cap while running: trim it in the background. Any thread.
    private func compactIfFull() {
        let full = storeLock.withLock {
            guard allKeys, !compacting, indexBytes > StoreCap.maxBytes / 10 * 11 || index.count > StoreCap.maxCount + 1_000 || StoreCap.doorFull(count: doorCount, bytes: doorBytes) else { return false }
            compacting = true; return true
        }
        if full { work.async { self.compact() } }
    }

    /// Counts `p` in the store. False if the store already has a packet under its id that this one doesn't replace.
    @discardableResult private func indexed(_ p: Packet, _ kind: StoreCap.Kind) -> Bool {
        storeLock.withLock {
            let had = index[p.id]
            guard had == nil || (had?.kind == .unreadable && kind != .unreadable) else { return false } // a readable packet replaces junk sent first under its id
            index[p.id] = StoreCap.Entry(id: p.id, ts: p.ts, size: Packet.headerSize + p.cipher.count, kind: kind)
            indexBytes += Packet.headerSize + p.cipher.count - (had?.size ?? 0)
            return true
        }
    }

    /// A packet that arrived: kept, and counted, under the name it goes by (`StoreCap.name`), which is returned. The first
    /// packet stored under an id goes by that id; any other packet with that id is kept too, by its key, in a file of its
    /// own. Nothing replaces anything: whoever sends junk, or a message of their own, first under an id doesn't keep the
    /// real packet out of the store.
    @discardableResult private func keep(_ p: Packet, _ kind: StoreCap.Kind) -> String {
        let (name, first, isNew): (String, Bool, Bool) = storeLock.withLock {
            let first = index[p.id] == nil, name = StoreCap.name(p, first: first)
            if index[name] != nil { return (name, first, false) }
            let size = Packet.headerSize + p.cipher.count
            index[name] = StoreCap.Entry(id: name, ts: p.ts, size: size, kind: kind)
            indexBytes += size
            if kind == .door { doorCount += 1; doorBytes += size }
            return (name, first, true)
        }
        if isNew { (first ? store : more).append(p) }
        return name
    }

    /// The id this phone's copy of a message is kept under in "history.bin": the packet's name, or for a packet that goes
    /// by its key the second half of it (a record's id is 8 bytes).
    private static func copyId(_ name: String) -> String { name.count > 16 ? String(name.suffix(16)) : name }

    /// Called by the router while it holds its lock: a copy of a stored packet came with more hops left. The saved ttl
    /// is raised too, or a restart would pass the packet on with the first copy's. Written 10 s later, together with
    /// those that came meanwhile, in one pass over the file.
    private func onRaised(_ p: Packet) {
        let first = storeLock.withLock { () -> Bool in
            let was = raisedTtl.isEmpty
            if raisedTtl.count < 1_000 { raisedTtl[MeshRouter.key(p)] = p.ttl }
            return was
        }
        guard first else { return }
        work.asyncAfter(deadline: .now() + 10) {
            let ttls = self.storeLock.withLock { () -> [String: Int] in let all = self.raisedTtl; self.raisedTtl = [:]; return all }
            self.store.raise(ttls); self.more.raise(ttls)
        }
    }

    // MARK: - Messages

    /// Shows the messages again: this group's and the Public channel's in `messages`, all groups' in `allMessages`,
    /// without blocked people and reported messages. Main thread.
    private func refresh() {
        let blocked = Set(Moderation.blocked.keys), hidden = Moderation.hidden // read once, not per message
        var ids: [String: String] = [:] // group code -> group id ("" if not known), looked up once per group
        let visible = raw.filter { m in
            if hidden.contains(m.id) { return false }
            if blocked.isEmpty { return true }
            var channel: String? = Blocks.everyone // a block holds in the channel it was made in (`Blocks`)
            if !m.isPublic {
                let code = m.group ?? ""
                if ids[code] == nil { ids[code] = groupId(code) ?? "" }
                channel = ids[code].flatMap { $0.isEmpty ? nil : $0 }
            }
            return !Blocks.hides(blocked, channel: channel, sender: m.sender)
        }
        allMessages = visible
        messages = visible.filter { $0.isPublic || $0.group == activeCode }
    }

    /// Adds a message in time order. Main thread.
    /// False if a message with this id is already there.
    @discardableResult private func add(_ m: Message) -> Bool {
        guard rawIds.insert(m.id).inserted else { return false }
        let i = raw.lastIndex { $0.ts <= m.ts }.map { $0 + 1 } ?? 0
        raw.insert(m, at: i)
        refresh()
        return true
    }

    /// Adds a received message unless another row already shows the very message it carries (`GroupCrypto.Opened.mark`):
    /// the same signed message can come in several packets. False if nothing was added. Main thread.
    private func show(_ m: Message, mark: String) -> Bool {
        let free = idsLock.withLock { () -> Bool in if let row = shownAs[mark], row != m.id { return false }; return true }
        guard free, add(m) else { return false }
        idsLock.withLock { shownAs[mark] = m.id }
        return true
    }

    /// The saved name of the group whose code is `code` (`Message.group`), for alerts. Main thread.
    func groupName(_ code: String?) -> String {
        if code == activeCode { return UserDefaults.standard.string(forKey: "groupName") ?? "your group" }
        return SavedGroups.all().first { $0.code == code }?.name ?? "a saved group"
    }

    /// Writes a message from this phone, to the group on screen (or the saved group `group`, e.g. answering its
    /// "Are you safe?") or to the Public channel. Call on the main thread.
    /// Returns false if it is too long for a LoRa radio that is linked now (it still travels the other ways).
    @discardableResult func send(_ text: String, isPublic: Bool = false, photo: Data? = nil, group: String? = nil) -> Bool {
        let target = group.flatMap { $0.isEmpty ? nil : $0 } ?? activeCode
        let code = isPublic ? GroupCrypto.publicCode : target
        let k = keys(code), cr = k.group // cached; derived here only if the user writes within a second of switching
        if !isPublic && k.removed { return true } // the screen no longer offers this
        if !isPublic && !k.joined { waitingToJoin[k.id, default: []].append((text, photo)); return true } // sent once an admin lets this phone in
        work.async { self.introIfDue(k, writing: true) } // members can check this message only with this phone's key
        let id = Packet.newId(mailbox: cr.mailbox), ts = Int64(Date().timeIntervalSince1970 * 1000)
        guard let c = sealOne(k, cr, isPublic: isPublic, id: id, ts: ts, text: text, photo: photo) else { return true }
        let p = Packet(id: id, ts: cr.hideTime(ts, c), ttl: Self.maxTtl, cipher: c)
        idsLock.withLock { _ = mine.insert(id) }
        store.append(p)
        indexed(p, isPublic ? .isPublic : .group)
        add(Message(id: id, ts: ts, sender: deviceId, name: name, text: text, isPublic: isPublic, photo: isPublic ? nil : photo,
                    group: isPublic ? nil : k.code)) // the group's code now, if `target` was one it has moved on from
        if !isPublic { deliveries.sent(group: k.id, id) } // only this group's receipts confirm it
        router.publish(p)
        return (!lora.connected || Meshtastic.fits(p)) && (!meshcore.connected || MeshCore.fits(p))
    }

    /// Sends a check-in with this phone's battery level and, if you share it, your position (a fresh GPS fix can take
    /// up to 10 s: `checkInSending` is set meanwhile and a second tap is ignored). The haptic comes right away.
    /// `group`: a saved group other than the one on screen. Main thread.
    func checkIn(_ c: CheckIn, needs: Set<Need> = [], people: Int? = nil, group: String? = nil, done: (() -> Void)? = nil) {
        guard checkInSending == nil else { return }
        checkInSending = c
        UINotificationFeedbackGenerator().notificationOccurred(c == .safe ? .success : .warning)
        let battery = Self.batteryPercent
        LocationService.shared.forCheckIn { [weak self] spot in
            guard let self else { return }
            self.send(c.text(battery: battery, spot: spot, needs: needs, people: people), group: group)
            self.checkInSending = nil
            done?()
        }
    }

    private func setStatus(_ key: String, _ line: String?) {
        DispatchQueue.main.async {
            self.status[key] = line
            let bt = self.ble.nodes, mc = self.mc.nodes, net = self.wifi.nodes
            let all = Set(bt).union(mc).union(net) // a phone linked several ways counts once
            self.bluetoothLinks = bt.count; self.wifiLinks = mc.count + net.count; self.wifiNetworkLinks = net.count
            self.linkedNodes = all
            self.phones = all.count; self.radioLinked = self.lora.connected; self.meshcoreLinked = self.meshcore.connected
            self.relaysLinked = self.nostr?.connected ?? 0
            #if DEBUG
            if CommandLine.arguments.contains("fakeRelays") { self.relaysLinked = 4 } // screenshots of the online state, offline
            #endif
            self.throughTor = self.nostr?.throughTor
            self.bluetooth = self.ble.state
            self.localNetworkDenied = self.wifi.localNetworkDenied
            self.watchTor()
        }
    }

    /// With "Connect through Tor": after 2 minutes without getting through, say so (ConnectionsView). Main thread.
    private func watchTor() {
        guard throughTor == false else { torWaitingSince = nil; torSlow = false; return }
        guard torWaitingSince == nil else { return }
        let since = Date()
        torWaitingSince = since
        DispatchQueue.main.asyncAfter(deadline: .now() + 120) { [weak self] in
            guard let self, self.torWaitingSince == since, self.throughTor == false else { return }
            self.torSlow = true
        }
    }

    /// Called by the router while it holds its lock: every transport only queues the packet.
    private func route(_ peer: String, _ p: Packet) {
        let (newlyMine, ownPacket, receipt) = idsLock.withLock {
            (mine.contains(p.id) && !sentIds.contains(p.id), mine.contains(p.id) || myReceipts.contains(p.id), receiptIds.contains(p.id))
        }
        // For the relays and the radios: did this phone write this very packet, or did a link bring it? Its id alone
        // doesn't say: anyone can send another packet under the id of one of this phone's (MeshRouter.source).
        let from = peer == LoraLink.peer || peer == MeshCoreLink.peer || peer == NostrLink.peer ? router.source(p) : nil
        let own = ownPacket && from == ""
        if peer == LoraLink.peer {
            if receipt { return }             // receipts stay off LoRa, where airtime is scarce
            lora.offer(p, mine: own)          // the radios send this phone's own packets first (LoraQueue)
            if !Meshtastic.fits(p) { return } // too long for the radio: not really sent
        }
        else if peer == MeshCoreLink.peer {
            if receipt { return }             // same rules as Meshtastic
            meshcore.offer(p, mine: own)
            if !MeshCore.fits(p) { return }
        }
        else if peer.hasPrefix(BleLink.prefix) { ble.send(peer, p) }
        else if peer.hasPrefix(MultipeerLink.prefix) { mc.send(peer, p) }
        else if peer.hasPrefix(WifiLink.prefix) { wifi.send(peer, p) }
        // Written on this phone (a message or a receipt): goes up first. "Sent" once a relay accepts it.
        else if peer == NostrLink.peer { nostr.send(p, mine: own, from: from ?? ""); return }
        if newlyMine { markHandedOff(p.id) }
    }

    /// One of my messages left this phone: to a phone, a radio or the internet relays ("Sent"). Saved on the phone,
    /// so the label survives restarts. Any thread.
    private func markHandedOff(_ id: String) {
        let list: [String]? = idsLock.withLock { mine.contains(id) && sentIds.add(id) ? sentIds.list : nil }
        guard let list else { return }
        UserDefaults.standard.set(list, forKey: "handedOff")
        DispatchQueue.main.async { self.handedOff = Set(list) }
    }

    /// What `p` is: tried with this group's keys, then the Public channel's (photos are group-only; in someone else's
    /// Everyone messages and places, offensive words are masked), then the other saved groups'. `group` says which
    /// group. Nothing is checked yet, except introductions, which carry their own key.
    private func see(_ p: Packet, _ k: (active: Keys?, others: [Keys], pub: Keys?)) -> Seen? {
        let box = Packet.mailbox(of: p.id) // every key has one mailbox: junk costs one try, not one per key this phone holds
        for keys in [k.active, k.pub].compactMap({ $0 }) + k.others {
          for e in keys.ring.all where e.group.mailbox == box {
            if let o = e.open(p) { return message(keys, o) }
            if let o = e.openReceipt(p) {
                guard let r = asMine(o.message, keys.me) else { return .forged }
                return .receipt(r, keys, o)
            }
          }
          // Only the Public channel reads through its door: in a group the code alone doesn't let anyone write.
          if keys.isPublic, keys.door.crypto.mailbox == box, let o = keys.door.crypto.openSigned(p) { return message(keys, o) }
          if keys.intros.mailbox == box, let o = keys.intros.openSigned(p) { return introduction(keys, o) ?? .forged }
          if !keys.isPublic {
              for d in [keys.door] + keys.oldDoors where d.rekeys.mailbox == box { // old doors: for removals that crossed
                  guard let o = d.rekeys.openSigned(p) else { continue }
                  guard let r = o.extra.flatMap(Rekey.decode) else { return .forged }
                  return .newKey(keys, o, r, p.id, d)
              }
          }
        }
        return nil
    }

    private func message(_ keys: Keys, _ o: GroupCrypto.Opened) -> Seen {
        guard var m = asMine(o.message, keys.me) else { return .forged } // a sender that is no member id: like a packet nobody can open
        if keys.isPublic {
            let mine = m.sender == deviceId
            m = Message(id: m.id, ts: m.ts, sender: m.sender, name: mine ? m.name : WordFilter.clean(m.name),
                        text: mine ? m.text : WordFilter.clean(m.text), isPublic: true)
        } else { m.group = keys.code }
        return .msg(m, keys, o, false)
    }

    private static let historyKey: Data = {
        if let k = Vault.get("history"), k.count == 32 { return k }
        var b = [UInt8](repeating: 0, count: 32); _ = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
        Vault.put("history", Data(b))
        return Data(b)
    }()

    /// Keeps a readable copy of a message opened with its own key: that key is about to be deleted. `id`: the name its
    /// packet goes by (`StoreCap.name`).
    private func remember(_ id: String, _ k: Keys, _ o: GroupCrypto.Opened) {
        guard let l = o.leaf, let blob = History.seal(key: Self.historyKey, id: id, group: k.id, epoch: l.epoch.id, o, index: l.index, counter: l.counter) else { return }
        history.append(Packet(id: Self.copyId(id), ts: o.message.ts, ttl: 0, cipher: blob))
    }

    /// A message from this phone's copy, while its epoch is still held: when the epoch goes, the message goes too.
    private func fromHistory(_ id: String, _ blob: Data, _ set: (active: Keys?, others: [Keys], pub: Keys?)) -> Seen? {
        guard let s = History.open(key: Self.historyKey, id: id, blob: blob),
              let k = ([set.active].compactMap({ $0 }) + set.others).first(where: { $0.id == s.group }),
              let e = k.ring.all.first(where: { $0.id == s.epoch }) ?? k.ring.all.first(where: { $0.hash == s.epoch }) else { return nil } // by hash: copies kept before epochs had an id
        var o = s.opened
        o.leaf = Leaf(epoch: e, index: s.index, counter: s.counter)
        guard var m = asMine(o.message, k.me) else { return nil }
        m.group = k.code
        return .msg(m, k, o, true)
    }

    /// The names of the packets whose copies in "history.bin" go with the epochs `compact` just deleted (`History.goes`):
    /// group id -> the epochs deleted, and those still held. A copy is sealed under its packet's name, and kept under
    /// `copyId` of it: a name longer than that is found in the index. On `work`.
    private func copies(of expired: [String: (gone: [Keyring.Epoch], held: [Keyring.Epoch])]) -> Set<String> {
        guard !expired.isEmpty else { return [] }
        let long = storeLock.withLock { Dictionary(index.keys.filter { $0.count > 16 }.map { (Self.copyId($0), $0) }, uniquingKeysWith: { a, _ in a }) }
        var out = Set<String>()
        history.forEach { p in
            for name in [p.id, long[p.id]].compactMap({ $0 }) {
                guard let s = History.open(key: Self.historyKey, id: name, blob: p.cipher) else { continue }
                if let e = expired[s.group], History.goes(s, with: e.gone, held: e.held) { out.insert(name) }
                break
            }
        }
        return out
    }

    /// Each held epoch's message keys, in the Keychain: they are saved after every message whose key was deleted.
    private func saveMessageKeys(_ k: Keys) {
        k.moveLock.withLock {
            var d = Data()
            for e in k.ring.all {
                guard let m = e.messageKeys?.encode() else { continue }
                d.append(Data(e.id.utf8))
                d.append(contentsOf: [UInt8(m.count >> 24 & 255), UInt8(m.count >> 16 & 255), UInt8(m.count >> 8 & 255), UInt8(m.count & 255)])
                d.append(m)
            }
            Vault.put("mkeys.\(k.id)", d)
        }
    }

    /// A group message goes under its own key, deleted here at once: from then on only this phone's copy can show it (spec "Message keys").
    private func sealOne(_ k: Keys, _ cr: GroupCrypto, isPublic: Bool, id: String, ts: Int64, text: String, photo: Data?) -> Data? {
        if !isPublic, let e = k.ring.currentOrNil, let keys = e.messageKeys, let i = keys.index(k.me), let n = keys.takeNext(), let mk = keys.key(i, n) {
            guard let c = try? cr.seal(messageKey: mk, index: i, counter: n, id: id, ts: ts, sender: k.me, name: name, text: text, photo: photo, sign: { try k.sign($0) }) else { return nil }
            guard c.count <= Packet.maxCipher else { keys.forget(i, n); saveMessageKeys(k); return nil } // longer than any phone takes, and than the store reads back
            if var o = cr.open(messageKey: mk, index: i, counter: n, Packet(id: id, ts: ts, ttl: 0, cipher: c), at: ts) {
                o.leaf = Leaf(epoch: e, index: i, counter: n)
                remember(id, k, o)
            }
            keys.forget(i, n)
            saveMessageKeys(k)
            return c
        }
        return (try? cr.seal(id: id, ts: ts, sender: k.me, name: name, text: text, photo: isPublic ? nil : photo, sign: { try k.sign($0) }))
            .flatMap { $0.count <= Packet.maxCipher ? $0 : nil }
    }

    /// A valid introduction: the 4th field is 0x02 and a public key whose hash starts with the sender's id, and it signed it.
    private func introduction(_ k: Keys, _ o: GroupCrypto.Opened) -> Seen? {
        guard let e = o.extra else { return nil }
        let withPq = e.count == 99 + MlKem.publicSize && e.first == 3 // 0x03, signing key (33), encryption key (65), ML-KEM key (1184)
        guard withPq || (k.isPublic && e.count == 99 && e.first == 2) else { return nil } // 0x02, without the ML-KEM key: the Public channel only
        if withPq, MlKem.encapsulate(Data(e.suffix(MlKem.publicSize))) == nil { return nil } // a key nobody could seal to would block every new key
        let pub = Data(e[e.startIndex + 1 ..< e.startIndex + 34]), enc = Data(e[e.startIndex + 34 ..< e.startIndex + 99]), id = o.message.sender
        guard o.message.name.utf8.count <= 200, MemberKey.id(pub) == id, (try? P256.KeyAgreement.PublicKey(x963Representation: enc)) != nil, // names are 40 characters at most in the app
              let c = MemberKey.Checker(pub), c.verify(digest: o.digest, signature: o.signature) else { return nil }
        return .intro(k, id, c, enc, o.message.name, o.message.ts, withPq ? Data(e.suffix(MlKem.publicSize)) : nil)
    }

    /// On this phone, its own messages carry `deviceId` as sender: one id for "me" in every group. Nil for a packet whose
    /// sender is no member id, or is `deviceId` itself (`Senders.shown`): nothing received may pass for written here.
    private func asMine(_ m: Message, _ me: String) -> Message? {
        guard let s = Senders.shown(wire: m.sender, me: me, device: deviceId) else { return nil }
        return s == m.sender ? m : m.withSender(s)
    }

    /// A packet seen for the first time: keep it, and show it if a saved group or the Public channel can read it and
    /// its signature checks (or its sender's key isn't known yet: shown as not verified, checked when it comes).
    /// Messages of every saved group are confirmed with that group's receipt key and alerted.
    private func onDeliver(_ p: Packet) {
        #if DEBUG
        DebugLog.write("received \(p.id) sent-at \(p.ts)")
        #endif
        switch see(p, keySet) {
        case .intro(let k, let id, let c, let enc, let who, let ts, let pq)?:
            keep(p, k.isPublic ? .isPublic : doorKind(k, id, signed: true)) // through a group's door: the group's own only from someone in it
            let fresh = learn(k, id, c, enc: enc, encAt: ts, pq: pq, name: who)
            #if DEBUG
            if fresh { DebugLog.write("introduction \(p.id): a new member key") }
            #endif
            // Not in the current epoch: a request to join. It waits for an admin here to let them in.
            // At most one alert a minute in a group: the requests themselves are in the chat (`joinRequests`).
            let asking = fresh && !k.isPublic && !k.removed && id != k.me && !k.members.contains(id) && k.ring.currentOrNil?.admins.contains(k.me) == true && !declined(k).contains(id)
                && storeLock.withLock { () -> Bool in
                    let at = Self.nowMs()
                    guard Joining.alertDue(last: joinAlertAt[k.id] ?? 0, now: at) else { return false }
                    joinAlertAt[k.id] = at; return true
                }
            DispatchQueue.main.async {
                self.resolve(k, id)
                self.refresh()
                if asking { Notifier.shared.received(Message(id: "join-\(id)", ts: Self.nowMs(), sender: id, name: who, text: "asks to join", group: k.code)) }
            }
        case .newKey(let k, let o, let r, let pid, let d)?:
            let ok = signed(o, r), was = k.ring.currentOrNil
            if acceptRekey(k, o, r, pid, d) {
                // Our introduction again, at once: newcomers need our keys to check our messages. Messages stored
                // before the epoch came may open now; relays follow its mailbox.
                UserDefaults.standard.removeObject(forKey: "introAt.\(k.id)")
                let first = rescanLock.withLock { () -> Bool in defer { rescanFlag.on = true }; return !rescanFlag.on }
                if first { work.async {
                    self.rescanLock.withLock { self.rescanFlag.on = false }
                    self.load()
                    self.nostr.resubscribe()
                    for g in [self.keySet.active].compactMap({ $0 }) + self.keySet.others { self.introIfDue(g) }
                } }
            }
            // Classed once the keyring has decided: the key that lets this phone in is from someone in the group it now knows.
            keep(p, doorKind(k, o.message.sender, signed: ok))
            // Made after our current epoch, yet numbered below it: that phone missed our keys. Answered after 0-3 s unless another member did.
            if d === k.door, ok, k.ring.behind(r, maker: o.message.sender) {
                work.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0..<3_000))) { self.answerBehind(k, made: r.made, at: was) }
            }
            if !k.ring.stillToRemove().isEmpty { work.asyncAfter(deadline: .now() + .milliseconds(Int.random(in: 0..<3_000))) { self.finishRemovals(k) } }
        case .msg(let m0, let k, let o, _)?:
            let ok = check(k, o)
            if ok == false {
                keep(p, .unreadable)
                #if DEBUG
                DebugLog.write("dropped \(p.id): signature doesn't check")
                #endif
                break
            }
            // Another packet under an id that is taken, which only brings again a message already shown, or names this phone
            // as its sender (the same message sealed again): nothing to keep or show.
            if storeLock.withLock({ index[p.id] != nil }), m0.sender == deviceId || idsLock.withLock({ shownAs[o.mark] != nil }) { break }
            // Any other packet under an id that is taken is a message of its own: kept and shown by its name (`StoreCap.name`).
            let name = keep(p, m0.isPublic ? .isPublic : .group)
            var m = name == p.id ? m0 : m0.withId(name); m.verified = ok == true
            remember(name, k, o)
            if ok == true, let l = o.leaf { l.forget(); saveMessageKeys(k) } // this message's key is gone: only this phone's copy can show it now
            if k.rejoining, m.sender != deviceId, m.ts >= k.rejoiningSince { setRejoining(k, 0) } // someone wrote in a key this phone has: it's back
            DispatchQueue.main.async {
                let others = !m.isPublic && m.sender != self.deviceId
                let fresh = self.show(m, mark: o.mark)
                // It waits for its sender's key only as the message shown under its id: another packet with that id,
                // checked later, must not mark or remove this row.
                if ok == nil { self.unchecked.message(o.key, channel: ObjectIdentifier(k), sender: o.message.sender, id: m.id, shown: fresh, Pending(k: k, o: o, receipt: nil)) }
                if fresh, !m.isPublic, m.sender == self.deviceId { self.deliveries.sent(group: k.id, m.id) } // written here before the store was lost: its receipts count again
                // Not for a message already shown: another packet under its id, sealed again by a member, alerts and confirms nothing.
                guard fresh, others else { return }
                self.ack(p.id, k) // confirmed by its packet id, whatever name it goes by here
                guard self.visible(m) else { return }
                Notifier.shared.received(m)
            }
        case .receipt(let r, let k, let o)?:
            keep(p, .group)
            idsLock.withLock { _ = receiptIds.add(p.id) }
            switch check(k, o) {
            case true?: DispatchQueue.main.async { self.deliveries.add(group: k.id, r) }
            case nil: DispatchQueue.main.async { self.unchecked.receipt(o.key, channel: ObjectIdentifier(k), sender: o.message.sender, Pending(k: k, o: o, receipt: r)) }
            case false?: break
            }
        default:
            keep(p, .unreadable)
        }
        compactIfFull()
    }

    /// Confirms a group message in the next receipt, with that group's key. Messages arriving less than 2 s apart
    /// share one receipt, for at most 10 s (ReceiptBatch). Main thread.
    private func ack(_ id: String, _ key: Keys) {
        let now = Self.uptimeMs()
        if pendingAcks.isEmpty { firstAck = now; ackTimer(after: ReceiptBatch.quietMs) }
        lastAck = now
        pendingAcks.append((id, key))
    }

    private func ackTimer(after ms: Int64) {
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int(ms))) { [weak self] in
            guard let self, !self.pendingAcks.isEmpty else { return }
            let now = Self.uptimeMs()
            if ReceiptBatch.due(firstMs: self.firstAck, lastMs: self.lastAck, nowMs: now) { // a receipt doesn't show how soon this phone got the message
                DispatchQueue.main.asyncAfter(deadline: .now() + Double.random(in: 0..<20)) { [weak self] in self?.flushAcks() }
            }
            else { self.ackTimer(after: Swift.max(10, Swift.min(self.lastAck + ReceiptBatch.quietMs, self.firstAck + ReceiptBatch.maxWaitMs) - now)) }
        }
    }

    private func flushAcks() {
        let batch = pendingAcks
        pendingAcks = []
        var groups: [(key: Keys, ids: [String])] = []
        for a in batch {
            if let i = groups.firstIndex(where: { $0.key.code == a.key.code }) { groups[i].ids.append(a.id) } else { groups.append((a.key, [a.id])) }
        }
        for (k, ids) in groups {
            let rc = k.receipts
            for b in Receipt.batches(ids) {
                let id = Packet.newId(mailbox: rc.mailbox), ts = Int64(Date().timeIntervalSince1970 * 1000)
                guard let c = try? rc.seal(id: id, ts: ts, sender: k.me, name: name, text: Receipt.text(for: b), sign: { try k.sign($0) }) else { continue }
                let p = Packet(id: id, ts: rc.hideTime(ts, c), ttl: Self.maxTtl, cipher: c)
                idsLock.withLock { _ = receiptIds.add(id); _ = myReceipts.insert(id) }
                store.append(p)
                indexed(p, .group)
                router.publish(p)
            }
        }
    }

    private static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    private static let hexDigits = Array("0123456789abcdef".utf8)
    private static func hex(_ d: Data) -> String {
        var out = [UInt8](); out.reserveCapacity(d.count * 2)
        for b in d { out.append(hexDigits[Int(b >> 4)]); out.append(hexDigits[Int(b & 15)]) }
        return String(decoding: out, as: UTF8.self)
    }
    private static func unhex(_ h: String) -> Data {
        var d = Data(), i = h.startIndex
        while i < h.endIndex { let j = h.index(i, offsetBy: 2); d.append(UInt8(h[i..<j], radix: 16) ?? 0); i = j }
        return d
    }
    private static func uptimeMs() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }
}

/// Someone with the code asking to be let into a group; its admins decide (spec "Joining").
struct JoinRequest: Identifiable { let id: String, name: String, pub: Data }

/// A line in the group's chat: "Marco joined", "Anna removed Marco".
struct GroupEvent: Identifiable { let ts: Int64, text: String; var id: String { "\(ts)-\(text)" } }

/// Where one of my messages is: still on this phone, given to a phone in range, or confirmed by group members.
enum Delivery: Equatable {
    case waiting, sent, delivered([Reader])
}

extension Engine {
    /// nil for other people's messages, and for my older ones that haven't gone out yet.
    func delivery(of m: Message) -> Delivery? {
        guard m.sender == deviceId else { return nil }
        if !m.isPublic, let r = deliveries.readers[m.id], !r.isEmpty { return .delivered(r) }
        if handedOff.contains(m.id) { return .sent }
        return m.ts >= startedAt ? .waiting : nil
    }
}

#if DEBUG
import UIKit

/// Debug builds only: Library/Application Support/debug.log with receive times and app state changes (no message
/// text), to check from a Mac (`devicectl device copy from ...`) whether messages arrive while the phone is locked.
enum DebugLog {
    private static let lock = NSLock()
    private static let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("debug.log")

    static func start() {
        DispatchQueue.main.async { write(UIApplication.shared.applicationState == .background ? "app started in background" : "app started") }
        let nc = NotificationCenter.default
        nc.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) { _ in write("app in background") }
        nc.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) { _ in write("app in foreground") }
        nc.addObserver(forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: nil) { _ in write("phone locked") }
        nc.addObserver(forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: nil) { _ in write("phone unlocked") }
    }

    /// The log is kept to about 2 MB: past 1 MB it becomes "debug.old.log", replacing the one before. Neither goes in a backup.
    private static let maxBytes: UInt64 = 1 << 20
    private static let old = url.deletingLastPathComponent().appendingPathComponent("debug.old.log")

    static func write(_ s: String) {
        let line = Data("\(Int64(Date().timeIntervalSince1970 * 1000)) \(s)\n".utf8)
        lock.lock(); defer { lock.unlock() }
        if let h = try? FileHandle(forWritingTo: url) {
            let end = (try? h.seekToEnd()) ?? 0
            try? h.write(contentsOf: line)
            try? h.close()
            if end + UInt64(line.count) > maxBytes {
                try? FileManager.default.removeItem(at: old)
                try? FileManager.default.moveItem(at: url, to: old)
                var u = old, v = URLResourceValues(); v.isExcludedFromBackup = true; try? u.setResourceValues(v) // a log an earlier version began
            }
        } else {
            try? line.write(to: url)
            var u = url, v = URLResourceValues(); v.isExcludedFromBackup = true; try? u.setResourceValues(v)
        }
    }
}
#endif
