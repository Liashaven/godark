import Foundation
import CryptoKit
import Security

/// Member keys and signatures (spec/FORMAT.md, "Member ids", "Signatures", "Person emoji"): P-256 with Apple's own
/// crypto. Same as Android's P256.kt.
public enum MemberKey {
    /// First 8 bytes of SHA-256(public key), as 16 lowercase hex chars.
    public static func id(_ pub: Data) -> String { Hex.encode(Data(SHA256.hash(data: pub)).prefix(8)) }

    /// The 16 emoji indices of a member's public key: the first 96 bits of the hash, 6 bits each.
    public static func emoji(_ pub: Data) -> [Int] {
        let h = Array(SHA256.hash(data: Data("darkproof-person-emoji-v1".utf8) + pub))
        return (0..<16).map { i in
            let bit = 6 * i, at = bit / 8
            return ((Int(h[at]) << 8 | Int(h[at + 1])) >> (10 - bit % 8)) & 63
        }
    }

    /// The key of a 33-byte compressed point, or nil if it isn't one on P-256.
    public static func publicKey(_ compressed: Data) -> P256.Signing.PublicKey? {
        guard compressed.count == 33, compressed.first == 2 || compressed.first == 3 else { return nil }
        return try? P256.Signing.PublicKey(compressedRepresentation: compressed)
    }

    /// Signs the whole signed message (spec "Signatures"); returns r ‖ s.
    public static func sign(_ key: P256.Signing.PrivateKey, _ msg: Data) throws -> Data { try key.signature(for: msg).rawRepresentation }

    /// A checker for one member's key: r ‖ s against SHA-256 of the signed message (`digest`).
    public final class Checker: @unchecked Sendable { // SecKey is thread-safe
        public let pub: Data
        private let key: SecKey?
        public init?(_ compressed: Data) {
            guard let k = MemberKey.publicKey(compressed) else { return nil }
            pub = compressed
            let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                        kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256]
            key = SecKeyCreateWithData(k.x963Representation as CFData, attrs as CFDictionary, nil)
            if key == nil { return nil }
        }
        public func verify(digest: Data, signature raw: Data) -> Bool {
            guard let key, raw.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else { return false }
            return SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, sig.derRepresentation as CFData, nil)
        }
    }
}

/// The `sender` field of a received packet (spec/FORMAT.md, "Member ids"). Same as Android's Senders.
public enum Senders {
    /// A member id: 16 lowercase hex chars.
    public static func isMemberId(_ s: String) -> Bool {
        s.utf8.count == 16 && s.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    /// What the sender of a received message or receipt is called on this phone (`Message.sender`), or nil if the packet
    /// is to be treated like one nobody can open. `wire`: the packet's `sender`; `me`: this phone's member id in the
    /// channel that opened it; `device`: the mark this phone puts on its own messages, which is never sent.
    ///
    /// - A sender has to be a member id, or `web-` and one: no key can ever be known for anything else, so such a packet
    ///   could never be checked.
    /// - Only this phone's member id becomes `device`; that packet's signature is then checked with this phone's own key.
    ///   A `sender` that already equals `device` is refused, whatever its shape: it would be shown as written here.
    public static func shown(wire: String, me: String, device: String) -> String? {
        if wire == device || !isMemberId(wire.hasPrefix("web-") ? String(wire.dropFirst(4)) : wire) { return nil }
        return wire == me ? device : wire
    }
}

/// What waits for a sender's public key (spec/FORMAT.md, "Waiting for a key"): messages shown as "not verified yet" and
/// receipts, each checked when that sender's introduction arrives in its channel (the Public channel, or one group).
/// Same as Android's KeyWait.
///
/// - Packets are told apart by `GroupCrypto.Opened.key`, not by their id: several packets can carry one id, and not each
///   gets a row in the chat (`StoreCap.name`). A message waits only as the one its row shows, so that the check of
///   another packet with that id never marks or removes that row.
/// - Each channel has room for `max` of its own, and when it is full its oldest goes. The Public channel, where anyone
///   can write under ids that are never introduced, can't use up a group's room, nor one group another's.
/// - What waited for a row that left the chat goes with it (`forget`).
public struct KeyWait<Channel: Hashable, Item> {
    /// `row`: the id of the chat row this packet is shown as, or nil for a receipt.
    public struct Entry {
        public let key: String, sender: String, row: String?, item: Item
    }
    private let max: Int
    private var channels: [Channel: [Entry]] = [:]          // channel -> what waits there, oldest first
    private var rows: [String: (channel: Channel, key: String)] = [:] // chat row -> the channel and key of the packet it shows

    public init(max: Int = 1_000) { self.max = max }

    /// A message whose sender's key isn't known. `shown`: the chat row `id` was just made from this very packet. False,
    /// and nothing kept, if it wasn't: the row then shows another packet, and only that one's check may touch it.
    @discardableResult public mutating func message(_ key: String, channel: Channel, sender: String, id: String, shown: Bool, _ item: Item) -> Bool {
        guard shown else { return false }
        if let had = rows[id] { remove(had.channel, had.key) } // the row was made again, from this packet: what waited for the old one is void
        return put(channel, Entry(key: key, sender: Self.plain(sender), row: id, item: item))
    }

    /// A receipt whose sender's key isn't known. False if this very receipt already waits.
    @discardableResult public mutating func receipt(_ key: String, channel: Channel, sender: String, _ item: Item) -> Bool {
        put(channel, Entry(key: key, sender: Self.plain(sender), row: nil, item: item))
    }

    /// The key of member `sender` arrived in `channel`: what waited for it there, oldest first. It no longer waits.
    public mutating func take(channel: Channel, sender: String) -> [Entry] {
        guard let list = channels[channel] else { return [] }
        let out = list.filter { $0.sender == sender }
        for e in out { remove(channel, e.key) }
        return out
    }

    /// The chat rows `ids` are gone (the store was trimmed): nothing waits for them any more.
    public mutating func forget<S: Sequence>(_ ids: S) where S.Element == String {
        for id in ids { if let had = rows[id] { remove(had.channel, had.key) } }
    }

    /// How many packets wait in `channel`.
    public func count(_ channel: Channel) -> Int { channels[channel]?.count ?? 0 }

    private static func plain(_ sender: String) -> String { sender.hasPrefix("web-") ? String(sender.dropFirst(4)) : sender }

    private mutating func put(_ channel: Channel, _ e: Entry) -> Bool {
        var list = channels[channel] ?? []
        if list.contains(where: { $0.key == e.key }) { return false }
        while list.count >= max, let old = list.first {
            list.removeFirst()
            if let row = old.row, rows[row]?.key == old.key { rows[row] = nil }
        }
        list.append(e)
        channels[channel] = list
        if let row = e.row { rows[row] = (channel, e.key) }
        return true
    }

    private mutating func remove(_ channel: Channel, _ key: String) {
        guard var list = channels[channel], let i = list.firstIndex(where: { $0.key == key }) else { return }
        let e = list.remove(at: i)
        if let row = e.row, rows[row]?.key == key { rows[row] = nil }
        channels[channel] = list.isEmpty ? nil : list
    }
}
