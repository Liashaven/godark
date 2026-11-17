import Foundation
import CryptoKit

/// One sender's message keys in an epoch (spec "Message keys"): the leaves of a 16-level binary tree. A leaf can be used
/// and deleted in any order, because packets on a mesh arrive late and out of order. What is kept is only the nodes that
/// still lead to unused leaves, so nothing here can bring back a key that was deleted. Node ids: root 1, children 2x and 2x+1.
/// Not thread-safe: `MessageKeys` guards it. Same as Android's.
final class SenderTree {
    static let depth = 16, leaves = 1 << 16, maxNodes = 4096
    private(set) var nodes: [Int: Data]

    init(root: Data) { nodes = [1: root] }
    init(nodes: [Int: Data]) { self.nodes = nodes }

    private func holder(_ leaf: Int) -> Int { var at = leaf; while at >= 1 && nodes[at] == nil { at >>= 1 }; return at }
    private func level(_ node: Int) -> Int { Int.bitWidth - 1 - node.leadingZeroBitCount }
    private static func child(_ k: Data, _ b: Int) -> Data { MessageKeys.hmac(k, Data([UInt8(b)])) }

    /// Leaf `i`, or nil if it was deleted. Deletes nothing.
    func key(_ i: Int) -> Data? {
        guard (0..<Self.leaves).contains(i) else { return nil }
        let leaf = Self.leaves | i, at = holder(leaf)
        guard at >= 1, var k = nodes[at] else { return nil }
        var bit = Self.depth - level(at) - 1
        while bit >= 0 { k = Self.child(k, (leaf >> bit) & 1); bit -= 1 }
        return k
    }

    /// Deletes leaf `i`, keeping the branches that lead to every other leaf. Nothing happens if it is already gone.
    func forget(_ i: Int) {
        guard (0..<Self.leaves).contains(i), nodes.count < Self.maxNodes else { return }
        let leaf = Self.leaves | i
        var at = holder(leaf)
        guard at >= 1, var k = nodes.removeValue(forKey: at) else { return }
        var bit = Self.depth - level(at) - 1
        while bit >= 0 {
            let b = (leaf >> bit) & 1
            nodes[(at << 1) | (1 - b)] = Self.child(k, 1 - b)
            k = Self.child(k, b); at = (at << 1) | b; bit -= 1
        }
    }
}

/// Every member's message keys in one epoch, and how far this phone has got with its own (spec "Message keys"). Any thread.
public final class MessageKeys: @unchecked Sendable { // guarded by lock
    public let members: [String]
    private let trees: [SenderTree]
    private var next: Int
    private let lock = NSLock()

    init(members: [String], trees: [SenderTree], next: Int = 0) { self.members = members; self.trees = trees; self.next = next }

    static func hmac(_ key: Data, _ msg: Data) -> Data { Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key))) }

    /// What an epoch's random secret becomes for mailboxes, receipts and headers; the secret itself isn't kept.
    public static func outer(_ secret: Data) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), info: Data("darkproof-epoch-outer-v1".utf8), outputByteCount: 32).withUnsafeBytes { Data($0) }
    }

    public static func of(_ secret: Data, members: [String]) -> MessageKeys {
        MessageKeys(members: members, trees: members.map { SenderTree(root: hmac(secret, Data("darkproof-tree-v1".utf8) + Hex.decode($0))) })
    }

    public func index(_ member: String) -> Int? { members.firstIndex(of: member) }

    /// The key of `sender`'s message number `n`, if it is still there.
    public func key(_ sender: Int, _ n: Int) -> Data? {
        lock.withLock {
            guard trees.indices.contains(sender), let leaf = trees[sender].key(n) else { return nil }
            return Self.hmac(leaf, Data("darkproof-message-v1".utf8))
        }
    }

    public func forget(_ sender: Int, _ n: Int) { lock.withLock { if trees.indices.contains(sender) { trees[sender].forget(n) } } }

    /// The number of this phone's next message, or nil when an epoch's numbers have run out.
    public func takeNext() -> Int? { lock.withLock { guard next < SenderTree.leaves else { return nil }; defer { next += 1 }; return next } }

    public func encode() -> Data {
        lock.withLock {
            var d = Data()
            func be32(_ v: Int) { d.append(contentsOf: [UInt8(v >> 24 & 255), UInt8(v >> 16 & 255), UInt8(v >> 8 & 255), UInt8(v & 255)]) }
            func be16(_ v: Int) { d.append(contentsOf: [UInt8(v >> 8 & 255), UInt8(v & 255)]) }
            be32(next); be16(members.count)
            members.forEach { d.append(Hex.decode($0)) }
            for t in trees { be16(t.nodes.count); for (id, k) in t.nodes.sorted(by: { $0.key < $1.key }) { be32(id); d.append(k) } }
            return d
        }
    }

    public static func decode(_ data: Data) -> MessageKeys? {
        let b = [UInt8](data); var i = 0
        func take(_ n: Int) -> ArraySlice<UInt8>? { guard i + n <= b.count else { return nil }; defer { i += n }; return b[i..<(i + n)] }
        func int(_ n: Int) -> Int? { take(n).map { $0.reduce(0) { $0 << 8 | Int($1) } } }
        guard let next = int(4), let n = int(2) else { return nil }
        var members: [String] = [], trees: [SenderTree] = []
        for _ in 0..<n { guard let m = take(8) else { return nil }; members.append(Hex.encode(Data(m))) }
        for _ in 0..<n {
            guard let c = int(2) else { return nil }
            var nodes: [Int: Data] = [:]
            for _ in 0..<c { guard let id = int(4), let k = take(32) else { return nil }; nodes[id] = Data(k) }
            trees.append(SenderTree(nodes: nodes))
        }
        return MessageKeys(members: members, trees: trees, next: next)
    }
}

/// Which message key opened a packet: deleted once its signature has checked.
public struct Leaf: Sendable {
    public let epoch: Keyring.Epoch, index: Int, counter: Int
    public init(epoch: Keyring.Epoch, index: Int, counter: Int) { self.epoch = epoch; self.index = index; self.counter = counter }
    public func forget() { epoch.messageKeys?.forget(index, counter) }
}

/// This phone's readable copy of a message whose key it has deleted (spec "Message keys"), sealed with a key that stays
/// on the phone. It goes when the packet goes or the epoch does, so history lasts as long as before.
public enum History {
    public struct Saved: Sendable { public let group: String, epoch: String, opened: GroupCrypto.Opened, index: Int, counter: Int }

    private static func field(_ d: inout Data, _ b: Data) {
        d.append(contentsOf: [UInt8(b.count >> 24 & 255), UInt8(b.count >> 16 & 255), UInt8(b.count >> 8 & 255), UInt8(b.count & 255)]); d.append(b)
    }

    public static func seal(key: Data, id: String, group: String, epoch: String, _ o: GroupCrypto.Opened, index: Int, counter: Int) -> Data? {
        var d = Data()
        withUnsafeBytes(of: o.message.ts.bigEndian) { d.append(contentsOf: $0) }
        d.append(o.digest); d.append(o.signature)
        d.append(contentsOf: [UInt8(index >> 8 & 255), UInt8(index & 255), UInt8(counter >> 24 & 255), UInt8(counter >> 16 & 255), UInt8(counter >> 8 & 255), UInt8(counter & 255)])
        for f in [Data(group.utf8), Data(epoch.utf8), Data(o.message.sender.utf8), Data(o.message.name.utf8), Data(o.message.text.utf8), o.extra ?? Data()] { field(&d, f) }
        return (try? AES.GCM.seal(d, using: SymmetricKey(data: key), authenticating: Data(id.utf8)))?.combined
    }

    public static func open(key: Data, id: String, blob: Data) -> Saved? {
        guard let box = try? AES.GCM.SealedBox(combined: blob), let plain = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: Data(id.utf8)) else { return nil }
        let b = [UInt8](plain); var i = 0
        func take(_ n: Int) -> Data? { guard n >= 0, i + n <= b.count else { return nil }; defer { i += n }; return Data(b[i..<(i + n)]) }
        func int(_ n: Int) -> Int? { take(n).map { $0.reduce(0) { $0 << 8 | Int($1) } } }
        func next() -> Data? { int(4).flatMap(take) }
        func text() -> String? { next().map { String(decoding: $0, as: UTF8.self) } }
        guard let ts = take(8)?.reduce(UInt64(0), { $0 << 8 | UInt64($1) }), let digest = take(32), let sig = take(64), let index = int(2), let counter = int(4),
              let group = text(), let epoch = text(), let sender = text(), let name = text(), let msg = text(), let extra = next() else { return nil }
        var photo: Data?
        if extra.first == Photo.jpeg, extra.count > 1, extra.count - 1 <= Photo.maxBytes { photo = Data(extra.dropFirst()) }
        let m = Message(id: id, ts: Int64(bitPattern: ts), sender: sender, name: name, text: msg, photo: photo)
        return Saved(group: group, epoch: epoch, opened: GroupCrypto.Opened(message: m, signature: sig, digest: digest, extra: extra.isEmpty ? nil : extra), index: index, counter: counter)
    }

    /// True if copy `s` goes with the epochs in `gone`, which this phone has just deleted from its group: the copy goes
    /// when the epoch is deleted (spec "This phone's copy"), at once and not at the next read of the store. A copy kept
    /// before epochs had an id names its epoch by hash: it goes only if no epoch still `held` has that hash or id, since
    /// it would still be shown with that one. Same rule as Android's History.goesWith.
    public static func goes(_ s: Saved, with gone: [Keyring.Epoch], held: [Keyring.Epoch]) -> Bool {
        gone.contains { $0.id == s.epoch } || (gone.contains { $0.hash == s.epoch } && !held.contains { $0.id == s.epoch || $0.hash == s.epoch })
    }

    /// The largest copy a store of copies must read back: `seal` adds about 258 bytes (nonce, tag, lengths, the group id
    /// and the 64-character epoch id) to the fields of a packet of up to `Packet.maxCipher` bytes, so the copy of a legal
    /// message can be longer than any packet. 1 KiB of room covers that.
    public static let maxSealed = Packet.maxCipher + 1_024
}
