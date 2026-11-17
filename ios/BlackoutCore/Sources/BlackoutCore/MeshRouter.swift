import Foundation
import CryptoKit

/// Flooding with deduplication and store-and-forward. No platform dependencies.
/// Same rules as the Android MeshRouter (spec/FORMAT.md, "Forwarding rules").
/// `send` is called while the router's lock is held, so it must hand the packet off without blocking.
public final class MeshRouter: @unchecked Sendable { // all state is guarded by `lock`
    /// Hops a new packet gets. A received packet with more (v0.4 decoding allows up to 64) is lowered to this.
    public static let maxTtl = 16
    /// Packets dated more than this ahead of this phone's clock are dropped (spec/FORMAT.md, "Forwarding rules").
    public static let maxFutureMs: Int64 = 10 * 60_000
    public static func inFuture(_ ts: Int64, now: Int64) -> Bool { ts > now + maxFutureMs }
    public static func clamp(_ p: Packet) -> Packet { p.ttl > maxTtl ? p.withTtl(maxTtl) : p }

    private let send: (_ peer: String, _ p: Packet) -> Void
    private let deliver: (Packet) -> Void
    private let raised: (Packet) -> Void
    private let now: () -> Int64
    private let retentionMs: Int64
    private let maxStored: Int
    private let lock = NSRecursiveLock() // re-entrant, like Kotlin's @Synchronized
    private var peers: [String] = []     // insertion-ordered set
    private var seen = Set<String>(), seenBefore = Set<String>() // two generations: old ones are forgotten
    private var rotatedAt: Int64
    private var order: [String] = []     // stored keys, oldest first
    private var stored: [String: Packet] = [:]
    private var cameFrom: [String: String] = [:] // key -> the link that brought it (not for this phone's own)
    private var raisedByOther = Set<String>()    // keys whose stored copy came, with more hops, from another link than the first
    private var held: [String: Int] = [:]        // sender -> packets of it stored here
    private let minCipher: Int, maxPerMinute: Int, unlimited: (String) -> Bool
    private var pace: [String: (start: Int64, n: Int)] = [:] // sender -> this minute's new packets
    // A link id names one connection, and a neighbour can open as many as it likes: the limits count per sender. That
    // is the address at the link's other end, when the link says one (`peerUp`); else the link itself.
    private var senders: [String: String] = [:]   // link -> its sender, for the links that are up
    private var chargedTo: [String: String] = [:] // key -> the sender it counts against (not for this phone's own)
    private var paceSwept: Int64
    /// A link that takes its packets in pieces (`peerUp` with room): how much its queue still takes, and how far it got.
    private struct Window { let maxBytes: Int, maxPackets: Int; var bytes: Int, packets: Int, at: Int64 = 0 }
    private var windows: [String: Window] = [:]
    private var arrival: [String: Int64] = [:]    // key -> the order it was stored in
    private var arrivals: Int64 = 0
    /// Who the packets that were here before a restart count against, all together, when nothing says who brought them.
    public static let restored = "restored"
    /// The smallest real packet: IV, tag, signature and three empty text fields. Anything shorter is junk.
    public static let minSealed = 12 + 16 + 64 + 6
    /// New packets taken from one link in a minute: far more than phones really send, so a flood costs its sender time.
    public static let linkPerMinute = 3_000
    private static let maxSeen = 50_000 // packets remembered, so a stream of new ones can't fill the memory

    /// What makes two packets the same: the id, the header time and the content. An id alone isn't enough: someone who
    /// sees an id could send junk under it first, and the real packet would then be dropped as a duplicate. The seal is
    /// bound to the header time, so a copy with another time can't be opened: it is a different packet too. The ttl is
    /// left out, because it changes on every hop.
    public static func key(_ p: Packet) -> String {
        var h = SHA256()
        withUnsafeBytes(of: UInt64(bitPattern: p.ts).bigEndian) { h.update(bufferPointer: $0) }
        h.update(data: p.cipher)
        return p.id + ":" + h.finalize().prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// `raised`: a copy of a stored packet came with more hops left; the caller saves the higher ttl, so it survives a
    /// restart. Called, like `send`, while the router's lock is held.
    public init(send: @escaping (_ peer: String, _ p: Packet) -> Void,
                deliver: @escaping (Packet) -> Void,
                now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
                retentionMs: Int64 = 7 * 24 * 3_600_000,
                maxStored: Int = 500,
                minCipher: Int = 0, maxPerMinute: Int = 0, unlimited: @escaping (String) -> Bool = { _ in false },
                raised: @escaping (Packet) -> Void = { _ in }) {
        self.send = send; self.deliver = deliver; self.raised = raised; self.now = now
        self.retentionMs = retentionMs; self.maxStored = maxStored
        self.minCipher = minCipher; self.maxPerMinute = maxPerMinute; self.unlimited = unlimited
        rotatedAt = now(); paceSwept = rotatedAt
    }

    public var peerCount: Int { locked { peers.count } }

    /// After a restart: `all` is passed on again; `seenIds` are packets already handled (`key`), so they aren't shown twice.
    /// Packets dated in the future are left out. Peers already linked get the packets that are new to the router.
    /// `from`: the link that brought a packet (`key`) before the restart, if the caller kept that ("" if not): the
    /// packet doesn't go back to it (the relays, see `FromRelays`). Only the newest `maxStored` are taken, whoever
    /// brought them: which packets come back must not depend on what the caller knows about them. The packets nobody is
    /// named for count together as one sender's (`restored`), not as this phone's own: a neighbour's packets saved
    /// before the restart must not hold the store against what links bring afterwards.
    public func restore(_ all: [Packet], seenIds: Set<String> = [], from: (String) -> String = { _ in "" }) {
        locked {
            seen.formUnion(seenIds)
            let t = now()
            let known = all.filter { !Self.inFuture($0.ts, now: t) && stored[Self.key($0)] == nil }.sorted { $0.ts < $1.ts }
            for p in known { seen.insert(Self.key(p)) }
            let fresh = known.suffix(maxStored).map(Self.clamp)
            for p in fresh { let f = from(Self.key(p)); keep(p, from: f, pays: f.isEmpty ? Self.restored : sender(f)) }
            for p in fresh {
                let k = Self.key(p)
                if stored[k] != nil { for peer in peers where cameFrom[k] != peer { forward(peer, p) } }
            }
        }
    }

    /// A packet made on this phone. `from`: empty for this phone's own; a label no link uses for packets other people
    /// typed here (Android's Wi-Fi board), so they count against one share of the store, like the packets of one link.
    public func publish(_ p: Packet, from: String = "") { locked { seen.insert(Self.key(p)); keep(p, from: from); for peer in peers { forward(peer, p) } } }

    /// Where this very packet (`key`) came from: the link that brought it; "" if this phone made it or held it before
    /// a restart; nil if it isn't held for passing on. Another packet sent under the same id has its own answer, so
    /// the caller can tell a packet this phone wrote from one that only carries its id. May be called from `send`.
    public func source(_ p: Packet) -> String? { locked { let k = Self.key(p); return stored[k] == nil ? nil : cameFrom[k] ?? "" } }

    /// The link's minute is kept: closing a link and opening another doesn't start a new one.
    public func peerDown(_ peer: String) { locked { peers.removeAll { $0 == peer }; senders[peer] = nil; windows[peer] = nil } }

    /// A link that comes up gets everything stored, except what it brought itself: it has that already, and a packet
    /// that came from the relays never goes back up (spec/FORMAT.md, "Publish"). A packet another link brought later
    /// with more hops left does go to it.
    /// `sender`: who is at the other end, if the link layer can tell (an address): all links of one sender share one
    /// allowance (spec/FORMAT.md, "Limits on links"). nil leaves what was said before.
    /// `roomBytes`, `roomPackets`: for a link with a small send queue (Bluetooth): what the queue takes. Such a link gets
    /// the stored packets oldest first as far as they fit, and the rest, like every later packet, as it reports room
    /// again (`room`): what doesn't fit waits here, instead of pushing older packets out of the link's queue. Called
    /// again without room for a link that has it, everything stored goes to it once more, in pieces as before.
    public func peerUp(_ peer: String, sender: String? = nil, roomBytes: Int = 0, roomPackets: Int = 0) {
        locked {
            if !peers.contains(peer) { peers.append(peer) }
            prune()
            if let sender { senders[peer] = sender }
            if roomBytes > 0 && roomPackets > 0 {
                windows[peer] = Window(maxBytes: roomBytes, maxPackets: roomPackets, bytes: roomBytes, packets: roomPackets)
            }
            if windows[peer] != nil { windows[peer]?.at = 0; hand(peer) }
            else { for k in order { if let p = stored[k], cameFrom[k] != peer || raisedByOther.contains(k) { forward(peer, p) } } }
        }
    }

    /// A link that takes its packets in pieces sent `bytes` of `packets` packets (or dropped them): it has that much room again.
    public func room(_ peer: String, bytes: Int, packets: Int) {
        locked {
            guard var w = windows[peer] else { return }
            w.bytes = min(w.bytes + bytes, w.maxBytes); w.packets = min(w.packets + packets, w.maxPackets)
            windows[peer] = w
            hand(peer)
        }
    }

    /// Packets older than 7 days or more than 10 minutes in the future are dropped; ttl above 16 is lowered to 16. A copy
    /// of a packet still stored here that has more hops left replaces it and is passed on again: the ttl isn't
    /// authenticated, so a copy that came first with a low one must not decide how far the packet goes.
    /// True if the packet was new to this phone, so `from` is the link that brought it.
    @discardableResult public func receive(from: String, _ packet: Packet) -> Bool {
        locked { () -> Bool in
            let t = now()
            guard packet.ts >= t - retentionMs, !Self.inFuture(packet.ts, now: t), packet.cipher.count >= minCipher else { return false }
            let k = Self.key(packet)
            if seen.contains(k) || seenBefore.contains(k) {
                guard let had = stored[k] else { return false }
                let p = Self.clamp(packet)
                guard p.ttl > had.ttl, paced(from, t) else { return false } // the ttl must rise each time: at most 15 times a packet
                stored[k] = p; raised(p)
                if cameFrom[k] != from { raisedByOther.insert(k) }
                for peer in peers where peer != from { forward(peer, p, raised: k) }
                return false
            }
            guard paced(from, t) else { return false } // not marked as seen: it can still come later, or from someone else
            if t - rotatedAt > retentionMs || seen.count > Self.maxSeen { seenBefore = seen; seen = []; rotatedAt = t }
            seen.insert(k)
            let p = Self.clamp(packet)
            keep(p, from: from); deliver(p)
            for peer in peers where peer != from { forward(peer, p) }
            return true
        }
    }

    /// Counts one more packet taken from `from`. False once its sender is over its share of this minute.
    private func paced(_ from: String, _ t: Int64) -> Bool {
        guard maxPerMinute > 0, !unlimited(from) else { return true }
        if t - paceSwept >= 60_000 { pace = pace.filter { t - $0.value.start < 60_000 }; paceSwept = t } // minutes that are over
        let s = sender(from)
        var w = pace[s] ?? (t, 0)
        if t - w.start >= 60_000 { w = (t, 0) }
        w.n += 1
        pace[s] = w
        return w.n <= maxPerMinute
    }

    private func sender(_ from: String) -> String { senders[from] ?? from }
    /// `raised`: the key, when `p` is a copy with more hops of a packet that was stored before.
    private func forward(_ peer: String, _ p: Packet, raised: String? = nil) {
        guard let w = windows[peer] else { if p.ttl > 1 { send(peer, p.withTtl(p.ttl - 1)) }; return }
        // A link that takes its packets in pieces gets them in the order they were stored, as far as its queue has room.
        if let raised, (arrival[raised] ?? 0) <= w.at { // it has this one, with fewer hops: the new copy goes at once
            if p.ttl > 1 { windows[peer]?.bytes -= size(p); windows[peer]?.packets -= 1; send(peer, p.withTtl(p.ttl - 1)) }
        } else { hand(peer) }
    }
    private func size(_ p: Packet) -> Int { Packet.headerSize + p.cipher.count } // the encoded packet
    /// The stored packets `peer` hasn't had yet, oldest first, while its queue has room for the next one.
    private func hand(_ peer: String) {
        guard let start = windows[peer], start.at < arrivals else { return }
        for k in order {
            guard let w = windows[peer] else { return } // read anew each time: `send` may report room straight away
            guard let p = stored[k], let n = arrival[k], n > w.at else { continue }
            if p.ttl > 1 && (cameFrom[k] != peer || raisedByOther.contains(k)) {
                let empty = w.bytes >= w.maxBytes && w.packets >= w.maxPackets // an empty queue takes one packet, whatever its size
                if !empty && (w.packets < 1 || w.bytes < size(p)) { return }
                windows[peer]?.bytes -= size(p); windows[peer]?.packets -= 1; windows[peer]?.at = n
                send(peer, p.withTtl(p.ttl - 1))
            } else { windows[peer]?.at = n }
        }
    }
    private func keep(_ p: Packet, from: String, pays: String? = nil) {
        let k = Self.key(p)
        if stored[k] == nil {
            order.append(k)
            arrivals += 1; arrival[k] = arrivals
            if !from.isEmpty { cameFrom[k] = from }
            let who = pays ?? sender(from)
            if !who.isEmpty { chargedTo[k] = who; held[who, default: 0] += 1 }
        }
        stored[k] = p
        prune()
    }
    private func forget(_ k: String) {
        stored[k] = nil; raisedByOther.remove(k); arrival[k] = nil; cameFrom[k] = nil
        if let f = chargedTo.removeValue(forKey: k) { let n = held[f, default: 1] - 1; held[f] = n > 0 ? n : nil }
    }
    private func prune() {
        let cut = now() - retentionMs
        order.removeAll { k in
            guard let p = stored[k], p.ts >= cut else { forget(k); return true }
            return false
        }
        while order.count > maxStored {
            // One sender can't push everyone else's packets out: while it holds more than a quarter, its own oldest go first.
            // And however many senders there are, what they bring can't push out what this phone wrote: while the
            // packets that came from elsewhere hold more than half, the oldest of those goes.
            var i = 0
            if let top = held.max(by: { $0.value < $1.value }), top.value > maxStored / 4, let j = order.firstIndex(where: { chargedTo[$0] == top.key }) { i = j }
            else if chargedTo.count > maxStored / 2, let j = order.firstIndex(where: { chargedTo[$0] != nil }) { i = j }
            forget(order.remove(at: i))
        }
    }
    private func locked<T>(_ f: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return f() }
}

/// Which stored packets to remove when the store is over its cap (spec/FORMAT.md, "Storage"): first packets no saved
/// group can read, oldest first, then the oldest Public messages, and only then the oldest messages and receipts of
/// the saved groups. Same rules as the Android StoreCap.
public enum StoreCap {
    public static let maxBytes = 40 * 1024 * 1024
    public static let maxCount = 20_000
    /// The room `.door` packets have inside the cap, all saved groups together.
    public static let doorBytes = 4 * 1024 * 1024
    public static let doorCount = 1_000
    /// In the order they go: `.unreadable` first, `.group` last. `.door`: an introduction or a new key that came through a
    /// saved group's door from someone who isn't in that group (`door(mine:member:)`). The door opens with the code alone,
    /// so these are not the group's own: they have a small room of their own and never push a message out.
    public enum Kind: Int, Sendable { case unreadable, door, isPublic, group }
    /// `id`: what the packet goes by in the store (`name`). `size`: the encoded packet's length.
    public struct Entry: Sendable {
        public let id: String, ts: Int64, size: Int, kind: Kind
        public init(id: String, ts: Int64, size: Int, kind: Kind) { self.id = id; self.ts = ts; self.size = size; self.kind = kind }
    }

    /// Ids to remove so that at most `maxBytes` and `maxCount` remain, and of `.door` packets at most `doorBytes` and
    /// `doorCount`, their oldest first; empty if the store fits.
    public static func overflow(_ entries: some Collection<Entry>, maxBytes: Int = maxBytes, maxCount: Int = maxCount,
                                doorBytes: Int = doorBytes, doorCount: Int = doorCount) -> [String] {
        var out: [String] = []
        let door = entries.filter { $0.kind == .door }
        var held = door.reduce(0) { $0 + $1.size }, n = door.count
        if held > doorBytes || n > doorCount {
            for e in door.sorted(by: { ($0.ts, $0.id) < ($1.ts, $1.id) }) {
                if held <= doorBytes && n <= doorCount { break }
                out.append(e.id); held -= e.size; n -= 1
            }
        }
        let gone = Set(out)
        let rest = gone.isEmpty ? Array(entries) : entries.filter { !gone.contains($0.id) }
        var bytes = rest.reduce(0) { $0 + $1.size }, count = rest.count
        guard bytes > maxBytes || count > maxCount else { return out }
        for e in rest.sorted(by: { ($0.kind.rawValue, $0.ts, $0.id) < ($1.kind.rawValue, $1.ts, $1.id) }) {
            if bytes <= maxBytes && count <= maxCount { break }
            out.append(e.id); bytes -= e.size; count -= 1
        }
        return out
    }

    /// The class of a packet a saved group's door opened: an introduction that checks, or a new key. `mine`: this phone
    /// wrote it. `member`: it is signed by someone in the group (`Keyring.inGroup`).
    public static func door(mine: Bool, member: Bool) -> Kind { mine || member ? .group : .door }

    /// True once the `.door` packets take twice their room: the store is then trimmed without waiting for the cap.
    public static func doorFull(count: Int, bytes: Int) -> Bool { count > 2 * doorCount || bytes > 2 * doorBytes }

    /// What a packet goes by in the store and, if it is a message, in the chat. `first`: no packet is stored under its
    /// id yet. The first one goes by the id; any other packet with that id goes by its key (`MeshRouter.key`), so that
    /// every packet has a place of its own: whoever sends something first under an id doesn't keep the real packet out.
    public static func name(_ p: Packet, first: Bool) -> String { first ? p.id : MeshRouter.key(p) }

    /// The packet id inside a `name`.
    public static func packetId(_ name: String) -> String { String(name.prefix(16)) }

    /// A packet of the Everyone channel, for `everyone`. `holder`: who it counts for: its sender if the signature
    /// checked, and one name for all senders that couldn't be checked, one for all introductions. `own`: this phone's.
    public struct Held: Sendable {
        public let id: String, ts: Int64, holder: String, own: Bool
        public init(id: String, ts: Int64, holder: String, own: Bool = false) { self.id = id; self.ts = ts; self.holder = holder; self.own = own }
    }

    /// The Everyone channel keeps `max` packets (spec/FORMAT.md, "Storage on the phone"): the ids to remove when there
    /// are more. As in the router's store: while one holder has more than a quarter of `max`, its own oldest go first,
    /// so one sender can't push everyone else's messages and places out; otherwise the oldest of all. This phone's own
    /// go last, only when nothing else is left.
    public static func everyone(_ entries: some Collection<Held>, max: Int) -> [String] {
        var over = entries.count - max
        guard over > 0 else { return [] }
        let oldestFirst: (Held, Held) -> Bool = { ($0.ts, $0.id) < ($1.ts, $1.id) }
        let others = entries.filter { !$0.own }.sorted(by: oldestFirst)
        var first: [String: Int] = [:], left: [String: Int] = [:], of: [String: [Int]] = [:] // holder -> its packets (indexes into others), oldest first
        for (n, e) in others.enumerated() { of[e.holder, default: []].append(n); left[e.holder, default: 0] += 1 }
        var big = Set(left.filter { $0.value > max / 4 }.keys) // the holders over a quarter: few
        var out: [String] = [], gone = Set<Int>(), next = 0
        while over > 0 && out.count < others.count {
            let n: Int
            if let top = big.max(by: { (left[$0]!, $0) < (left[$1]!, $1) }) {
                n = of[top]![first[top, default: 0]]
                if left[top]! - 1 <= max / 4 { big.remove(top) }
            } else {
                while gone.contains(next) { next += 1 }
                n = next // the oldest of all is its holder's oldest
            }
            let h = others[n].holder
            first[h, default: 0] += 1; left[h]! -= 1
            gone.insert(n); out.append(others[n].id); over -= 1
        }
        if over > 0 { out += entries.filter(\.own).sorted(by: oldestFirst).prefix(over).map(\.id) }
        return out
    }
}

/// People asking to join a group (spec/FORMAT.md, "Joining"). Anyone with the code can introduce as many made-up keys
/// as they like through the door, so a phone keeps the keys of at most `maxAsking` people who aren't in the group, the
/// first to ask: a flood can't bury the chat under requests, and can't push out one that is waiting. Same as Android's.
public enum Joining {
    public static let maxAsking = 20
    public static let alertEveryMs: Int64 = 60_000

    /// Who is asking, by the date of their introduction, at most `maxAsking`. `introduced`: member id -> the date of the
    /// introduction that brought the key this phone keeps for them; older than 7 days no longer counts. `members`: the
    /// current epoch's; `declined`: turned down on this phone.
    public static func asking(_ introduced: [String: Int64], members: Set<String>, declined: Set<String>, me: String, now: Int64) -> [String] {
        introduced.filter { id, at in id != me && !members.contains(id) && !declined.contains(id) && at >= now - Keyring.keepMs }
            .sorted { ($0.value, $0.key) < ($1.value, $1.key) }.prefix(maxAsking).map(\.key)
    }

    /// True if the key of `id`, which this phone doesn't know yet, is kept: this phone's own, that of someone in a member
    /// list it holds (`listed`, `Keyring.everyone`), or there is room among those `asking`.
    public static func keeps(_ id: String, asking: [String], listed: Set<String>, me: String) -> Bool {
        id == me || listed.contains(id) || asking.count < maxAsking
    }

    /// True if an "asks to join" alert may be raised in a group whose last one was at `last`: at most one a minute.
    public static func alertDue(last: Int64, now: Int64) -> Bool { now - last >= alertEveryMs || now < last }
}

/// When a phone sends its introduction to the Public channel (spec/FORMAT.md, "Introductions"): when its user writes
/// there, and after that only while one of its own Everyone posts is still shown (7 days), so that readers can check
/// it. A phone whose user never posts on Everyone never announces itself there. Same as Android's PublicIntro.
public enum PublicIntro {
    public static let shownMs: Int64 = 7 * 24 * 3_600_000
    /// `writing`: a post to Everyone is being written now. `lastOwnPost`: the time of this phone's newest Everyone post, nil if it has none.
    public static func wanted(writing: Bool, lastOwnPost: Int64?, now: Int64) -> Bool {
        writing || lastOwnPost.map { now - $0 < shownMs } ?? false
    }
}

/// Two links between the same two phones (spec/FORMAT.md, "Wi-Fi networks"): which one stays. When both phones dialed
/// each other at about the same time (the older link is less than 10 s old), the link dialed by the smaller node id
/// stays, so both phones keep the same one. Otherwise, or when the same phone dialed both, the new link replaces the
/// old one: after a restart the old one may be dead without either side knowing. Same as the Android DuplicateLinks.
public enum DuplicateLinks {
    public static let sameTimeMs: Int64 = 10_000
    public static func keepNew(myId: String, remoteId: String, newDialedByMe: Bool, oldDialedByMe: Bool, oldAgeMs: Int64) -> Bool {
        if newDialedByMe == oldDialedByMe || oldAgeMs >= sameTimeMs { return true }
        let meSmaller = BleProtocol.keepMyCentralLink(myId: myId, remoteId: remoteId) // byte comparison of the node ids
        return newDialedByMe ? meSmaller : !meSmaller
    }
}

/// Who gets a place when links or connections run out, and which addresses are on the local network (spec/FORMAT.md,
/// "Node ids prove nothing", "Wi-Fi networks"). Pure rules, the same as Android's LinkLimits.
public enum LinkLimits {
    /// Wi-Fi links one address may hold: several phones can sit behind one address, but one device must not take every place.
    public static let perAddress = 8
    /// Connections that haven't said HELLO yet, and how many of them one address may have.
    public static let waiting = 16
    public static let waitingPerAddress = 4
    /// Discovered devices being dialed at once, and how many are remembered.
    public static let dials = 8
    public static let found = 256
    /// With every place taken and nobody holding more than one, a link at random gives way, at most once in this time.
    public static let rotateMs: Int64 = 30_000
    public enum Place: Equatable, Sendable { case room, full, giveWay(Int) }

    /// Whether `address` can have one more of `max` places. `held`: the address of each holder, oldest first. `.room`
    /// if there is one; else the index of the holder that gives way: the oldest of `address` itself once it has
    /// `perAddress`, else the oldest of the address that holds the most, if that is more than one; `.full` if every
    /// holder has a different address (the caller then decides: a link at random, or the one that waited longest).
    public static func giveWay(_ held: [String], address: String, max: Int, perAddress: Int) -> Place {
        if held.filter({ $0 == address }).count >= perAddress, let i = held.firstIndex(of: address) { return .giveWay(i) }
        if held.count < max { return .room }
        var counts: [String: Int] = [:]
        for a in held { counts[a, default: 0] += 1 }
        // of the addresses that hold the most, the one whose oldest link is oldest
        guard let top = counts.values.max(), top > 1, let i = held.firstIndex(where: { counts[$0] == top }) else { return .full }
        return .giveWay(i)
    }

    /// Whether an address (4 or 16 bytes) is on a local network: private or link-local (10/8, 172.16/12, 192.168/16,
    /// 169.254/16, fe80::/10, fc00::/7), or in the same network as `mine`, this phone's own address on that connection
    /// (the first 24 bits for IPv4, 64 for IPv6). Loopback isn't: that is another app on this phone.
    public static func local(_ address: [UInt8], mine: [UInt8]? = nil) -> Bool {
        let a = unmapped(address), m = mine.map(unmapped)
        func same(_ n: Int) -> Bool { guard let m, m.count == a.count else { return false }; return m.prefix(n) == a.prefix(n) }
        switch a.count {
        case 4:
            guard a[0] != 127 else { return false }
            return a[0] == 10 || (a[0] == 172 && (16...31).contains(a[1])) || (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254) || (a[0] != 0 && same(3))
        case 16:
            if a.prefix(15).allSatisfy({ $0 == 0 }) && a[15] <= 1 { return false }
            return (a[0] == 0xfe && a[1] & 0xc0 == 0x80) || a[0] & 0xfe == 0xfc || same(8)
        default: return false
        }
    }
    /// An IPv4 address written as IPv6 (::ffff:a.b.c.d) is that IPv4 address.
    private static func unmapped(_ a: [UInt8]) -> [UInt8] {
        a.count == 16 && a.prefix(10).allSatisfy({ $0 == 0 }) && a[10] == 0xff && a[11] == 0xff ? Array(a[12...]) : a
    }
}

/// An ordered set of ids that forgets the oldest beyond `max`, for lists saved on the phone. Not thread-safe.
public struct RecentIds: Sendable {
    private let max: Int
    private var order: [String] = []
    private var set = Set<String>()
    public init(max: Int, _ initial: [String] = []) { self.max = max; initial.forEach { add($0) } }
    /// True if `id` is new.
    @discardableResult public mutating func add(_ id: String) -> Bool {
        guard set.insert(id).inserted else { return false }
        order.append(id)
        if order.count > max { let n = order.count - max; order.prefix(n).forEach { set.remove($0) }; order.removeFirst(n) }
        return true
    }
    public func contains(_ id: String) -> Bool { set.contains(id) }
    public var count: Int { order.count }
    public var list: [String] { order }
}
