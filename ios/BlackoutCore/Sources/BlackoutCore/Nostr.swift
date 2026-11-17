import Foundation
import CryptoKit

/// GoDark packets as Nostr events on public relays (spec/FORMAT.md, "Internet relays"). Same events as the Android
/// app's Nostr.kt. Signing (BIP-340 Schnorr) is passed in, so this file has no secp256k1 dependency.
public enum Nostr {
    public static let kind = 3871              // must match Android's Nostr.KIND
    public static let tagPrefix = "dp1-"
    public static let keepSeconds: Int64 = 7 * 24 * 3600

    public static func tag(_ mailbox: UInt16) -> String { tagPrefix + String(format: "%04x", mailbox) }

    /// NIP-01 string escaping, for computing event ids exactly as relays do.
    public static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    /// The event id: SHA-256 of [0, pubkey, created_at, kind, tags, content] serialized as NIP-01 says.
    public static func eventId(pubkey: String, createdAt: Int64, kind: Int, tags: [[String]], content: String) -> String {
        let t = "[" + tags.map { "[" + $0.map(quote).joined(separator: ",") + "]" }.joined(separator: ",") + "]"
        let ser = "[0,\(quote(pubkey)),\(createdAt),\(kind),\(t),\(quote(content))]"
        return Hex.encode(Data(SHA256.hash(data: Data(ser.utf8))))
    }

    /// A signed event carrying one packet in its mailbox, findable by packet id, kept by relays for 7 days. `sign` makes a BIP-340 signature
    /// of the 32-byte id with the key whose x-only public key is `pubkey` (64 hex chars).
    public static func event(_ p: Packet, pubkey: String, now: Int64 = Int64(Date().timeIntervalSince1970),
                             sign: (Data) -> Data) -> [String: Any] {
        let tags = [["t", tag(Packet.mailbox(of: p.id))], ["x", p.id], ["expiration", String(now + keepSeconds)]]
        let content = p.encode().base64EncodedString()
        let id = eventId(pubkey: pubkey, createdAt: now, kind: kind, tags: tags, content: content)
        return ["id": id, "pubkey": pubkey, "created_at": now, "kind": kind, "tags": tags, "content": content,
                "sig": Hex.encode(sign(Hex.decode(id)))]
    }

    /// A NIP-56 report (kind 1984) of the event that carried a Public message.
    public static func report(eventId reported: String, author: String, pubkey: String,
                              now: Int64 = Int64(Date().timeIntervalSince1970), sign: (Data) -> Data) -> [String: Any] {
        let tags = [["e", reported, "other"], ["p", author]]
        let id = eventId(pubkey: pubkey, createdAt: now, kind: 1984, tags: tags, content: "")
        return ["id": id, "pubkey": pubkey, "created_at": now, "kind": 1984, "tags": tags, "content": "",
                "sig": Hex.encode(sign(Hex.decode(id)))]
    }

    public static func publish(_ event: [String: Any]) -> String { json(["EVENT", event]) }

    /// The Public channel's mailbox (spec/FORMAT.md, "Mailboxes"): worldwide, so it is caught up one page only.
    public static let publicMailbox: UInt16 = 0x9576
    public static let page = 500                    // events per catch-up REQ
    public static let maxPages = 4                  // pages per group mailbox and relay link
    public static let sinceMarginSeconds: Int64 = 1_500 // catch-up starts 25 min before the last time seen: events are dated up to 17 min back, and clocks differ
    /// An event's date: the current time, rounded down to about 17 minutes, so stored events don't give away when they were sent.
    public static func blurred(_ now: Int64) -> Int64 { now - now % 1024 }
    public static let relayPerMinute = 6_000        // messages taken from one relay link in a minute (100 a second)

    /// New events for all these mailboxes, as they arrive. `since` 7 days back so events from phones with a slow clock
    /// still match; `limit` 1 because stored events come from the catch-up REQs.
    public static func live(_ subId: String, mailboxes: [UInt16], now: Int64 = Int64(Date().timeIntervalSince1970)) -> String {
        json(["REQ", subId, ["kinds": [kind], "#t": mailboxes.map(tag), "since": now - keepSeconds, "limit": 1] as [String: Any]])
    }

    /// One catch-up page of one mailbox: the newest `page` events since `since`, and not newer than `until` if set.
    public static func catchUp(_ subId: String, mailbox: UInt16, since: Int64, until: Int64?) -> String {
        var f: [String: Any] = ["kinds": [kind], "#t": [tag(mailbox)], "since": since, "limit": page]
        if let until { f["until"] = until }
        return json(["REQ", subId, f])
    }

    /// A relay's answer to an event: ["OK", event id, accepted, message]. "duplicate:" refusals count as accepted.
    public struct Ok: Sendable {
        public let eventId: String, accepted: Bool, reason: String
        public init(eventId: String, accepted: Bool, reason: String) { self.eventId = eventId; self.accepted = accepted; self.reason = reason }
    }
    public static func ok(_ text: String) -> Ok? {
        guard let a = array(text), a.count >= 3, a[0] as? String == "OK",
              let id = a[1] as? String, let accepted = a[2] as? Bool else { return nil }
        let why = a.count > 3 ? a[3] as? String ?? "" : ""
        return Ok(eventId: id, accepted: accepted || why.lowercased().hasPrefix("duplicate"), reason: why)
    }

    /// The end of a subscription's stored events: ["EOSE", id] (complete) or ["CLOSED", id, reason] (not complete).
    public static func end(_ text: String) -> (subId: String, complete: Bool)? {
        guard let a = array(text), a.count >= 2,
              let type = a[0] as? String, let id = a[1] as? String else { return nil }
        switch type {
        case "EOSE": return (id, true)
        case "CLOSED": return (id, false)
        default: return nil
        }
    }

    /// What makes two copies of a packet the same packet on the relays: its timestamp and cipher (ttl changes on every
    /// hop). First 16 bytes of SHA-256(ts as 8 bytes big-endian ‖ cipher), in hex.
    public static func digest(_ p: Packet) -> String {
        var h = SHA256()
        withUnsafeBytes(of: UInt64(bitPattern: p.ts).bigEndian) { h.update(bufferPointer: $0) }
        h.update(data: p.cipher)
        return Hex.encode(Data(h.finalize().prefix(16)))
    }

    /// Asks which of these packets the relay already has (by the "x" tag), before passing them on.
    public static func have(_ subId: String, packetIds: [String]) -> String {
        json(["REQ", subId, ["kinds": [kind], "#x": packetIds, "limit": packetIds.count] as [String: Any]])
    }

    public static func close(_ subId: String) -> String { json(["CLOSE", subId]) }

    /// A subscription id: `prefix`, then 8 random bytes in hex, new for each link set and each use (spec/FORMAT.md,
    /// "Subscribe"). Nothing in it comes from this phone's clock or is shared with its other link sets, so a relay
    /// can't use it to tell that the links of two groups belong to one phone.
    public static func subId(_ prefix: String) -> String {
        var g = SystemRandomNumberGenerator() // cryptographically secure on Apple platforms
        return prefix + Hex.encode(Data((0..<8).map { _ in UInt8.random(in: .min ... .max, using: &g) }))
    }

    /// The link set a packet goes up on (spec/FORMAT.md, "One set of links per group"): its group's only if this phone
    /// wrote it (`mine`: a message, receipt, introduction or new key); everything it only passes on goes up with the
    /// Public channel's (""). The mailbox in a packet id is whatever its sender chose, so for anyone else's packet it
    /// must never pick a group's links and key: a neighbour could then see, from the key a junk packet came back under,
    /// which mailboxes this phone holds. `boxes`: scope id -> its mailboxes.
    public static func scope(_ packetId: String, mine: Bool, boxes: [String: [UInt16]]) -> String {
        guard mine else { return "" }
        let box = Packet.mailbox(of: packetId)
        return boxes.first { !$0.key.isEmpty && $0.value.contains(box) }?.key ?? ""
    }

    /// True if a link set takes a packet a relay sent on it (spec/FORMAT.md, "Mailboxes of a link"): only a packet of
    /// one of its own `mailboxes`, or the answer to its `#x` lookup in flight (`asked`: the packet ids it named). A
    /// relay chooses what it sends on a link; anything else it sends there is dropped, so it can't plant a packet on
    /// one group's link that this phone would later name on another.
    public static func takes(_ p: Packet, mailboxes: [UInt16], asked: Set<String>) -> Bool {
        mailboxes.contains(Packet.mailbox(of: p.id)) || asked.contains(p.id)
    }

    /// The reason, if this is a relay refusing an event (["OK", id, false, reason]); else nil.
    public static func refusal(_ text: String) -> String? {
        guard let a = array(text), a.count >= 3,
              a[0] as? String == "OK", a[2] as? Bool == false else { return nil }
        return a.count > 3 ? a[3] as? String ?? "" : ""
    }

    /// A refusal that means "slow down": NIP-01's "rate-limited:" and "blocked:", and what relays really say
    /// ("rate limited", "banned: too many rate-limit violations").
    public static func isThrottle(_ reason: String) -> Bool {
        let r = reason.lowercased()
        return ["rate", "banned", "blocked"].contains { r.hasPrefix($0) }
    }

    /// The event that carried a Public packet, as a report names it. Its id is the hash of its own fields, so the id
    /// stands for this author, kind and content; whether the author really signed it is checked when a report is made
    /// (`signed`), not for every event that arrives.
    public struct Subject: Equatable, Sendable {
        public let eventId: String, pubkey: String, sig: String
    }

    /// What a relay sent: a GoDark packet with the event id and author, and its time and subscription (for catching
    /// up), or nil for anything else, also for an event whose id or author isn't 32 bytes of lowercase hex.
    /// `reaches`: the event is one the packet's recipients get, so the packet may count as on the relays.
    /// `subject`: what a report of this packet may name, if the event is fit for that.
    public struct Received {
        public let packet: Packet; public let eventId: String; public let pubkey: String
        public let createdAt: Int64; public let subId: String
        public let reaches: Bool; public let subject: Subject?
    }
    public static func received(_ text: String) -> Received? {
        guard let a = array(text), a.count >= 3,
              a[0] as? String == "EVENT", let e = a[2] as? [String: Any], e["kind"] as? Int == kind,
              let content = e["content"] as? String, let raw = Data(base64Encoded: content), let p = Packet.decode(raw),
              let id = e["id"] as? String, let pub = e["pubkey"] as? String else { return nil }
        let created = (e["created_at"] as? NSNumber)?.int64Value ?? 0
        guard created >= 0 else { return nil } // no event is from before 1970: a hostile relay
        // Kept for reports: a relay can make them as long as a whole message, and a real id or key is never longer.
        guard isHex(id, bytes: 32), isHex(pub, bytes: 32) else { return nil }
        let tags = e["tags"] as? [[String]] // nil if they aren't lists of strings: no real event has anything else
        return Received(packet: p, eventId: id, pubkey: pub, createdAt: created, subId: a[1] as? String ?? "",
                        reaches: tags.map { reaches($0, p, created) } ?? false,
                        subject: tags.flatMap { subject(e, $0, p, id: id, pubkey: pub, created: created, content: content) })
    }

    /// The subscription and date of any event a relay sent, whatever it carries; nil for other messages. A catch-up
    /// counts every event of a page (`CatchUp.frame`): anyone can post events that carry no packet under a mailbox's tag.
    public static func dated(_ text: String) -> (subId: String, createdAt: Int64)? {
        guard let a = array(text), a.count >= 3, a[0] as? String == "EVENT",
              let sub = a[1] as? String, let e = a[2] as? [String: Any] else { return nil }
        return (sub, (e["created_at"] as? NSNumber)?.int64Value ?? 0)
    }

    /// `bytes` bytes of lowercase hex, as NIP-01 writes ids, keys and signatures.
    private static func isHex(_ s: String, bytes: Int) -> Bool {
        s.utf8.count == bytes * 2 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// True if subscribers of the packet's mailbox get this event (spec/FORMAT.md, "Publish"): it carries their tag, no
    /// relay may delete it before the 7 days are over, and it isn't dated before the packet (a catch-up asks by date).
    /// A copy in any other event must not stop this phone from posting the packet.
    private static func reaches(_ tags: [[String]], _ p: Packet, _ created: Int64) -> Bool {
        let box = tag(Packet.mailbox(of: p.id))
        guard tags.contains(where: { $0.count >= 2 && $0[0] == "t" && $0[1] == box }) else { return false }
        let (sum, over) = created.addingReportingOverflow(keepSeconds)
        let kept = over ? Int64.max : sum
        if tags.contains(where: { $0.first == "expiration" && ($0.count >= 2 ? Int64($0[1]) ?? 0 : 0) < kept }) { return false }
        return created >= p.ts / 1000 - sinceMarginSeconds
    }

    /// What a report of `p` may name: only for the Public channel's mailbox, and only if `id` is the hash of the event's own fields.
    private static func subject(_ e: [String: Any], _ tags: [[String]], _ p: Packet, id: String, pubkey: String, created: Int64, content: String) -> Subject? {
        guard Packet.mailbox(of: p.id) == publicMailbox, // only Public messages are reported
              let sig = e["sig"] as? String, isHex(sig, bytes: 64),
              eventId(pubkey: pubkey, createdAt: created, kind: kind, tags: tags, content: content) == id else { return nil }
        return Subject(eventId: id, pubkey: pubkey, sig: sig)
    }

    /// True if `s`'s author signed it (BIP-340). With the id being the hash of the event's fields, the event is then really theirs.
    public static func signed(_ s: Subject) -> Bool {
        guard isHex(s.eventId, bytes: 32), isHex(s.pubkey, bytes: 32), isHex(s.sig, bytes: 64) else { return false }
        return Schnorr.verify(pubkey: Hex.decode(s.pubkey), message: Hex.decode(s.eventId), signature: Hex.decode(s.sig))
    }

    /// A real message from a relay is 4 levels of JSON deep.
    static let maxDepth = 16
    /// A relay's message as an array, or nil. JSONSerialization recurses once per nesting level, and a relay could send
    /// enough levels to run off the end of a background thread's small stack, which ends the app.
    /// A message with a zero byte is refused: JSON text in UTF-8 has none, and JSONSerialization reads bytes that have
    /// them as UTF-16 or UTF-32, where the brackets counted here are not the ones it parses.
    static func array(_ text: String) -> [Any]? {
        var depth = 0, quoted = false, escaped = false
        for b in text.utf8 {
            if b == 0 { return nil }
            if quoted {
                if escaped { escaped = false } else if b == 0x5C { escaped = true } else if b == 0x22 { quoted = false }
            } else if b == 0x22 {
                quoted = true
            } else if b == 0x5B || b == 0x7B {
                depth += 1
                if depth > maxDepth { return nil }
            } else if b == 0x5D || b == 0x7D {
                depth -= 1
            }
        }
        return try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [Any]
    }

    private static func json(_ o: Any) -> String {
        (try? JSONSerialization.data(withJSONObject: o, options: [.withoutEscapingSlashes])).map { String(decoding: $0, as: UTF8.self) } ?? "[]"
    }
}

/// Which relay event a report of a Public message names (spec/FORMAT.md, "Reports"). A relay, and whoever posts to it,
/// chooses everything an EVENT frame says, so: only events whose id is the hash of their own fields are kept
/// (`Nostr.Subject`); they are kept under the very packet they carried (`MeshRouter.key`), so an event with another
/// packet under the same packet id never stands in for it; each relay's first event for a packet stays, so no relay
/// replaces what another sent; and the one named is the first whose signature checks. Not thread-safe. Same as Android's.
public final class ReportSubjects {
    public static let max = 2_000, perPacket = 8
    private struct Seen { let relay: String; let s: Nostr.Subject; var checked = false }
    private let limit: Int
    private var byPacket: [String: [Seen]] = [:], order: [String] = [] // MeshRouter.key -> each relay's first event; oldest packet first
    private var ids: [String: Int] = [:]                                // packet id -> packets kept under it

    public init(max: Int = ReportSubjects.max) { limit = max }

    private func forget(_ key: String) {
        byPacket[key] = nil
        let id = String(key.prefix(while: { $0 != ":" })), n = (ids[id] ?? 1) - 1
        ids[id] = n > 0 ? n : nil
    }

    /// `relay` sent the event `r`.
    public func note(relay: String, _ r: Nostr.Received) {
        guard let s = r.subject else { return }
        let k = MeshRouter.key(r.packet)
        if byPacket[k] == nil {
            byPacket[k] = []; order.append(k); ids[r.packet.id, default: 0] += 1
            while order.count > limit { forget(order.removeFirst()) }
        }
        guard let list = byPacket[k], list.count < Self.perPacket, !list.contains(where: { $0.relay == relay || $0.s == s }) else { return }
        byPacket[k]?.append(Seen(relay: relay, s: s))
    }

    /// True if some relay event carried a packet with this id: only then is it worth finding out which packet the phone shows.
    public func knows(_ packetId: String) -> Bool { ids[packetId] != nil }

    /// The event a report of exactly this packet (`MeshRouter.key`) names: the first one kept whose signature checks.
    /// Nil: the report waits.
    public func of(_ packetKey: String) -> Nostr.Subject? {
        guard var list = byPacket[packetKey] else { return nil }
        while let c = list.first {
            if c.checked || Nostr.signed(c.s) { list[0].checked = true; byPacket[packetKey] = list; return c.s }
            list.removeFirst() // not its author's: a relay made it up
        }
        forget(packetKey); order.removeAll { $0 == packetKey }
        return nil
    }

    public var count: Int { byPacket.count }
}

/// The packets a relay brought this phone first (spec/FORMAT.md, "Publish": they never go back up), remembered across
/// restarts: `MeshRouter.key` of the `max` with the newest packet time. The packets a phone passes on again after a
/// restart are the 500 newest it holds, so every one of them that came from a relay is still in here, whatever a relay
/// sends in between. Saved on the phone as "<key>=<packet time>,…". Thread-safe. Same as Android's FromRelays.
public final class FromRelays: @unchecked Sendable { // all state is guarded by `lock`
    public static let max = 1_000
    public static let pref = "fromRelays"
    private let limit: Int
    private let lock = NSLock()
    private var at: [String: Int64] = [:] // key -> packet time
    private var dirty = false

    public init(_ saved: String = "", max: Int = FromRelays.max) {
        limit = max
        for e in saved.split(separator: ",") {
            guard let i = e.lastIndex(of: "="), i > e.startIndex, let v = Int64(e[e.index(after: i)...]) else { continue }
            at[String(e[..<i])] = v
        }
        trim()
    }

    /// True when something was added since `save()`.
    public var changed: Bool { lock.lock(); defer { lock.unlock() }; return dirty }

    /// A relay brought `p`, and it was new to this phone.
    public func add(_ p: Packet) {
        lock.lock(); defer { lock.unlock() }
        let k = MeshRouter.key(p)
        guard at[k] == nil else { return }
        at[k] = p.ts; trim()
        if at[k] != nil { dirty = true }
    }

    public func contains(_ key: String) -> Bool { lock.lock(); defer { lock.unlock() }; return at[key] != nil }
    public var count: Int { lock.lock(); defer { lock.unlock() }; return at.count }
    public func save() -> String {
        lock.lock(); defer { lock.unlock() }
        dirty = false
        return at.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
    }

    /// Full: the packets with the oldest time go, the ones a restart would pass on last.
    private func trim() {
        while at.count > limit, let oldest = at.min(by: { $0.value < $1.value }) { at[oldest.key] = nil }
    }
}

/// Where the catch-up of each relay and mailbox starts next time (spec/FORMAT.md, "Subscribe"), in seconds, saved on
/// the phone as "<relay url>|<mailbox hex>=<seconds>,…". Same format as Android's RelaySince. Not thread-safe.
public final class RelaySince {
    public static let max = 400
    private var at: [String: Int64] = [:]
    private var order: [String] = []   // oldest change first
    /// True when something moved since `save()`.
    public private(set) var changed = false

    public init(_ saved: String = "") {
        for e in saved.split(separator: ",") {
            guard let i = e.lastIndex(of: "="), let v = Int64(e[e.index(after: i)...]) else { continue }
            let k = String(e[..<i]); if at[k] == nil { order.append(k) }; at[k] = v
        }
    }
    public func get(_ relay: String, _ mailbox: UInt16) -> Int64? { at[key(relay, mailbox)] }
    /// Moves the start forward to `t`; never back.
    public func advance(_ relay: String, _ mailbox: UInt16, to t: Int64) {
        let k = key(relay, mailbox)
        if let old = at[k], old >= t { return }
        order.removeAll { $0 == k }; order.append(k); at[k] = t; changed = true
        while order.count > Self.max { at[order.removeFirst()] = nil }
    }
    /// What a catch-up of `mailbox` on `relay` left out when it stopped at its page limit: the events dated from the
    /// first time to the second. The next links fetch it (`CatchUp`). Nil if nothing is owed. Saved with the starts,
    /// as "<relay url>|<mailbox hex>|from=<seconds>" and "…|until=<seconds>".
    public func owed(_ relay: String, _ mailbox: UInt16) -> (from: Int64, until: Int64)? {
        let k = key(relay, mailbox)
        guard let from = at[k + Self.from], let until = at[k + Self.until], from < until else { return nil }
        return (from, until)
    }
    /// What is owed from now on: the events dated `from` to `until`; nothing if `from` isn't before `until`.
    public func owe(_ relay: String, _ mailbox: UInt16, from: Int64, until: Int64) {
        let kf = key(relay, mailbox) + Self.from, ku = key(relay, mailbox) + Self.until
        if at[kf] == from && at[ku] == until { return }
        let had = at[kf] != nil || at[ku] != nil
        order.removeAll { $0 == kf || $0 == ku }; at[kf] = nil; at[ku] = nil
        if from < until {
            order.append(kf); order.append(ku); at[kf] = from; at[ku] = until
            while order.count > Self.max { at[order.removeFirst()] = nil }
        }
        if had || from < until { changed = true }
    }
    public func save() -> String { changed = false; return order.map { "\($0)=\(at[$0]!)" }.joined(separator: ",") }
    private func key(_ relay: String, _ mailbox: UInt16) -> String { relay + "|" + String(format: "%04x", mailbox) }
    private static let from = "|from", until = "|until"
}

/// Catch-up on one relay link (spec/FORMAT.md, "Subscribe"): one REQ per mailbox, one mailbox at a time, in the order
/// given (groups before the Public channel), so a busy mailbox never crowds out another. A page that comes back full
/// is followed by an older one (`until`), up to `Nostr.maxPages` for a group and one for the Public channel. A mailbox
/// whose catch-up ends with EOSE starts next time where this one started; a refused one (CLOSED) or one with no answer
/// is left for the next link. Every event of a page counts, whatever it carries (`frame`). A group mailbox whose last
/// page was still full was not read to the end: what is older is owed (`RelaySince.owed`), and the next links fetch it
/// with the pages they have left, so a full mailbox never makes a phone skip older events for good.
/// Times in seconds. Not thread-safe. Same as Android's CatchUp.
/// A relay's messages this minute. Outlives its links: dropping the link and coming back doesn't buy a new share.
public final class RelayPace {
    public var from: Int64 = 0, n = 0
    public init() {}
}

public final class CatchUp {
    public struct Req: Sendable {
        public let subId: String, mailbox: UInt16, since: Int64, until: Int64?
        public var text: String { Nostr.catchUp(subId, mailbox: mailbox, since: since, until: until) }
    }
    private let relay: String
    private let since: RelaySince
    private let prefix: String
    private var todo: [UInt16] = []
    /// Mailboxes caught up on this link: their live events move the saved start forward.
    public private(set) var done = Set<UInt16>()
    /// The REQ waiting for its EOSE, and when it was sent.
    public private(set) var current: Req?
    public private(set) var sentAt: Int64 = 0
    private var startedAt: Int64 = 0
    private var pages = 0, count = 0, oldest = Int64.max, n = 0
    private let pace: RelayPace
    private var throttled = false
    private var owed = false // the REQ waiting asks for what an earlier catch-up left out

    public init(relay: String, since: RelaySince, prefix: String = "cu", pace: RelayPace = RelayPace()) {
        self.relay = relay; self.since = since; self.prefix = prefix; self.pace = pace
    }

    /// One more message from this relay: false if it is over its share for this minute. Relays aren't held to the limit
    /// for links, which would let one of them use up the share of the others, so each has its own. What this drops is
    /// fetched again on the next link: nothing moves the saved start forward once a link went over.
    public func allow(now: Int64) -> Bool {
        if now - pace.from >= 60 { pace.from = now; pace.n = 0 }
        pace.n += 1
        if pace.n > Nostr.relayPerMinute { throttled = true; return false }
        return true
    }

    public func add(_ mailboxes: [UInt16]) {
        for m in mailboxes where !done.contains(m) && !todo.contains(m) && m != current?.mailbox { todo.append(m) }
    }

    /// The next REQ to send, if none is waiting for its answer.
    public func next(now: Int64) -> Req? {
        guard current == nil, !todo.isEmpty else { return nil }
        let m = todo.removeFirst()
        startedAt = now; pages = 0; owed = false
        return page(m, from: Swift.max(now - Nostr.keepSeconds, (since.get(relay, m) ?? 0) - Nostr.sinceMarginSeconds), until: nil, now: now)
    }

    public func event(_ subId: String, createdAt: Int64) {
        if current?.subId == subId { count += 1; oldest = Swift.min(oldest, createdAt) }
    }

    /// A message from the relay. If it is an event of the page waiting, it counts, also when it carries no packet or
    /// one this link doesn't take: 500 such events are a full page, and an older one follows. Counting only packets
    /// let anyone end a catch-up early with junk under the mailbox's tag.
    public func frame(_ text: String) { if let e = Nostr.dated(text) { event(e.subId, createdAt: e.createdAt) } }

    /// `subId` ended: EOSE (`complete`) or CLOSED / no answer. Returns the next REQ: an older page, or the next mailbox.
    public func end(_ subId: String, complete: Bool, now: Int64) -> Req? {
        guard let c = current, c.subId == subId else { return nil }
        current = nil
        if complete && !throttled {
            let max = c.mailbox == Nostr.publicMailbox ? 1 : Nostr.maxPages
            let full = count >= Nostr.page
            let older = oldest == c.until ? oldest - 1 : oldest // where an older page starts
            if owed { since.owe(relay, c.mailbox, from: c.since, until: full ? older : c.since) } // a page that isn't full was the last of it
            else {
                if full && pages < max { return page(c.mailbox, from: c.since, until: older, now: now) }
                done.insert(c.mailbox)
                since.advance(relay, c.mailbox, to: startedAt)
                // Still full at the page limit: what is older was not read, and the start has moved past it. It is owed,
                // together with what was owed before. Not for the Public channel, which is one page by design.
                if full && c.mailbox != Nostr.publicMailbox {
                    since.owe(relay, c.mailbox, from: Swift.min(c.since, since.owed(relay, c.mailbox)?.from ?? c.since), until: older)
                }
            }
            // What an earlier catch-up left out, with the pages this link has left; never more than 7 days back.
            if let left = since.owed(relay, c.mailbox), pages < max {
                let from = Swift.max(left.from, now - Nostr.keepSeconds)
                if from < left.until { owed = true; return page(c.mailbox, from: from, until: left.until, now: now) }
                since.owe(relay, c.mailbox, from: 0, until: 0) // too old to matter
            }
        }
        return next(now: now)
    }

    /// A live event of `mailbox` made at `createdAt`: once caught up, the saved start follows it (never past now).
    public func live(_ mailbox: UInt16, createdAt: Int64, now: Int64) {
        if done.contains(mailbox) && !throttled { since.advance(relay, mailbox, to: Swift.min(createdAt, now)) }
    }

    private func page(_ m: UInt16, from: Int64, until: Int64?, now: Int64) -> Req {
        count = 0; oldest = .max; pages += 1; sentAt = now; n += 1
        let r = Req(subId: prefix + String(n), mailbox: m, since: from, until: until)
        current = r
        return r
    }
}

/// What this phone still has to post to the relays (spec/FORMAT.md, "Publish"), and what they confirmed. Own packets
/// go first, newest first; anyone else's are first looked up with `#x` and posted only if no relay returned the same
/// packet (`MeshRouter.key`) in an event its recipients get (`Nostr.Received.reaches`). A packet counts as sent only once
/// a relay answered ["OK", <event id>, true, …]; if every
/// relay it went to refused it, or none accepted it within 30 s, it is queued again, up to 3 tries. The queues keep the
/// newest packets when full. Not thread-safe. Same rules as Android's RelayOutbox.
///
/// Everything here tells packets apart as the router does (`MeshRouter.key`: id, time and content), never by id alone:
/// another packet sent under the id of a real one neither takes its place in a queue nor counts as it once posted.
/// A packet this phone wrote is never held up by packets it only passes on: an older one is looked up before them and
/// then goes up with the own packets. The links that brought the others take turns, so the packets of one link,
/// whatever time they claim, can't take every lookup and every post; and the two queues for them are bounded in
/// bytes as well as in number.
public final class RelayOutbox {
    public static let ownMax = 500, candidatesMax = 5_000, missingMax = 2_000
    public static let sentMax = 3_000, onRelaysMax = 5_000, flightsMax = 300
    /// The most bytes of packets (encoded sizes) waiting for the lookup, and as many waiting to be posted after it.
    /// A packet can be 16 KB: the counts alone let a neighbour park over 100 MB of junk here.
    public static let queueBytes = 8 * 1024 * 1024
    public static let freshMs: Int64 = 2_400_000 // own packets younger than this go up without asking first (their date is up to 35 minutes back)
    public static let answerMs: Int64 = 30_000   // how long a post waits for a relay to accept it
    public static let tries = 3
    /// A bridged packet waits up to this long, at random, before the relays are asked about it: phones that got it at
    /// the same moment then don't all find it missing and all post it. Own packets never wait.
    public static let jitterMs: Int64 = 30_000
    private static let handedMax = 200, linksMax = 256

    /// A queued packet. `k`: what tells it from every other (`MeshRouter.key`). `mine`: written on this phone.
    /// `from`: the link that brought it, "" if none did.
    private struct Item {
        let p: Packet, k: String, mine: Bool, from: String
        var size: Int { Packet.headerSize + p.cipher.count }
    }
    /// A queue of packets by `MeshRouter.key`, and the bytes they take.
    private struct Lane {
        let max: Int, maxBytes: Int
        private(set) var q: [String: Item] = [:]
        private(set) var bytes = 0
        init(_ max: Int, _ maxBytes: Int = .max) { self.max = max; self.maxBytes = maxBytes }
        mutating func add(_ i: Item) { remove(i.k); q[i.k] = i; bytes += i.size }
        @discardableResult mutating func remove(_ k: String) -> Item? {
            guard let i = q.removeValue(forKey: k) else { return nil }
            bytes -= i.size
            return i
        }
    }
    private final class Flight {
        let i: Item, relays: Set<String>, at: Int64
        var refused = Set<String>(), over = false
        init(_ i: Item, _ relays: Set<String>, _ at: Int64) { self.i = i; self.relays = relays; self.at = at }
    }
    private let now: () -> Int64
    private let jitter: () -> Int64
    private var due: [String: Int64] = [:]         // candidate -> when the relays may be asked about it
    private var own = Lane(RelayOutbox.ownMax)                                    // written on this phone: up first, newest first
    private var candidates = Lane(RelayOutbox.candidatesMax, RelayOutbox.queueBytes) // not yet looked up: anyone else's, and this phone's older ones
    private var missing = Lane(RelayOutbox.missingMax, RelayOutbox.queueBytes)    // anyone else's, looked up: no relay has them, so this phone posts them
    private var flying = Set<String>()             // posted, waiting for an answer
    private var sent: RecentIds                    // on the relays already
    private var onRelays = Set<String>(), onRelaysOrder: [String] = [] // the packets a relay sent in an event their recipients get
    private var flights: [String: Flight] = [:], flightOrder: [String] = []     // event id -> post; ended ones stay a while
    private var triesOf: [String: Int] = [:]
    private var handed: [String: Item] = [:], handedOrder: [String] = [] // given out by toCheck or next, until the caller says what became of them
    private var served: [String: Int] = [:], turns = 0                   // link -> the turn in which a packet it brought was last posted
    /// True when the sent list changed since `sentList()`: the caller saves it.
    public private(set) var changed = false

    /// `sent`: the saved list. What older builds saved by id alone is dropped.
    public init(sent: [String] = [], now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
                jitter: @escaping () -> Int64 = { Int64.random(in: 0..<RelayOutbox.jitterMs) }) {
        self.sent = RecentIds(max: Self.sentMax, sent.filter { $0.contains(":") }); self.now = now; self.jitter = jitter
    }

    /// The router offers a packet. `mine`: this very packet was written on this phone (a message or a receipt), not
    /// another one sent under its id. `from`: the link that brought it, "" if none did.
    public func offer(_ p: Packet, mine: Bool, from: String = "") {
        let t = now(), k = MeshRouter.key(p)
        guard !sent.contains(k), !flying.contains(k), !onRelays.contains(k),
              p.ts >= t - Nostr.keepSeconds * 1000 else { return }
        triesOf[k] = nil
        let i = Item(p: p, k: k, mine: mine, from: mine ? "" : from)
        if mine && p.ts > t - Self.freshMs { put(&own, i) }
        else if missing.q[k] == nil, own.q[k] == nil, put(&candidates, i) {
            if due[k] == nil { due[k] = t + jitter() }
            if due.count > Self.candidatesMax { due = due.filter { candidates.q[$0.key] != nil } }
        }
    }

    /// The next packet to post: the newest own one, else (if `bridged`) one no relay had. Too old ones are skipped.
    public func next(bridged: Bool) -> (packet: Packet, fromOwn: Bool)? {
        guard let i = newest(&own) ?? (bridged ? turn(&missing) : nil) else { return nil }
        hand(i)
        return (i.p, i.mine)
    }
    private func old(_ q: inout Lane) { // checked again right before posting
        let cut = now() - Nostr.keepSeconds * 1000
        for i in q.q.values where i.p.ts < cut { q.remove(i.k) }
    }
    private func newest(_ q: inout Lane) -> Item? {
        old(&q)
        guard let i = q.q.values.max(by: { $0.p.ts < $1.p.ts }) else { return nil }
        q.remove(i.k)
        return i
    }
    private static func newestFirst(_ a: Item, _ b: Item) -> Bool { a.p.ts != b.p.ts ? a.p.ts > b.p.ts : a.k < b.k }
    /// The next of the packets this phone only passes on: the links that brought them take turns, the one whose turn
    /// was longest ago first, and of its packets the newest. A link that keeps sending packets dated ahead of everyone
    /// else's gets its turn and no more.
    private func turn(_ q: inout Lane) -> Item? {
        old(&q)
        // A link seen for the first time waits behind the ones already here: a new link name doesn't jump the queue.
        for i in q.q.values.filter({ served[$0.from] == nil }).sorted(by: Self.newestFirst) where served[i.from] == nil {
            turns += 1; served[i.from] = turns
        }
        guard let i = q.q.values.min(by: { a, b in
            let sa = served[a.from] ?? 0, sb = served[b.from] ?? 0
            return sa != sb ? sa < sb : Self.newestFirst(a, b)
        }) else { return nil }
        q.remove(i.k); turns += 1; served[i.from] = turns
        if served.count > Self.linksMax { let here = Set(q.q.values.map(\.from)); served = served.filter { here.contains($0.key) } }
        return i
    }

    private func hand(_ i: Item) {
        if handed[i.k] == nil { handedOrder.append(i.k) }
        handed[i.k] = i
        while handedOrder.count > Self.handedMax { handed[handedOrder.removeFirst()] = nil }
    }
    private func taken(_ k: String) -> Item? {
        guard let i = handed.removeValue(forKey: k) else { return nil }
        handedOrder.removeAll { $0 == k }
        return i
    }

    /// `p` went out as event `eventId` to `relays`.
    public func posted(eventId: String, _ p: Packet, fromOwn: Bool, relays: Set<String>) {
        let k = MeshRouter.key(p)
        flights[eventId] = Flight(taken(k) ?? Item(p: p, k: k, mine: fromOwn, from: ""), relays, now()); flightOrder.append(eventId); flying.insert(k)
        while flightOrder.count > Self.flightsMax {
            if let f = flights.removeValue(forKey: flightOrder.removeFirst()), !f.over { flying.remove(f.i.k) }
        }
    }

    /// A relay answered an event. Returns the packet id if this made a packet written on this phone sent (the caller reports it), else nil.
    public func answer(relay: String, _ ok: Nostr.Ok) -> String? {
        guard let f = flights[ok.eventId] else { return nil }
        if ok.accepted {
            flights[ok.eventId] = nil; flightOrder.removeAll { $0 == ok.eventId }; flying.remove(f.i.k)
            return told(f.i)
        }
        f.refused.insert(relay)
        if !f.over && f.refused.isSuperset(of: f.relays) { fail(f) }
        return nil
    }

    /// Posts that no relay accepted within 30 s are queued again.
    public func expire() {
        let t = now()
        for id in flightOrder { if let f = flights[id], !f.over, t - f.at >= Self.answerMs { fail(f) } }
    }

    private func fail(_ f: Flight) {
        f.over = true; flying.remove(f.i.k)
        guard !sent.contains(f.i.k) else { return }
        let n = (triesOf[f.i.k] ?? 0) + 1; triesOf[f.i.k] = n
        if triesOf.count > Self.missingMax { triesOf = [f.i.k: n] } // rarely: forget old counts
        guard n < Self.tries else { return } // until the router offers it again (next link to the relays)
        if f.i.mine { put(&own, f.i) } else { put(&missing, f.i) }
    }

    /// A relay sent this event. Returns the packet's id if a queued copy is the same packet, which is now sent, and this
    /// phone wrote it; else nil.
    /// An event the packet's recipients don't get (`Nostr.Received.reaches`) counts for nothing: anyone can post one,
    /// and it must not stop this phone from posting the packet where they do get it.
    public func fromRelay(_ r: Nostr.Received) -> String? { r.reaches ? fromRelay(r.packet) : nil }

    /// A relay has this packet in an event its recipients get. Returns its id if a queued copy is the same packet, which is now sent, and this phone wrote it; else nil.
    public func fromRelay(_ p: Packet) -> String? {
        let k = MeshRouter.key(p)
        if onRelays.insert(k).inserted { onRelaysOrder.append(k) }
        while onRelaysOrder.count > Self.onRelaysMax { onRelays.remove(onRelaysOrder.removeFirst()) }
        guard let queued = own.q[k] ?? candidates.q[k] ?? missing.q[k] ?? flights.values.first(where: { $0.i.k == k && !$0.over })?.i else { return nil }
        return told(queued)
    }

    /// Up to `n` packets to look up on the relays (`#x`): first the ones this phone wrote, then the others, the links
    /// that brought them taking turns; of each, the newest first.
    public func toCheck(_ n: Int) -> [Packet] {
        let t = now()
        let ready = candidates.q.values.filter { (due[$0.k] ?? 0) <= t }
        let links = Dictionary(grouping: ready.filter { !$0.mine }, by: \.from).values.map { $0.sorted(by: Self.newestFirst) }
        var batch = ready.filter(\.mine).sorted(by: Self.newestFirst), r = 0
        while batch.count < n, links.contains(where: { $0.count > r }) {
            batch += links.compactMap { $0.count > r ? $0[r] : nil }.sorted(by: Self.newestFirst); r += 1
        }
        batch = Array(batch.prefix(n))
        for i in batch { candidates.remove(i.k); due[i.k] = nil; hand(i) }
        return batch.map(\.p)
    }

    /// After the lookup: packets a relay returned with the same contents are sent (the ids of those this phone wrote
    /// are returned), the rest get posted: this phone's own with its own packets, the others in their turn.
    public func checked(_ batch: [Packet]) -> [String] {
        var found: [String] = []
        for p in batch {
            let k = MeshRouter.key(p), i = taken(k) ?? Item(p: p, k: k, mine: false, from: "")
            if onRelays.contains(k) { if let id = told(i) { found.append(id) } }
            else if !sent.contains(k), !flying.contains(k) { if i.mine { put(&own, i) } else { put(&missing, i) } }
        }
        return found
    }

    /// What is saved on the phone: the packets that went up, as `MeshRouter.key`.
    public func sentList() -> [String] { changed = false; return sent.list }
    /// True if a packet with this id is on the relays; `isSent` with the packet says whether that very packet is.
    public func isSent(_ id: String) -> Bool { sent.list.contains { $0.hasPrefix(id + ":") } }
    public func isSent(_ p: Packet) -> Bool { sent.contains(MeshRouter.key(p)) }
    public var queued: Int { own.q.count + candidates.q.count + missing.q.count }
    /// The bytes of packets (encoded sizes) in the three queues.
    public var queuedBytes: Int { own.bytes + candidates.bytes + missing.bytes }

    private func markSent(_ k: String) -> Bool {
        guard sent.add(k) else { return false }
        changed = true; own.remove(k); candidates.remove(k); missing.remove(k)
        return true
    }

    /// `i` is on the relays now. Its id, for the caller to show "Sent", only if this phone wrote this very packet.
    private func told(_ i: Item) -> String? { markSent(i.k) && i.mine ? i.p.id : nil }

    /// Queues `i`, making room if the queue is full (`loser`). False if it was not taken.
    @discardableResult private func put(_ q: inout Lane, _ i: Item) -> Bool {
        if q.q[i.k] == nil {
            while q.q.count >= q.max || q.bytes + i.size > q.maxBytes {
                guard let out = Self.loser(q, i) else { return false }
                q.remove(out.k)
            }
        }
        q.add(i)
        return true
    }

    /// Full queue, in packets or in bytes: which packet makes room for `i`, or nil if `i` is the one that isn't taken.
    /// A packet this phone wrote never gives way to one it only passes on. Among those, as in the router's store
    /// (spec/FORMAT.md, "A full queue"): while one link's packets are more than a quarter of the queue, that link's
    /// oldest goes, also for its own next packet; otherwise the oldest of all, if `i` is newer.
    private static func loser(_ q: Lane, _ i: Item) -> Item? {
        let others = q.q.values.filter { !$0.mine }
        if others.isEmpty {
            guard i.mine, let oldest = q.q.values.min(by: { $0.p.ts < $1.p.ts }), oldest.p.ts < i.p.ts else { return nil }
            return oldest
        }
        let byCount = q.q.count >= q.max
        var held: [String: Int] = [:]
        for x in others { held[x.from, default: 0] += byCount ? 1 : x.size }
        if !i.mine { held[i.from, default: 0] += byCount ? 1 : i.size }
        if let top = held.max(by: { $0.value < $1.value }), top.value > (byCount ? q.max : q.maxBytes) / 4,
           let oldest = others.filter({ $0.from == top.key }).min(by: { $0.p.ts < $1.p.ts }) {
            return i.mine || top.key != i.from || oldest.p.ts < i.p.ts ? oldest : nil
        }
        guard let oldest = others.min(by: { $0.p.ts < $1.p.ts }), i.mine || oldest.p.ts < i.p.ts else { return nil }
        return oldest
    }
}

/// "Connect through Tor" (spec/FORMAT.md, "Tor"): nothing goes to the relays until the Tor Project says this phone's
/// traffic leaves through Tor.
public enum TorCheck {
    public static let url = URL(string: "https://check.torproject.org/api/ip")!

    /// The answer looks like {"IsTor": true, "IP": …}.
    public static func isTor(_ data: Data) -> Bool {
        ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["IsTor"] as? Bool == true
    }
}
