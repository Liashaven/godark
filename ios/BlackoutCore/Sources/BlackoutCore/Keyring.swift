import Foundation
import CryptoKit

/// A group's epoch secrets (spec/DESIGN-v0.6-groups.md, "Keys"): a phone reads with every one it holds and writes with
/// `current`, the highest epoch, and among two of the same epoch the one whose secret has the smaller SHA-256 (every
/// phone picks the same without talking). An epoch goes 7 days after a newer one replaced it; the current one stays.
/// Same as Android's.
public final class Keyring: @unchecked Sendable { // guarded by lock
    public final class Epoch: @unchecked Sendable {
        public let number: Int64, made: Int64, group: GroupCrypto, receipts: GroupCrypto, intros: GroupCrypto, hash: String
        /// Member ids, from the rekey that brought it.
        public let secret: Data, members: [String], admins: [String]
        /// `by`: who made it. After a removal, `removes` is who went, `code` the group's new code, `via` the code it came
        /// through, and `rank` where its maker stood among the admins of the epoch before (0 = listed first, the group's creator).
        /// Any other key has `byAdmin` there if an admin of the epoch before made it.
        public let code: String?, via: String?, removes: String?, by: String?, rank: Int
        /// When this phone got it, by its own clock; `made` is whatever its maker wrote.
        public let taken: Int64
        /// What tells this epoch from every other on this phone: its secret together with its number, maker and, for a removal,
        /// new code and person removed. The secret alone doesn't: whoever was given one can send it again in a key of their own.
        public let id: String
        /// From when this phone counts this epoch's age: its date, or its arrival here if that was later. A maker can't move it back.
        public var since: Int64 { Swift.max(made, taken) }
        /// Each sender's message keys (spec "Message keys"). Nil for an epoch older than them.
        public var messageKeys: MessageKeys?
        public init(number: Int64, made: Int64, secret: Data, members: [String] = [], admins: [String] = [],
                    code: String? = nil, via: String? = nil, removes: String? = nil, by: String? = nil, rank: Int = .max, messageKeys: MessageKeys? = nil, taken: Int64? = nil) {
            self.messageKeys = messageKeys
            self.number = number; self.made = made; self.secret = secret; self.members = members; self.admins = admins
            self.code = code; self.via = via; self.removes = removes; self.by = by; self.rank = rank; self.taken = taken ?? made
            group = GroupCrypto.fromSecret(secret); receipts = group.receipts(); intros = group.intros()
            hash = Hex.encode(Data(SHA256.hash(data: secret)))
            id = Hex.encode(Data(SHA256.hash(data: Data("\(hash)|\(number)|\(by ?? "")|\(code ?? "")|\(removes ?? "")".utf8))))
        }

        /// A new epoch from its random `secret`, which isn't kept: only what it derives is, each sender's message keys included.
        /// `roster`: everyone in it, even when `members` is left empty because it is kept only to read with.
        public static func fresh(number: Int64, made: Int64, secret: Data, roster: [String]? = nil, members: [String], admins: [String],
                                 code: String? = nil, via: String? = nil, removes: String? = nil, by: String? = nil, rank: Int = .max, taken: Int64? = nil) -> Epoch {
            Epoch(number: number, made: made, secret: MessageKeys.outer(secret), members: members, admins: admins, code: code, via: via, removes: removes, by: by, rank: rank,
                  messageKeys: MessageKeys.of(secret, members: roster ?? members), taken: taken)
        }

        /// Everyone this epoch's secret was sealed to: its message keys keep the list when `members` is left empty (`fresh`'s `roster`).
        public var roster: [String] { messageKeys?.members ?? members }

        /// True if `sender` (a member id; a `web-` in front doesn't count) is in this epoch. Only they write in it.
        public func lists(_ sender: String) -> Bool { roster.contains(sender.hasPrefix("web-") ? String(sender.dropFirst(4)) : sender) }

        /// A packet of this epoch: with its own message key if it has one, else (a sender whose numbers ran out, an epoch from
        /// before message keys) with the epoch's key. Either way only from someone in the epoch. Every member holds the epoch's
        /// key, and so does someone removed since: under it, an id nobody was let in with would be shown as "not verified
        /// yet" for good, with any name.
        public func open(_ p: Packet) -> GroupCrypto.Opened? {
            if let keys = messageKeys, let h = group.header(p), let mk = keys.key(h.index, h.counter), var o = group.open(messageKey: mk, index: h.index, counter: h.counter, p) {
                let sender = o.message.sender.hasPrefix("web-") ? String(o.message.sender.dropFirst(4)) : o.message.sender
                guard keys.members.indices.contains(h.index), keys.members[h.index] == sender else { return nil } // sealed under someone else's position: it must not use up their key
                o.leaf = Leaf(epoch: self, index: h.index, counter: h.counter)
                return o
            }
            guard let o = group.openSigned(p), lists(o.message.sender) else { return nil }
            return o
        }

        /// A receipt of this epoch (spec "Delivery receipts"), from someone in it.
        public func openReceipt(_ p: Packet) -> GroupCrypto.Opened? {
            guard let o = receipts.openSigned(p), lists(o.message.sender) else { return nil }
            return o
        }
    }
    public static let keepMs: Int64 = 7 * 24 * 3_600_000, hourMs: Int64 = 3_600_000
    /// A phone waits a random time up to this after the week is up, so the group's phones don't all make a new key at once.
    public static let maxDelayMs: Int64 = 6 * 3_600_000
    public static let maxMembers = 100
    /// The `rank` of a key that isn't a removal, made by an admin of the epoch before it: after every removal, before any other key.
    public static let byAdmin = Int.max - 1
    private static let maxEpochs = 64
    private static let maxReadingPerMaker = 4 // epochs kept only to read with, from one maker
    private static let maxParts = 512         // opened parts remembered
    private static let maxUnopenedPerHour = 4 // parts of one maker's keys that didn't open, before no more are tried
    private static let maxUnopenedJoining = 16 // the same from all makers together, on a phone with no epoch yet
    private static let maxEpoch: Int64 = 1 << 53
    private static let maxKeysPerHour = 4 // from one member, except admins, as they arrive here
    private var lately: [String: [Int64]] = [:] // lock: maker -> when this phone took their last new keys

    /// True if `maker` brought `maxKeysPerHour` new keys in the last hour by this phone's clock: the date in a key is whatever its maker wrote. Hold the lock.
    private func manyLately(_ maker: String, _ now: Int64) -> Bool { (lately[maker] ?? []).filter { now - $0 < Self.hourMs }.count >= Self.maxKeysPerHour }

    /// Hold the lock.
    private func arrived(_ maker: String, _ now: Int64) {
        if lately.count > Self.maxMembers * 4 { lately = [:] } // only limits a flood: forgetting is harmless
        lately[maker, default: []].append(now)
        if lately[maker]!.count > Self.maxKeysPerHour { lately[maker]!.removeFirst() }
    }

    /// The epochs that say who is in, who decides and how senior they are, from those numbered `number`, just before a key:
    /// not one kept only for reading, which a member can write with any list they like and so would make themselves an admin.
    /// Nor, of several, one that lost and whose maker a removal has taken out, then or since: through an old door they can
    /// still send a rival, and its admin list would decide about their next key. Else `cur`. Hold the lock.
    private func counting(_ number: Int64, _ cur: Epoch) -> [Epoch] {
        let real = list.filter { $0.number == number && !$0.members.isEmpty }.sorted(by: Self.first)
        let kept = real.enumerated().filter { $0.offset == 0 || !outSince($0.element.by, number) }.map(\.element)
        return kept.isEmpty ? [cur] : kept
    }

    /// True if a removal that won its number, `from` or above, took `id` out. Hold the lock.
    private func outSince(_ id: String?, _ from: Int64) -> Bool {
        guard let id else { return false }
        return list.contains { $0.removes == id && $0.number >= from && isWinner($0) }
    }

    /// True if rules about how often a member may make a key don't apply to `r`: admins. Hold the lock.
    private func exempt(_ r: Rekey, _ maker: String) -> Bool {
        guard let cur = pick() else { return true }
        return counting(r.epoch &- 1, cur).contains { $0.admins.contains(maker) }
    }

    private static let maxJump: Int64 = 1000             // how far ahead of this phone's epoch a rekey may be numbered
    private static let maxAheadMs: Int64 = 10 * 60_000   // clocks differ; a date further ahead would put off the weekly key

    /// True if an epoch this phone has had since `made` (`Epoch.since`) is due for its weekly replacement on a phone whose random delay is `delay`.
    public static func weeklyDue(made: Int64, now: Int64, delay: Int64) -> Bool { now >= made + keepMs + delay }
    /// True if the epoch is past every phone's delay: this phone missed the group's new key, or the whole group was quiet.
    public static func overdue(made: Int64, now: Int64) -> Bool { now >= made + keepMs + maxDelayMs }

    private let lock = NSLock()
    private var list: [Epoch] = []
    private var isClosed = false // lock

    /// A removal went past this phone while it was still joining: its code no longer works, so no first key is taken through
    /// it any more, or the person removed, whom an invite made earlier still names, could let the phone into a group of their
    /// own. The engine saves it. Only a removal made by an admin the invite names does this: anyone who has the code can
    /// sign one, and must not be able to shut a phone out of the group it is joining.
    public var closed: Bool { get { lock.withLock { isClosed } } set { lock.withLock { isClosed = newValue } } }

    public init() {}

    /// False if this epoch was there already. The same secret under another number, maker or kind is another epoch, judged
    /// like any other: if the first key to bring a secret kept out every later one, a member could send an admin's secret
    /// on in a key of their own and so have the admin's key ignored.
    @discardableResult public func add(_ e: Epoch) -> Bool {
        lock.withLock {
            if list.contains(where: { $0.id == e.id }) { return false }
            list.append(e)
            // An epoch kept only to read with decides nothing, and a member can make as many as the hourly limits allow: one
            // maker has at most a few here, and when the keyring is full they go before any epoch that was the group's own.
            if e.members.isEmpty, let by = e.by {
                let theirs = list.filter { $0.members.isEmpty && $0.by == by }
                if theirs.count > Self.maxReadingPerMaker, let worst = theirs.max(by: Self.first) { list.removeAll { $0 === worst } }
            }
            if list.count > Self.maxEpochs { // every packet is tried with each of them: a flood can't make that endless
                let reading = list.filter { $0.members.isEmpty }
                if let worst = (reading.isEmpty ? list : reading).max(by: Self.first) { list.removeAll { $0 === worst } }
            }
            return true
        }
    }

    /// Everyone in a member list this phone holds: in the group now, or until a removal or a new key not long ago.
    public func everyone() -> Set<String> { lock.withLock { Set(list.flatMap(\.members)) } }

    /// True if `id` is in the group as far as this phone knows: in the member list of an epoch it holds that says who is
    /// in, and not taken out by a removal that won. What such a person sends through the door (their introduction, a new
    /// key) is kept like the group's messages; anyone else's has a small room of its own (`StoreCap.Kind.door`).
    public func inGroup(_ id: String) -> Bool {
        lock.withLock { list.contains { $0.members.contains(id) } && !list.contains { $0.removes == id && isWinner($0) } }
    }

    private var parts = RecentIds(max: Keyring.maxParts) // lock: sealed parts this phone has opened (`partMark`), oldest first
    private var partsChanged = false                     // lock

    /// The sealed parts this phone has opened, oldest first: the engine saves them after the keyring and gives them back with `restoreParts`.
    public var openedParts: [String] { lock.withLock { parts.list } }
    public func restoreParts(_ marks: [String]) { lock.withLock { marks.forEach { parts.add($0) } } }
    /// True, once, if a part was opened since the last call: time to save `openedParts`.
    public func partsToSave() -> Bool { lock.withLock { let c = partsChanged; partsChanged = false; return c } }

    /// Names one member's sealed part of one new key without opening it: SHA-256 of the box and of the key's maker, number, date and kind, the first 16 bytes in hex.
    public static func partMark(_ box: Data, maker: String, _ r: Rekey) -> String {
        var h = SHA256()
        h.update(data: box); h.update(data: Data("|\(maker)|\(r.epoch)|\(r.made)|\(r.removal ? 1 : 0)".utf8))
        return Hex.encode(Data(h.finalize().prefix(16)))
    }

    private var unopened: [String: [Int64]] = [:] // lock: maker -> when their last parts for this phone didn't open

    /// True if no more parts of `maker` are tried for now: `maxUnopenedPerHour` of theirs didn't open in the last hour.
    /// A phone with no epoch (`joining`) can't tell who is in the group, and a maker is then whoever holds the code: it
    /// stops at `maxUnopenedJoining` in all. Hold the lock.
    private func triedOut(_ maker: String, _ now: Int64, joining: Bool) -> Bool {
        func recent(_ q: [Int64]) -> Int { q.filter { abs(now - $0) < Self.hourMs }.count }
        if recent(unopened[maker] ?? []) >= Self.maxUnopenedPerHour { return true }
        return joining && unopened.values.reduce(0) { $0 + recent($1) } >= Self.maxUnopenedJoining
    }

    /// Hold the lock.
    private func didNotOpen(_ maker: String, _ now: Int64) {
        if unopened.count > Self.maxMembers * 4 { unopened = [:] } // only limits a flood: forgetting is harmless
        unopened[maker, default: []].append(now)
        if unopened[maker]!.count > Self.maxUnopenedPerHour { unopened[maker]!.removeFirst() }
    }

    /// True if an epoch numbered `number` and dated `made` is past its week at `now`: a newer one replaced it more than 7
    /// days ago, so `expire` would drop it at once. Hold the lock.
    private func past(_ number: Int64, _ made: Int64, _ now: Int64) -> Bool {
        guard let next = list.filter({ $0.number > number }).map(\.since).min() else { return false }
        return Swift.max(next, made) < now - Self.keepMs
    }

    public var current: Epoch { lock.withLock { pick()! } }
    public var currentOrNil: Epoch? { lock.withLock { pick() } }

    /// Every epoch, the current one first: the order phones try them in.
    public var all: [Epoch] { lock.withLock { guard let c = pick() else { return [] }; return [c] + list.filter { $0 !== c } } }

    /// Drops the epochs replaced more than 7 days before `now`, never the current one; returns what went. Counted from
    /// the next epoch, not this one: a message written on its last day can still arrive a week later. What lost to an epoch
    /// that goes, goes with it: dated later and left alone, a rival removal would count as the one that won. A newer epoch
    /// replaced it when this phone got that one, if that was after its date (`Epoch.since`): a member's key dated long ago
    /// would otherwise have this phone delete the epoch before it at once.
    @discardableResult public func expire(now: Int64) -> [Epoch] {
        lock.withLock {
            guard let c = pick() else { return [] }
            let old = list.filter { e in
                guard e !== c, let next = list.filter({ $0.number > e.number }).map(\.since).min() else { return false }
                return Swift.max(next, e.made) < now - Self.keepMs
            }
            let gone = old + list.filter { e in e !== c && !old.contains { $0 === e } && old.contains { $0.number == e.number && isWinner($0) } }
            list.removeAll { e in gone.contains { $0 === e } }
            return gone
        }
    }

    /// True if removal `e` is now the one to follow: the newest, or a late one that beat the rival this phone had followed.
    public func leads(_ e: Epoch) -> Bool {
        lock.withLock { isWinner(e) && (lastMoved() === e || list.contains { $0 !== e && $0.code != nil && $0.number == e.number }) }
    }

    /// People a removal that lost took out, who are still in the current epoch: an admin's phone finishes the job.
    public func stillToRemove() -> [String] {
        lock.withLock {
            guard let cur = pick() else { return [] }
            let gone = Set(Set(list.filter { $0.code != nil }.map(\.number)).flatMap { goneAt($0) })
            return cur.members.filter(gone.contains)
        }
    }

    /// Admins added by rekeys of the current number that didn't win: the next rekey an admin makes keeps them.
    public func rivalAdmins() -> [String] {
        lock.withLock {
            guard let cur = pick() else { return [] }
            let gone = goneAt(cur.number)
            var out: [String] = []
            for e in list where e.number == cur.number && e !== cur && !(e.by.map(gone.contains) ?? false) {
                for a in e.admins where !cur.admins.contains(a) && !gone.contains(a) && !out.contains(a) { out.append(a) }
            }
            return out
        }
    }

    /// Who the removals numbered `number` took out, most senior admin first. A removal by someone a more senior one removed
    /// doesn't count. Nor does one that lost, once its maker is no longer an admin of the current epoch: removed since, they
    /// could still send one late through an older door, and a phone can't tell when it was made. Hold the lock.
    private func goneAt(_ number: Int64) -> Set<String> {
        guard let admins = pick()?.admins else { return [] }
        var out = Set<String>()
        for e in list.filter({ $0.code != nil && $0.number == number }).sorted(by: Self.first) where !(e.by.map(out.contains) ?? false) {
            if let r = e.removes, isWinner(e) || (e.by.map(admins.contains) ?? false) { out.insert(r) }
        }
        return out
    }

    /// True if removal `r`, whose signature checked out, tells a phone that is asking its way back that the group has moved
    /// on without it: its maker is an admin of the current epoch whom no removal that won has taken out. Anyone who has the
    /// code can sign a removal, so one from anybody else says nothing.
    public func movedOn(_ r: Rekey, maker: String) -> Bool {
        lock.withLock {
            guard let cur = pick() else { return false }
            return r.removal && cur.admins.contains(maker) && !outSince(maker, 0)
        }
    }

    /// What a phone does with a rekey whose signature checked out.
    public enum Taken {
        /// Not allowed, or nothing for this phone.
        case ignored
        /// This phone was removed: that removal's epoch number, its maker's rank and its maker.
        case removed(number: Int64, rank: Int, by: String)
        /// This phone is still joining and a removal went past without it: its code no longer works.
        case closed
        /// A new epoch. `moveTo`: the code the group follows now. `back`: a removal that outranks the one that removed this phone.
        case added(Epoch, moveTo: String?, back: Bool)
        /// A new key numbered `number` lists this phone, but the part it carries for it doesn't open. The others can't see that
        /// and may have moved on to it, so this phone asks its way back with a key of its own, as one that was away does.
        /// `rank`: that key's `Epoch.rank`, to tell later whether a key that did get here beats it.
        case leftOut(number: Int64, rank: Int)
    }

    /// The whole decision about rekey `r` (spec "New key"), the same on both apps so that phones given the same rekeys
    /// in any order agree. `door`: the code it came through; `oldDoor`: the group has moved on from that code. `me`: this
    /// phone's member id. `removedAt`: the removal that removed this phone, and `removedBy` its maker. `pinned`: its maker
    /// is one the invite named, or the invite named nobody. `named`: the invite named admins and its maker is one of them
    /// (nil: as `pinned`): only then does a removal that leaves a joining phone out close its invite. `inUse`: the codes of
    /// the other groups saved on this phone: a removal can't move this group onto one of them. `open` opens this phone's
    /// sealed part.
    public func take(_ r: Rekey, maker: String, me: String, door: String, oldDoor: Bool, removedAt: (number: Int64, rank: Int)?,
                     now: Int64 = Int64(Date().timeIntervalSince1970 * 1000), pinned: Bool = true, removedBy: String? = nil, named: Bool? = nil,
                     inUse: [String] = [], open: (Data) -> Data?) -> Taken {
        let seniority = rank(r, maker: maker), mine = r.parts.first { $0.id == me }
        if mine == nil && r.members.contains(me) { return .ignored } // this phone's part is in another packet of the same key
        if let at = removedAt, !(r.removal && mine != nil && lock.withLock({ undoes(r, seniority, at, removedBy) })) { return .ignored }
        guard let admins = admit(r, maker: maker, oldDoor: oldDoor ? door : nil, now: now, pinned: pinned) else { return .ignored }
        let cur = currentOrNil
        let below = oldDoor && lock.withLock { overrules(r, maker, door) } // numbered below the removal this phone followed, and by a more senior admin: it leads all the same
        if r.removal, r.answers == me, let cur, r.epoch >= cur.number || below, !outranked(r, maker: maker) { return .removed(number: r.epoch, rank: seniority, by: maker) } // a later rejoin has a higher epoch
        guard let mine else {
            guard r.removal && cur == nil && (named ?? pinned) else { return .ignored }
            closed = true
            return .closed
        }
        // Kept only to read with, and already past the week such an epoch is kept: not taken, or a stored new key read
        // again would bring back an epoch this phone deleted, with every message key in it.
        if !r.removal, let cur, r.epoch < cur.number, lock.withLock({ past(r.epoch, r.made, now) }) { return .ignored }
        let level = standing(r, maker: maker)
        // A part is opened once. The phone reads its stored new keys again at every start and after each new epoch, and
        // each opening is a key agreement in its secure hardware; an epoch it has since deleted must not come back either.
        let mark = Self.partMark(mine.box, maker: maker, r)
        if lock.withLock({ parts.contains(mark) }) { return .ignored }
        // Nor is a part tried once its maker has sent a few that don't open: it then counts as one that doesn't.
        let tried = lock.withLock { !triedOut(maker, now, joining: cur == nil) }
        // unbox checks the shape: anyone with the code can seal a part, and a wrong-sized secret must not reach fromSecret.
        guard let plain = tried ? open(mine.box) : nil, let opened = Rekey.unbox(plain, removal: r.removal) else {
            if tried { lock.withLock { didNotOpen(maker, now) } }
            // A part that doesn't open, in a key the others may be writing with by now: one above the current epoch, or one that could come before it.
            if !r.removal, !oldDoor, let cur, r.epoch > cur.number || (r.epoch == cur.number && cur.code == nil && level <= cur.rank) { return .leftOut(number: r.epoch, rank: level) }
            return .ignored
        }
        if let code = opened.code, inUse.contains(code) { return .ignored } // that code is another group's on this phone: following it would put this group in its place
        // Numbered below the current epoch: it opens old messages and proves nothing about who is in. Except a removal,
        // which can become the current epoch again even when it arrives late, and which only an admin can make.
        lock.withLock { parts.add(mark); partsChanged = true }
        let forReadingOnly = !r.removal && cur.map { r.epoch < $0.number } ?? false
        let e = Epoch.fresh(number: r.epoch, made: r.made, secret: opened.secret, roster: r.members, members: forReadingOnly ? [] : r.members, admins: admins, code: opened.code,
                      via: r.removal ? door : nil, removes: r.removal ? r.answers : nil, by: maker, rank: level, taken: now)
        let counted = lock.withLock { !exempt(r, maker) }
        guard add(e) else { return .ignored }
        if counted { lock.withLock { arrived(maker, now) } }
        let follow = opened.code != nil && (leads(e) || (below && won(e)))
        if follow { dropAbove(e.number) }
        return .added(e, moveTo: follow ? opened.code : nil, back: removedAt != nil)
    }

    /// True if removal `r` outranks the one that removed this phone (`at`: its number and its maker's rank; `by`: its maker):
    /// the same number from a more senior admin, or a lower number from an admin who stands before `by` in the admin list
    /// of the epoch before `r`. A removal numbered above it never does. Hold the lock.
    private func undoes(_ r: Rekey, _ seniority: Int, _ at: (number: Int64, rank: Int), _ by: String?) -> Bool {
        if r.epoch == at.number { return seniority < at.rank }
        guard r.epoch < at.number, let by else { return false }
        return seniority < place(r.epoch &- 1, by)
    }

    /// True if removal `r`, through the old door `door`, is numbered below the removal this phone followed out of that door
    /// and its maker stands before the maker of every removal held above it, in the admin list of the epoch before `r`.
    /// That is a senior admin's removal of someone who got their own keys here first: a key and then a removal one number
    /// higher would otherwise shut the senior admin's removal out for good. Without the seniority, someone removed could
    /// pick a lower number and undo their own removal. Hold the lock.
    private func overrules(_ r: Rekey, _ maker: String, _ door: String) -> Bool {
        guard r.removal, let left = list.filter({ $0.code != nil && $0.via == door }).min(by: Self.first), r.epoch < left.number else { return false }
        let mine = rankOf(r, maker)
        guard mine != .max else { return false }
        return !list.contains { e in
            guard e.code != nil, e.number > r.epoch else { return false }
            guard let by = e.by else { return true }
            return place(r.epoch &- 1, by) <= mine
        }
    }

    /// The `rank` of the epoch rekey `r` brings. A removal's is its maker's seniority. Any other key made by an admin
    /// of the epoch before it has `byAdmin`, so it comes before one of the same number that wasn't, whatever the hashes:
    /// a member picks their key's secret, and could otherwise undo an admin's choice to let someone in. A phone still
    /// joining goes by the admin list of the key that lets it in. The engine uses this for the keys it makes too.
    public func standing(_ r: Rekey, maker: String) -> Int {
        lock.withLock {
            if r.removal { return rankOf(r, maker) }
            guard let cur = pick() else { return r.admins.contains(maker) ? Self.byAdmin : .max }
            return counting(r.epoch &- 1, cur).contains { $0.admins.contains(maker) } ? Self.byAdmin : .max
        }
    }

    /// True if `maker` already made an epoch within an hour of `made`.
    public func tooSoon(_ maker: String, made: Int64) -> Bool { lock.withLock { madeWithinAnHour(maker, made) } }

    private var answered: [String: Int64] = [:] // lock: member -> when this phone last counted a key of theirs as one from a phone that is behind

    /// True if member `maker` made `r` after this phone's current epoch but numbered it lower: their phone missed our keys.
    /// Not with a date more than 10 minutes ahead, which no later key could ever be newer than; and for one member only
    /// once an hour by this phone's clock, since each time some phone answers with a full new key for everyone.
    public func behind(_ r: Rekey, maker: String, now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        lock.withLock {
            guard let c = pick(), !r.removal, r.epoch < c.number, r.made > c.made, r.made <= now + Self.maxAheadMs, c.members.contains(maker) else { return false }
            if let at = answered[maker], abs(now - at) < Self.hourMs { return false }
            if answered.count > Self.maxMembers * 4 { answered = [:] } // only limits a flood: forgetting is harmless
            answered[maker] = now
            return true
        }
    }

    /// The newest removal: its code is the one the group follows.
    public var lastMove: Epoch? { lock.withLock { lastMoved() } }

    /// After a removal: anything numbered above it was made through the old door by someone who hadn't heard.
    public func dropAbove(_ number: Int64) { lock.withLock { list.removeAll { $0.number > number } } }

    /// True if `id` was removed before `ts`: what a removed member writes afterwards isn't shown. A removal that lost doesn't count.
    public func removed(_ id: String, before ts: Int64) -> Bool { lock.withLock { list.contains { $0.removes == id && ts > $0.made && isWinner($0) } } }

    /// True if a message or receipt under the id `id`, dated `ts`, isn't shown, whoever signed it.
    /// - No epoch here that says who is in lists `id`. An epoch kept only to read with opens packets, but its list is
    ///   whatever its maker wrote: a member could put a made-up id in one and write under it.
    /// - A removal that won took `id` out. `had`: this phone had accepted the packet before (its own copy of the message,
    ///   or one waiting for its sender's key): then its date decides (`removed(_:before:)`). Seen for the first time, it
    ///   isn't shown whatever its date. The date is the sender's to write, and someone removed still has the keys of the
    ///   epochs before, which phones read with for another week: dated a minute before the removal, anything they wrote
    ///   in that week would pass.
    /// A keyring with no member list at all (the Public channel's) shuts nobody out.
    public func shutOut(_ id: String, at ts: Int64, had: Bool) -> Bool {
        lock.withLock {
            let lists = list.filter { !$0.members.isEmpty }
            if !lists.isEmpty && !lists.contains(where: { $0.members.contains(id) }) { return true }
            return list.contains { $0.removes == id && isWinner($0) && (!had || ts > $0.made) }
        }
    }

    /// True if no other epoch with `e`'s number comes before it.
    public func won(_ e: Epoch) -> Bool { lock.withLock { isWinner(e) } }

    /// Where `maker` stood among the admins of the epoch before `r`: the lower, the more senior. Read from the epochs `admit` reads, for the same reasons.
    public func rank(_ r: Rekey, maker: String) -> Int { lock.withLock { rankOf(r, maker) } }

    /// True if a removal this phone holds outranks `r`, so `r` can't take effect.
    public func outranked(_ r: Rekey, maker: String) -> Bool {
        lock.withLock { let mine = rankOf(r, maker); return list.contains { $0.code != nil && $0.number == r.epoch && $0.rank < mine } }
    }

    /// The admins rekey `r` gives its epoch on this phone, or nil if it must be ignored (spec "New key"). `maker` is
    /// its checked signer; `oldDoor`: the code it came through if the group has moved on from it, else nil.
    /// - A phone still joining takes the first one that includes it, from an admin its invite named (`pinned`). With a typed
    ///   code it has nothing better to trust than the code. Once `closed`, it takes none.
    /// - Someone a removal that won its number took out decides nothing afterwards, even if a rival epoch this phone holds
    ///   still lists them as an admin, and adds nothing: no key of theirs is taken, whatever its number and door. The epoch
    ///   before the removal still lists them for a week, and a key they numbered below it, through the old door, would be
    ///   kept to read with: dated late, it outlives the removal, and then nothing says its maker was removed. Only a
    ///   removal of theirs is still judged: refused when numbered one above that removal, or below it through the current
    ///   door (they may have learnt the new code); below it through the old door, seniority decides (`overrules`).
    /// - Only admins of the epoch before it may leave people out, change the admins or remove someone. A removal needs
    ///   that epoch here: picking a higher number can't put it ahead of a removal that outranks it.
    /// - Through an old door only a rival removal counts, numbered the same as the removal this phone followed out of it,
    ///   or a key numbered below that one, which arrived late. A removal numbered below it counts only from an admin
    ///   more senior than whoever made the removals held above it (`overrules`).
    /// - Older than the current epoch: kept only to read with, so it can't change who is in, and only from someone who
    ///   has been a member, or anyone with an old code could fill the phone with keys.
    /// - At most one per member per hour, except admins' and rekeys that let someone new in.
    /// - Numbers and times that make no sense, and groups over `maxMembers`, are refused.
    public func admit(_ r: Rekey, maker: String, oldDoor: String?, now: Int64 = Int64(Date().timeIntervalSince1970 * 1000), pinned: Bool = true) -> [String]? {
        guard (1...Self.maxEpoch).contains(r.epoch), r.made >= 0, r.made <= now + Self.maxAheadMs, r.members.count <= Self.maxMembers else { return nil }
        return lock.withLock {
            guard let cur = pick() else { return oldDoor == nil && pinned && !isClosed ? r.admins : nil }
            if r.epoch > cur.number + Self.maxJump { return nil }
            if list.contains(where: { $0.removes == maker && isWinner($0) && (!r.removal || $0.number == r.epoch - 1 || (oldDoor == nil && $0.number > r.epoch)) }) { return nil }
            if r.removal && !list.contains(where: { $0.number == r.epoch - 1 }) { return nil }
            let before = counting(r.epoch - 1, cur)
            let byAdmin = before.contains { $0.admins.contains(maker) }
            if r.removal && (!byAdmin || r.answers.map { r.members.contains($0) } != false) { return nil }
            if let oldDoor {
                guard let left = list.filter({ $0.code != nil && $0.via == oldDoor }).min(by: Self.first) else { return nil }
                if r.removal ? r.epoch > left.number || (r.epoch < left.number && !overrules(r, maker, oldDoor)) : r.epoch >= left.number { return nil }
            }
            if !byAdmin && (madeWithinAnHour(maker, r.made) || manyLately(maker, now)) { return nil }
            let knownMaker = list.contains { $0.members.contains(maker) }
            if r.epoch < cur.number { return knownMaker ? (byAdmin ? r.admins : before[0].admins) : nil }
            if !byAdmin && (!before[0].members.contains(maker) || Set(before[0].members) != Set(r.members)) { return nil }
            return byAdmin ? r.admins : before[0].admins
        }
    }

    /// Highest number first. For the same number a removal beats anything else (or the removed person would still be
    /// in), then the most senior admin's removal: its maker can't choose that, as they could a hash. Then a key an admin
    /// made, before one from a member who isn't. Then the smallest hash, and for one secret in two keys the smallest
    /// maker id, then code.
    private static func first(_ a: Epoch, _ b: Epoch) -> Bool {
        if a.number != b.number { return a.number > b.number }
        if (a.code == nil) != (b.code == nil) { return a.code != nil }
        if a.rank != b.rank { return a.rank < b.rank }
        if a.hash != b.hash { return a.hash < b.hash }
        let x = a.by ?? "", y = b.by ?? ""
        if x != y { return x < y }
        return (a.code ?? "") < (b.code ?? "")
    }
    private func isWinner(_ e: Epoch) -> Bool { !list.contains { $0 !== e && $0.number == e.number && Self.first($0, e) } }
    private func madeWithinAnHour(_ maker: String, _ made: Int64) -> Bool { list.contains { $0.by == maker && abs($0.made - made) < Self.hourMs } }
    private func rankOf(_ r: Rekey, _ maker: String) -> Int { place(r.epoch &- 1, maker) } // runs before admit has checked r: wrapping subtraction, so a crafted number can't crash
    /// Where `id` stands among the admins of the epochs numbered `number` that count: the lower, the more senior. Hold the lock.
    private func place(_ number: Int64, _ id: String) -> Int {
        guard let cur = pick(), list.contains(where: { $0.number == number }) else { return .max }
        return counting(number, cur).compactMap { $0.admins.firstIndex(of: id) }.min() ?? .max
    }
    private func pick() -> Epoch? { list.min(by: Self.first) }
    private func lastMoved() -> Epoch? { list.filter { $0.code != nil }.min(by: Self.first) }
}
