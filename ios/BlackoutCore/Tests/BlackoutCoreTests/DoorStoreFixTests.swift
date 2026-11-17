import XCTest
import CryptoKit
@testable import BlackoutCore

/// What someone who only holds a group's code, or an ordinary member, can do to other phones' stored messages and keys:
/// found in the 2026-11-13 audit. The same cases as Android's DoorStoreFixTest. Dummy keys only.
final class DoorStoreFixTests: XCTestCase {
    private let hour: Int64 = 3_600_000, day: Int64 = 24 * 3_600_000, now: Int64 = 1_000 * 24 * 3_600_000
    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444"
    private var all: [String] { [anna, ben, cara] }
    private func secret(_ b: Int) -> Data { Data((0..<32).map { UInt8(truncatingIfNeeded: b * 31 + $0) }) }
    private func id(_ i: Int) -> String { String(format: "%016x", 0xF0000 + i) }
    /// A new key; a part is opened by handing its box back.
    private func key(_ n: Int64, _ made: Int64, _ s: Int, members: [String]? = nil) -> Rekey {
        Rekey(epoch: n, made: made, maker: Data(count: 33), admins: [anna], answers: nil, parts: (members ?? all).map { ($0, Rekey.box(secret(s), code: nil)) })
    }
    /// Epoch `n`, a day old: Anna (admin), Ben and Cara.
    private func ring(_ n: Int64 = 5) -> Keyring {
        let r = Keyring(); r.add(.fresh(number: n, made: now - day, secret: secret(Int(n)), members: all, admins: [anna], taken: now - day)); return r
    }
    private func take(_ r: Keyring, _ k: Rekey, _ by: String, _ me: String, _ at: Int64, open: @escaping (Data) -> Data? = { $0 }) -> String {
        switch r.take(k, maker: by, me: me, door: "door", oldDoor: false, removedAt: nil, now: at, open: open) {
        case .added: return "added"
        case .ignored: return "ignored"
        case .leftOut: return "leftOut"
        case .removed: return "removed"
        case .closed: return "closed"
        }
    }

    // MARK: 1. Door packets: anyone with the code can write them, so they are not the group's own

    func testAFloodThroughTheDoorNeverPushesAMessageOut() {
        let kept = (1...200).map { StoreCap.Entry(id: "m\($0)", ts: 1_000 + Int64($0), size: 300, kind: .group) }
            + (1...5).map { StoreCap.Entry(id: "p\($0)", ts: 1_000 + Int64($0), size: 300, kind: .isPublic) }
            + (1...5).map { StoreCap.Entry(id: "u\($0)", ts: 1_000 + Int64($0), size: 300, kind: .unreadable) }
        // Forged new keys of the largest size, dated newest: enough to fill the whole store.
        let forged = (1...2_881).map { StoreCap.Entry(id: "f\($0)", ts: 9_000 + Int64($0), size: 16_018, kind: .door) }
        let gone = Set(StoreCap.overflow(kept + forged))
        XCTAssertTrue(gone.allSatisfy { $0.hasPrefix("f") }, "only door packets go")
        XCTAssertLessThanOrEqual(forged.filter { !gone.contains($0.id) }.reduce(0) { $0 + $1.size }, StoreCap.doorBytes)
        XCTAssertTrue(gone.contains("f1") && !gone.contains("f2881"), "the oldest of them first")
        // The smallest introductions, more of them than the store holds packets.
        let small = (1...21_001).map { StoreCap.Entry(id: "i\($0)", ts: 9_000 + Int64($0), size: 181, kind: .door) }
        let gone2 = Set(StoreCap.overflow(kept + small))
        XCTAssertTrue(gone2.allSatisfy { $0.hasPrefix("i") }); XCTAssertEqual(small.count - gone2.count, StoreCap.doorCount)
        // Classed like the group's own packets, as they were, the same flood removed every message.
        let asGroup = forged.map { StoreCap.Entry(id: $0.id, ts: $0.ts, size: $0.size, kind: .group) }
        XCTAssertEqual(StoreCap.overflow(kept + asGroup).filter { $0.hasPrefix("m") }.count, 200)
    }

    func testDoorPacketsWithinTheirRoomGoAfterJunkAndBeforeMessages() {
        let e = [StoreCap.Entry(id: "g1", ts: 1, size: 100, kind: .group), StoreCap.Entry(id: "d1", ts: 2, size: 100, kind: .door),
                 StoreCap.Entry(id: "p1", ts: 3, size: 100, kind: .isPublic), StoreCap.Entry(id: "u1", ts: 4, size: 100, kind: .unreadable),
                 StoreCap.Entry(id: "d2", ts: 5, size: 100, kind: .door)]
        XCTAssertEqual(StoreCap.overflow(e, maxBytes: 500, maxCount: 5), [])
        XCTAssertEqual(StoreCap.overflow(e, maxBytes: 100, maxCount: 5), ["u1", "d1", "d2", "p1"])
        XCTAssertEqual(StoreCap.overflow(e, maxBytes: 10_000, maxCount: 5, doorCount: 1), ["d1"], "their own room first")
        XCTAssertEqual(StoreCap.overflow(e, maxBytes: 200, maxCount: 5, doorBytes: 0), ["d1", "d2", "u1"])
        XCTAssertFalse(StoreCap.doorFull(count: 2 * StoreCap.doorCount, bytes: 2 * StoreCap.doorBytes))
        XCTAssertTrue(StoreCap.doorFull(count: 2 * StoreCap.doorCount + 1, bytes: 0)); XCTAssertTrue(StoreCap.doorFull(count: 1, bytes: 2 * StoreCap.doorBytes + 1))
    }

    func testWhoWroteADoorPacketDecidesItsClass() {
        let r = ring()
        XCTAssertTrue(r.inGroup(ben)); XCTAssertFalse(r.inGroup(dan), "someone who only holds the code")
        XCTAssertFalse(Keyring().inGroup(anna), "a phone still joining knows nobody")
        // Anna removes Cara: the epoch before still lists her, but what she sends through a door is no longer the group's.
        r.add(.fresh(number: 6, made: now, secret: secret(6), members: [anna, ben], admins: [anna], code: "AAAA-AAAA-AAAA-AAAA", via: "d1", removes: cara, by: anna, rank: 0, taken: now))
        XCTAssertFalse(r.inGroup(cara)); XCTAssertTrue(r.everyone().contains(cara)); XCTAssertTrue(r.inGroup(ben))
        XCTAssertEqual(StoreCap.door(mine: false, member: r.inGroup(ben)), .group)
        XCTAssertEqual(StoreCap.door(mine: false, member: r.inGroup(cara)), .door)
        XCTAssertEqual(StoreCap.door(mine: false, member: r.inGroup(dan)), .door)
        XCTAssertEqual(StoreCap.door(mine: true, member: false), .group, "a phone's own request to join stays")
    }

    // MARK: 2. Join requests: a made-up key costs nothing

    /// What the engines do with a checked introduction: keep its key or not (`Joining.keeps`).
    private final class Directory {
        let me: String, members: Set<String>, now: Int64
        var known: [String: Int64] = [:], declined = Set<String>()
        init(_ me: String, _ members: Set<String>, _ now: Int64) { self.me = me; self.members = members; self.now = now }
        func asking() -> [String] { Joining.asking(known, members: members, declined: declined, me: me, now: now) }
        func arrive(_ id: String, _ at: Int64) -> Bool {
            if known[id] == nil && !Joining.keeps(id, asking: asking(), listed: members, me: me) { return false }
            known[id] = at; return true
        }
    }

    func testAFloodOfMadeUpKeysCannotCrowdOutARealRequest() {
        let d = Directory(anna, [anna, ben], now), real = id(0)
        XCTAssertTrue(d.arrive(real, now - hour))
        // 500 made-up keys, dated as far back as a packet can be so as to sort first.
        XCTAssertEqual((1...500).filter { d.arrive(id($0), now - 6 * day) }.count, Joining.maxAsking - 1)
        XCTAssertEqual(d.asking().count, Joining.maxAsking); XCTAssertTrue(d.asking().contains(real), "the real request is still there")
        XCTAssertEqual(d.known.count, Joining.maxAsking, "nothing more is saved")
        XCTAssertTrue(d.arrive(ben, now), "a member's key is always kept"); XCTAssertFalse(d.asking().contains(ben))
        XCTAssertTrue(d.arrive(real, now), "and a request that is already there can be updated")
        // Turning one down makes room for one more; so does a request that is a week old.
        d.declined = [id(1)]; XCTAssertTrue(d.arrive(id(600), now)); XCTAssertFalse(d.arrive(id(601), now))
        d.known[id(2)] = now - 8 * day; XCTAssertFalse(d.asking().contains(id(2))); XCTAssertTrue(d.arrive(id(602), now))
        XCTAssertEqual(d.asking().count, Joining.maxAsking)
    }

    func testMoreRequestsThanTheRoomSavedEarlierAreNotAllShown() {
        var known: [String: Int64] = [:]
        for i in 1...300 { known[id(i)] = now - Int64(i) * 1_000 }
        let shown = Joining.asking(known, members: [anna], declined: [], me: anna, now: now)
        XCTAssertEqual(shown.count, Joining.maxAsking); XCTAssertEqual(shown.first, id(300))
        XCTAssertEqual(Joining.asking(known, members: Set(known.keys), declined: [], me: anna, now: now), [])
    }

    func testJoinAlertsComeAtMostOnceAMinute() {
        XCTAssertTrue(Joining.alertDue(last: 0, now: now)); XCTAssertFalse(Joining.alertDue(last: now - 59_000, now: now)); XCTAssertTrue(Joining.alertDue(last: now - 60_000, now: now))
        XCTAssertTrue(Joining.alertDue(last: now + hour, now: now), "a clock set back doesn't silence them")
    }

    // MARK: 3. Stored new keys are read again at every start

    func testADeletedEpochDoesNotComeBackFromItsStoredNewKey() {
        let t0 = now, r = ring()
        let six = key(6, t0, 6), seven = key(7, t0 + day, 7)
        XCTAssertEqual(take(r, six, anna, ben, t0), "added")
        XCTAssertEqual(take(r, seven, anna, ben, t0 + day), "added")
        XCTAssertEqual(r.expire(now: t0 + 9 * day).map(\.number).sorted(), [5, 6])
        var opened = 0
        XCTAssertEqual(take(r, six, anna, ben, t0 + 9 * day) { opened += 1; return $0 }, "ignored")
        XCTAssertEqual(opened, 0, "the part isn't even opened"); XCTAssertEqual(r.all.map(\.number), [7])
        // A phone that no longer knows which parts it opened refuses it too: the epoch is past its week.
        let again = Keyring(); again.add(.fresh(number: 7, made: t0 + day, secret: secret(7), members: all, admins: [anna], by: anna, taken: t0 + day))
        XCTAssertEqual(take(again, six, anna, ben, t0 + 9 * day) { opened += 1; return $0 }, "ignored")
        XCTAssertEqual(opened, 0)
    }

    func testAKeyThatArrivesLateWithinItsWeekIsStillTaken() {
        // A phone that was away gets epoch 7 first and then 6: it reads what was written with 6 for another week.
        let r = ring()
        XCTAssertEqual(take(r, key(7, now - 2 * day, 7), anna, ben, now), "added")
        XCTAssertEqual(take(r, key(6, now - 6 * day, 6), anna, ben, now + hour), "added")
        XCTAssertEqual(r.current.number, 7); XCTAssertTrue(r.all.contains { $0.number == 6 && $0.messageKeys != nil })
        XCTAssertTrue(r.expire(now: now + 6 * day).isEmpty); XCTAssertEqual(r.expire(now: now + 8 * day).map(\.number).sorted(), [5, 6])
    }

    func testAPartIsOpenedOnceAlsoAfterARestart() {
        let r = ring(), six = key(6, now, 6)
        var opened = 0
        XCTAssertFalse(r.partsToSave())
        XCTAssertEqual(take(r, six, anna, ben, now) { opened += 1; return $0 }, "added")
        XCTAssertTrue(r.partsToSave()); XCTAssertFalse(r.partsToSave()); XCTAssertEqual(r.openedParts.count, 1)
        for i in 0..<5 { XCTAssertEqual(take(r, six, anna, ben, now + Int64(i)) { opened += 1; return $0 }, "ignored") }
        XCTAssertEqual(opened, 1, "read again from the store: not opened again")
        // After a restart the engine gives the keyring its epochs and the parts it opened.
        let next = Keyring(); r.all.forEach { next.add($0) }; next.restoreParts(r.openedParts)
        XCTAssertEqual(take(next, six, anna, ben, now + hour) { opened += 1; return $0 }, "ignored"); XCTAssertEqual(opened, 1)
        // The same box in someone else's key is another part: one secret can travel in two keys.
        XCTAssertEqual(take(next, key(6, now + 1, 6), cara, ben, now + hour) { opened += 1; return $0 }, "added"); XCTAssertEqual(opened, 2)
        XCTAssertNotEqual(Keyring.partMark(Data(count: 40), maker: anna, six), Keyring.partMark(Data(count: 40), maker: ben, six))
    }

    // MARK: 4. One id, several packets

    func testThePacketStoredFirstUnderAnIdGoesByItAndTheOthersByTheirKey() {
        let a = Packet(id: "00000000000000a1", ts: now, ttl: 16, cipher: Data(repeating: 1, count: 98)), b = Packet(id: a.id, ts: now, ttl: 16, cipher: Data(repeating: 2, count: 98))
        XCTAssertEqual(StoreCap.name(a, first: true), a.id); XCTAssertEqual(StoreCap.name(b, first: false), MeshRouter.key(b))
        XCTAssertNotEqual(StoreCap.name(a, first: false), StoreCap.name(b, first: false)); XCTAssertEqual(StoreCap.name(b.withTtl(3), first: false), StoreCap.name(b, first: false))
        XCTAssertEqual(StoreCap.packetId(StoreCap.name(b, first: false)), a.id); XCTAssertEqual(StoreCap.packetId(a.id), a.id)
    }

    func testTheSameSignedMessageHasOneMarkAndAnotherMessageUnderItsIdAnother() throws {
        let g = GroupCrypto.fromSecret(Data(repeating: 7, count: 32)), id = String(format: "%04x", g.mailbox) + "000000000009", t: Int64 = 1_800_000_000_000
        func open(_ text: String, _ iv: UInt8, _ sender: String) throws -> GroupCrypto.Opened {
            let c = try g.seal(id: id, ts: t, sender: sender, name: "Ben", text: text, iv: Data(repeating: iv, count: 12))
            return try XCTUnwrap(g.openSigned(Packet(id: id, ts: g.hideTime(t, c), ttl: 16, cipher: c)))
        }
        let first = try open("dummy text", 1, ben), again = try open("dummy text", 2, ben), other = try open("another text", 3, ben), others = try open("dummy text", 4, cara)
        XCTAssertNotEqual(first.key, again.key, "two packets")
        XCTAssertEqual(first.mark, again.mark, "one message, sealed and signed again")
        XCTAssertNotEqual(first.mark, other.mark); XCTAssertNotEqual(first.mark, others.mark)
        XCTAssertTrue(first.mark.hasPrefix("\(id):")); XCTAssertEqual(first.mark.count, 33)
    }

    // MARK: 5. The 64 epochs a phone holds

    func testAMembersOldKeysDoNotPushOutTheEpochsBefore() {
        let r = Keyring()
        for n: Int64 in 5...7 { r.add(.fresh(number: n, made: now - (8 - n) * day, secret: secret(Int(n)), members: all, admins: [anna], taken: now - (8 - n) * day)) }
        // Ben, a member: keys numbered below the current epoch, dated an hour apart, four an hour as they arrive.
        for i: Int64 in 1...70 { _ = take(r, key(6, now - i * hour, 100 + Int(i)), ben, anna, now + i * 16 * 60_000) }
        XCTAssertEqual(r.all.filter { !$0.members.isEmpty }.map(\.number).sorted(), [5, 6, 7], "the group's own epochs stay")
        XCTAssertEqual(r.all.filter { $0.members.isEmpty && $0.by == ben }.count, 4, "one maker has only a few kept to read with")
        XCTAssertEqual(r.current.number, 7)
    }

    func testAFullKeyringDropsWhatIsKeptOnlyToReadWithFirst() {
        let r = Keyring()
        for n: Int64 in 1...60 { r.add(.init(number: n, made: now, secret: secret(Int(n)), members: all, admins: [anna])) }
        // Keys kept only to read with, from many makers, numbered above most of the group's own.
        for i in 1...10 { r.add(.init(number: 59, made: now, secret: secret(100 + i), members: [], admins: [anna], by: id(i))) }
        XCTAssertEqual(r.all.count, 64); XCTAssertEqual(r.all.filter { !$0.members.isEmpty }.map(\.number).sorted(), Array(1...60))
        // With nothing of that kind left to drop, the lowest goes, as before.
        let full = Keyring()
        for n: Int64 in 1...70 { full.add(.init(number: n, made: now, secret: secret(Int(n)), members: all, admins: [anna])) }
        XCTAssertEqual(full.all.map(\.number).sorted(), Array(7...70))
    }

    // MARK: 6. Parts that don't open

    func testPartsThatDoNotOpenAreTriedOnlyAFewTimesAnHour() {
        let r = ring()
        var tries = 0
        // Ben, a member, sends 50 keys whose part for this phone is garbage: each try is a key agreement in secure hardware.
        let got = (1...50).map { i in take(r, key(6, now, 200 + i), ben, anna, now + Int64(i)) { _ in tries += 1; return nil } }
        XCTAssertEqual(tries, 4); XCTAssertTrue(got.allSatisfy { $0 == "leftOut" }, "each still counts as a key this phone was left out of")
        // Another member's key is tried, and opens.
        XCTAssertEqual(take(r, key(6, now, 300), cara, anna, now + 60) { tries += 1; return $0 }, "added"); XCTAssertEqual(tries, 5)
        // An hour later Ben's are tried again.
        _ = take(r, key(7, now + hour, 301), ben, anna, now + hour + 100) { _ in tries += 1; return nil }; XCTAssertEqual(tries, 6)
    }

    func testAPhoneStillJoiningStopsTryingWhateverTheMaker() {
        // With a typed code anyone who holds it can send a first key, each under a key pair made for it.
        let r = Keyring()
        var tries = 0
        for i in 1...200 {
            let k = Rekey(epoch: 1, made: now, maker: Data(count: 33), admins: [id(i)], answers: dan, parts: [id(i), dan].map { ($0, Data(count: 40)) })
            _ = take(r, k, id(i), dan, now + Int64(i)) { _ in tries += 1; return nil }
        }
        XCTAssertEqual(tries, 16); XCTAssertNil(r.currentOrNil)
        // An hour later the key that lets it in is opened.
        let real = Rekey(epoch: 6, made: now + hour, maker: Data(count: 33), admins: [anna], answers: dan, parts: (all + [dan]).map { ($0, Rekey.box(secret(9), code: nil)) })
        XCTAssertEqual(take(r, real, anna, dan, now + hour + 300) { tries += 1; return $0 }, "added")
    }

    // MARK: 7. "That phone is behind"

    func testAKeyDatedFarAheadIsNotFromAPhoneThatFellBehind() {
        let r = ring(7)
        XCTAssertFalse(r.behind(Rekey(epoch: 6, made: now + 400 * day, maker: Data(count: 33), admins: [], answers: nil, parts: []), maker: ben, now: now), "no key made later could ever be newer than this")
        XCTAssertFalse(r.behind(key(6, now + 11 * 60_000, 1), maker: ben, now: now))
        XCTAssertFalse(r.behind(key(6, now, 1), maker: dan, now: now), "not from someone who isn't in")
        XCTAssertFalse(r.behind(key(6, now - 2 * day, 1), maker: ben, now: now), "made before the current epoch")
        XCTAssertTrue(r.behind(key(6, now + 9 * 60_000, 1), maker: ben, now: now), "clocks differ by minutes")
    }

    func testOneMemberIsAnsweredOnceAnHour() {
        let r = ring(7)
        XCTAssertTrue(r.behind(key(6, now - 60_000, 1), maker: ben, now: now))
        XCTAssertFalse((2...50).contains { r.behind(key(6, now - 60_000 + Int64($0), $0), maker: ben, now: now + Int64($0) * 1_000) })
        XCTAssertTrue(r.behind(key(6, now - 60_000, 60), maker: cara, now: now + 60_000), "another member's phone can be behind too")
        XCTAssertTrue(r.behind(key(6, now + hour, 61), maker: ben, now: now + hour), "an hour later Ben's is answered again")
    }

    // MARK: 8. Reading a new key before its signature is checked

    func testANewKeyThatListsTooManyIsNotRead() {
        let key33 = Data(count: 33), many = (1...101).map(id)
        XCTAssertNil(Rekey.decode(Rekey(epoch: 6, made: 1, maker: key33, admins: [anna], answers: nil, parts: Rekey.split(many)[0].map { ($0, Data(count: 1)) }, removal: false, members: many).encode()), "101 members")
        XCTAssertNil(Rekey.decode(Rekey(epoch: 6, made: 1, maker: key33, admins: many, answers: nil, parts: [(anna, Data(count: 1))]).encode()), "101 admins")
        XCTAssertNil(Rekey.decode(Rekey(epoch: 6, made: 1, maker: key33, admins: [anna], answers: nil, parts: many.prefix(11).map { ($0, Data(count: 1)) }).encode()), "11 parts")
        // As many member ids as a packet holds, and parts that all name the last one: not even the lists are read.
        let huge = Rekey(epoch: 6, made: 1, maker: key33, admins: [anna], answers: nil, parts: (1...700).map { _ in (id(990), Data()) }, removal: false, members: (1...990).map(id))
        XCTAssertNil(Rekey.decode(huge.encode()))
    }

    func testTheLargestGroupsKeyIsStillRead() throws {
        let hundred = (1...100).map(id)
        for some in Rekey.split(hundred) {
            let r = try XCTUnwrap(Rekey.decode(Rekey(epoch: 6, made: 1, maker: Data(repeating: 3, count: 33), admins: hundred, answers: hundred[99], parts: some.map { ($0, Data(repeating: 9, count: 40)) }, removal: false, members: hundred).encode()))
            XCTAssertEqual(r.members, hundred); XCTAssertEqual(r.admins, hundred); XCTAssertEqual(r.parts.map(\.id), some); XCTAssertEqual(r.answers, hundred[99])
        }
        XCTAssertEqual(Rekey.decode(Rekey(epoch: 6, made: 1, maker: Data(count: 33), admins: [id(1)], answers: nil, parts: [(id(1), Data(count: 1))]).encode())?.members.first, "00000000000f0001", "ids read as lowercase hex")
        XCTAssertEqual(Rekey.decode(Rekey(epoch: 6, made: 1, maker: Data(count: 33), admins: ["fedcba9876543210"], answers: nil, parts: [("fedcba9876543210", Data(count: 1))]).encode())?.admins.first, "fedcba9876543210")
    }
}
