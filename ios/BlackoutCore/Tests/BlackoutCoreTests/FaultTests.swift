import XCTest
import CryptoKit
@testable import BlackoutCore

/// Simulated phones running the real decision code (`Keyring.take`), given the same new keys in every order
/// (spec/DESIGN-v0.6-groups.md, step 6). The same cases as Android's FaultTest.
final class FaultTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444", eve = "5555555555555555"
    private var all: [String] { [anna, ben, cara, dan] }
    private let now: Int64 = 1_000_000_000_000, hour: Int64 = 3_600_000

    private func secret(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }

    private struct Pkt { let r: Rekey, maker: String, door: String }

    /// Number `n`, by `by`, sealed for `members`, through code `door`. `removes`: a removal to the new code `code`.
    private func pkt(_ n: Int64, _ by: String, _ members: [String], _ door: String, _ s: UInt8, removes: String? = nil, code: String? = nil,
                     admins: [String]? = nil, answers: String? = nil, made: Int64? = nil) -> Pkt {
        Pkt(r: Rekey(epoch: n, made: made ?? now - 100 * hour + n * hour, maker: Data(count: 33), admins: (admins ?? [anna, ben]).filter(members.contains),
                     answers: answers ?? removes, parts: members.map { (id: $0, box: Rekey.box(secret(s), code: code)) }, removal: removes != nil), maker: by, door: door)
    }

    /// A phone as the engines run one: it reads the store again after every new epoch, oldest first.
    private final class Phone {
        let me: String, ring = Keyring(), now: Int64
        var door = "d1", old: [String] = [], removedAt: (number: Int64, rank: Int)?, removedBy: String?, seen: [Pkt] = []
        var leftOut: (number: Int64, rank: Int)?
        init(_ me: String, epoch: Keyring.Epoch?, now: Int64) { self.me = me; self.now = now; if let epoch { ring.add(epoch) } }
        func get(_ p: Pkt) { seen.append(p); if tryIt(p) { settle() } }
        private func tryIt(_ p: Pkt) -> Bool {
            guard p.door == door || old.contains(p.door) else { return false }
            switch ring.take(p.r, maker: p.maker, me: me, door: p.door, oldDoor: p.door != door, removedAt: removedAt, now: now, removedBy: removedBy, open: { $0 }) {
            case .added(_, let moveTo, let back):
                if back { removedAt = nil; removedBy = nil }
                if let moveTo, moveTo != door { old.insert(door, at: 0); door = moveTo }
                return true
            case .removed(let n, let r, let by): removedAt = (n, r); removedBy = by; return false
            case .leftOut(let n, let rank): leftOut = (n, rank); return false
            default: return false
            }
        }
        private func settle() { var again = true; while again { again = false; for p in seen.sorted(by: { $0.r.made < $1.r.made }) where tryIt(p) { again = true } } }
    }

    private func phone(_ me: String, admins: [String]? = nil) -> Phone {
        Phone(me, epoch: .init(number: 5, made: now - 200 * hour, secret: secret(99), members: all, admins: admins ?? [anna, ben]), now: now)
    }
    private func after(_ me: String, _ ps: [Pkt]) -> Phone { let p = phone(me); ps.forEach(p.get); return p }
    /// A phone that has the code and no epoch yet.
    private func joining(_ me: String, _ ps: [Pkt]) -> Phone { let p = Phone(me, epoch: nil, now: now); ps.forEach(p.get); return p }
    private func orders(_ l: [Pkt]) -> [[Pkt]] {
        l.count < 2 ? [l] : l.indices.flatMap { i -> [[Pkt]] in var rest = l; let x = rest.remove(at: i); return orders(rest).map { [x] + $0 } }
    }

    func testTwoAdminsRemovingDifferentPeopleAtOnce() {
        let a = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA"), b = pkt(6, ben, [anna, ben, dan], "d1", 2, removes: cara, code: "BBBB-BBBB-BBBB-BBBB")
        for o in orders([a, b]) {
            for me in [anna, ben] {
                let p = after(me, o)
                XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.removes, dan); XCTAssertEqual(p.ring.stillToRemove(), [cara]); XCTAssertNil(p.removedAt)
            }
            let c = after(cara, o); XCTAssertEqual(c.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertNil(c.removedAt) // told first by the removal that lost: undone
            XCTAssertNotNil(after(dan, o).removedAt)
            let finish = pkt(7, anna, [anna, ben], "AAAA-AAAA-AAAA-AAAA", 3, removes: cara, code: "AAAA-AAAA-AAAA-AAA2")
            for me in [anna, ben] { let p = after(me, o + [finish]); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAA2"); XCTAssertTrue(p.ring.stillToRemove().isEmpty) }
            XCTAssertNotNil(after(cara, o + [finish]).removedAt)
        }
    }

    func testAdminsRemovingEachOther() {
        let a = pkt(6, anna, [anna, cara, dan], "d1", 1, removes: ben, code: "AAAA-AAAA-AAAA-AAAA"), b = pkt(6, ben, [ben, cara, dan], "d1", 2, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")
        for o in orders([a, b]) {
            for me in [anna, cara, dan] {
                let p = after(me, o)
                XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertNil(p.removedAt); XCTAssertTrue(p.ring.stillToRemove().isEmpty); XCTAssertFalse(p.ring.removed(anna, before: now))
            }
            XCTAssertNotNil(after(ben, o).removedAt)
        }
    }

    func testARemovedAdminCantComeBackLater() {
        let out = pkt(6, anna, [anna, cara, dan], "d1", 1, removes: ben, code: "AAAA-AAAA-AAAA-AAAA")
        let join = pkt(7, anna, [anna, cara, dan, eve], "AAAA-AAAA-AAAA-AAAA", 2, admins: [anna], answers: eve)
        let p = after(cara, [out, join, pkt(6, ben, [ben, cara, dan], "d1", 3, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")])
        XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 7); XCTAssertFalse(p.ring.removed(anna, before: now))
        let q = after(cara, [out, join, pkt(8, ben, [ben, cara, dan], "d1", 4, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")])
        XCTAssertEqual(q.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(q.ring.current.number, 7)
        XCTAssertEqual(after(cara, [out, pkt(7, ben, all, "d1", 5)]).ring.current.number, 6)
    }

    /// The first dummy secret from 4 up whose epoch sorts before the one made from `s`: whoever makes a key picks its secret, and so its hash.
    private func lowerThan(_ s: UInt8) -> UInt8 { (4...99).first { hashOf($0) < hashOf(s) }! }
    private func hashOf(_ b: UInt8) -> String { Keyring.Epoch.fresh(number: 1, made: 0, secret: secret(b), members: [ben], admins: []).hash }

    func testARemovedAdminWhoLearnsTheNewCodeDecidesNothing() {
        let a = "AAAA-AAAA-AAAA-AAAA"
        let out = pkt(6, anna, [anna, cara, dan], "d1", 1, removes: ben, code: a)
        let rival = pkt(6, ben, [ben, cara, dan], "d1", 3, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")  // allowed through the old door; it loses
        let crossed = pkt(6, dan, all, "d1", 2)                                                          // a member's key that crossed the removal
        let key = pkt(7, ben, [ben, cara, dan], a, 4, admins: [ben])
        let removal = pkt(7, ben, [ben, cara, dan], a, 5, removes: anna, code: "BBBB-BBBB-BBBB-BBB2", admins: [ben])
        // Either of those still lists him as an admin. Through the new door his next key is refused all the same.
        for held in [[out, rival], [crossed, out]] { for next in [key, removal] { for o in orders(held + [next]) { for me in [cara, anna] {
            let p = after(me, o)
            XCTAssertEqual(p.door, a); XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.by, anna)
            XCTAssertFalse(p.ring.removed(anna, before: now)); XCTAssertNil(p.removedAt)
        } } } }
        // Nor does the admin list he wrote in his rival removal give anyone else a say.
        let list = pkt(6, ben, [ben, cara, dan], "d1", 3, removes: anna, code: "BBBB-BBBB-BBBB-BBBB", admins: [ben, dan])
        XCTAssertEqual(after(cara, [out, list, pkt(7, dan, [cara, dan], a, 8, admins: [dan])]).ring.current.number, 6)
        // A removal he numbers below his own, to have it judged against an epoch in which he still was an admin, is refused too.
        let p = phone(cara); p.ring.add(.init(number: 4, made: now - 300 * hour, secret: secret(98), members: all, admins: [anna, ben]))
        p.get(out)
        for door in ["d1", a] { p.get(pkt(5, ben, [anna, ben, cara], door, 6, removes: dan, code: "CCCC-CCCC-CCCC-CCCC")) }
        XCTAssertFalse(p.ring.removed(dan, before: now)); XCTAssertTrue(p.ring.stillToRemove().isEmpty); XCTAssertEqual(p.door, a)
    }

    func testALateKeyThroughTheOldDoorCantRaiseARemovedAdminsSeniority() {
        let a = "AAAA-AAAA-AAAA-AAAA"
        for admins in [[dan, anna, ben], [anna, ben]] {                                                  // Anna removes Ben, who is listed after her
            let key = pkt(6, anna, all, "d1", 1, admins: admins), out = pkt(7, anna, [anna, cara, dan], "d1", 2, removes: ben, code: a, admins: admins)
            let late = pkt(6, ben, all, "d1", 3, admins: [ben])                                          // kept only to read with, and it names him alone
            let rival = pkt(7, ben, [ben, cara, dan], "d1", lowerThan(2), removes: anna, code: "BBBB-BBBB-BBBB-BBBB", admins: [ben])
            for me in [cara, anna] {
                let p = phone(me, admins: admins); [key, out, late, rival].forEach(p.get)
                XCTAssertEqual(p.ring.rank(rival.r, maker: ben), admins.firstIndex(of: ben))
                XCTAssertEqual(p.door, a); XCTAssertEqual(p.ring.current.by, anna); XCTAssertFalse(p.ring.removed(anna, before: now)); XCTAssertNil(p.removedAt)
            }
        }
    }

    func testALateRivalRemovalByAnAdminRemovedSinceCountsForNothing() {
        let a = "AAAA-AAAA-AAAA-AAAA", a2 = "AAAA-AAAA-AAAA-AAA2"
        // Anna removes Dan (6), then Ben (7). Ben still knows the code from before 6, when he was an admin.
        func check(_ me: String, _ admins: [String], _ named: String) {
            let r1 = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: a, admins: admins), r2 = pkt(7, anna, [anna, cara], a, 2, removes: ben, code: a2, admins: admins)
            let p = phone(me, admins: admins); p.get(r1); p.get(r2)
            p.get(pkt(6, ben, [anna, ben, cara].filter { $0 != named }, "d1", 3, removes: named, code: "CCCC-CCCC-CCCC-CCCC", admins: [ben]))
            XCTAssertTrue(p.ring.stillToRemove().isEmpty); XCTAssertEqual(p.door, a2); XCTAssertEqual(p.ring.current.number, 7) // no admin's phone finishes it
            // Nor does the admin list he wrote in it make him senior: his rival to his own removal still loses, whatever its hash.
            p.get(pkt(7, ben, [ben, cara], a, lowerThan(2), removes: anna, code: "BBBB-BBBB-BBBB-BBBB", admins: [ben]))
            XCTAssertEqual(p.door, a2); XCTAssertEqual(p.ring.current.by, anna); XCTAssertFalse(p.ring.removed(anna, before: now)); XCTAssertNil(p.removedAt)
        }
        check(anna, [anna, ben], cara); check(cara, [anna, ben, cara], anna)
    }

    func testAJuniorAdminsRivalRemovalDoesntStopTheSeniorOne() { // Ben's removal of Anna lost to hers of Dan; she can still remove him, and then his counts for nothing
        let r1 = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA"), b = pkt(6, ben, [ben, cara, dan], "d1", 2, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")
        let r2 = pkt(7, anna, [anna, cara], "AAAA-AAAA-AAAA-AAAA", 3, removes: ben, code: "AAAA-AAAA-AAAA-AAA2")
        for o in orders([r1, b, r2]) {
            let p = after(cara, o)
            XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAA2"); XCTAssertEqual(p.ring.current.removes, ben); XCTAssertTrue(p.ring.stillToRemove().isEmpty); XCTAssertFalse(p.ring.removed(anna, before: now))
        }
    }

    func testTheCreatorOverrulesANewerAdmin() {
        let out = pkt(6, ben, [ben, cara, dan], "d1", 1, removes: anna, code: "BBBB-BBBB-BBBB-BBBB")
        let join = pkt(7, cara, [ben, cara, dan, eve], "BBBB-BBBB-BBBB-BBBB", 2, admins: [ben], answers: eve)
        let rival = pkt(6, anna, [anna, cara, dan], "d1", 3, removes: ben, code: "AAAA-AAAA-AAAA-AAAA")
        for o in orders([out, join, rival]) {
            let p = after(cara, o); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.removes, ben)
        }
    }

    func testARemovalBuiltOnOneThatLost() { // Ben removes Dan, then Anna through his new code, while Anna's rival removal was on its way
        let junior = pkt(6, ben, [anna, ben, cara], "d1", 1, removes: dan, code: "BBBB-BBBB-BBBB-BBBB")
        let next = pkt(7, ben, [ben, cara], "BBBB-BBBB-BBBB-BBBB", 2, removes: anna, code: "BBBB-BBBB-BBBB-BBB2")
        let senior = pkt(6, anna, [anna, ben, cara], "d1", 3, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")
        for o in orders([junior, next, senior]) { let p = after(cara, o); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6) }
    }

    func testASeniorAdminsRemovalNumberedBelowAJuniorOnesStillWins() { // Ben, whom Anna is removing, gets a key and then his removal of her to a phone first
        let a = "AAAA-AAAA-AAAA-AAAA", b = "BBBB-BBBB-BBBB-BBBB"
        let ben6 = pkt(6, ben, all, "d1", 1), ben7 = pkt(7, ben, [ben, cara, dan], "d1", 2, removes: anna, code: b)
        let anna6 = pkt(6, anna, [anna, cara, dan], "d1", 3, removes: ben, code: a)
        for o in orders([ben6, ben7, anna6]) {
            for me in [cara, dan, anna] {
                let p = after(me, o)
                XCTAssertEqual(p.door, a); XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.by, anna); XCTAssertEqual(p.ring.current.admins, [anna])
                XCTAssertTrue(p.ring.removed(ben, before: now)); XCTAssertFalse(p.ring.removed(anna, before: now)); XCTAssertNil(p.removedAt)
            }
            XCTAssertNotNil(after(ben, o).removedAt)                                                     // his own phone is told, in every order
        }
        let first = after(cara, [ben6, ben7])
        XCTAssertEqual(first.door, b); XCTAssertNotNil(first.ring.admit(anna6.r, maker: anna, oldDoor: "d1", now: now)) // through what is now an old door, numbered below the removal followed out of it
        // A member his higher-numbered removal named is back in when hers, which keeps them, arrives.
        let out7 = pkt(7, ben, [anna, ben, cara], "d1", 2, removes: dan, code: b)
        for o in orders([ben6, out7, anna6]) { let p = after(dan, o); XCTAssertNil(p.removedAt); XCTAssertEqual(p.door, a); XCTAssertEqual(p.ring.current.number, 6) }
        // Only seniority does that. A junior admin can't number a removal below a senior one's to undo it, and nobody overrules themselves.
        let key = pkt(6, anna, all, "d1", 4), out = pkt(7, anna, [anna, ben, cara], "d1", 5, removes: dan, code: a)
        let late = pkt(6, ben, [ben, cara, dan], "d1", 6, removes: anna, code: b), own = pkt(6, anna, [anna, cara, dan], "d1", 7, removes: ben, code: "CCCC-CCCC-CCCC-CCCC")
        for me in [cara, dan] { for o in orders([late, own]) {
            let p = after(me, [key, out] + o)
            XCTAssertEqual(p.removedAt != nil, me == dan); XCTAssertEqual(p.door, me == dan ? "d1" : a)
            if me == cara { XCTAssertEqual(p.ring.current.number, 7); XCTAssertFalse(p.ring.removed(anna, before: now)); XCTAssertFalse(p.ring.removed(ben, before: now)) }
        } }
    }

    func testASecretSentOnInAnotherKeyDoesntShutOutTheKeyItCameFrom() {
        let a = "AAAA-AAAA-AAAA-AAAA"
        let removal = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: a)                    // Anna removes Dan
        // Cara, who isn't an admin, got its secret in her part and sends it on in a key of her own: numbered the same, above or below.
        for n: Int64 in [6, 7, 4] { for o in orders([pkt(n, cara, all, "d1", 1), removal]) {
            let p = after(ben, o)
            XCTAssertEqual(p.door, a); XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.by, anna); XCTAssertEqual(p.ring.current.removes, dan)
            XCTAssertFalse(p.ring.current.members.contains(dan)); XCTAssertTrue(p.ring.removed(dan, before: now)); XCTAssertTrue(p.ring.current === p.ring.lastMove)
        } }
        // The same goes for an admin's key that lets someone in.
        let join = pkt(6, anna, all + [eve], "d1", 2, answers: eve)
        for o in orders([pkt(6, cara, all, "d1", 2), join]) { let p = after(ben, o); XCTAssertEqual(p.ring.current.by, anna); XCTAssertTrue(p.ring.current.members.contains(eve)) }
        // Either key read again changes nothing.
        let p = after(ben, [pkt(6, cara, all, "d1", 1), removal]), held = p.ring.all.count
        XCTAssertEqual(p.ring.all.filter { $0.number == 6 }.count, 2)
        p.get(removal); p.get(pkt(6, cara, all, "d1", 1)); XCTAssertEqual(p.ring.all.count, held)
    }

    func testAMembersKeyCantUndoAnAdminsChoiceToLetSomeoneIn() {
        let join = pkt(6, anna, all + [eve], "d1", 1, answers: eve)                                      // Anna lets Eve in
        let rival = pkt(6, cara, all, "d1", lowerThan(1))                                                // Cara, not an admin: the same number, without Eve, and a hash that sorts first
        for o in orders([join, rival]) { for me in [anna, ben, dan] {
            let p = after(me, o)
            XCTAssertEqual(p.ring.current.number, 6); XCTAssertEqual(p.ring.current.by, anna); XCTAssertTrue(p.ring.current.members.contains(eve))
            XCTAssertEqual(p.ring.all.filter { $0.number == 6 }.count, 2)                                // hers is kept, to read what she wrote with it
        } }
        // Eve's phone, still joining, has only Anna's key to go by. A member's key that lists the same people can't take it either.
        let same = pkt(6, cara, all + [eve], "d1", lowerThan(1), made: now - 90 * hour)
        for o in orders([rival, same]) { XCTAssertEqual(joining(eve, [join] + o).ring.current.by, anna) }
        // Two keys from members who aren't admins still settle by the hash, as before.
        let other = pkt(6, dan, all, "d1", 1)
        for o in orders([rival, other]) { XCTAssertEqual(after(ben, o).ring.current.by, cara) }
    }

    func testAKeyThatListsSomeoneWithoutAPartTheyCanOpen() throws {
        func fromDan(_ parts: [(id: String, box: Data)], _ members: [String]? = nil) -> Rekey {
            Rekey(epoch: 6, made: now - 94 * hour, maker: Data(count: 33), admins: [anna, ben], answers: nil, parts: parts, members: members ?? all)
        }
        let good = Rekey.box(secret(1), code: nil)
        // No part for Cara: every phone can see that, and refuses the key as it comes off the wire.
        XCTAssertNil(Rekey.decode(fromDan([anna, ben, dan].map { (id: $0, box: good) }).encode()))
        XCTAssertNotNil(Rekey.decode(fromDan(all.map { (id: $0, box: good) }).encode()))
        // A bigger group's key goes in several packets: each has to hold exactly its share of the parts.
        let many = (1...25).map { String(format: "%016x", $0) }, shares = Rekey.split(many)
        for share in shares { XCTAssertNotNil(Rekey.decode(fromDan(share.map { (id: $0, box: good) }, many).encode())) }
        XCTAssertNil(Rekey.decode(fromDan(shares[1].dropFirst().map { (id: $0, box: good) }, many).encode()))        // one of its people left out
        XCTAssertNil(Rekey.decode(fromDan(many.filter { $0 != many[4] }.map { (id: $0, box: good) }, many).encode())) // everyone but one, in a single packet
        // A part that doesn't open: only Cara's phone can tell. The others take the key and write with it.
        let spoiled = Pkt(r: try XCTUnwrap(Rekey.decode(fromDan(all.map { (id: $0, box: $0 == cara ? Data(count: 5) : good) }).encode())), maker: dan, door: "d1")
        let phones = all.map { me -> Phone in let p = phone(me); p.get(spoiled); return p }, hers = phones[2]
        for p in phones where p !== hers { XCTAssertEqual(p.ring.current.number, 6); XCTAssertTrue(p.ring.current.members.contains(cara)); XCTAssertNil(p.leftOut) }
        let out = try XCTUnwrap(hers.leftOut)
        XCTAssertEqual(hers.ring.current.number, 5); XCTAssertEqual(out.number, 6); XCTAssertEqual(out.rank, .max)
        // Her phone asks its way back as the engines do, like one that was away: with its own next key. It has Dan's number, so the hash decides.
        func agreed(_ ps: [Phone]) -> Bool { Set(ps.map { $0.ring.current.id }).count == 1 }
        let lost = pkt(6, cara, all, "d1", (4...99).first { hashOf($0) > hashOf(1) }!)
        phones.forEach { $0.get(lost) }
        XCTAssertFalse(agreed(phones)); XCTAssertEqual(phones[0].ring.current.by, dan); XCTAssertEqual(hers.ring.current.by, cara)
        hers.leftOut = nil; hers.get(spoiled); XCTAssertNotNil(hers.leftOut)                              // read again from the store: still the key the others follow
        // So an hour later it makes one more, numbered above both, and everyone moves to it.
        let back = pkt(7, cara, all, "d1", 7)
        phones.forEach { $0.get(back) }
        XCTAssertTrue(agreed(phones)); for p in phones { XCTAssertEqual(p.ring.current.number, 7); XCTAssertEqual(p.ring.current.by, cara) }
        hers.leftOut = nil; hers.get(spoiled); XCTAssertNil(hers.leftOut)                                 // read again: it is below her epoch now
        // When her first key sorts before Dan's, that one already settles it.
        let lucky = all.map { me -> Phone in let p = phone(me); p.get(spoiled); p.get(pkt(6, cara, all, "d1", lowerThan(1))); return p }
        XCTAssertTrue(agreed(lucky)); XCTAssertEqual(lucky[0].ring.current.by, cara)
        // Not answered: a key numbered below the current epoch, one that an admin's key of the same number beats whatever the hashes, or a removal, which only an admin can make.
        let late = phone(cara); late.get(pkt(7, anna, all, "d1", 8)); late.get(spoiled); XCTAssertNil(late.leftOut)
        let beaten = phone(cara); beaten.get(pkt(6, anna, all, "d1", 8)); beaten.get(spoiled); XCTAssertNil(beaten.leftOut)
        let gone = Rekey(epoch: 6, made: now - 94 * hour, maker: Data(count: 33), admins: [anna], answers: dan,
                         parts: [anna, ben, cara].map { (id: $0, box: $0 == cara ? Data(count: 5) : Rekey.box(secret(9), code: "AAAA-AAAA-AAAA-AAAA")) }, removal: true)
        let removed = phone(cara); removed.get(Pkt(r: gone, maker: anna, door: "d1")); XCTAssertNil(removed.leftOut)
    }

    func testNewKeysInEveryOrder() {
        let ps = [pkt(6, anna, all, "d1", 1), pkt(7, ben, all, "d1", 2), pkt(8, anna, all + [eve], "d1", 3, answers: eve),
                  pkt(9, anna, [anna, ben, cara, eve], "d1", 4, removes: dan, code: "AAAA-AAAA-AAAA-AAAA"), pkt(10, ben, [anna, ben, cara, eve], "AAAA-AAAA-AAAA-AAAA", 5)]
        let first = after(cara, ps)
        XCTAssertEqual(first.ring.current.number, 10); XCTAssertEqual(first.door, "AAAA-AAAA-AAAA-AAAA")
        for o in orders(ps) { let p = after(cara, o); XCTAssertEqual(p.ring.current.hash, first.ring.current.hash); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.all.count, first.ring.all.count) }
    }

    func testAPhoneAwayForTenDays() {
        let p = after(cara, [pkt(12, dan, all, "d1", 1)])
        XCTAssertEqual(p.ring.current.number, 12); XCTAssertEqual(p.ring.current.admins, [anna, ben])
        let group = after(anna, [pkt(12, dan, all, "d1", 1)]), mine = pkt(6, cara, all, "d1", 2, made: now)
        XCTAssertTrue(group.ring.behind(mine.r, maker: cara))
        group.get(mine); XCTAssertEqual(group.ring.current.number, 12)
        XCTAssertEqual(after(cara, [mine, pkt(13, anna, all, "d1", 3, made: now + 1)]).ring.current.number, 13)
    }

    func testAPhoneAwayWhenSomeoneWasRemovedHasToWaitForTheMissingKeys() {
        let p = after(cara, [pkt(8, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")]); XCTAssertEqual(p.door, "d1")
        p.get(pkt(6, anna, all, "d1", 2)); XCTAssertEqual(p.door, "d1")
        p.get(pkt(7, anna, all, "d1", 3)); XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA")
    }

    func testARemovedPhoneGetsNowhere() {
        let out = pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")
        let p = after(cara, [out])
        p.get(pkt(7, dan, all, "d1", 2)); p.get(pkt(7, dan, [cara], "d1", 3, removes: anna, code: "DDDD-DDDD-DDDD-DDDD"))
        XCTAssertEqual(p.door, "AAAA-AAAA-AAAA-AAAA"); XCTAssertEqual(p.ring.current.number, 6)
        XCTAssertTrue(p.ring.removed(dan, before: now)); XCTAssertFalse(p.ring.removed(cara, before: now))
        let d = after(dan, [out]); XCTAssertNotNil(d.removedAt)
        d.get(pkt(7, anna, [anna, ben, cara], "AAAA-AAAA-AAAA-AAAA", 4)); XCTAssertEqual(d.ring.current.number, 5)
    }

    func testSomeoneRemovedAddsNoKeys() {
        let a = "AAAA-AAAA-AAAA-AAAA"
        let p = after(cara, [pkt(6, anna, [anna, ben, cara], "d1", 1, removes: dan, code: a)]) // Anna removed Dan: the group moved on from d1
        let before = p.ring.all.count
        // Dan still has the old code, and epoch 5, which lists him, stays for a week. A key numbered below his removal, with a
        // secret and a date he chose, would be kept to read with: he could write with it once the removal itself has expired.
        p.get(pkt(5, dan, [dan, cara], "d1", 3, made: now))
        p.get(pkt(4, dan, all, "d1", 4, made: now - 2 * hour))
        XCTAssertEqual(p.ring.all.count, before); XCTAssertFalse(p.ring.all.contains { $0.by == dan })
        // Nor through the current door, should he learn the new code, whatever its number.
        p.get(pkt(7, anna, [anna, ben, cara], a, 5)); p.get(pkt(8, anna, [anna, ben, cara], a, 6)); p.get(pkt(9, anna, [anna, ben, cara], a, 7))
        XCTAssertEqual(p.ring.current.number, 9)
        p.get(pkt(8, dan, [dan, cara], a, 8, made: now - 4 * hour)); p.get(pkt(5, dan, [dan, cara], a, 9, made: now - 6 * hour))
        XCTAssertFalse(p.ring.all.contains { $0.by == dan })
        // A member's late key through the old door is still kept to read with.
        let held = p.ring.all.count
        p.get(pkt(5, ben, all, "d1", 10)); XCTAssertEqual(p.ring.all.count, held + 1)
    }

    func testANameInAKeyKeptForReadingLetsNobodyWrite() throws {
        // A member's key numbered below the current epoch is kept to read with, whatever member list it carries.
        let p = after(cara, [pkt(6, anna, all, "d1", 1)])
        p.get(pkt(4, dan, [dan, cara, eve], "d1", 2)) // it lists Eve, whom nobody let in
        let planted = try XCTUnwrap(p.ring.all.first { $0.by == dan })
        XCTAssertTrue(planted.members.isEmpty); XCTAssertTrue(planted.lists(eve)) // so it opens what is sealed under her id
        XCTAssertTrue(p.ring.shutOut(eve, at: now, had: false)); XCTAssertTrue(p.ring.shutOut(eve, at: now, had: true)) // but nothing under it is shown
        for m in all { XCTAssertFalse(p.ring.shutOut(m, at: now, had: false)) }
        XCTAssertFalse(Keyring().shutOut(eve, at: now, had: false)) // the Public channel has no epochs: anyone writes there
    }

    func testAStrangerWithAnOldCodeCantFillThePhoneWithKeys() {
        let p = after(cara, [pkt(6, anna, all, "d1", 1), pkt(7, anna, [anna, ben, cara], "d1", 2, removes: dan, code: "AAAA-AAAA-AAAA-AAAA")])
        let before = p.ring.all.count
        p.get(pkt(3, eve, [cara], "d1", 3)); XCTAssertEqual(p.ring.all.count, before) // late, through the old door, from someone who never was in
        p.get(pkt(3, ben, all, "d1", 4)); XCTAssertEqual(p.ring.all.count, before + 1) // from a member: kept to read with
    }

    func testManyRivalsInRandomOrders() {
        var rnd = SeededRandom(seed: 42); let admins = [anna, ben, cara]
        func sha(_ b: UInt8) -> String { Hex.encode(Data(SHA256.hash(data: secret(b)))) }
        for round in 0..<300 {
            let makers = Array(admins.shuffled(using: &rnd).prefix(2 + Int.random(in: 0...1, using: &rnd))) // each admin at most once: a phone numbers its own one after the other
            let rivals: [(p: Pkt, by: String, i: UInt8)] = makers.enumerated().map { i, by in
                let t = all.filter { $0 != by }[Int.random(in: 0..<3, using: &rnd)]
                return (pkt(6, by, all.filter { $0 != t }, "d1", 10 + UInt8(i), removes: t, code: "CCCC-CCCC-CCCC-CCC\(i + 2)", admins: admins), by, UInt8(i))
            }
            let winner = rivals.min { a, b in
                let x = admins.firstIndex(of: a.by)!, y = admins.firstIndex(of: b.by)!
                return x != y ? x < y : sha(10 + a.i) < sha(10 + b.i)
            }!
            for me in all {
                let p = phone(me, admins: admins)
                for q in rivals.map(\.p).shuffled(using: &rnd) { p.get(q) }
                if winner.p.r.answers == me { XCTAssertNotNil(p.removedAt, "round \(round)") }
                else { XCTAssertNil(p.removedAt, "round \(round)"); XCTAssertEqual(p.door, "CCCC-CCCC-CCCC-CCC\(winner.i + 2)", "round \(round)") }
            }
        }
    }

    /// On iPhone a bad value traps and takes the app down, so this one matters most here.
    func testCrippledRekeysDoNothing() {
        let good = pkt(6, anna, all, "d1", 1, removes: dan, code: "AAAA-AAAA-AAAA-AAAA").r.encode()
        var rnd = SeededRandom(seed: 7)
        for n in 0..<good.count { XCTAssertNil(Rekey.decode(good.prefix(n))) }
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: all, admins: [anna]))
        func exercise(_ d: Data) {
            guard let x = Rekey.decode(d) else { return }
            _ = r.take(x, maker: anna, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: now, open: { $0 }) // whatever came out of decode must not crash
            _ = r.behind(x, maker: anna); _ = r.outranked(x, maker: anna)
        }
        for _ in 0..<3000 {
            var b = [UInt8](good)
            for _ in 0...Int.random(in: 0..<6, using: &rnd) { b[Int.random(in: 0..<b.count, using: &rnd)] = UInt8.random(in: 0...255, using: &rnd) }
            exercise(Data(b))
        }
        for _ in 0..<1000 { exercise(Data((0..<Int.random(in: 0..<300, using: &rnd)).map { _ in UInt8.random(in: 0...255, using: &rnd) })) }
    }
}

/// So a failure can be reproduced.
private struct SeededRandom: RandomNumberGenerator {
    var x: UInt64
    init(seed: UInt64) { x = seed &* 0x9E3779B97F4A7C15 | 1 }
    mutating func next() -> UInt64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
}
