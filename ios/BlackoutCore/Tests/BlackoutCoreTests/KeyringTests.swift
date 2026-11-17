import XCTest
import CryptoKit
@testable import BlackoutCore

/// Keyring (spec/DESIGN-v0.6-groups.md, "Keys"): the same cases as Android's KeyringTest.
final class KeyringTests: XCTestCase {
    private func secret(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }
    private func hash(_ b: UInt8) -> String { Hex.encode(Data(SHA256.hash(data: secret(b)))) }

    func testCurrentIsTheHighestEpochThenTheSmallestHash() {
        let r = Keyring()
        XCTAssertTrue(r.add(.init(number: 1, made: 1_000, secret: secret(1))))
        XCTAssertFalse(r.add(.init(number: 1, made: 2_000, secret: secret(1)))) // the same secret twice: kept once
        r.add(.init(number: 2, made: 3_000, secret: secret(2))); r.add(.init(number: 2, made: 3_000, secret: secret(3)))
        XCTAssertEqual(r.current.number, 2); XCTAssertEqual(r.current.hash, min(hash(2), hash(3)))
        XCTAssertEqual(r.all.count, 3); XCTAssertTrue(r.all.first === r.current)
    }

    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444"
    private func rekey(_ epoch: Int64, _ members: [String], admins: [String]? = nil, removes: String? = nil, made: Int64 = 1, answers: String? = nil) -> Rekey {
        Rekey(epoch: epoch, made: made, maker: Data(count: 33), admins: admins ?? [anna], answers: answers ?? removes, parts: members.map { (id: $0, box: Data(count: 1)) }, removal: removes != nil)
    }
    /// Epoch 5: Anna (admin), Ben and Cara.
    private func ring() -> Keyring { let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna])); return r }

    func testOnlyAdminsLeavePeopleOut() {
        XCTAssertNil(ring().admit(rekey(6, [anna, ben]), maker: ben, oldDoor: nil))
        XCTAssertEqual(ring().admit(rekey(6, [anna, ben]), maker: anna, oldDoor: nil), [anna])
    }

    func testTheCodeAloneDoesntLetAnyoneIn() {
        let members = [anna, ben, cara, dan]
        XCTAssertNil(ring().admit(rekey(6, members), maker: dan, oldDoor: nil, now: 2))                       // someone not in yet, adding themselves
        XCTAssertNil(ring().admit(rekey(6, members, admins: [dan]), maker: dan, oldDoor: nil, now: 2))        // and claiming to be the admin
        XCTAssertNil(ring().admit(rekey(6, members, answers: dan), maker: ben, oldDoor: nil, now: 2))         // a member can't add them either
        XCTAssertEqual(ring().admit(rekey(6, members, answers: dan), maker: anna, oldDoor: nil, now: 2), [anna]) // an admin can
        XCTAssertEqual(ring().admit(rekey(6, members, admins: [anna, ben]), maker: anna, oldDoor: nil), [anna, ben])
    }

    func testOnlyAdminsRemoveAndTheRemovedPersonMustBeGone() {
        XCTAssertNil(ring().admit(rekey(6, [anna, ben], removes: cara), maker: ben, oldDoor: nil))
        XCTAssertEqual(ring().admit(rekey(6, [anna, ben], removes: cara), maker: anna, oldDoor: nil), [anna])
        XCTAssertNil(ring().admit(rekey(6, [anna, ben, cara], removes: cara), maker: anna, oldDoor: nil))
    }

    func testAPhoneStillJoiningTakesTheFirstRekey() {
        XCTAssertEqual(Keyring().admit(rekey(6, [dan], admins: [dan]), maker: dan, oldDoor: nil), [dan])
        XCTAssertNil(Keyring().admit(rekey(6, [dan], admins: [dan], removes: cara), maker: dan, oldDoor: "old"))
    }

    func testAPhoneStillJoiningTakesNoKeyOnceARemovalWentPast() {
        let eve = "5555555555555555", annaKey = Data(repeating: 1, count: 33), benKey = Data(repeating: 2, count: 33)
        let pins = Invite.pin(annaKey) + Invite.pin(benKey)                                   // an invite made while Anna and Ben were the admins
        let first = Rekey(epoch: 1, made: 2, maker: benKey, admins: [ben], answers: eve, parts: [ben, eve].map { (id: $0, box: Rekey.box(secret(2), code: nil)) })
        func take(_ r: Keyring, _ k: Rekey, _ by: String) -> String {
            switch r.take(k, maker: by, me: eve, door: "d1", oldDoor: false, removedAt: nil, now: 10, pinned: Invite.allows(pins, maker: k.maker), open: { $0 }) {
            case .added: return "added"
            case .closed: return "closed"
            case .removed: return "removed"
            case .ignored: return "ignored"
            case .leftOut: return "left out"
            }
        }
        XCTAssertEqual(take(Keyring(), first, ben), "added")                                  // until then, either of them lets it in
        let r = Keyring()
        let removal = Rekey(epoch: 6, made: 1, maker: annaKey, admins: [anna], answers: ben, parts: [anna, cara].map { (id: $0, box: Rekey.box(secret(1), code: "AAAA-AAAA-AAAA-AAAA")) }, removal: true)
        XCTAssertEqual(take(r, removal, anna), "closed"); XCTAssertTrue(r.closed)
        // Ben still has the old code and answers the request himself. The invite names him, but its code no longer works.
        XCTAssertEqual(take(r, first, ben), "ignored"); XCTAssertNil(r.currentOrNil)
        let again = Keyring(); again.closed = true
        XCTAssertEqual(take(again, first, ben), "ignored")                                    // nor after a restart: the engine saved it
        // A removal from someone the invite doesn't name closes nothing.
        let other = Keyring(), zed = Data(repeating: 9, count: 33)
        XCTAssertEqual(take(other, Rekey(epoch: 6, made: 1, maker: zed, admins: [dan], answers: ben, parts: [(id: dan, box: Rekey.box(secret(3), code: "AAAA-AAAA-AAAA-AAAA"))], removal: true), dan), "ignored")
        XCTAssertFalse(other.closed); XCTAssertEqual(take(other, first, ben), "added")
    }

    func testSeniorityIsReadFromEpochsWithAMemberList() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        r.add(.init(number: 6, made: 1, secret: secret(6), members: [anna, ben, cara], admins: [anna, ben]))
        for n: Int64 in 4...5 { r.add(.init(number: n, made: 1, secret: secret(UInt8(n) + 3), members: [], admins: [ben], by: ben)) } // kept only to read with: their admins are whatever their maker wrote
        XCTAssertEqual(r.rank(rekey(6, [anna]), maker: ben), 1); XCTAssertEqual(r.rank(rekey(6, [anna]), maker: anna), 0)
        XCTAssertEqual(r.rank(rekey(5, [anna]), maker: ben), 1)                               // only such an epoch before it: the current epoch's list
        XCTAssertEqual(r.rank(rekey(9, [anna]), maker: anna), .max)                           // none before it
    }

    func testLateEpochsAreOnlyForReading() {
        let r = ring(); r.add(.init(number: 9, made: 1, secret: secret(9), members: [anna, ben, cara, dan], admins: [anna]))
        XCTAssertNotNil(r.admit(rekey(3, [ben]), maker: ben, oldDoor: nil))
        XCTAssertEqual(r.current.number, 9)
    }

    func testThroughAnOldDoorOnlyARivalRemovalCounts() {
        let r = ring()
        r.add(.init(number: 6, made: 1, secret: secret(6), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
        XCTAssertNotNil(r.admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(6, [anna, cara]), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(7, [anna, cara], removes: ben), maker: anna, oldDoor: "old"))
        XCTAssertNil(r.admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: "another"))
        XCTAssertNil(r.admit(rekey(6, [anna, ben, cara], removes: dan), maker: cara, oldDoor: "old"))
    }

    func testARemovalBeatsAnythingElseOfTheSameNumber() {
        for (a, b) in [(UInt8(1), UInt8(2)), (2, 1), (3, 4), (4, 3)] {
            let r = Keyring()
            r.add(.init(number: 6, made: 1, secret: secret(a), members: [anna, ben, cara], admins: [anna]))
            r.add(.init(number: 6, made: 1, secret: secret(b), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
            XCTAssertEqual(r.current.removes, cara); XCTAssertTrue(r.current === r.lastMove)
        }
    }

    func testTheMostSeniorAdminsRemovalWinsWhateverTheHash() {
        for (a, b) in [(UInt8(1), UInt8(2)), (2, 1), (3, 4), (4, 3)] {
            for seniorFirst in [true, false] {
                let r = Keyring()
                let senior = Keyring.Epoch(number: 6, made: 1, secret: secret(a), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0)
                let junior = Keyring.Epoch(number: 6, made: 1, secret: secret(b), members: [ben, cara], admins: [ben], code: "code-b", via: "old", removes: anna, by: ben, rank: 1)
                for e in seniorFirst ? [senior, junior] : [junior, senior] { r.add(e) }
                XCTAssertTrue(r.current === senior); XCTAssertTrue(r.lastMove === senior); XCTAssertTrue(r.won(senior)); XCTAssertFalse(r.won(junior))
            }
        }
    }

    func testRankIsThePlaceInTheAdminList() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        XCTAssertEqual(r.rank(rekey(6, [anna]), maker: anna), 0); XCTAssertEqual(r.rank(rekey(6, [anna]), maker: ben), 1)
        XCTAssertEqual(r.rank(rekey(6, [anna]), maker: cara), .max)
    }

    func testARemovalThatLostSilencesNobody() {
        let r = ring()
        r.add(.init(number: 6, made: 500, secret: secret(6), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0))
        r.add(.init(number: 6, made: 500, secret: secret(7), members: [ben, cara], admins: [ben], code: "code-b", via: "old", removes: anna, by: ben, rank: 1))
        XCTAssertTrue(r.removed(ben, before: 501)); XCTAssertFalse(r.removed(anna, before: 501))
        XCTAssertTrue(r.shutOut(ben, at: 1, had: false)); XCTAssertFalse(r.shutOut(anna, at: 1, had: false)); XCTAssertFalse(r.shutOut(anna, at: 501, had: true))
    }

    func testARemovalCantPickAHigherNumberToGetAhead() {
        XCTAssertNil(ring().admit(rekey(9, [anna, cara], removes: ben), maker: anna, oldDoor: nil)) // this phone has no epoch 8
        XCTAssertNotNil(ring().admit(rekey(6, [anna, cara], removes: ben), maker: anna, oldDoor: nil))
    }

    func testOutrankedOnlyByAMoreSeniorRemovalOfTheSameNumber() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        XCTAssertFalse(r.outranked(rekey(6, [ben, cara], removes: anna), maker: ben))
        r.add(.init(number: 6, made: 1, secret: secret(6), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0))
        XCTAssertTrue(r.outranked(rekey(6, [ben, cara], removes: anna), maker: ben))
        XCTAssertFalse(r.outranked(rekey(6, [anna, cara], removes: ben), maker: anna))
    }

    func testAKeyDatedLongAgoCantExpireTheOnesBeforeItEarly() {
        let day: Int64 = 24 * 3_600_000, r = Keyring()
        r.add(.init(number: 1, made: 20 * day, secret: secret(1))); r.add(.init(number: 2, made: 0, secret: secret(2)))
        XCTAssertTrue(r.expire(now: 21 * day).isEmpty)
    }

    func testAMembersKeyDatedLongAgoNeitherExpiresOlderEpochsNorMakesTheWeeklyKeyDue() throws {
        let day: Int64 = 24 * 3_600_000, hour: Int64 = 3_600_000, now = 1000 * day, two = [anna, ben]
        // Anna's phone: epoch 1 is 8 days old, epoch 2 replaced it an hour ago.
        func r() -> Keyring {
            let k = Keyring()
            k.add(.fresh(number: 1, made: now - 8 * day, secret: secret(1), members: two, admins: [anna], by: anna)); k.add(.fresh(number: 2, made: now - hour, secret: secret(2), members: two, admins: [anna], by: anna))
            return k
        }
        func bens(_ made: Int64) throws -> Rekey { try XCTUnwrap(Rekey.decode(Rekey(epoch: 3, made: made, maker: Data(count: 33), admins: [anna], answers: nil, parts: two.map { (id: $0, box: Data(count: 1)) }).encode())) }
        XCTAssertTrue(r().expire(now: now).isEmpty)
        for made in [now - 60_000, 0] {                                                       // Ben, who isn't an admin, dates his key a minute ago, or in 1970
            let ring = r()
            guard case .added = ring.take(try bens(made), maker: ben, me: anna, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in self.secret(3) }) else { return XCTFail("not added") }
            let cur = ring.current
            XCTAssertEqual(cur.number, 3); XCTAssertEqual(cur.made, made); XCTAssertEqual(cur.taken, now)
            XCTAssertTrue(ring.expire(now: now).isEmpty, "dated \(made)"); XCTAssertEqual(ring.all.map(\.number).sorted(), [1, 2, 3])
            XCTAssertFalse(Keyring.weeklyDue(made: cur.since, now: now, delay: 0)); XCTAssertFalse(Keyring.overdue(made: cur.since, now: now))
            XCTAssertTrue(Keyring.weeklyDue(made: cur.since, now: now + 7 * day, delay: 0))  // a week after it got here
            XCTAssertEqual(ring.expire(now: now - hour + 7 * day + 1).map(\.number), [1])    // a week after epoch 2 replaced it, as without Ben's key
        }
        let saved = Keyring.Epoch(number: 4, made: 5 * day, secret: secret(4)); XCTAssertEqual(saved.taken, 5 * day); XCTAssertEqual(saved.since, 5 * day) // saved before phones noted the arrival: its date
    }

    func testTheSameSecretInAnotherKeyIsAnotherEpoch() {
        let r = Keyring(), five = Keyring.Epoch(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]); r.add(five)
        XCTAssertFalse(r.add(.init(number: 5, made: 9, secret: secret(5), members: [anna], admins: [anna])))                               // the same key read again: kept once
        XCTAssertTrue(r.add(.init(number: 6, made: 2, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben], by: cara)))      // its secret in a key of Cara's: held beside it
        XCTAssertTrue(r.add(.init(number: 6, made: 2, secret: secret(5), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna, rank: 0))) // and in a removal of Anna's, which wins
        XCTAssertFalse(r.add(.init(number: 6, made: 3, secret: secret(5), members: [], admins: [anna], by: cara)))                         // Cara's again, kept only to read with: still one
        XCTAssertEqual(r.all.count, 3); XCTAssertTrue(r.all.contains { $0 === five }); XCTAssertEqual(r.current.removes, cara)
        XCTAssertEqual(Set(r.all.map(\.id)).count, 3); XCTAssertEqual(Set(r.all.map(\.hash)).count, 1)
        // Of two keys with one secret, number and standing, the maker's id decides, whichever came first.
        for order in [[ben, cara], [cara, ben]] {
            let k = Keyring(); for by in order { k.add(.init(number: 6, made: 2, secret: secret(5), members: [anna, ben, cara], admins: [anna], by: by)) }
            XCTAssertEqual(k.current.by, ben)
        }
    }

    func testAnAdminsKeyComesBeforeAMembersOfTheSameNumber() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        XCTAssertEqual(r.standing(rekey(6, [anna, ben, cara]), maker: ben), Keyring.byAdmin); XCTAssertEqual(r.standing(rekey(6, [anna, ben, cara]), maker: cara), .max)
        XCTAssertEqual(r.standing(rekey(6, [anna, cara], removes: ben), maker: ben), 1)                      // a removal keeps its maker's place
        XCTAssertEqual(r.standing(rekey(9, [anna, ben, cara]), maker: anna), Keyring.byAdmin)                // no epoch 8 here: the current one says who is an admin, as for admit
        XCTAssertEqual(Keyring().standing(rekey(6, [dan], admins: [anna]), maker: anna), Keyring.byAdmin)    // still joining: the key's own list
        XCTAssertEqual(Keyring().standing(rekey(6, [dan], admins: [anna]), maker: cara), .max)
        for bad in [Int64(0), -1, .min, .max] { XCTAssertEqual(r.standing(rekey(bad, [anna]), maker: cara), .max) } // must not crash
        for (a, b) in [(UInt8(1), UInt8(2)), (2, 1), (3, 4), (4, 3)] { for adminFirst in [true, false] {
            let k = Keyring()
            let admins = Keyring.Epoch(number: 6, made: 1, secret: secret(a), members: [anna, ben, cara, dan], admins: [anna], by: anna, rank: Keyring.byAdmin)
            let members = Keyring.Epoch(number: 6, made: 1, secret: secret(b), members: [anna, ben, cara], admins: [anna], by: cara)
            for e in adminFirst ? [admins, members] : [members, admins] { k.add(e) }
            XCTAssertTrue(k.current === admins); XCTAssertTrue(k.won(admins)); XCTAssertFalse(k.won(members))
            k.add(.init(number: 6, made: 1, secret: secret(9), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: ben, rank: 1)); XCTAssertEqual(k.current.removes, cara) // a removal still beats both
        } }
    }

    func testTheWeeklyKeyWaitsForAWeekAndThisPhonesDelay() {
        let day: Int64 = 24 * 3_600_000, hour: Int64 = 3_600_000
        XCTAssertFalse(Keyring.weeklyDue(made: 0, now: 7 * day - 1, delay: 0))
        XCTAssertTrue(Keyring.weeklyDue(made: 0, now: 7 * day, delay: 0))
        XCTAssertFalse(Keyring.weeklyDue(made: 0, now: 7 * day + 2 * hour, delay: 3 * hour))
        XCTAssertTrue(Keyring.weeklyDue(made: 0, now: 7 * day + 3 * hour, delay: 3 * hour))
        XCTAssertFalse(Keyring.overdue(made: 0, now: 7 * day + 6 * hour - 1)); XCTAssertTrue(Keyring.overdue(made: 0, now: 7 * day + 6 * hour))
    }

    func testOneRekeyPerMemberPerHour() {
        let hour: Int64 = 3_600_000, everyone = [anna, ben, cara], now = 100 * hour
        func r() -> Keyring { let k = ring(); k.add(.init(number: 6, made: 50 * hour, secret: secret(6), members: everyone, admins: [anna], by: ben)); return k }
        XCTAssertNil(r().admit(rekey(7, everyone, made: 50 * hour + 1), maker: ben, oldDoor: nil, now: now))
        XCTAssertNotNil(r().admit(rekey(7, everyone, made: 51 * hour), maker: ben, oldDoor: nil, now: now))
        XCTAssertNotNil(r().admit(rekey(7, everyone, made: 50 * hour + 1), maker: cara, oldDoor: nil, now: now))
        let k = r(); k.add(.init(number: 7, made: 50 * hour, secret: secret(7), members: everyone, admins: [anna], by: anna))
        XCTAssertNotNil(k.admit(rekey(8, everyone, made: 50 * hour + 1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(r().admit(rekey(7, everyone + [dan], made: 51 * hour, answers: dan), maker: ben, oldDoor: nil, now: now)) // a member can't let someone in
    }

    func testNonsenseNumbersAndTimesAndHugeGroupsAreRefused() {
        let now: Int64 = 1_000_000_000, everyone = [anna, ben, cara]
        for bad in [Int64(0), -1, .min, .max, (1 << 53) + 1] {
            XCTAssertNil(ring().admit(rekey(bad, everyone), maker: anna, oldDoor: nil, now: now))
            XCTAssertNil(Keyring().admit(rekey(bad, everyone), maker: anna, oldDoor: nil, now: now))
            XCTAssertEqual(ring().rank(rekey(bad, everyone), maker: anna), .max) // runs before admit: must not crash
        }
        XCTAssertNil(ring().admit(rekey(1006, everyone), maker: anna, oldDoor: nil, now: now))
        XCTAssertNotNil(ring().admit(rekey(1005, everyone), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, everyone, made: now + 10 * 60_000 + 1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, everyone, made: -1), maker: anna, oldDoor: nil, now: now))
        XCTAssertNil(ring().admit(rekey(6, (1...101).map { String(format: "%016x", $0) }), maker: anna, oldDoor: nil, now: now))
        XCTAssertNotNil(ring().admit(rekey(6, (1...99).map { String(format: "%016x", $0) } + [anna]), maker: anna, oldDoor: nil, now: now))
    }

    func testSomeoneInNoEpochCantMakeAKey() {
        let hour: Int64 = 3_600_000, now = 100 * hour, everyone = [anna, ben, cara], r = ring()
        for i in 0..<8 { XCTAssertNil(r.admit(rekey(6, everyone + [dan], made: now), maker: String(format: "%016x", 100 + i), oldDoor: nil, now: now)) }
        XCTAssertNil(r.admit(rekey(6, everyone, made: now), maker: String(format: "%016x", 200), oldDoor: nil, now: now))
        XCTAssertNotNil(r.admit(rekey(6, everyone, made: now - 2 * hour), maker: ben, oldDoor: nil, now: now))
    }

    func testAFloodOfKeysCantGrowTheRingForever() {
        let r = Keyring()
        for n in Int64(1)...200 { r.add(.init(number: n, made: n, secret: Data((0..<32).map { UInt8(truncatingIfNeeded: n >> Int64($0 % 8)) }))) }
        XCTAssertEqual(r.all.count, 64); XCTAssertEqual(r.current.number, 200); XCTAssertEqual(r.all.map(\.number).min(), 137)
    }

    func testTheEpochBeforeIsPickedTheSameWayOnBothApps() {
        let hashes = [UInt8(1), 2].sorted { hash($0) < hash($1) }
        for order in [hashes, hashes.reversed()] {
            let r = Keyring()
            for b in order { r.add(.init(number: 5, made: 1, secret: secret(b), members: b == hashes[0] ? [anna, ben] : [anna, ben, cara], admins: [anna])) }
            r.add(.init(number: 7, made: 1, secret: secret(9), members: [anna, ben, cara], admins: [anna]))
            XCTAssertNotNil(r.admit(rekey(6, [anna, ben], made: 100), maker: ben, oldDoor: nil, now: 200))
        }
    }

    func testAPhoneThatMissedKeysIsSpotted() {
        let r = Keyring(); r.add(.init(number: 9, made: 1000, secret: secret(9), members: [anna, ben], admins: [anna]))
        XCTAssertTrue(r.behind(rekey(4, [ben], made: 2000), maker: ben))
        XCTAssertFalse(r.behind(rekey(9, [ben], made: 2000), maker: ben))
        XCTAssertFalse(r.behind(rekey(4, [ben], made: 500), maker: ben))
        XCTAssertFalse(r.behind(rekey(4, [cara], made: 2000), maker: cara))
        XCTAssertFalse(r.behind(rekey(4, [ben], removes: cara, made: 2000), maker: ben))
    }

    func testWhatsAboveARemovalGoesAndTheRemovedStaySilent() {
        let r = ring()
        r.add(.init(number: 6, made: 500, secret: secret(6), members: [anna, ben], admins: [anna], code: "new", via: "old", removes: cara, by: anna))
        r.add(.init(number: 8, made: 1, secret: secret(8)))
        r.dropAbove(6); XCTAssertEqual(r.current.number, 6)
        XCTAssertFalse(r.removed(cara, before: 500)); XCTAssertTrue(r.removed(cara, before: 501)); XCTAssertFalse(r.removed(ben, before: 501))
    }

    func testOldEpochsGoButNeverTheCurrentOne() {
        let day: Int64 = 24 * 3_600_000, r = Keyring()
        r.add(.init(number: 1, made: 0, secret: secret(1))); r.add(.init(number: 2, made: 6 * day, secret: secret(2)))
        XCTAssertTrue(r.expire(now: 8 * day).isEmpty) // replaced 2 days ago: a message written on its last day can still come
        XCTAssertEqual(r.expire(now: 14 * day).map(\.number), [1])
        XCTAssertEqual(r.all.map(\.number), [2])
        XCTAssertTrue(r.expire(now: 30 * day).isEmpty) // the current one stays, however old
    }

    func testWhatLostGoesWithTheEpochThatBeatIt() {
        let day: Int64 = 24 * 3_600_000, r = ring()
        r.add(.init(number: 6, made: 1 * day, secret: secret(6), members: [anna, cara], admins: [anna], code: "code-a", via: "old", removes: ben, by: anna, rank: 0)) // Anna removes Ben
        r.add(.init(number: 6, made: 5 * day, secret: secret(7), members: [ben, cara], admins: [ben], code: "code-b", via: "old", removes: anna, by: ben, rank: 1))  // his rival removal lost; he dated it later
        r.add(.init(number: 7, made: 2 * day, secret: secret(8), members: [anna, cara], admins: [anna]))
        XCTAssertEqual(r.expire(now: 10 * day).map(\.number).sorted(), [5, 6, 6])              // or it would be the only removal numbered 6 left, and so the one that won
        XCTAssertFalse(r.removed(anna, before: 10 * day)); XCTAssertTrue(r.stillToRemove().isEmpty)
    }

    func testGroupIdIsStableAndKeysComeFromTheSecret() {
        XCTAssertEqual(GroupCrypto(code: "test-group-1").groupId(), "ccb162da8b97168602926c8bb8f8f4c6") // Python, like Android
        XCTAssertEqual(GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).groupId(), GroupCrypto(code: "test-group-1").groupId())
        XCTAssertEqual(GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).mailbox, GroupCrypto(code: "test-group-1").mailbox)
    }
}
