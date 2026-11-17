import XCTest
@testable import BlackoutCore

/// Attacks found in the 2026-11-08 assessment. Each of these failed before its fix; Android's RelayAttackTest checks the same.
final class RelayAttackTests: XCTestCase {
    private let now: Int64 = 1_800_000_000_000
    private let hour: Int64 = 3_600_000
    private func pid(_ i: Int) -> String { String(format: "%016llx", i) }
    private func pkt(_ id: String, _ fill: UInt8 = 0x55) -> Packet { Packet(id: id, ts: now, ttl: 16, cipher: Data(repeating: fill, count: 98)) }
    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", dan = "4444444444444444"
    private func ring() -> Keyring { let r = Keyring(); r.add(.init(number: 5, made: now - hour * 200, secret: Data(repeating: 5, count: 32), members: [anna, ben, cara], admins: [anna])); return r }
    private var n = 0
    private func box() -> Data { n += 1; return Data((0..<32).map { UInt8(truncatingIfNeeded: n >> ($0 % 3 * 8)) }) }
    private func taken(_ r: Keyring, _ k: Rekey, _ maker: String, at: Int64? = nil) -> Bool {
        if case .added = r.take(k, maker: maker, me: anna, door: "door", oldDoor: false, removedAt: nil, now: at ?? now, open: { _ in self.box() }) { return true }
        return false
    }
    private func key(_ e: Int64, _ made: Int64, _ m: [String], answers: String? = nil) -> Rekey {
        Rekey(epoch: e, made: made, maker: Data(count: 33), admins: [anna], answers: answers, parts: m.map { (id: $0, box: Data(count: 1)) })
    }

    // One hostile relay, or any peer, could use up the copies allowed per id and so stop the real packet on every other path.
    func testJunkUnderAnIdNeverStopsTheRealPacketFromAnotherLink() {
        var got: [Packet] = []
        let r = MeshRouter(send: { _, _ in }, deliver: { got.append($0) }, now: { self.now }, minCipher: 98, maxPerMinute: 3000, unlimited: { $0 == "nostr" })
        let id = pid(1)
        for i in 1...200 { r.receive(from: "nostr", pkt(id, UInt8(i))) }
        r.receive(from: "ble:neighbour", pkt(id, 0xFF))
        XCTAssertEqual(got.filter { $0.cipher.first == 0xFF }.count, 1)
    }

    // A member could date keys as they liked and so make as many as they wanted.
    func testAMemberCantMakeUnlimitedKeysByBackdatingThem() {
        let r = ring(); var below = 0
        for i in 1...100 where taken(r, key(4, now - hour * Int64(i), [anna]), ben) { below += 1 }
        XCTAssertLessThanOrEqual(below, 4)
        let other = ring(), all = [anna, ben, cara]; var above = 0
        for i in 1...40 where taken(other, key(other.current.number + 1, now - hour * Int64(i + 1), all), ben) { above += 1 }
        XCTAssertLessThanOrEqual(above, 4)
        XCTAssertTrue(taken(other, key(other.current.number + 1, now + hour * 2, all), ben, at: now + hour * 2), "a key an hour later is taken again")
    }

    func testOnlyAnAdminLetsSomeoneIn() {
        let r = ring(), all = [anna, ben, cara]
        XCTAssertFalse(taken(r, key(r.current.number + 1, now, all + [dan], answers: dan), ben))
        XCTAssertTrue(taken(r, key(r.current.number + 1, now, all + [dan], answers: dan), anna))
    }

    func testAnExistingMembersIdDoesntMakeAKeyAJoinAndEscapeTheLimit() {
        let r = ring(), all = [anna, ben, cara]; var added = 0
        for i in 1...40 where taken(r, key(r.current.number + 1, now - hour * Int64(i + 1), all, answers: cara), ben) { added += 1 }
        XCTAssertLessThanOrEqual(added, 4)
    }

    // A plain member could name themselves admin in a key numbered below the current one, then remove the group's creator.
    private func forge(_ r: Keyring, me: String) -> Keyring.Taken {
        let x = String(format: "%016llx", 0xC1)
        _ = r.take(Rekey(epoch: 4, made: now, maker: Data(count: 33), admins: [ben], answers: x, parts: [(id: cara, box: Data(count: 1)), (id: anna, box: Data(count: 1)), (id: x, box: Data(count: 1))]),
                   maker: ben, me: me, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in self.box() })
        return r.take(Rekey(epoch: 5, made: now, maker: Data(count: 33), admins: [ben], answers: anna, parts: [(id: ben, box: Data(count: 1)), (id: cara, box: Data(count: 1))], removal: true),
                      maker: ben, me: me, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in Data(repeating: 9, count: 32) + Data("ATTK-ATTK-ATTK-ATTK".utf8) })
    }
    private func isIgnored(_ t: Keyring.Taken) -> Bool { if case .ignored = t { return true }; return false }

    func testAMemberCantMakeThemselvesAdminWithAKeyBelowTheCurrentOne() {
        let forCara = ring()
        XCTAssertTrue(isIgnored(forge(forCara, me: cara)))
        XCTAssertEqual(forCara.current.admins, [anna])
        XCTAssertTrue(isIgnored(forge(ring(), me: anna)), "the creator stays in")
    }

    func testAKeyBelowTheCurrentOneCantBeUsedToLeavePeopleOut() {
        let r = ring(), x = String(format: "%016llx", 0xC2)
        _ = taken(r, Rekey(epoch: 4, made: now - hour, maker: Data(count: 33), admins: [anna], answers: x, parts: [(id: anna, box: Data(count: 1)), (id: x, box: Data(count: 1))]), ben)
        XCTAssertNil(r.admit(Rekey(epoch: 5, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(id: anna, box: Data(count: 1)), (id: x, box: Data(count: 1))]), maker: ben, oldDoor: nil, now: now))
    }

    func testAKeyBelowTheCurrentOneStillOpensOldMessagesButListsNobody() {
        let r = ring(), x = String(format: "%016llx", 0xC3)
        XCTAssertTrue(taken(r, key(4, now - hour, [anna, x], answers: x), ben))
        let late = r.all.first { $0.number == 4 }!
        XCTAssertTrue(late.members.isEmpty); XCTAssertEqual(late.admins, [anna]); XCTAssertEqual(r.current.number, 5)
        XCTAssertNil(r.admit(key(4, now, [anna]), maker: x, oldDoor: nil, now: now), "someone listed only there is still a stranger to it")
    }

    func testARealAdminCanStillRemoveAfterAKeyArrivedLate() {
        let r = ring(), x = String(format: "%016llx", 0xC4)
        XCTAssertTrue(taken(r, key(4, now - hour, [anna, x], answers: x), ben)) // before the removal: the epoch before it exists, read-only
        let removal = Rekey(epoch: 5, made: now, maker: Data(count: 33), admins: [anna], answers: cara, parts: [(id: anna, box: Data(count: 1)), (id: ben, box: Data(count: 1))], removal: true)
        XCTAssertNotNil(r.admit(removal, maker: anna, oldDoor: nil, now: now))
    }

    // Found when these fixes were attacked: a removal that arrives late can become current, so it must keep its members.
    func testALateRemovalThatBecomesCurrentKeepsItsMembers() {
        let r = ring(), all = [anna, ben, cara]
        XCTAssertTrue(taken(r, key(7, now, all), ben))
        let removal = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: cara, parts: [(id: anna, box: Data(count: 1)), (id: ben, box: Data(count: 1))], removal: true)
        let t = r.take(removal, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in Data(repeating: 6, count: 32) + Data("NNNN-GGGG-KKKK-ZZZZ".utf8) })
        guard case .added(_, let moveTo, _) = t, moveTo != nil else { return XCTFail("not followed") }
        XCTAssertEqual(r.current.number, 6); XCTAssertEqual(r.current.members, [anna, ben])
    }

    func testARelayThatDropsTheLinkDoesntGetANewShare() {
        let pace = RelayPace(), t: Int64 = 1_800_000_000
        let first = CatchUp(relay: "r", since: RelaySince(), pace: pace)
        for _ in 0..<Nostr.relayPerMinute { XCTAssertTrue(first.allow(now: t)) }
        XCTAssertFalse(CatchUp(relay: "r", since: RelaySince(), pace: pace).allow(now: t + 5))
    }

    // Each relay link has its own limit, and what went over it is fetched again.
    func testARelayOverItsShareIsCutOffAndItsCatchUpIsNotMarkedDone() {
        let s = RelaySince(), c = CatchUp(relay: "r", since: s), t: Int64 = 1_800_000_000
        c.add([0x1234])
        let req = c.next(now: t)!
        for _ in 0..<Nostr.relayPerMinute { XCTAssertTrue(c.allow(now: t)) }
        XCTAssertFalse(c.allow(now: t))
        XCTAssertNil(c.end(req.subId, complete: true, now: t))
        XCTAssertNil(s.get("r", 0x1234), "the saved start must not move")
        XCTAssertTrue(c.allow(now: t + 60), "a new minute")
    }

    func testAnotherRelaysLinkKeepsItsOwnShare() {
        let a = CatchUp(relay: "a", since: RelaySince()), b = CatchUp(relay: "b", since: RelaySince()), t: Int64 = 1_800_000_000
        for _ in 0...Nostr.relayPerMinute { _ = a.allow(now: t) }
        XCTAssertFalse(a.allow(now: t)); XCTAssertTrue(b.allow(now: t))
    }

    // Before the fix a frame like this ended the app: JSONSerialization ran off the end of a background thread's stack.
    func testDeepJsonFromARelayDoesntEndTheApp() {
        let done = expectation(description: "parsed")
        let t = Thread {
            for deep in [String(repeating: "{\"a\":", count: 200_000), String(repeating: "[", count: 200_000)] {
                XCTAssertNil(Nostr.ok(deep)); XCTAssertNil(Nostr.end(deep)); XCTAssertNil(Nostr.received(deep)); XCTAssertNil(Nostr.refusal(deep))
            }
            done.fulfill()
        }
        t.stackSize = 512 * 1024 // what a background thread gets
        t.start()
        wait(for: [done], timeout: 30)
    }

    func testBracketsInsideStringsDontCount() {
        let ok = "[\"OK\",\"abc\",true,\"" + String(repeating: "[{", count: 1000) + "\\\"\"]"
        XCTAssertEqual(Nostr.ok(ok)?.eventId, "abc")
    }

    func testRealEventsAreNotTooDeep() {
        let e = "[\"EVENT\",\"s\",{\"id\":\"a\",\"pubkey\":\"b\",\"created_at\":1,\"kind\":3871,\"tags\":[[\"t\",\"dp1-1\"],[\"x\",\"y\"]],\"content\":\"AA==\",\"sig\":\"c\"}]"
        XCTAssertNotNil(Nostr.array(e))
    }
}
