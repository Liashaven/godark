import XCTest
@testable import BlackoutCore

/// Invites, group codes and joining (spec/FORMAT.md, "Invites", "Accepting a new key", "Removals and the code"): the
/// same cases as Android's InviteFixTest. Ids, keys and codes are made up.
final class InviteFixTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", cara = "3333333333333333", zed = "9999999999999999"
    private let annaKey = Data(repeating: 1, count: 33), benKey = Data(repeating: 2, count: 33), zedKey = Data(repeating: 9, count: 33)
    private let code = "AAAA-BBBB-CCCC-DDDD", other = "HHHH-HHHH-HHHH-HHHH"
    private func secret(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }
    private func name(_ t: Keyring.Taken) -> String {
        switch t {
        case .added: return "added"
        case .closed: return "closed"
        case .removed: return "removed"
        case .ignored: return "ignored"
        case .leftOut: return "left out"
        }
    }

    func testALinkReadLaterDoesNotChangeTheAdminsAPendingJoinTrusts() {
        // The user says Join to an invite that names Anna: from then on only she can let this phone in.
        var saved = Invite.joinPins([:], groups: [], code: code, pins: Invite.pin(annaKey))
        XCTAssertEqual(saved, [code: Invite.pin(annaKey)])
        // The phone now has the code. A second link for it, naming someone else, is read or even said yes to: nothing changes.
        saved = Invite.joinPins(saved, groups: [code], code: code, pins: Invite.pin(zedKey))
        XCTAssertTrue(Invite.allows(saved[code] ?? "", maker: annaKey)); XCTAssertFalse(Invite.allows(saved[code] ?? "", maker: zedKey))
        XCTAssertEqual(Invite.joinPins(saved, groups: [code], code: code, pins: ""), saved)   // nor does typing the code again drop them
        // Joining other groups, however many, never pushes them out while the group is saved.
        var groups = [code]
        for i in 0..<40 { let c = String(format: "KKKK-KKKK-KKKK-KK%02d", i); saved = Invite.joinPins(saved, groups: groups, code: c, pins: Invite.pin(zedKey)); groups.append(c) }
        XCTAssertEqual(saved[code], Invite.pin(annaKey)); XCTAssertEqual(saved.count, 41)
        // What was kept for a code that is no longer saved goes; a typed code names nobody.
        saved = Invite.joinPins(saved, groups: [other], code: "MMMM-MMMM-MMMM-MMMM", pins: "")
        XCTAssertTrue(saved.isEmpty)
        XCTAssertEqual(Invite.joinPins([code: Invite.pin(zedKey)], groups: [], code: code, pins: ""), [:]) // left over from before: not trusted for a typed code
    }

    func testNoPinsNameNobody() {
        let pins = Invite.pin(annaKey) + Invite.pin(benKey)
        XCTAssertTrue(Invite.names(pins, maker: annaKey)); XCTAssertTrue(Invite.names(pins, maker: benKey)); XCTAssertFalse(Invite.names(pins, maker: zedKey))
        XCTAssertTrue(Invite.allows("", maker: zedKey)); XCTAssertFalse(Invite.names("", maker: zedKey))
    }

    func testARemovalFromSomeoneWhoOnlyHasTheCodeClosesNoPendingJoin() {
        func removal(_ key: Data, _ by: String) -> Rekey {
            Rekey(epoch: 6, made: 1, maker: key, admins: [by], answers: ben, parts: [(id: by, box: Rekey.box(secret(3), code: code))], removal: true)
        }
        func take(_ r: Keyring, _ k: Rekey, _ by: String, _ pins: String) -> String {
            name(r.take(k, maker: by, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: 10, pinned: Invite.allows(pins, maker: k.maker),
                        named: Invite.names(pins, maker: k.maker), open: { $0 }))
        }
        // A typed code, or a link that names nobody: nothing tells an admin's removal from one signed by anyone who has the code.
        let typed = Keyring()
        XCTAssertEqual(take(typed, removal(zedKey, zed), zed, ""), "ignored"); XCTAssertFalse(typed.closed)
        XCTAssertEqual(take(typed, removal(annaKey, anna), anna, ""), "ignored"); XCTAssertFalse(typed.closed)
        let first = Rekey(epoch: 1, made: 2, maker: annaKey, admins: [anna], answers: cara, parts: [anna, cara].map { (id: $0, box: Rekey.box(secret(2), code: nil)) })
        XCTAssertEqual(take(typed, first, anna, ""), "added")                                 // so the group can still let it in
        // An invite that names Anna: her removal closes it, one from somebody it doesn't name closes nothing.
        let pins = Invite.pin(annaKey), invited = Keyring()
        XCTAssertEqual(take(invited, removal(zedKey, zed), zed, pins), "ignored"); XCTAssertFalse(invited.closed)
        XCTAssertEqual(take(invited, removal(annaKey, anna), anna, pins), "closed"); XCTAssertTrue(invited.closed)
    }

    func testOnlyAnAdminsRemovalTellsAPhoneComingBackThatTheGroupMovedOn() {
        let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna]))
        func removal(_ by: String) -> Rekey {
            Rekey(epoch: 9, made: 2, maker: Data(count: 33), admins: [by], answers: ben, parts: [(id: by, box: Rekey.box(secret(6), code: code))], removal: true)
        }
        XCTAssertFalse(r.movedOn(removal(zed), maker: zed))                                   // someone who only has the code
        XCTAssertFalse(r.movedOn(removal(cara), maker: cara))                                 // a member who isn't an admin
        XCTAssertTrue(r.movedOn(removal(anna), maker: anna))
        XCTAssertFalse(r.movedOn(Rekey(epoch: 9, made: 2, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(id: anna, box: Data(count: 1))]), maker: anna)) // not a removal
        XCTAssertFalse(Keyring().movedOn(removal(anna), maker: anna))                         // no epoch: the invite's admins decide (take)
        // An admin a removal took out says nothing either, even if the list still has them.
        let two = Keyring(); two.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna, ben]))
        two.add(.init(number: 6, made: 2, secret: secret(6), members: [anna, cara], admins: [anna, ben], code: code, via: "d1", removes: ben, by: anna, rank: 0))
        XCTAssertFalse(two.movedOn(removal(ben), maker: ben)); XCTAssertTrue(two.movedOn(removal(anna), maker: anna))
    }

    func testARemovalCannotMoveAGroupOntoTheCodeOfAnotherSavedGroup() {
        func ring() -> Keyring { let r = Keyring(); r.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, ben, cara], admins: [anna])); return r }
        let removal = Rekey(epoch: 6, made: 2, maker: Data(count: 33), admins: [anna], answers: ben, parts: [anna, cara].map { (id: $0, box: Rekey.box(secret(6), code: other)) }, removal: true)
        let r = ring()
        XCTAssertEqual(name(r.take(removal, maker: anna, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: 10, inUse: [other], open: { $0 })), "ignored")
        XCTAssertEqual(r.current.number, 5); XCTAssertNil(r.lastMove)                         // nothing was added: the group stays where it is
        if case .added(_, let moveTo, _) = ring().take(removal, maker: anna, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: 10, inUse: ["JJJJ-JJJJ-JJJJ-JJJJ"], open: { $0 }) {
            XCTAssertEqual(moveTo, other)                                                     // a code no other group here has is followed as before
        } else { XCTFail("not added") }
        // A phone still joining with a typed code takes the first key that includes it, but not onto another group's code.
        let first = Rekey(epoch: 1, made: 2, maker: Data(count: 33), admins: [zed], answers: ben, parts: [zed, cara].map { (id: $0, box: Rekey.box(secret(7), code: other)) }, removal: true)
        let joining = Keyring()
        XCTAssertEqual(name(joining.take(first, maker: zed, me: cara, door: "d1", oldDoor: false, removedAt: nil, now: 10, inUse: [other], open: { $0 })), "ignored")
        XCTAssertNil(joining.currentOrNil); XCTAssertFalse(joining.closed)
    }

    /// Holds today without a change; kept so that both apps go on agreeing (a code one accepted and the other refused would split the group).
    func testAGeneratedCodeEndsWhereItEnds() {
        XCTAssertTrue(Invite.isGeneratedCode(code)); XCTAssertNotNil(Rekey.unbox(Rekey.box(secret(1), code: code), removal: true))
        for tail in ["\n", "\r\n", "\r", "\u{85}", "\u{2028}", "\u{2029}", "\u{0B}", "\u{0C}", " "] {
            XCTAssertFalse(Invite.isGeneratedCode(code + tail)); XCTAssertFalse(Invite.isGeneratedCode(tail + code))
            XCTAssertNil(Rekey.unbox(Rekey.box(secret(1), code: code + tail), removal: true))
        }
    }

    /// Holds today without a change. A second set of keys made from a code the group has moved on from would call that
    /// code the current door (the engines no longer make one: Engine.keys). Even so, someone a removal took out adds
    /// nothing through it.
    func testSomeoneRemovedAddsNothingThroughTheOldDoorEvenIfItIsTakenForTheCurrentOne() {
        let ring = Keyring(); ring.add(.init(number: 5, made: 1, secret: secret(5), members: [anna, cara, zed], admins: [anna, zed]))
        let removal = Rekey(epoch: 6, made: 2, maker: Data(count: 33), admins: [anna], answers: zed, parts: [anna, cara].map { (id: $0, box: Rekey.box(secret(6), code: code)) }, removal: true)
        XCTAssertEqual(name(ring.take(removal, maker: anna, me: cara, door: "old", oldDoor: false, removedAt: nil, now: 10, open: { $0 })), "added")
        let same = Rekey(epoch: 6, made: 3, maker: Data(count: 33), admins: [zed], answers: nil, parts: [zed, cara].map { (id: $0, box: Rekey.box(secret(7), code: nil)) })
        XCTAssertEqual(name(ring.take(same, maker: zed, me: cara, door: "old", oldDoor: false, removedAt: nil, now: 10, open: { $0 })), "ignored")
        let next = Rekey(epoch: 7, made: 4, maker: Data(count: 33), admins: [zed], answers: nil, parts: [zed, cara].map { (id: $0, box: Rekey.box(secret(8), code: nil)) })
        XCTAssertEqual(name(ring.take(next, maker: zed, me: cara, door: "old", oldDoor: false, removedAt: nil, now: 10, open: { $0 })), "ignored")
        XCTAssertEqual(ring.current.number, 6); XCTAssertEqual(ring.current.admins, [anna])
    }
}
