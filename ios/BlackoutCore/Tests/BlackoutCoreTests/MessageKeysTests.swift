import XCTest
import CryptoKit
@testable import BlackoutCore

/// Per-message keys (spec "Message keys"). Same cases as Android's MessageKeysTest.
final class MessageKeysTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", secret = Data(repeating: 9, count: 32)
    private let id = "6a44000000000009", ts: Int64 = 1_794_000_123_456
    private func keys() -> MessageKeys { .of(secret, members: [anna, ben]) }

    func testMatchesTheSharedVector() throws {
        let v = try XCTUnwrap(VectorsTests.vectors.first { $0["kind"] == "message-key" })
        let s = Hex.decode(v["secret"]!), outer = MessageKeys.outer(s), g = GroupCrypto.fromSecret(outer)
        XCTAssertEqual(Hex.encode(outer), v["outer"]); XCTAssertEqual(String(g.mailbox), v["mailbox"])
        let mk = try XCTUnwrap(MessageKeys.of(s, members: [v["member_0"]!, v["member_1"]!]).key(1, 5)); XCTAssertEqual(Hex.encode(mk), v["key_1_5"])
        let t = Int64(v["ts"]!)!
        let c = try g.seal(messageKey: mk, index: 1, counter: 5, id: v["id"]!, ts: t, sender: v["sender"]!, name: v["name"]!, text: v["text"]!, iv: Hex.decode(v["iv"]!)) { _ in Hex.decode(v["signature"]!) }
        XCTAssertEqual(Hex.encode(c), v["cipher"]); XCTAssertEqual(String(g.hideTime(t, c)), v["wire_ts"])
        let p = Packet(id: v["id"]!, ts: Int64(v["wire_ts"]!)!, ttl: 16, cipher: Hex.decode(v["cipher"]!))
        XCTAssertEqual(g.header(p)?.index, 1); XCTAssertEqual(g.header(p)?.counter, 5)
        let o = try XCTUnwrap(g.open(messageKey: mk, index: 1, counter: 5, p))
        XCTAssertEqual(o.message.text, v["text"]); XCTAssertEqual(o.message.ts, t); XCTAssertEqual(o.message.sender, v["sender"])
        // What the signature covers: the position and number too, under a tag of its own.
        XCTAssertEqual(Hex.encode(o.digest), Hex.encode(Data(SHA256.hash(data: Hex.decode(try XCTUnwrap(v["signed_message"]))))))
    }

    func testDeletedKeyIsGoneAndTheOthersStay() throws {
        let k = keys(), before = try (0...9).map { try XCTUnwrap(k.key(1, $0)) }
        k.forget(1, 4)
        XCTAssertNil(k.key(1, 4))
        for i in 0...9 where i != 4 { XCTAssertEqual(k.key(1, i), before[i], "key \(i)") }
    }

    func testKeysCanBeDeletedInAnyOrder() {
        let k = keys(), whole = keys()
        var g = SystemRandomNumberGenerator()
        let order = Array(0..<300).shuffled(using: &g)
        order.prefix(150).forEach { k.forget(0, $0) }
        order.prefix(150).forEach { XCTAssertNil(k.key(0, $0)) }
        order.dropFirst(150).forEach { XCTAssertEqual(k.key(0, $0), whole.key(0, $0)) }
    }

    func testEachSenderHasItsOwnKeys() { XCTAssertNotEqual(keys().key(0, 0), keys().key(1, 0)) }
    func testDeletingOneSendersKeyLeavesTheOthers() { let k = keys(); k.forget(0, 3); XCTAssertNotNil(k.key(1, 3)) }

    func testWhatWasDeletedStaysDeletedAfterARestart() throws {
        let k = keys(); k.forget(1, 7); _ = k.takeNext(); _ = k.takeNext()
        let back = try XCTUnwrap(MessageKeys.decode(k.encode()))
        XCTAssertNil(back.key(1, 7)); XCTAssertEqual(back.key(1, 8), keys().key(1, 8)); XCTAssertEqual(back.takeNext(), 2); XCTAssertEqual(back.members, [anna, ben])
    }

    func testNumbersOutsideTheTreeHaveNoKey() { XCTAssertNil(keys().key(0, 65_536)); XCTAssertNil(keys().key(0, -1)); XCTAssertNil(keys().key(5, 0)) }

    func testWhenTheNumbersRunOutThereIsNoNext() throws {
        var d = keys().encode(); d.replaceSubrange(0..<4, with: [0, 1, 0, 0])
        XCTAssertNil(try XCTUnwrap(MessageKeys.decode(d)).takeNext())
    }

    private func epoch() -> Keyring.Epoch { .fresh(number: 6, made: 1, secret: secret, members: [anna, ben], admins: [anna]) }
    private func sealed(_ e: Keyring.Epoch, _ n: Int, at: Int64? = nil, forged: Bool = false) throws -> Packet {
        let t = at ?? ts
        let c = try e.group.seal(messageKey: try XCTUnwrap(e.messageKeys?.key(1, n)), index: 1, counter: n, id: id, ts: t, sender: ben, name: "Ben", text: "message \(n)") { forged ? Data(count: 64) : try MemberKey.sign(TestKeys.key, $0) }
        return Packet(id: id, ts: e.group.hideTime(t, c), ttl: 16, cipher: c)
    }
    private func signedByBen(_ o: GroupCrypto.Opened) -> Bool { MemberKey.Checker(TestKeys.pub)?.verify(digest: o.digest, signature: o.signature) ?? false }

    func testTwoPhonesWithTheSameSecretReadEachOther() throws {
        let o = try XCTUnwrap(epoch().open(try sealed(epoch(), 2)))
        XCTAssertEqual(o.message.text, "message 2"); XCTAssertEqual(o.message.ts, ts); XCTAssertEqual(o.leaf?.counter, 2); XCTAssertEqual(o.leaf?.index, 1)
    }

    func testOnceDeletedTheEpochCantOpenThePacketAgain() throws {
        let e = epoch(), p = try sealed(epoch(), 2)
        try XCTUnwrap(e.open(p)?.leaf).forget()
        XCTAssertNil(e.open(p))
    }

    func testOpeningAloneDoesntDeleteTheKey() throws {
        let e = epoch(), forged = try sealed(epoch(), 3, forged: true)
        XCTAssertNotNil(e.open(forged)); XCTAssertNotNil(e.messageKeys?.key(1, 3))
    }

    func testMemberCantUseUpSomeoneElsesKey() throws {
        // Ben seals under Anna's position and number and signs as himself: the signature would check, so it must not open.
        let e = epoch(), g = epoch().group
        let c = try g.seal(messageKey: try XCTUnwrap(epoch().messageKeys?.key(0, 7)), index: 0, counter: 7, id: id, ts: ts, sender: ben, name: "Ben", text: "not Anna") { try MemberKey.sign(TestKeys.key, $0) }
        XCTAssertNil(e.open(Packet(id: id, ts: g.hideTime(ts, c), ttl: 16, cipher: c)))
        XCTAssertNotNil(e.messageKeys?.key(0, 7))
    }

    func testSignedMessageCantBeSealedAgainUnderAnotherNumber() throws {
        // Every member holds every member's message keys. One of them reads Ben's message number 2 and seals its body and
        // signature again under Ben's unused number 9. If that signature checked, phones would delete Ben's key 9, and
        // what he later writes under it could no longer be opened.
        let e = epoch(), insider = epoch()
        let first = try XCTUnwrap(insider.open(try sealed(epoch(), 2)))
        XCTAssertTrue(signedByBen(first))
        let c = try insider.group.seal(messageKey: try XCTUnwrap(insider.messageKeys?.key(1, 9)), index: 1, counter: 9, id: id, ts: ts, sender: ben, name: "Ben", text: "message 2") { _ in first.signature }
        let again = e.open(Packet(id: id, ts: insider.group.hideTime(ts, c), ttl: 16, cipher: c))
        XCTAssertFalse(again.map(signedByBen) ?? false)
        XCTAssertNotNil(e.messageKeys?.key(1, 9))
    }

    func testSignatureDoesntMoveBetweenTheEpochKeyAndAMessageKey() throws {
        // Unpadded, both kinds of packet have the same body: only what is signed around it tells them apart.
        let e = epoch(), g = epoch().group, keys = try XCTUnwrap(epoch().messageKeys)
        let own = try g.seal(messageKey: try XCTUnwrap(keys.key(1, 2)), index: 1, counter: 2, id: id, ts: ts, sender: ben, name: "Ben", text: "hello", pad: .none) { try MemberKey.sign(TestKeys.key, $0) }
        let first = try XCTUnwrap(epoch().open(Packet(id: id, ts: g.hideTime(ts, own), ttl: 16, cipher: own)))
        XCTAssertTrue(signedByBen(first))
        let shared = try g.seal(id: id, ts: ts, sender: ben, name: "Ben", text: "hello", pad: .none) { _ in first.signature }
        XCTAssertFalse(signedByBen(try XCTUnwrap(e.open(Packet(id: id, ts: g.hideTime(ts, shared), ttl: 16, cipher: shared)))))
        // The other way round, it would use up a number: Ben's message under the epoch's key, sealed again under his number 9.
        let plain = try g.seal(id: id, ts: ts, sender: ben, name: "Ben", text: "hello", pad: .none) { try MemberKey.sign(TestKeys.key, $0) }
        let second = try XCTUnwrap(e.open(Packet(id: id, ts: g.hideTime(ts, plain), ttl: 16, cipher: plain)))
        XCTAssertTrue(signedByBen(second))
        let moved = try g.seal(messageKey: try XCTUnwrap(keys.key(1, 9)), index: 1, counter: 9, id: id, ts: ts, sender: ben, name: "Ben", text: "hello", pad: .none) { _ in second.signature }
        XCTAssertFalse(signedByBen(try XCTUnwrap(e.open(Packet(id: id, ts: g.hideTime(ts, moved), ttl: 16, cipher: moved)))))
    }

    private func readingOnly() -> Keyring.Epoch { .fresh(number: 6, made: 1, secret: secret, roster: [anna, ben], members: [], admins: [anna]) }
    private func beforeMessageKeys() -> Keyring.Epoch { .init(number: 6, made: 1, secret: MessageKeys.outer(secret), members: [anna, ben], admins: [anna]) }

    func testTheEpochKeyOpensOnlyWhatItsMembersWrote() throws {
        // Every member holds the epoch's key, and so does someone removed since. Sealed with it, a packet under an id
        // nobody was let in with would be shown as "not verified yet", with any name: it must not open.
        let g = epoch().group, madeUp = "3333333333333333"
        func sealedAs(_ sender: String) throws -> Packet {
            let c = try g.seal(id: id, ts: ts, sender: sender, name: "Anna", text: "I need help") { _ in Data(count: 64) }
            return Packet(id: id, ts: g.hideTime(ts, c), ttl: 16, cipher: c)
        }
        XCTAssertNil(epoch().open(try sealedAs(madeUp)))
        XCTAssertNil(readingOnly().open(try sealedAs(madeUp)))
        XCTAssertNil(beforeMessageKeys().open(try sealedAs(madeUp)))
        // A member whose numbers ran out writes with the epoch's key: that still opens, also in an epoch kept only to read with.
        for e in [epoch(), readingOnly(), beforeMessageKeys()] {
            let o = try XCTUnwrap(e.open(try sealedAs(ben)))
            XCTAssertEqual(o.message.sender, ben); XCTAssertNil(o.leaf)
            XCTAssertNotNil(e.open(try sealedAs("web-\(ben)")))
        }
    }

    func testReceiptCountsOnlyFromSomeoneInTheEpoch() throws {
        let rc = epoch().receipts, rid = "6a4400000000000b"
        func receipt(_ sender: String) throws -> Packet {
            let c = try rc.seal(id: rid, ts: ts, sender: sender, name: "Anna", text: id) { _ in Data(count: 64) }
            return Packet(id: rid, ts: rc.hideTime(ts, c), ttl: 16, cipher: c)
        }
        XCTAssertNil(epoch().openReceipt(try receipt("3333333333333333")))
        XCTAssertNil(readingOnly().openReceipt(try receipt("3333333333333333")))
        XCTAssertEqual(epoch().openReceipt(try receipt(ben))?.message.sender, ben)
        XCTAssertNotNil(readingOnly().openReceipt(try receipt(anna)))
        XCTAssertNil(epoch().openReceipt(try sealed(epoch(), 1))) // a message isn't a receipt
    }

    func testWhatSomeoneRemovedWritesIsShownOnlyIfThisPhoneHadItBefore() throws {
        // Ben was removed at ts. Phones go on reading with epoch 6, whose keys he has, for another week.
        let ring = Keyring(); ring.add(epoch())
        ring.add(.fresh(number: 7, made: ts, secret: Data(repeating: 7, count: 32), members: [anna], admins: [anna], code: "AAAA-AAAA-AAAA-AAAA", via: "old", removes: ben, by: anna, rank: 0))
        // He writes afterwards and dates it a minute before: it opens, the signature is his, and its date says "before".
        let p = try sealed(epoch(), 2, at: ts - 60_000)
        let o = try XCTUnwrap(ring.all.compactMap { $0.open(p) }.first)
        XCTAssertTrue(signedByBen(o)); XCTAssertFalse(ring.removed(ben, before: o.message.ts))
        XCTAssertTrue(ring.shutOut(ben, at: o.message.ts, had: false))   // seen for the first time now: not shown, whatever its date
        XCTAssertTrue(ring.shutOut(ben, at: 0, had: false))
        XCTAssertFalse(ring.shutOut(ben, at: o.message.ts, had: true))   // this phone had it before the removal came: it stays
        XCTAssertFalse(ring.shutOut(ben, at: ts, had: true)); XCTAssertTrue(ring.shutOut(ben, at: ts + 1, had: true)) // unless it is dated after the removal
        XCTAssertFalse(ring.shutOut(anna, at: ts + 1, had: false))       // nobody else is touched
    }

    func testBoardMessageCountsAsThePhonesOwn() throws {
        let g = epoch().group
        let c = try g.seal(messageKey: try XCTUnwrap(epoch().messageKeys?.key(1, 2)), index: 1, counter: 2, id: id, ts: ts, sender: "web-\(ben)", name: "Visitor", text: "hello") { try MemberKey.sign(TestKeys.key, $0) }
        XCTAssertNotNil(epoch().open(Packet(id: id, ts: g.hideTime(ts, c), ttl: 16, cipher: c))?.leaf)
    }

    func testTheEpochSecretIsntKept() { let e = epoch(); XCTAssertNotEqual(e.secret, secret); XCTAssertEqual(e.secret, MessageKeys.outer(secret)) }

    func testAKeyKeptForReadingStillOpens() throws {
        let e = Keyring.Epoch.fresh(number: 6, made: 1, secret: secret, roster: [anna, ben], members: [], admins: [anna])
        XCTAssertNotNil(e.open(try sealed(epoch(), 1)))
    }

    func testTheCopyKeepsTheMessage() throws {
        let key = Data(repeating: 3, count: 32), e = epoch(), o = try XCTUnwrap(e.open(try sealed(epoch(), 4)))
        let s = try XCTUnwrap(History.open(key: key, id: id, blob: try XCTUnwrap(History.seal(key: key, id: id, group: "group", epoch: e.hash, o, index: 1, counter: 4))))
        XCTAssertEqual(s.opened.message.text, "message 4"); XCTAssertEqual(s.opened.message.ts, ts); XCTAssertEqual(s.epoch, e.hash); XCTAssertEqual(s.group, "group")
        XCTAssertEqual(s.opened.digest, o.digest); XCTAssertEqual(s.opened.signature, o.signature); XCTAssertEqual(s.index, 1); XCTAssertEqual(s.counter, 4)
    }

    func testTheCopyNeedsItsKeyAndId() throws {
        let key = Data(repeating: 3, count: 32), e = epoch(), o = try XCTUnwrap(e.open(try sealed(epoch(), 4)))
        let b = try XCTUnwrap(History.seal(key: key, id: id, group: "group", epoch: e.hash, o, index: 1, counter: 4))
        XCTAssertNil(History.open(key: Data(count: 32), id: id, blob: b)); XCTAssertNil(History.open(key: key, id: "6a4400000000000a", blob: b))
    }

    func testMessageFitsTheSmallestSize() throws { XCTAssertEqual(try sealed(epoch(), 0).encode().count, 163) }
}
