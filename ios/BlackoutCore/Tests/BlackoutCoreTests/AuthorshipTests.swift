import XCTest
import CryptoKit
@testable import BlackoutCore

/// Who wrote a message, and what the app shows about that: found in the 2026-11-13 audit. The rules live in the core
/// (KeyWait, Senders, Deliveries, Blocks, Checked, Vouch.key, ChatCard) so that they can be checked here; Engine only
/// calls them. Android's AuthorshipTest checks the same. Dummy keys only.
final class AuthorshipTests: XCTestCase {
    private let now: Int64 = 1_800_000_000_000
    private let everyone = GroupCrypto(code: GroupCrypto.publicCode)
    private func memberId(_ k: P256.Signing.PrivateKey) -> String { MemberKey.id(k.publicKey.compressedRepresentation) }
    private func pid(_ i: Int) -> String { String(format: "%016x", i) }
    private func checks(_ k: P256.Signing.PrivateKey, _ o: GroupCrypto.Opened) -> Bool {
        MemberKey.Checker(k.publicKey.compressedRepresentation)!.verify(digest: o.digest, signature: o.signature)
    }
    private func opened(_ id: String, sender: String, name: String, text: String, sign: @escaping (Data) throws -> Data) throws -> GroupCrypto.Opened {
        let c = try everyone.seal(id: id, ts: now, sender: sender, name: name, text: text, photo: nil, extra: nil, iv: nil, sign: sign)
        return try XCTUnwrap(everyone.openSigned(Packet(id: id, ts: now, ttl: 16, cipher: c)))
    }

    // MARK: - A waiting signature check belongs to one packet, not to an id

    /// F: under T's id, with a signature that doesn't check. G: the same packet id, signed by A. Both open; A's introduction comes next.
    func testTheCheckOfAnotherPacketWithTheSameIdDoesNotReachTheMessageShown() throws {
        let a = P256.Signing.PrivateKey(), aId = memberId(a), t = "aaaaaaaaaaaaaaaa"
        let id = Packet.newId(mailbox: everyone.mailbox)
        let f = try opened(id, sender: t, name: "Tina", text: "forged") { _ in try MemberKey.sign(a, Data("another message".utf8)) }
        let g = try opened(id, sender: aId, name: "A", text: "real") { try MemberKey.sign(a, $0) }
        XCTAssertFalse(checks(a, f)); XCTAssertTrue(checks(a, g))
        XCTAssertNotEqual(f.key, g.key, "one id, two packets")

        var w = KeyWait<String, GroupCrypto.Opened>()
        XCTAssertTrue(w.message(f.key, channel: Blocks.everyone, sender: t, id: id, shown: true, f))     // F came first: it is the row shown, not verified
        XCTAssertFalse(w.message(g.key, channel: Blocks.everyone, sender: aId, id: id, shown: false, g)) // the chat has that id already: G is not shown
        XCTAssertTrue(w.take(channel: Blocks.everyone, sender: aId).isEmpty, "G's check must not mark the row that shows F")
        let forT = w.take(channel: Blocks.everyone, sender: t)                                           // T's own introduction checks F, and F fails
        XCTAssertEqual(forT.map(\.row), [id]); XCTAssertEqual(forT.first?.item.message.text, "forged")
        XCTAssertEqual(w.count(Blocks.everyone), 0)
    }

    /// The other order: T's real message is shown, then a packet with its id and a bad signature. T's introduction must check the real one.
    func testALaterPacketWithTheSameIdDoesNotReplaceTheWaitingCheck() throws {
        let t = P256.Signing.PrivateKey(), tId = memberId(t), id = Packet.newId(mailbox: everyone.mailbox)
        let real = try opened(id, sender: tId, name: "Tina", text: "real") { try MemberKey.sign(t, $0) }
        let fake = try opened(id, sender: tId, name: "Tina", text: "fake") { _ in Data(repeating: 1, count: 64) }
        var w = KeyWait<String, GroupCrypto.Opened>()
        XCTAssertTrue(w.message(real.key, channel: Blocks.everyone, sender: tId, id: id, shown: true, real))
        XCTAssertFalse(w.message(fake.key, channel: Blocks.everyone, sender: tId, id: id, shown: false, fake))
        let got = w.take(channel: Blocks.everyone, sender: tId)
        XCTAssertEqual(got.map(\.item.message.text), ["real"])
        XCTAssertTrue(checks(t, try XCTUnwrap(got.first).item))
    }

    func testAReceiptAndAMessageWithOnePacketIdBothWait() {
        var w = KeyWait<String, String>()
        let id = pid(1), sender = "1111111111111111"
        XCTAssertTrue(w.message("\(id):m", channel: "g", sender: sender, id: id, shown: true, "message"))
        XCTAssertTrue(w.receipt("\(id):r", channel: "g", sender: sender, "receipt"))
        XCTAssertFalse(w.receipt("\(id):r", channel: "g", sender: sender, "receipt"), "the same receipt, read again from the store")
        XCTAssertEqual(w.take(channel: "g", sender: sender).map(\.item), ["message", "receipt"])
    }

    func testARowMadeAgainFromAnotherPacketDropsWhatWaitedForTheOldOne() {
        var w = KeyWait<String, String>()
        let id = pid(2)
        w.message("\(id):old", channel: "g", sender: "1111111111111111", id: id, shown: true, "old")
        w.message("\(id):new", channel: "g", sender: "2222222222222222", id: id, shown: true, "new") // the old row left the chat, a new one was made
        XCTAssertTrue(w.take(channel: "g", sender: "1111111111111111").isEmpty)
        XCTAssertEqual(w.take(channel: "g", sender: "2222222222222222").map(\.item), ["new"])
    }

    // MARK: - The waiting list: the Public channel can't use up a group's room, and it empties

    func testEveryoneMessagesFromSendersNeverIntroducedLeaveTheGroupsRoomAlone() {
        var w = KeyWait<String, Int>()
        let member = "1111111111111111"
        for i in 0..<5_000 { XCTAssertTrue(w.message("\(pid(i)):x", channel: Blocks.everyone, sender: pid(0xf000 + i), id: pid(i), shown: true, i)) }
        XCTAssertEqual(w.count(Blocks.everyone), 1_000)
        // A group message that arrives before its sender's introduction still waits, and is checked when it comes.
        XCTAssertTrue(w.message("\(pid(9_000)):x", channel: "group", sender: member, id: pid(9_000), shown: true, 9_000))
        XCTAssertTrue(w.receipt("\(pid(9_001)):x", channel: "group", sender: member, 9_001))
        XCTAssertEqual(w.take(channel: "group", sender: member).map(\.item), [9_000, 9_001])
        // In the Public channel the newest stay: a full list drops its own oldest.
        XCTAssertTrue(w.take(channel: Blocks.everyone, sender: pid(0xf000)).isEmpty)
        XCTAssertEqual(w.take(channel: Blocks.everyone, sender: pid(0xf000 + 4_999)).map(\.item), [4_999])
    }

    func testWhatWaitedForARowThatLeftTheChatGoesWithIt() {
        var w = KeyWait<String, Int>(max: 3)
        for i in 0..<3 { w.message("\(pid(i)):x", channel: "g", sender: "1111111111111111", id: pid(i), shown: true, i) }
        w.forget([pid(0), pid(1), "0000000000000fff"])
        XCTAssertEqual(w.count("g"), 1)
        XCTAssertEqual(w.take(channel: "g", sender: "1111111111111111").map(\.item), [2])
        XCTAssertEqual(w.count("g"), 0)
    }

    func testAWifiBoardPostWaitsForItsHostPhonesKey() {
        var w = KeyWait<String, String>()
        let host = "1111111111111111"
        w.message("\(pid(3)):x", channel: Blocks.everyone, sender: "web-\(host)", id: pid(3), shown: true, "board post")
        XCTAssertEqual(w.take(channel: Blocks.everyone, sender: host).map(\.item), ["board post"])
    }

    // MARK: - Nothing received may pass for written on this phone

    func testASenderThatIsThisPhonesOwnMarkIsRefused() {
        let me = "0123456789abcdef", device = "7c0d995b-2c4" // the shape of a device id: 12 characters of a UUID
        XCTAssertNil(Senders.shown(wire: device, me: me, device: device))
        XCTAssertNil(Senders.shown(wire: "1111111111111111", me: me, device: "1111111111111111"), "whatever shape the saved mark has")
        XCTAssertEqual(Senders.shown(wire: me, me: me, device: device), device, "only this phone's member id becomes its mark")
        XCTAssertEqual(Senders.shown(wire: "2222222222222222", me: me, device: device), "2222222222222222")
        XCTAssertEqual(Senders.shown(wire: "web-\(me)", me: me, device: device), "web-\(me)") // a Wi-Fi board post is someone else's
    }

    func testASenderHasToBeAMemberId() {
        let me = "0123456789abcdef", device = "7c0d995b-2c4"
        for bad in ["", "alice", "7c0d995b-2c5", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "web-", "web-web-0123456789abcdef", " 0123456789abcdef", "0123456789abcdeg"] {
            XCTAssertNil(Senders.shown(wire: bad, me: me, device: device), bad)
        }
        XCTAssertTrue(Senders.isMemberId(memberId(P256.Signing.PrivateKey())))
    }

    /// What the engine does with it: the Public channel opens a packet whose sender is the phone's mark, and the rule turns it away.
    func testAPublicPacketUnderThisPhonesMarkOpensButIsNotShown() throws {
        let device = "7c0d995b-2c4", stranger = P256.Signing.PrivateKey()
        let o = try opened(Packet.newId(mailbox: everyone.mailbox), sender: device, name: "Stranger", text: "hello") { try MemberKey.sign(stranger, $0) }
        XCTAssertEqual(o.message.sender, device)
        XCTAssertNil(Senders.shown(wire: o.message.sender, me: memberId(P256.Signing.PrivateKey()), device: device))
    }

    // MARK: - Receipts: bound to their group, limited, and only for messages written here

    private func receipt(_ sender: String, _ name: String, _ ts: Int64, _ ids: [String]) -> Message {
        Message(id: "r\(sender)\(ts)", ts: ts, sender: sender, name: name, text: Receipt.text(for: ids))
    }

    func testAReceiptFromAnotherGroupConfirmsNothing() {
        var d = Deliveries()
        let inA = pid(0xa1)
        d.sent(group: "group-a", inA)
        d.add(group: "group-b", receipt("3333333333333333", "Grandma Rosa", 100, [inA])) // a member of B lists an id seen on the air
        XCTAssertNil(d.readers[inA])
        d.add(group: "group-a", receipt("4444444444444444", "Lucia", 200, [inA]))
        XCTAssertEqual(d.readers[inA]?.map(\.name), ["Lucia"])
    }

    func testAReceiptCountsAtMost200Ids() {
        let many = (0..<935).map(pid) // what fits in one packet
        XCTAssertEqual(Receipt.ids(in: Receipt.text(for: many)).count, 200)
        XCTAssertEqual(Receipt.ids(in: Receipt.text(for: many)), Array(many.prefix(200)))
        var d = Deliveries()
        many.forEach { d.sent(group: "g", $0) }
        d.add(group: "g", receipt("3333333333333333", "Marco", 100, many))
        XCTAssertEqual(d.readers.count, 200)
    }

    func testIdsThatAreNoMessageOfThisPhoneTakeNoMemory() {
        var d = Deliveries()
        let mine = pid(1)
        d.sent(group: "g", mine)
        for i in 0..<200 { d.add(group: "g", receipt("3333333333333333", "Marco", Int64(100 + i), (0..<200).map { pid(1_000 + 200 * i + $0) })) }
        XCTAssertTrue(d.readers.isEmpty, "\(d.readers.count) ids kept")
        d.add(group: "g", receipt("3333333333333333", "Marco", 100, [pid(5), mine]))
        XCTAssertEqual(Array(d.readers.keys), [mine])
        d.forget([mine]) // the message left the store
        XCTAssertTrue(d.readers.isEmpty)
        d.add(group: "g", receipt("3333333333333333", "Marco", 100, [mine]))
        XCTAssertNil(d.readers[mine])
    }

    /// The iPhone builds the table from the stored packets off the main thread, then adds it to the live one.
    func testATableBuiltFromTheStoreIsAddedToTheLiveOne() {
        let a = pid(0xa), b = pid(0xb)
        var live = Deliveries()
        live.sent(group: "g", a)
        live.add(group: "g", receipt("4444444444444444", "Lucia", 300, [a]))
        var stored = Deliveries()
        stored.sent(group: "g", a); stored.sent(group: "h", b)
        stored.add(group: "g", receipt("3333333333333333", "Marco", 200, [a]))
        stored.add(group: "g", receipt("4444444444444444", "Lucia R.", 100, [a]))
        stored.add(group: "h", receipt("5555555555555555", "Sara", 150, [b]))
        live.merge(stored)
        XCTAssertEqual(live.readers[a]?.map(\.name), ["Lucia R.", "Marco"])
        XCTAssertEqual(live.readers[b]?.map(\.name), ["Sara"])
        var again = live
        again.merge(stored)
        XCTAssertEqual(again, live)
        live.add(group: "g", receipt("6666666666666666", "Ben", 400, [b])) // b is group h's
        XCTAssertEqual(live.readers[b]?.count, 1)
    }

    // MARK: - Blocking: per channel, and only a checked sender

    func testABlockMadeInEveryoneDoesNotHideAGroupMember() {
        let bea = "5555555555555555", group = "0f0e0d0c0b0a09080706050403020100"
        let troll = Message(id: pid(1), ts: now, sender: bea, name: "Troll", text: "spam", isPublic: true) // posted under Bea's group id
        XCTAssertTrue(Blocks.canBlock(troll, me: "7c0d995b-2c4"))
        let blocked: Set<String> = [Blocks.key(channel: Blocks.everyone, sender: troll.sender)]
        XCTAssertTrue(Blocks.hides(blocked, channel: Blocks.everyone, sender: bea))
        XCTAssertFalse(Blocks.hides(blocked, channel: group, sender: bea), "Bea's check-ins and calls for help in the group stay")
        XCTAssertFalse(Blocks.hides([Blocks.key(channel: group, sender: bea)], channel: "another group", sender: bea))
        XCTAssertFalse(Blocks.hides(blocked, channel: nil, sender: bea))
    }

    func testTheSenderOfAnUncheckedMessageCannotBeBlocked() {
        var m = Message(id: pid(1), ts: now, sender: "5555555555555555", name: "Troll", text: "spam", isPublic: true)
        XCTAssertTrue(Blocks.canBlock(m, me: "7c0d995b-2c4"))
        XCTAssertFalse(Blocks.canBlock(m.withSender("7c0d995b-2c4"), me: "7c0d995b-2c4"), "not one's own")
        m.verified = false
        XCTAssertFalse(Blocks.canBlock(m, me: "7c0d995b-2c4"))
    }

    func testABlockSavedBeforeBlocksHadAChannelStillHides() {
        XCTAssertTrue(Blocks.hides(["5555555555555555"], channel: "any group", sender: "5555555555555555"))
        XCTAssertTrue(Blocks.hides(["5555555555555555"], channel: Blocks.everyone, sender: "5555555555555555"))
        XCTAssertFalse(Blocks.hides(["5555555555555555"], channel: Blocks.everyone, sender: "6666666666666666"))
    }

    // MARK: - A checked person's name: what draws the same matches

    func testAnInvisibleCharacterDoesNotChangeANameKey() {
        XCTAssertEqual(Vouch.key("An\u{200B}na"), Vouch.key("Anna"))
        XCTAssertEqual(Vouch.key("Anna\u{2060}"), Vouch.key("Anna"))
        for c in ["\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}", "\u{00AD}", "\u{200E}", "\u{200F}", "\u{202E}", "\u{2066}", "\u{034F}", "\u{061C}", "\u{180E}", "\u{3164}", "\u{FFA0}", "\u{FE0F}",
                  "\u{001F}", "\u{0000}", "\u{007F}", "\u{E0061}", "\u{E0100}"] {
            XCTAssertEqual(Vouch.key("Mar\(c)co"), "marco", "U+\(String(c.unicodeScalars.first!.value, radix: 16)) inside")
            XCTAssertEqual(Vouch.key("Marco\(c)"), "marco", "U+\(String(c.unicodeScalars.first!.value, radix: 16)) at the end")
        }
        for c in ["\u{0085}", "\u{00A0}", "\u{2003}", "\u{2028}", "\u{3000}", "\u{2800}", "\t", "\n"] {
            XCTAssertEqual(Vouch.key("Anna\(c)Maria\(c)"), "anna maria", "U+\(String(c.unicodeScalars.first!.value, radix: 16))")
        }
    }

    func testCompatibilityFormsOfANameMatchIt() {
        XCTAssertEqual(Array(Vouch.key("Jose\u{0301}").unicodeScalars), Array("jos\u{00E9}".unicodeScalars)) // e + combining accent, scalar by scalar
        XCTAssertEqual(Array(Vouch.key("JOS\u{00C9}").unicodeScalars), Array("jos\u{00E9}".unicodeScalars))
        XCTAssertEqual(Vouch.key("\u{FF21}\u{FF4E}\u{FF4E}\u{FF41}"), "anna")                                         // full-width letters
        XCTAssertEqual(Array(Vouch.key("a\u{200D}\u{0301}nna").unicodeScalars), Array("\u{00E1}nna".unicodeScalars)) // the accent joins its letter once the joiner is gone
        XCTAssertEqual(Vouch.key("  Grandma\tROSA "), "grandma rosa")
        XCTAssertEqual(Vouch.key("Anna Maria"), "anna maria")
        XCTAssertNotEqual(Vouch.key("Marco"), Vouch.key("Marc\u{043E}")) // a look-alike letter is still another name
        for n in ["Anna", "Jose\u{0301}", "\u{FF21}nna\u{200B}", "Grandma  Rosa"] { XCTAssertEqual(Vouch.key(Vouch.key(n)), Vouch.key(n)) }
    }

    func testACheckedPersonsNameWithAnInvisibleCharacterStillWarns() {
        let g = "0f0e0d0c0b0a09080706050403020100", anna = "1111111111111111", other = "2222222222222222"
        let checked = [Checked.entry(group: g, id: anna, name: "Anna")]
        XCTAssertEqual(checked, ["\(g)|\(anna)|anna"])
        XCTAssertTrue(Checked.newKey(checked, group: g, id: other, name: "Anna"))
        XCTAssertTrue(Checked.newKey(checked, group: g, id: other, name: "Anna\u{200B}"))
        XCTAssertTrue(Checked.newKey(checked, group: g, id: other, name: "An\u{00AD}na "))
        XCTAssertFalse(Checked.newKey(checked, group: g, id: anna, name: "Anna\u{200B}"), "her own key")
        XCTAssertFalse(Checked.newKey(checked, group: g, id: other, name: "Marco"))
        XCTAssertFalse(Checked.newKey(checked, group: "ffffffffffffffffffffffffffffffff", id: other, name: "Anna"), "another group")
        // An entry saved by an older version keeps the older key; it is matched all the same.
        XCTAssertTrue(Checked.newKey(["\(g)|\(anna)|anna\u{FE0F}"], group: g, id: other, name: "Anna"))
        XCTAssertTrue(Checked.newKey(["\(g)|\(anna)|a|b"], group: g, id: other, name: "A|B"))
        XCTAssertFalse(Checked.newKey(["\(g)|\(anna)|a|b"], group: g, id: other, name: "B"))
    }

    func testMarkingAPersonCheckedReplacesTheOlderKeyForTheirName() {
        let g = "0f0e0d0c0b0a09080706050403020100"
        var checked = Checked.marked([], group: g, id: "1111111111111111", name: "Anna")
        checked = Checked.marked(checked, group: g, id: "3333333333333333", name: "Marco")
        checked = Checked.marked(checked, group: g, id: "2222222222222222", name: "Anna\u{200B}") // Anna's new phone, compared again
        XCTAssertEqual(Set(checked), ["\(g)|2222222222222222|anna", "\(g)|3333333333333333|marco"])
        XCTAssertFalse(Checked.newKey(checked, group: g, id: "2222222222222222", name: "Anna"))
        XCTAssertTrue(Checked.newKey(checked, group: g, id: "1111111111111111", name: "Anna"))
    }

    // MARK: - Check-ins, reports and "Are you safe?" are group messages

    func testAnEveryonePostThatLooksLikeACheckInIsPlainText() {
        func everyone(_ text: String) -> Message { Message(id: pid(1), ts: now, sender: "5555555555555555", name: "Marco Rossi", text: text, isPublic: true) }
        func group(_ text: String) -> Message { Message(id: pid(1), ts: now, sender: "5555555555555555", name: "Marco Rossi", text: text, group: "dummy-code") }
        let help = CheckIn.help.text(battery: 5, spot: Spot(lat: 45.4642, lon: 9.19), needs: [.injured, .trapped], people: 4)
        let report = Vouch(subject: "Grandma", status: .help).text
        for text in [help, CheckIn.safe.text(battery: nil, spot: nil), report, AreYouSafe().text, AreYouSafe(to: "Marco").text] {
            XCTAssertEqual(ChatCard.of(everyone(text)), .text, text)
            XCTAssertNotEqual(ChatCard.of(group(text)), .text, text)
        }
        XCTAssertEqual(ChatCard.of(group(help)), .checkIn(.help))
        XCTAssertEqual(ChatCard.of(group(report)), .vouch(Vouch.of(report)!))
        XCTAssertEqual(ChatCard.of(group(AreYouSafe().text)), .ask(AreYouSafe()))
        // Places stay Public channel messages; in a group the same text is plain text, as before.
        let place = Place(kind: .water, note: "tap at the school gym", spot: nil).text
        XCTAssertEqual(ChatCard.of(everyone(place)), .place(Place.of(place)!))
        XCTAssertEqual(ChatCard.of(group(place)), .text)
        XCTAssertEqual(ChatCard.of(everyone("hello")), .text)
    }
}
