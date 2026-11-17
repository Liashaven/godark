import XCTest
import CryptoKit
@testable import BlackoutCore

/// What the phone keeps, and for how long: copies of messages go with their epoch (spec "This phone's copy"), and the
/// store of copies reads back the copy of any legal message. Same cases as Android's StoredDataFixTest, and one for the
/// iPhone's store.
final class StoredDataFixTests: XCTestCase {
    private let anna = "1111111111111111", ben = "2222222222222222", group = "00112233445566778899aabbccddeeff"
    private let key = Data(repeating: 3, count: 32), day: Int64 = 86_400_000

    private func epoch(_ n: Int64, made: Int64, secret: UInt8) -> Keyring.Epoch {
        .fresh(number: n, made: made, secret: Data(repeating: secret, count: 32), members: [anna, ben], admins: [anna])
    }

    /// Ben's message `i` in `e`, opened with its message key, and this phone's sealed copy of it naming `named`.
    private func sealedCopy(_ e: Keyring.Epoch, _ i: Int, named: String? = nil, text: String? = nil) throws -> (id: String, blob: Data, packet: Packet) {
        let id = "6a4400000000000\(i)", ts = e.made + 1_000
        let mk = try XCTUnwrap(e.messageKeys?.key(1, i))
        let c = try e.group.seal(messageKey: mk, index: 1, counter: i, id: id, ts: ts, sender: ben, name: "B", text: text ?? "message \(i)") { try MemberKey.sign(TestKeys.key, $0) }
        let p = Packet(id: id, ts: e.group.hideTime(ts, c), ttl: 16, cipher: c)
        let o = try XCTUnwrap(e.open(p))
        return (id, try XCTUnwrap(History.seal(key: key, id: id, group: group, epoch: named ?? e.id, o, index: 1, counter: i)), p)
    }

    private func copy(_ e: Keyring.Epoch, _ i: Int, named: String? = nil) throws -> History.Saved {
        let s = try sealedCopy(e, i, named: named)
        return try XCTUnwrap(History.open(key: key, id: s.id, blob: s.blob))
    }

    func testACopyGoesWithTheEpochThatWasDeleted() throws {
        let ring = Keyring(), one = epoch(1, made: 0, secret: 1), two = epoch(2, made: day, secret: 2)
        ring.add(one); ring.add(two)
        let old = try copy(one, 1), new = try copy(two, 2)
        let gone = ring.expire(now: day + 8 * day)
        XCTAssertEqual(gone.map(\.id), [one.id])
        XCTAssertTrue(History.goes(old, with: gone, held: ring.all))
        XCTAssertFalse(History.goes(new, with: gone, held: ring.all))
    }

    func testNothingGoesWhileNoEpochIsDeleted() throws {
        let ring = Keyring(), one = epoch(1, made: 0, secret: 1), two = epoch(2, made: day, secret: 2)
        ring.add(one); ring.add(two)
        let gone = ring.expire(now: day + 6 * day)
        XCTAssertTrue(gone.isEmpty)
        XCTAssertFalse(History.goes(try copy(one, 1), with: gone, held: ring.all))
    }

    func testAnOldCopyNamingItsEpochByHashGoesOnlyIfNoHeldEpochHasThatHash() throws {
        let one = epoch(1, made: 0, secret: 1), again = epoch(3, made: 2 * day, secret: 1) // the same secret, sent again under another number
        let old = try copy(one, 1, named: one.hash)
        XCTAssertTrue(History.goes(old, with: [one], held: [epoch(2, made: day, secret: 2)]))
        XCTAssertFalse(History.goes(old, with: [one], held: [again])) // still shown with that one
    }

    func testACopyOfAnotherEpochIsLeftAlone() throws {
        let one = epoch(1, made: 0, secret: 1), two = epoch(2, made: day, secret: 2)
        XCTAssertFalse(History.goes(try copy(two, 3), with: [one], held: [two]))
    }

    /// A legal group message near the largest size: its copy is longer than any packet, so a store that read copies
    /// back with the packet limit stopped at it and lost every copy after it.
    func testTheCopyOfTheLongestMessageIsReadBack() throws {
        let e = epoch(1, made: 0, secret: 1)
        let s = try sealedCopy(e, 1, text: String(repeating: "a", count: 15_800))
        XCTAssertLessThanOrEqual(s.packet.cipher.count, Packet.maxCipher)
        XCTAssertNotNil(Packet.decode(s.packet.encode())) // a packet every phone takes
        XCTAssertGreaterThan(s.blob.count, Packet.maxCipher) // its copy is longer than any packet
        let record = Packet(id: s.id, ts: 0, ttl: 0, cipher: s.blob).encode()
        XCTAssertNil(Packet.decode(record)) // what the store read before
        let back = try XCTUnwrap(Packet.decode(record, limit: History.maxSealed))
        XCTAssertEqual(try XCTUnwrap(History.open(key: key, id: s.id, blob: back.cipher)).opened.message.text.count, 15_800)
    }
}
