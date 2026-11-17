import XCTest
import CryptoKit
@testable import BlackoutCore

/// Rekey payloads: the same cases as Android's RekeyTest.
final class RekeyTests: XCTestCase {
    func testRoundTripAndOnlyMyPart() throws {
        let gid = GroupCrypto(code: "test-group-1").groupId(), pid = "6a44000000000009"
        let anna = P256.KeyAgreement.PrivateKey(), ben = P256.KeyAgreement.PrivateKey()
        let annaId = "1111111111111111", benId = "2222222222222222", secret = Data(repeating: 7, count: 32)
        let parts = try [(annaId, anna), (benId, ben)].map { (id: $0.0, box: try Hpke.seal(secret, to: $0.1.publicKey, info: Rekey.info(gid), aad: Rekey.aad(pid, $0.0))) }
        let r = Rekey(epoch: 3, made: 1_794_000_000_000, maker: TestKeys.pub, admins: [annaId], answers: benId, parts: parts)
        let back = try XCTUnwrap(Rekey.decode(r.encode()))
        XCTAssertEqual(back, r); XCTAssertEqual(back.members, [annaId, benId]); XCTAssertEqual(back.answers, benId)
        let benPart = back.parts.first { $0.id == benId }!.box
        XCTAssertEqual(Hpke.open(benPart, with: ben, info: Rekey.info(gid), aad: Rekey.aad(pid, benId)), secret)
        XCTAssertNil(Hpke.open(benPart, with: anna, info: Rekey.info(gid), aad: Rekey.aad(pid, benId)))
        XCTAssertNil(Hpke.open(benPart, with: ben, info: Rekey.info(gid), aad: Rekey.aad(pid, annaId)))
        XCTAssertNil(Rekey.decode(r.encode() + Data([0])))
        XCTAssertNil(Rekey.decode(Rekey(epoch: 1, made: 1, maker: TestKeys.pub, admins: [], answers: nil, parts: []).encode())?.answers)
    }

    func testRekeysTravelAtTheDoorWithTheirOwnKey() throws {
        let door = GroupCrypto(code: "test-group-1")
        XCTAssertEqual(door.rekeys().mailbox, door.mailbox)
        let id = Packet.newId(mailbox: door.mailbox)
        let c = try door.rekeys().seal(id: id, ts: 1, sender: "c482f374ea24d954", name: "Anna", text: "",
                                       extra: Rekey(epoch: 1, made: 1, maker: TestKeys.pub, admins: [], answers: nil, parts: []).encode()) { try MemberKey.sign(TestKeys.key, $0) }
        let p = Packet(id: id, ts: 1, ttl: 16, cipher: c)
        XCTAssertNil(door.open(p)); XCTAssertNil(door.intros().open(p))
        XCTAssertEqual(door.rekeys().openSigned(p)?.extra?.first, Rekey.type)
    }

    func testRemovalCarriesItsTypeAndTheNewCode() throws {
        let r = Rekey(epoch: 4, made: 9, maker: TestKeys.pub, admins: ["1111111111111111"], answers: "3333333333333333", parts: [(id: "1111111111111111", box: Data(count: 3))], removal: true)
        let back = try XCTUnwrap(Rekey.decode(r.encode()))
        XCTAssertTrue(back.removal); XCTAssertEqual(back.answers, "3333333333333333"); XCTAssertEqual(r.encode().first, Rekey.removalType)
        XCTAssertNil(Rekey.decode(Rekey(epoch: 4, made: 9, maker: TestKeys.pub, admins: [], answers: nil, parts: [], removal: true).encode()))
        let secret = Data(repeating: 7, count: 32)
        let opened = try XCTUnwrap(Rekey.unbox(Rekey.box(secret, code: "K7QF-2M9X-PA4T-W8RJ"), removal: true))
        XCTAssertEqual(opened.secret, secret); XCTAssertEqual(opened.code, "K7QF-2M9X-PA4T-W8RJ")
        XCTAssertNil(try XCTUnwrap(Rekey.unbox(Rekey.box(secret, code: nil), removal: false)).code)
        // Anyone with the code can seal a part: wrong shapes are refused, not trusted.
        XCTAssertNil(Rekey.unbox(Data(count: 31), removal: false)); XCTAssertNil(Rekey.unbox(Data(count: 33), removal: false))
        XCTAssertNil(Rekey.unbox(Data(count: 32), removal: true)); XCTAssertNil(Rekey.unbox(Data(count: 32 + 201), removal: true))
        XCTAssertNil(Rekey.unbox(Data(count: 32) + Data([0xFF]), removal: true)) // not UTF-8: refused on both apps, or the group would split
    }

    func testRekeyBytesMatchAndroid() {
        // The same values as the Android test produce the same bytes: header, member list, then 8+2+box per part.
        let r = Rekey(epoch: 1, made: 2, maker: Data(count: 33), admins: ["0102030405060708"], answers: nil, parts: [(id: "1111111111111111", box: Data(count: 3))])
        XCTAssertEqual(Hex.encode(r.encode()), "06" + "0000000000000001" + "0000000000000002" + String(repeating: "00", count: 33)
                       + "01" + "0102030405060708" + "0000000000000000" + "0001" + "1111111111111111" + "0001" + "1111111111111111" + "0003" + "000000")
    }
}
