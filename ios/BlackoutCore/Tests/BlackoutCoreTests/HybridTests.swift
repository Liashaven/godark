import XCTest
import CryptoKit
@testable import BlackoutCore

/// Post-quantum keys and new keys split over packets (spec "Sealing for one member", "New keys"). Same cases as Android's HybridTest.
final class HybridTests: XCTestCase {
    private func of(_ kind: String) throws -> [String: String] { try XCTUnwrap(VectorsTests.vectors.first { $0["kind"] == kind }) }
    private func newRecipient() -> P256.KeyAgreement.PrivateKey { P256.KeyAgreement.PrivateKey() }
    private func open(_ box: Data, _ r: P256.KeyAgreement.PrivateKey, _ seed: Data?, aad: Data? = nil) -> Data? {
        Hybrid.open(box, to: r.publicKey, agree: { try r.sharedSecretFromKeyAgreement(with: $0) }, seed: seed, info: info, aad: aad ?? self.aad)
    }
    private let info = Data("darkproof-rekey-v1".utf8), aad = Data(repeating: 9, count: 16), secret = Data(repeating: 7, count: 32)
    private let anna = "1111111111111111", ben = "2222222222222222", now: Int64 = 1_794_000_000_000

    func testMlKemVector() throws {
        let v = try of("mlkem"), seed = Hex.decode(v["seed"]!)
        XCTAssertEqual(Hex.encode(try XCTUnwrap(MlKem.publicKey(seed: seed))), v["public_key"])
        XCTAssertEqual(Hex.encode(try XCTUnwrap(MlKem.decapsulate(seed: seed, cipher: Hex.decode(v["cipher"]!)))), v["shared"])
    }

    func testKeyMadeHereWorks() throws {
        let k = try XCTUnwrap(MlKem.newKey())
        XCTAssertEqual(k.pub.count, MlKem.publicSize)
        let e = try XCTUnwrap(MlKem.encapsulate(k.pub))
        XCTAssertEqual(e.cipher.count, MlKem.cipherSize); XCTAssertEqual(e.shared.count, 32)
        XCTAssertEqual(MlKem.decapsulate(seed: k.seed, cipher: e.cipher), e.shared)
    }

    func testKeyThatIsntOneIsRefused() { XCTAssertNil(MlKem.encapsulate(Data(count: 10))) }

    func testPskModeMatchesTheSharedVector() throws {
        let v = try of("hpke-psk")
        let r = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(v["recipient_private"]!))
        let e = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(v["ephemeral_private"]!))
        let psk = Hex.decode(v["psk"]!), info = Hex.decode(v["info"]!), aad = Hex.decode(v["aad"]!), plain = Hex.decode(v["plaintext"]!), sealed = Hex.decode(v["sealed"]!)
        XCTAssertEqual(try Hpke.seal(plain, to: r.publicKey, info: info, aad: aad, ephemeral: e, psk: psk), sealed)
        XCTAssertEqual(Hpke.open(sealed, with: r, info: info, aad: aad, psk: psk), plain)
        XCTAssertNil(Hpke.open(sealed, with: r, info: info, aad: aad))
        XCTAssertNil(Hpke.open(sealed, with: r, info: info, aad: aad, psk: Data(count: 32)))
    }

    /// RFC 9180 PSK mode as Apple implements it, in both directions.
    func testPskModeAgreesWithCryptoKit() throws {
        let r = newRecipient(), psk = Data(repeating: 3, count: 32), key = SymmetricKey(data: psk), suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
        let ours = try Hpke.seal(secret, to: r.publicKey, info: info, aad: aad, psk: psk)
        var theirs = try HPKE.Recipient(privateKey: r, ciphersuite: suite, info: info, encapsulatedKey: ours.prefix(Hpke.encSize), presharedKey: key, presharedKeyIdentifier: Hpke.pskId)
        XCTAssertEqual(try theirs.open(ours.dropFirst(Hpke.encSize), authenticating: aad), secret)
        var sender = try HPKE.Sender(recipientKey: r.publicKey, ciphersuite: suite, info: info, presharedKey: key, presharedKeyIdentifier: Hpke.pskId)
        let box = try sender.seal(secret, authenticating: aad)
        XCTAssertEqual(Hpke.open(sender.encapsulatedKey + box, with: r, info: info, aad: aad, psk: psk), secret)
    }

    func testHybridBoxOpensWithBothKeys() throws {
        let r = newRecipient(), k = try XCTUnwrap(MlKem.newKey())
        let box = try Hybrid.seal(secret, to: r.publicKey, pq: k.pub, info: info, aad: aad)
        XCTAssertEqual(box.count, MlKem.cipherSize + Hpke.encSize + 32 + 16)
        XCTAssertEqual(open(box, r, k.seed), secret)
    }

    func testOneOfTheTwoKeysIsNotEnough() throws {
        let r = newRecipient(), k = try XCTUnwrap(MlKem.newKey()), other = try XCTUnwrap(MlKem.newKey())
        let box = try Hybrid.seal(secret, to: r.publicKey, pq: k.pub, info: info, aad: aad)
        XCTAssertNil(open(box, newRecipient(), k.seed)) // right ML-KEM key, wrong P-256 key
        XCTAssertNil(open(box, r, other.seed))          // right P-256 key, wrong ML-KEM key
        XCTAssertNil(open(box, r, nil))                 // no ML-KEM key at all
    }

    func testChangedBoxIsRefused() throws {
        let r = newRecipient(), k = try XCTUnwrap(MlKem.newKey())
        let box = try Hybrid.seal(secret, to: r.publicKey, pq: k.pub, info: info, aad: aad)
        for at in [0, MlKem.cipherSize - 1, MlKem.cipherSize, box.count - 1] {
            var bad = box; bad[at] = bad[at] &+ 1
            XCTAssertNil(open(bad, r, k.seed), "byte \(at)")
        }
        XCTAssertNil(open(box, r, k.seed, aad: Data(repeating: 1, count: 16)))
    }

    func testPlainHpkeIsRefused() throws {
        let r = newRecipient(), k = try XCTUnwrap(MlKem.newKey())
        XCTAssertNil(open(try Hpke.seal(secret, to: r.publicKey, info: info, aad: aad), r, k.seed))
        XCTAssertThrowsError(try Hybrid.seal(secret, to: r.publicKey, pq: Data(count: 10), info: info, aad: aad))
    }

    func testKeyGoesInOneThreeOrTenPackets() {
        for (n, k) in [(1, 1), (10, 1), (11, 3), (30, 3), (31, 10), (100, 10)] { XCTAssertEqual(Rekey.packets(n), k, "\(n) members") }
    }

    func testSplittingKeepsEveryoneAndAtMostTenInAPacket() {
        for n in [1, 7, 10, 11, 29, 30, 31, 64, 100] {
            let people = Array(0..<n), packets = Rekey.split(people)
            XCTAssertEqual(packets.flatMap { $0 }.sorted(), people); XCTAssertTrue(packets.allSatisfy { $0.count <= Rekey.partsPerPacket })
        }
    }

    func testMemberListIsSeparateFromTheParts() throws {
        let members = (1...11).map { String(format: "%016x", $0) }, share = Rekey.split(members)[1]      // a key for 11 goes in 3 packets
        let r = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [members[0]], answers: nil, parts: share.map { ($0, Data(count: 4)) }, members: members)
        let back = try XCTUnwrap(Rekey.decode(r.encode()))
        XCTAssertEqual(back.members, members); XCTAssertEqual(back.parts.map(\.id), share); XCTAssertEqual(r.encode().first, Rekey.type)
        // Up to 10 members it is one packet with a part for each: listing someone and giving them none is refused.
        XCTAssertNil(Rekey.decode(Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(ben, Data(count: 4))], members: [anna, ben]).encode()))
    }

    func testPartForSomeoneNotInTheListIsRefused() {
        XCTAssertNil(Rekey.decode(Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [], answers: nil, parts: [(ben, Data(count: 4))], members: [anna]).encode()))
    }

    private func isIgnored(_ t: Keyring.Taken) -> Bool { if case .ignored = t { return true }; return false }

    func testPacketWithoutMyPartIsIgnoredAndTheOneWithItCounts() {
        let r = Keyring(); r.add(.init(number: 5, made: now - 200 * 3_600_000, secret: Data(repeating: 5, count: 32), members: [anna, ben], admins: [anna]))
        let other = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(anna, Data(count: 1))], members: [anna, ben])
        XCTAssertTrue(isIgnored(r.take(other, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in XCTFail("not this phone's part"); return nil })))
        let mine = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(ben, Data(count: 1))], members: [anna, ben])
        if case .added = r.take(mine, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in Data(repeating: 6, count: 32) }) {} else { XCTFail("not added") }
    }

    func testPhoneStillJoiningWaitsForItsOwnPacketOfARemoval() {
        let removal = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: "3333333333333333", parts: [(anna, Data(count: 1))], removal: true, members: [anna, ben])
        XCTAssertTrue(isIgnored(Keyring().take(removal, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in nil })))
        let notIn = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: "3333333333333333", parts: [(anna, Data(count: 1))], removal: true, members: [anna])
        if case .closed = Keyring().take(notIn, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, open: { _ in nil }) {} else { XCTFail("not closed") }
    }

    func testPhoneJoiningFromAnInviteTakesKeysOnlyFromTheAdminsItNames() {
        let key = Rekey(epoch: 1, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(ben, Data(count: 1))], members: [anna, ben])
        XCTAssertTrue(isIgnored(Keyring().take(key, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, pinned: false, open: { _ in Data(repeating: 6, count: 32) })))
        if case .added = Keyring().take(key, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, pinned: true, open: { _ in Data(repeating: 6, count: 32) }) {} else { XCTFail("not added") }
    }

    func testSomeoneTheInviteDoesntNameCantCloseIt() {
        let notIn = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: "3333333333333333", parts: [(anna, Data(count: 1))], removal: true, members: [anna])
        XCTAssertTrue(isIgnored(Keyring().take(notIn, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, pinned: false, open: { _ in nil })))
    }

    func testTheInvitesAdminsMatterOnlyWhileJoining() {
        let r = Keyring(); r.add(.init(number: 5, made: now - 200 * 3_600_000, secret: Data(repeating: 5, count: 32), members: [anna, ben], admins: [anna]))
        let mine = Rekey(epoch: 6, made: now, maker: Data(count: 33), admins: [anna], answers: nil, parts: [(ben, Data(count: 1))], members: [anna, ben])
        if case .added = r.take(mine, maker: anna, me: ben, door: "door", oldDoor: false, removedAt: nil, now: now, pinned: false, open: { _ in Data(repeating: 6, count: 32) }) {} else { XCTFail("not added") }
    }

    func testLargestNewKeyFitsInItsPackets() throws {
        let members = (0..<100).map { String(format: "%016x", $0) }, box = Data(count: MlKem.cipherSize + Hpke.encSize + 32 + 19 + 16)
        let packets = Rekey.split(members).map { some in
            Rekey(epoch: 7, made: 1, maker: Data(count: 33), admins: members, answers: String(format: "%016x", 200), parts: some.map { ($0, box) }, removal: true, members: members)
        }
        XCTAssertEqual(packets.count, 10)
        let crypto = GroupCrypto.fromSecret(Data(repeating: 1, count: 32)), id = "0123456789abcdef"
        for r in packets {
            let p = Packet(id: id, ts: 1, ttl: 16, cipher: try crypto.seal(id: id, ts: 1, sender: anna, name: String(repeating: "n", count: 200), text: "", extra: r.encode(), pad: .full) { try MemberKey.sign(TestKeys.key, $0) })
            XCTAssertEqual(p.encode().count, 16_018)
            XCTAssertNotNil(Rekey.decode(try XCTUnwrap(crypto.openSigned(p)?.extra)))
        }
    }
}
