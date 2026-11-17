import XCTest
@testable import BlackoutCore

/// Checks the Swift implementation byte-for-byte against spec/test-vectors.txt, which the Android app also checks.
final class VectorsTests: XCTestCase {
    static let vectors: [[String: String]] = {
        // .../Blackout/ios/BlackoutCore/Tests/BlackoutCoreTests/VectorsTests.swift -> .../Blackout/spec/test-vectors.txt
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let text = try! String(contentsOf: url.appendingPathComponent("spec/test-vectors.txt"), encoding: .utf8)
        return text.components(separatedBy: "\n\n").map { block in
            var v: [String: String] = [:]
            for line in block.split(separator: "\n") where !line.hasPrefix("#") {
                if let r = line.range(of: ": ") { v[String(line[..<r.lowerBound])] = String(line[r.upperBound...]) }
            }
            return v
        }.filter { !$0.isEmpty }
    }()
    private func of(_ kind: String) -> [[String: String]] { Self.vectors.filter { $0["kind"] == kind } }
    private func code(_ v: [String: String]) -> String {
        v["code"] ?? String(decoding: Hex.decode(v["code_hex"]!), as: UTF8.self)
    }

    func testVectorFileHasAllKinds() {
        XCTAssertEqual(of("kdf").count, 4) // includes the Public channel code
        XCTAssertEqual(of("member").count, 2)
        XCTAssertEqual(of("signed").count, 1); XCTAssertEqual(of("signed-intro").count, 1)
    }

    func testMemberIdsAndEmojiMatch() {
        for v in of("member") {
            let pub = Hex.decode(v["public_key"]!)
            XCTAssertEqual(MemberKey.id(pub), v["member_id"])
            XCTAssertEqual(MemberKey.emoji(pub).map(String.init).joined(separator: " "), v["emoji"])
            XCTAssertEqual(MemberKey.publicKey(pub)?.compressedRepresentation, pub)
        }
    }

    func testKeyDerivationMatches() {
        for v in of("kdf") { XCTAssertEqual(Hex.encode(GroupCrypto.deriveKey(code(v))), v["key"], "\(v)") }
    }

    private func checkSigned(_ v: [String: String], _ crypto: GroupCrypto) throws {
        let id = v["id"]!, ts = Int64(v["ts"]!)!, sig = Hex.decode(v["signature"]!)
        let p = try XCTUnwrap(Packet.decode(Hex.decode(v["packet"]!)))
        XCTAssertEqual(p.id, id); XCTAssertEqual(p.ts, ts); XCTAssertEqual(p.ttl, 16)
        let o = try XCTUnwrap(crypto.openSigned(p))
        XCTAssertEqual(o.message.sender, v["member_id"]); XCTAssertEqual(o.message.name, v["name"]); XCTAssertEqual(o.signature, sig)
        let checker = try XCTUnwrap(MemberKey.Checker(Hex.decode(v["public_key"]!)))
        XCTAssertTrue(checker.verify(digest: o.digest, signature: o.signature))
        var bad = sig; bad[63] &+= 1
        XCTAssertFalse(checker.verify(digest: o.digest, signature: bad)) // one bit off: no
        XCTAssertFalse(MemberKey.Checker(TestKeys.pub)!.verify(digest: o.digest, signature: o.signature)) // another key: no
        // Sealing the same body with the same signature and IV gives the same bytes.
        let again = try crypto.seal(id: id, ts: ts, sender: o.message.sender, name: o.message.name, text: o.message.text,
                                    extra: o.extra, iv: Hex.decode(v["iv"]!), pad: .none) { _ in sig }
        XCTAssertEqual(Hex.encode(Packet(id: id, ts: ts, ttl: 16, cipher: again).encode()), v["packet"])
    }

    func testSignedMessageMatches() throws {
        for v in of("signed") {
            try checkSigned(v, GroupCrypto(code: v["code"]!))
            let p = Packet.decode(Hex.decode(v["packet"]!))!
            XCTAssertEqual(GroupCrypto(code: v["code"]!).open(p)?.text, v["text"])
            XCTAssertNil(GroupCrypto(code: "wrong-code").open(p))
        }
    }

    func testIntroductionMatches() throws {
        for v in of("signed-intro") {
            XCTAssertEqual(Hex.encode(GroupCrypto.deriveIntroKey(GroupCrypto.deriveKey(v["code"]!))), v["intro_key"])
            let intros = GroupCrypto(code: v["code"]!).intros()
            try checkSigned(v, intros)
            let p = Packet.decode(Hex.decode(v["packet"]!))!
            XCTAssertEqual(Hex.encode(intros.openSigned(p)!.extra!), "02" + v["public_key"]!) // 0x02, then the public key
            XCTAssertNil(GroupCrypto(code: v["code"]!).open(p)) // not a message
        }
    }

    func testOldV02PacketsAreRejected() {
        var raw = Hex.decode(of("signed")[0]["packet"]!); raw[0] = 0xB1
        XCTAssertNil(Packet.decode(raw))
    }
}
