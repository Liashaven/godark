import XCTest
import CryptoKit
@testable import BlackoutCore

/// Our HPKE against Apple's own (CryptoKit HPKE, macOS 14+), both ways, and against the shared vector that Android also checks.
final class HpkeTests: XCTestCase {
    private func key(_ label: String) -> P256.KeyAgreement.PrivateKey {
        try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data(SHA256.hash(data: Data(label.utf8))))
    }

    func testOpensWhatAppleSeals() throws {
        guard #available(macOS 14, iOS 17, *) else { throw XCTSkip("CryptoKit HPKE needs macOS 14") }
        let r = key("darkproof-hpke-recipient"), info = Data("darkproof-rekey-v1".utf8), aad = Data("aad".utf8)
        var sender = try HPKE.Sender(recipientKey: r.publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: info)
        let ct = try sender.seal(Data("group secret".utf8), authenticating: aad)
        XCTAssertEqual(Hpke.open(sender.encapsulatedKey + ct, with: r, info: info, aad: aad), Data("group secret".utf8))
        XCTAssertNil(Hpke.open(sender.encapsulatedKey + ct, with: r, info: Data("other".utf8), aad: aad)) // wrong info: no
        XCTAssertNil(Hpke.open(sender.encapsulatedKey + ct, with: key("someone else"), info: info, aad: aad)) // wrong key: no
    }

    func testAppleOpensWhatWeSeal() throws {
        guard #available(macOS 14, iOS 17, *) else { throw XCTSkip("CryptoKit HPKE needs macOS 14") }
        let r = key("darkproof-hpke-recipient"), info = Data("darkproof-rekey-v1".utf8), aad = Data("aad".utf8)
        let sealed = try Hpke.seal(Data("group secret".utf8), to: r.publicKey, info: info, aad: aad)
        var recipient = try HPKE.Recipient(privateKey: r, ciphersuite: .P256_SHA256_AES_GCM_256, info: info,
                                           encapsulatedKey: sealed.prefix(Hpke.encSize))
        XCTAssertEqual(try recipient.open(sealed.dropFirst(Hpke.encSize), authenticating: aad), Data("group secret".utf8))
    }

    /// The Mac's own Secure Enclave, when this machine and session have one: the same calls the iPhone makes.
    func testSecureEnclaveKeys() throws {
        guard SecureEnclave.isAvailable, let r = try? SecureEnclave.P256.KeyAgreement.PrivateKey(), let s = try? SecureEnclave.P256.Signing.PrivateKey()
        else { throw XCTSkip("no usable Secure Enclave here") }
        let secret = Data(repeating: 7, count: 32), info = Data("darkproof-rekey-v1".utf8), aad = Data("aad".utf8)
        let sealed = try Hpke.seal(secret, to: r.publicKey, info: info, aad: aad)
        XCTAssertEqual(Hpke.open(sealed, to: r.publicKey, agree: { try r.sharedSecretFromKeyAgreement(with: $0) }, info: info, aad: aad), secret)
        XCTAssertNil(Hpke.open(sealed, to: r.publicKey, agree: { try r.sharedSecretFromKeyAgreement(with: $0) }, info: Data("other".utf8), aad: aad))
        let msg = Data("signed message".utf8), checker = try XCTUnwrap(MemberKey.Checker(s.publicKey.compressedRepresentation))
        XCTAssertTrue(checker.verify(digest: Data(SHA256.hash(data: msg)), signature: try s.signature(for: msg).rawRepresentation))
        XCTAssertFalse(checker.verify(digest: Data(SHA256.hash(data: Data("other".utf8))), signature: try s.signature(for: msg).rawRepresentation))
    }

    func testSharedVector() throws {
        let v = try XCTUnwrap(VectorsTests.vectors.first { $0["kind"] == "hpke" })
        let r = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(v["recipient_private"]!))
        XCTAssertEqual(Hex.encode(r.publicKey.x963Representation), v["recipient_public"])
        let e = try P256.KeyAgreement.PrivateKey(rawRepresentation: Hex.decode(v["ephemeral_private"]!))
        let sealed = try Hpke.seal(Hex.decode(v["plaintext"]!), to: r.publicKey, info: Hex.decode(v["info"]!), aad: Hex.decode(v["aad"]!), ephemeral: e)
        XCTAssertEqual(Hex.encode(sealed), v["sealed"])
        XCTAssertEqual(Hpke.open(sealed, with: r, info: Hex.decode(v["info"]!), aad: Hex.decode(v["aad"]!)), Hex.decode(v["plaintext"]!))
    }

    /// Prints the shared vector (run once to fill spec/test-vectors.txt; Apple's HPKE checks it above and here).
    func testPrintVector() throws {
        guard #available(macOS 14, iOS 17, *) else { throw XCTSkip("CryptoKit HPKE needs macOS 14") }
        let r = key("darkproof-hpke-recipient"), e = key("darkproof-hpke-ephemeral")
        let info = Data("darkproof-rekey-v1".utf8), aad = Data("6a44000000000003".utf8), pt = Data(repeating: 0x42, count: 32)
        let sealed = try Hpke.seal(pt, to: r.publicKey, info: info, aad: aad, ephemeral: e)
        var recipient = try HPKE.Recipient(privateKey: r, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: sealed.prefix(Hpke.encSize))
        XCTAssertEqual(try recipient.open(sealed.dropFirst(Hpke.encSize), authenticating: aad), pt)
        print("HPKE-VECTOR\nkind: hpke\nrecipient_private: \(Hex.encode(r.rawRepresentation))\nrecipient_public: \(Hex.encode(r.publicKey.x963Representation))\nephemeral_private: \(Hex.encode(e.rawRepresentation))\ninfo: \(Hex.encode(info))\naad: \(Hex.encode(aad))\nplaintext: \(Hex.encode(pt))\nsealed: \(Hex.encode(sealed))\nHPKE-END")
    }
}
