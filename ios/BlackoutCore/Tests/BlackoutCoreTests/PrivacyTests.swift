import XCTest
import CryptoKit
@testable import BlackoutCore

/// Blurred times (spec "Times"). Android's PrivacyTest has the same cases.
final class PrivacyTests: XCTestCase {
    private let crypto = GroupCrypto.fromSecret(Data(repeating: 7, count: 32)), id = "0123456789abcdef", real: Int64 = 1_794_000_123_456
    private func sealed() throws -> Data { try crypto.seal(id: id, ts: real, sender: "aabbccddeeff0011", name: "Ann", text: "hi") { try MemberKey.sign(TestKeys.key, $0) } }

    func testHeaderShowsAnEarlierTimeAndTheKeyGivesTheRealOne() throws {
        let c = try sealed(), wire = crypto.hideTime(real, c)
        XCTAssertLessThan(wire, real); XCTAssertLessThan(real - wire, 2 * GroupCrypto.timeWindow)
        let o = try XCTUnwrap(crypto.openSigned(Packet(id: id, ts: wire, ttl: 16, cipher: c)))
        XCTAssertEqual(o.message.ts, real)
        XCTAssertTrue(try XCTUnwrap(MemberKey.Checker(TestKeys.pub)).verify(digest: o.digest, signature: o.signature))
    }

    func testTwoMessagesSentTogetherDontShowIt() throws {
        let wires = Set(try (0..<20).map { _ in crypto.hideTime(real, try sealed()) })
        XCTAssertGreaterThan(wires.count, 15)
    }

    func testAnotherKeyCantOpenIt() throws {
        let c = try sealed()
        XCTAssertNil(GroupCrypto.fromSecret(Data(repeating: 8, count: 32)).openSigned(Packet(id: id, ts: crypto.hideTime(real, c), ttl: 16, cipher: c)))
    }

    func testChangingTheHeaderTimeIsDetected() throws {
        let c = try sealed()
        XCTAssertNil(crypto.openSigned(Packet(id: id, ts: crypto.hideTime(real, c) + 1, ttl: 16, cipher: c)))
    }

    func testEventIsDatedAtMostSeventeenMinutesBack() {
        for n: Int64 in [1_794_000_000, 1_794_000_513, 1_794_001_023] { let b = Nostr.blurred(n); XCTAssertLessThanOrEqual(b, n); XCTAssertLessThan(n - b, 1024); XCTAssertEqual(b % 1024, 0) }
        XCTAssertGreaterThan(Nostr.sinceMarginSeconds, 1024)
    }
}
