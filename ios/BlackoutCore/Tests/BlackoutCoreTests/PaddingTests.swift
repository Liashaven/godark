import XCTest
import CryptoKit
@testable import BlackoutCore

/// Spec "Padding": relays and anyone reading them see only a few packet sizes. Android's PaddingTest uses the same table.
final class PaddingTests: XCTestCase {
    private let crypto = GroupCrypto.fromSecret(Data(repeating: 7, count: 32))
    private let id = "0123456789abcdef", member = "aabbccddeeff0011"

    private func packet(_ text: String, photo: Data? = nil, extra: Data? = nil, pad: Pad = .size) throws -> Packet {
        Packet(id: id, ts: 1_000, ttl: 16, cipher: try crypto.seal(id: id, ts: 1_000, sender: member, name: "Ann", text: text, photo: photo, extra: extra, pad: pad) { try MemberKey.sign(TestKeys.key, $0) })
    }

    func testPaddingAmountsAreTheSameOnBothPlatforms() {
        for (size, expected) in [(1, 162), (163, 0), (164, 69), (233, 0), (234, 278), (512, 0), (513, 511), (1024, 0),
                                 (1025, 1023), (4097, 4095), (8193, 7825), (16018, 0), (16019, 0)] {
            XCTAssertEqual(Packet.padding(size, .size), expected, "size \(size)")
        }
        XCTAssertEqual(Packet.padding(1000, .full), 15_018); XCTAssertEqual(Packet.padding(16_018, .full), 0)
        XCTAssertEqual(Packet.padding(1000, .none), 0)
    }

    func testMessagesOfDifferentLengthsAreTheSameSize() throws {
        XCTAssertEqual(Set(try (0...20).map { try packet(String(repeating: "x", count: $0)).encode().count }), [163])
        XCTAssertEqual(Set(try (200...300).map { try packet(String(repeating: "x", count: $0)).encode().count }), [512])
    }

    func testEverySizeIsOneOfTheListedSizes() throws {
        for n in [0, 50, 100, 150, 400, 900, 2000, 3900, 7000, 12_000] {
            XCTAssertTrue(Packet.sizes.contains(try packet(String(repeating: "y", count: n)).encode().count), "text of \(n)")
        }
    }

    func testPaddedPacketOpensAndItsSignatureChecks() throws {
        let o = try XCTUnwrap(crypto.openSigned(try packet("hello")))
        XCTAssertEqual(o.message.text, "hello"); XCTAssertNil(o.extra); XCTAssertNil(o.message.photo)
        XCTAssertTrue(try XCTUnwrap(MemberKey.Checker(TestKeys.pub)).verify(digest: o.digest, signature: o.signature))
    }

    func testOneByteOfPaddingIsIgnored() throws {
        // 110 overhead + 2+16 + 2+3 + 2+n = 163 - 1 when n = 27: one byte of padding, too short to read as a field.
        let p = try packet(String(repeating: "x", count: 27))
        XCTAssertEqual(p.encode().count, 163)
        let o = try XCTUnwrap(crypto.openSigned(p))
        XCTAssertEqual(o.message.text.count, 27); XCTAssertNil(o.extra)
    }

    func testFourthFieldSurvivesPadding() throws {
        let extra = Data(repeating: 2, count: 99), photo = Data(repeating: 3, count: 5_000)
        XCTAssertEqual(crypto.openSigned(try packet("", extra: extra))?.extra, extra)
        let withPhoto = try packet("cap", photo: photo)
        XCTAssertEqual(withPhoto.encode().count, 8192)
        XCTAssertEqual(crypto.openSigned(withPhoto)?.message.photo, photo)
    }

    func testShortPacketsStillFitTheRadios() throws {
        XCTAssertTrue(MeshCore.fits(try packet("I'm safe")))
        XCTAssertTrue(Meshtastic.fits(try packet(String(repeating: "x", count: 70))))
    }

    func testFullPaddingIsAlwaysTheLargestSize() throws {
        for n in [0, 500, 9000] { XCTAssertEqual(try packet(String(repeating: "z", count: n), pad: .full).encode().count, 16_018) }
    }

    func testUnpaddedPacketStillOpens() throws {
        XCTAssertEqual(crypto.openSigned(try packet("old", pad: .none))?.message.text, "old")
    }
}
