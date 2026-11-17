import XCTest
import CryptoKit
@testable import BlackoutCore

/// Encryption keys that change every week, codes that can't be guessed, and the longer person check. Same cases on Android.
final class KeyChangesTests: XCTestCase {
    private let day: Int64 = 24 * 3_600_000
    private typealias E = EncSchedule.Entry

    func testKeyIsReplacedAfterAWeek() {
        let l = [E(n: 0, made: 1_000)]
        XCTAssertFalse(EncSchedule.due(l, now: 1_000 + 7 * day - 1)); XCTAssertTrue(EncSchedule.due(l, now: 1_000 + 7 * day))
        XCTAssertTrue(EncSchedule.due([], now: 0))
    }

    func testNewKeyBecomesCurrentAndOldOneIsMarked() {
        XCTAssertEqual(EncSchedule.rotated([E(n: 0, made: 1_000)], now: 9_000), [E(n: 0, made: 1_000, replaced: 9_000), E(n: 1, made: 9_000)])
    }

    func testReplacedKeyIsDeletedAfterTwoWeeksAndCurrentNever() {
        let l = [E(n: 0, made: 0, replaced: day), E(n: 1, made: day)]
        XCTAssertEqual(EncSchedule.expired(l, now: day + 14 * day - 1), [])
        XCTAssertEqual(EncSchedule.expired(l, now: day + 14 * day), [l[0]])
        XCTAssertEqual(EncSchedule.expired(l, now: day + 1000 * day), [l[0]])
    }

    func testOnlyTheNewestKeysAreEverKept() {
        let l = (0..<12).map { E(n: $0, made: Int64($0), replaced: $0 == 11 ? 0 : Int64($0 + 1)) }
        let gone = EncSchedule.expired(l, now: 12)
        let left = l.filter { !gone.contains($0) }
        XCTAssertEqual(left.count, 8); XCTAssertEqual(left.last?.n, 11)
    }

    func testScheduleIsSavedAndJunkIsIgnored() {
        let l = [E(n: 0, made: 5, replaced: 9), E(n: 1, made: 9)]
        XCTAssertEqual(EncSchedule.parse(EncSchedule.save(l)), l)
        XCTAssertEqual(EncSchedule.parse("nonsense,1:2,a:b:c"), [])
    }

    func testOlderIntroductionDoesntReplaceAKey() {
        XCTAssertTrue(EncSchedule.isNewer(known: 100, ts: 101)); XCTAssertFalse(EncSchedule.isNewer(known: 100, ts: 100))
        XCTAssertFalse(EncSchedule.isNewer(known: 100, ts: 99))
    }

    func testRemovalCantMoveTheGroupToACodeThatCanBeGuessed() {
        let secret = Data(repeating: 1, count: 32)
        XCTAssertNotNil(Rekey.unbox(Rekey.box(secret, code: "K7QF-2M9X-PA4T-W8RJ"), removal: true))
        for weak in ["short", "password123", "k7qf-2m9x-pa4t-w8rj", "K7QF-2M9X-PA4T-W8R"] {
            XCTAssertNil(Rekey.unbox(Rekey.box(secret, code: weak), removal: true), weak)
        }
    }

    func testPersonCheckHasSixteenEmojiFromTheFirst96Bits() {
        let pub = Data(repeating: 2, count: 33)
        let ix = MemberKey.emoji(pub)
        XCTAssertEqual(ix.count, 16); XCTAssertTrue(ix.allSatisfy { (0...63).contains($0) })
        let h = Array(SHA256.hash(data: Data("darkproof-person-emoji-v1".utf8) + pub)).prefix(12)
        let bits = Array(h.map { String(repeating: "0", count: 8 - String($0, radix: 2).count) + String($0, radix: 2) }.joined())
        XCTAssertEqual(stride(from: 0, to: 96, by: 6).map { Int(String(bits[$0..<$0 + 6]), radix: 2)! }, ix)
    }

    func testEmojiGoEightToALine() {
        XCTAssertEqual(Fingerprint.emojiLines(MemberKey.emoji(Data(repeating: 2, count: 33))).split(separator: "\n").count, 2)
    }
}
