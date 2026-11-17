import XCTest
@testable import BlackoutCore

final class AppLockFixTests: XCTestCase {
    // "Lock DarkProof": coming back.

    func testAsksOnFirstOpenAndAfterAMinute() {
        XCTAssertTrue(LockGrace.asksAgain(unlockedOnce: false, awaySeconds: nil))
        XCTAssertTrue(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: 60))
        XCTAssertTrue(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: 3_600))
    }

    func testNoAskWithinTheMinute() {
        XCTAssertFalse(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: nil))
        XCTAssertFalse(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: 0))
        XCTAssertFalse(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: 59.9))
    }

    /// The claim: a clock set back made the time away negative, and the app opened without asking.
    func testATimeAwayBelowZeroAsksAgain() {
        XCTAssertTrue(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: -3_600))
        XCTAssertTrue(LockGrace.asksAgain(unlockedOnce: true, awaySeconds: -0.001))
    }

    // Answers under an "Are you safe?" alert.

    private let saved = ["tagNew": "NEW-CODE", "tagInUse": "IN-USE"]

    func testAnswerGoesToTheSavedGroupThatAsked() {
        XCTAssertEqual(AnswerGroup.of(tag: "tagNew", saved: saved, moves: []), .group("NEW-CODE"))
        XCTAssertEqual(AnswerGroup.of(tag: "", saved: saved, moves: []), .group(nil))
        XCTAssertEqual(AnswerGroup.of(tag: nil, saved: saved, moves: []), .group(nil))
    }

    func testAnswerFollowsTheAskingGroupToItsNewCode() {
        var moves = AnswerGroup.noting(from: "tagOld", to: "tagMid", in: [])
        moves = AnswerGroup.noting(from: "tagMid", to: "tagNew", in: moves) // moved twice
        XCTAssertEqual(AnswerGroup.of(tag: "tagOld", saved: saved, moves: moves), .group("NEW-CODE"))
        XCTAssertEqual(AnswerGroup.of(tag: "tagMid", saved: saved, moves: moves), .group("NEW-CODE"))
    }

    func testAnswerForAGroupNoLongerSavedGoesNowhere() {
        XCTAssertEqual(AnswerGroup.of(tag: "tagUnknown", saved: saved, moves: []), .gone)
        let moves = AnswerGroup.noting(from: "tagLeft", to: "tagGone", in: [])
        XCTAssertEqual(AnswerGroup.of(tag: "tagLeft", saved: saved, moves: moves), .gone)
        let loop = AnswerGroup.noting(from: "tagB", to: "tagA", in: AnswerGroup.noting(from: "tagA", to: "tagB", in: []))
        XCTAssertEqual(AnswerGroup.of(tag: "tagA", saved: saved, moves: loop), .gone) // never loops
    }

    func testMovesAreKeptWithinTheirLimit() {
        var moves: [String] = []
        for i in 0..<(AnswerGroup.maxMoves + 50) { moves = AnswerGroup.noting(from: "t\(i)", to: "t\(i + 1)", in: moves) }
        XCTAssertEqual(moves.count, AnswerGroup.maxMoves)
        XCTAssertEqual(AnswerGroup.noting(from: "a", to: "c", in: ["a>b"]), ["a>c"])
    }
}
