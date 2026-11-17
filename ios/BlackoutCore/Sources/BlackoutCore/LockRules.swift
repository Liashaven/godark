import Foundation

// Rules of "Lock GoDark" and of the one-tap answers, kept in the core so unit tests run. The Android app follows
// the same ones (LockRules.kt).

/// When "Lock GoDark" asks again on coming back.
public enum LockGrace {
    public static let seconds: Double = 60

    /// `awaySeconds`: how long the app was away since it was last left unlocked, on a clock nobody can set (the app
    /// uses ContinuousClock, which keeps counting while the phone sleeps); nil if it wasn't left since. A time that
    /// can't be (below zero) asks again.
    public static func asksAgain(unlockedOnce: Bool, awaySeconds: Double?) -> Bool {
        !unlockedOnce || awaySeconds.map { $0 < 0 || $0 >= seconds } == true
    }
}

/// Where a one-tap answer under an "Are you safe?" alert goes. Alerts name their group by a tag of its code.
public enum AnswerGroup {
    public enum To: Equatable {
        /// The saved group's code now; nil: the group in use (the alert named no group).
        case group(String?)
        /// The group that asked isn't saved on this phone any more: the answer goes nowhere, not to another group.
        case gone
    }

    /// `tag`: the alert's tag ("" or nil: none). `saved`: tag -> code of each saved group. `moves`: what `noting` kept.
    public static func of(tag: String?, saved: [String: String], moves: [String]) -> To {
        guard var tag, !tag.isEmpty else { return .group(nil) }
        var seen: Set<String> = []
        while seen.insert(tag).inserted {
            if let code = saved[tag] { return .group(code) }
            guard let next = moves.last(where: { $0.hasPrefix(tag + ">") }) else { break }
            tag = String(next.dropFirst(tag.count + 1))
        }
        return .gone
    }

    /// The most moves kept: a group gets a new code only when someone is removed.
    public static let maxMoves = 200

    /// `moves` with "the group tagged `from` is now tagged `to`" added, newest last, as a plain array UserDefaults can save.
    public static func noting(from: String, to: String, in moves: [String]) -> [String] {
        Array((moves.filter { !$0.hasPrefix(from + ">") } + [from + ">" + to]).suffix(maxMoves))
    }
}
