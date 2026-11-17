import Foundation

// Small rules the iPhone app's screens, map and assistant follow, kept in the core so unit tests run.
// The Android app follows the same ones (Protocol.kt, ScreenRules.kt).

/// "Connect through Tor" (Connections): on unless the user turned it off.
public enum TorSetting {
    /// A value that was never saved means on. `UserDefaults.bool(forKey:)` says false for it, which let the map go
    /// online while the switch showed on and the relays used Tor: whoever needs the setting asks here.
    public static func isOn(_ d: UserDefaults = .standard) -> Bool { d.object(forKey: "tor") as? Bool ?? true }
}

/// What the on-device AI is given of other people's words, sized for its 4,096-token window. Those people choose what
/// their text costs: a token is never less than one byte of UTF-8, and digits, signs and rare letters cost a token a
/// byte. So their text is measured in bytes, the most it can cost: with the app's instructions (about 350 tokens) and
/// the answer, a summary of `maxSituationBytes` always leaves room for the question. Same as Android's `AiContext`.
public enum AiContext {
    /// The whole summary (Situation.text).
    public static let maxSituationBytes = 2_000
    /// "Catch me up": the group's messages of the last hours, which go with half a summary.
    public static let maxCatchUpBytes = 1_500

    /// Text from other people, for the assistant: one line, at most `max` UTF-16 units, whole characters only, and it
    /// can't close the <data> block around it. A character that alone is longer than `max` (a letter with thousands
    /// of marks on it) is left out with everything after it.
    public static func field(_ s: String, max: Int = 40) -> String {
        let line = s.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }.joined(separator: " ")
            .replacingOccurrences(of: "<", with: "‹").replacingOccurrences(of: ">", with: "›")
        var out = "", units = 0
        for ch in line {
            units += ch.utf16.count
            if units > max { break }
            out.append(ch)
        }
        return out
    }

    /// The start of `s` that fits `bytes` bytes of UTF-8, whole characters only.
    public static func head(_ s: String, bytes: Int) -> String {
        if s.utf8.count <= bytes { return s }
        var n = 0, end = s.startIndex
        for i in s.indices {
            n += s[i].utf8.count
            if n > bytes { break }
            end = s.index(after: i)
        }
        return String(s[..<end])
    }

    /// The end of `s` that fits `bytes` bytes of UTF-8, whole characters only.
    public static func tail(_ s: String, bytes: Int) -> String {
        if s.utf8.count <= bytes { return s }
        var n = 0, start = s.endIndex
        for i in s.indices.reversed() {
            n += s[i].utf8.count
            if n > bytes { break }
            start = i
        }
        return String(s[start...])
    }
}

extension Photo {
    /// The shape a chat row gives a received picture: its width over its height, kept between 1:3 and 3:1, and the
    /// row crops what doesn't fit. The sender chooses the picture: one a pixel wide and very tall would otherwise
    /// make a row hundreds of screens high (on Android, higher than a layout can be, which ended the app).
    public static func shape(width: Double, height: Double) -> Double {
        let r = width / height
        guard width > 0, height > 0, r.isFinite else { return 1 }
        return min(max(r, 1.0 / 3), 3)
    }
}

/// The ids of the messages the user reported or hid, as they are saved on the phone.
public enum HiddenMessages {
    public static let max = 2_000

    /// `ids` with `id` added, the newest `max`, as a plain array: the only kind UserDefaults can save. The slice that
    /// `suffix` returns is not one, and saving it ends the app.
    public static func adding(_ id: String, to ids: [String]) -> [String] { Array((ids + [id]).suffix(max)) }
}
