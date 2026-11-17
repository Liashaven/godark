import Foundation
import BlackoutCore

/// People the user blocked and messages the user reported or hid: both are hidden everywhere (chats, places, people,
/// alerts). Kept only on this phone. Reports also go to the internet relays when there is internet. Same rules as Android.
/// A block holds for the channel it was made in, Everyone or one group, and only a checked message's sender can be
/// blocked (`Blocks`, `Engine.block`): an unchecked message can be hidden, not its sender.
enum Moderation {
    private static let d = UserDefaults.standard

    /// What is blocked (`Blocks.key`: the channel and the sender id) and the name that sender had.
    static var blocked: [String: String] { d.dictionary(forKey: "blocked") as? [String: String] ?? [:] }
    /// `key`: `Blocks.key` of the channel and the sender. Called by `Engine.block`, which knows the channel.
    static func block(_ key: String, name: String) { var b = blocked; b[key] = name; d.set(b, forKey: "blocked") }
    /// `key`: a key of `blocked`.
    static func unblock(_ key: String) { var b = blocked; b.removeValue(forKey: key); d.set(b, forKey: "blocked") }

    /// Ids of messages the user reported or hid.
    static var hidden: Set<String> { Set(d.stringArray(forKey: "hidden") ?? []) }
    static func hide(_ id: String) { d.set(HiddenMessages.adding(id, to: d.stringArray(forKey: "hidden") ?? []), forKey: "hidden") }

    /// Reports waiting to go to the internet relays.
    static var pendingReports: [String] { d.stringArray(forKey: "reports") ?? [] }
    static func report(_ id: String) {
        hide(id)
        d.set(Array((pendingReports + [id]).suffix(200)), forKey: "reports")
    }
    static func reportsSent(_ ids: [String]) { d.set(pendingReports.filter { !ids.contains($0) }, forKey: "reports") }
}
