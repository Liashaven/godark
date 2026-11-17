import Foundation

/// When a member's encryption key changes (spec "Sealing for one member"). Each key is used for a week, then kept for two
/// more so new keys sealed to it can still be opened, then deleted: after that, recorded traffic sealed to it can't be
/// opened, even by someone who takes the phone. Pure rules; the keys are in the app's EncKeys. Same as Android's.
public enum EncSchedule {
    public static let rotateMs: Int64 = 7 * 24 * 3_600_000
    public static let keepMs: Int64 = 14 * 24 * 3_600_000
    public static let maxKeys = 8

    /// `replaced`: when a newer key took over; 0 for the current key. Oldest first in a list.
    public struct Entry: Equatable, Hashable, Sendable {
        public let n: Int, made: Int64
        public var replaced: Int64
        public init(n: Int, made: Int64, replaced: Int64 = 0) { self.n = n; self.made = made; self.replaced = replaced }
    }

    public static func parse(_ s: String) -> [Entry] {
        s.split(separator: ",").compactMap { e in
            let p = e.split(separator: ":", omittingEmptySubsequences: false)
            guard p.count == 3, let n = Int(p[0]), let m = Int64(p[1]), let r = Int64(p[2]) else { return nil }
            return Entry(n: n, made: m, replaced: r)
        }
    }

    public static func save(_ list: [Entry]) -> String { list.map { "\($0.n):\($0.made):\($0.replaced)" }.joined(separator: ",") }

    public static func due(_ list: [Entry], now: Int64) -> Bool { list.last.map { now - $0.made >= rotateMs } ?? true }

    /// The list once a new key has taken over.
    public static func rotated(_ list: [Entry], now: Int64) -> [Entry] {
        list.map { var e = $0; if e.replaced == 0 { e.replaced = now }; return e } + [Entry(n: (list.map(\.n).max() ?? -1) + 1, made: now)]
    }

    /// The keys that can be deleted now. The current key never is.
    public static func expired(_ list: [Entry], now: Int64) -> [Entry] {
        let old = list.filter { $0.replaced != 0 && now - $0.replaced >= keepMs }
        return old + Array(list.filter { !old.contains($0) }.dropLast(maxKeys))
    }

    /// An introduction replaces a member's encryption key only if it is newer: one played back can't bring back a key they deleted.
    public static func isNewer(known: Int64, ts: Int64) -> Bool { ts > known }
}
