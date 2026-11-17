import Foundation

/// A delivery receipt says "I got these messages" (spec/FORMAT.md, "Delivery receipts"). It travels as an ordinary
/// packet sealed with the group's receipt key; its text is the confirmed message ids separated by spaces.
public enum Receipt {
    /// Most ids in one receipt.
    public static let maxIds = 200

    public static func text(for ids: [String]) -> String { ids.joined(separator: " ") }

    /// The message ids a receipt confirms: its first `maxIds`. Whatever follows them is not read. Anything that isn't
    /// 16 lowercase hex characters is skipped.
    public static func ids(in text: String) -> [String] {
        Array(text.utf8.split(separator: 32).lazy.filter { id in
            id.count == 16 && id.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }.prefix(maxIds).map { String(decoding: $0, as: UTF8.self) })
    }

    /// Splits ids into receipt-sized batches.
    public static func batches(_ ids: [String]) -> [[String]] {
        stride(from: 0, to: ids.count, by: maxIds).map { Array(ids[$0..<min($0 + maxIds, ids.count)]) }
    }
}

/// Someone who confirmed getting a message.
public struct Reader: Equatable, Sendable {
    public let id: String   // their device id
    public var name: String
    public var ts: Int64    // their clock when they first confirmed it
    public init(id: String, name: String, ts: Int64) { self.id = id; self.name = name; self.ts = ts }
}

/// Who got which of this phone's own group messages, built from checked receipts (spec "Delivery receipts").
/// A receipt counts for a message only if this phone wrote that message (`sent`) in the group whose receipt key opened
/// the receipt: a member of one saved group can't confirm a message of another, and ids that are no message of this
/// phone's take no memory. Same as Android's Deliveries.
public struct Deliveries: Equatable, Sendable {
    /// Message id -> readers, earliest confirmation first.
    public private(set) var readers: [String: [Reader]] = [:]
    private var groups: [String: String] = [:] // this phone's own group messages: id -> group id

    public init() {}

    /// This phone wrote `messageId` in the group whose id is `group`.
    public mutating func sent(group: String, _ messageId: String) { if groups[messageId] == nil { groups[messageId] = group } }

    /// Adds a checked receipt opened with a receipt key of the group whose id is `group`. A reader counts once per
    /// message, with the time and name of their earliest receipt for it.
    public mutating func add(group: String, _ r: Message) {
        for id in Receipt.ids(in: r.text) where groups[id] == group {
            count(Reader(id: r.sender, name: r.name, ts: r.ts), for: id)
        }
    }

    /// Adds what `other` holds: the messages it knows as written here, and their readers. For a table built off the
    /// main thread from the stored packets.
    public mutating func merge(_ other: Deliveries) {
        for (id, group) in other.groups where groups[id] == nil { groups[id] = group }
        for (id, list) in other.readers {
            guard let group = other.groups[id], groups[id] == group else { continue }
            for r in list { count(r, for: id) }
        }
    }

    /// The messages `ids` left the store.
    public mutating func forget<S: Sequence>(_ ids: S) where S.Element == String {
        for id in ids { groups[id] = nil; readers[id] = nil }
    }

    private mutating func count(_ r: Reader, for id: String) {
        var list = readers[id] ?? []
        if let i = list.firstIndex(where: { $0.id == r.id }) {
            guard r.ts < list[i].ts else { return }
            list[i] = r
        } else {
            list.append(r)
        }
        readers[id] = list.sorted { $0.ts < $1.ts }
    }
}

/// When the next delivery receipt goes out (spec/FORMAT.md, "Delivery receipts"): 2 s after the last message to confirm
/// arrived, or 10 s after the first one, so a burst of arriving messages shares one receipt. Same as Android's.
public enum ReceiptBatch {
    public static let quietMs: Int64 = 2_000
    public static let maxWaitMs: Int64 = 10_000
    public static func due(firstMs: Int64, lastMs: Int64, nowMs: Int64) -> Bool {
        nowMs - lastMs >= quietMs || nowMs - firstMs >= maxWaitMs
    }
}
