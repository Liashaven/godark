import Foundation
import BlackoutCore

/// Append-only file of every packet seen, read back piece by piece (never the whole file at once). The Android app
/// keeps the same list in SQLite. Each record: 4-byte big-endian length, then the encoded packet. Its size is kept
/// under the store cap by Engine (StoreCap), which removes records with `remove`.
final class PacketStore {
    /// What a record goes by (`StoreCap.name`) in `forEachNamed` and `remove`. `.first`: "packets.bin", where the first
    /// record with an id goes by that id and a later one with the same id by its key (an older version wrote a readable
    /// packet after junk sent first under its id). `.key`: "more.bin", the packets that arrived under an id another
    /// packet had already taken: each goes by its key. `.id`: every record by its id (the copies in "history.bin").
    enum Naming { case id, first, key }
    private let naming: Naming
    private let url: URL
    /// The largest cipher a record may hold, written or read: a packet's, or for the copies in "history.bin" `History.maxSealed`.
    /// A longer record is never written, as the reader would take it for damage and stop there.
    private let limit: Int
    private let lock = NSLock() // appends and rewrites; reading needs no lock (a rewrite replaces the file atomically)
    private static let piece = 1 << 20

    /// `file`: "history.bin" holds this phone's readable copies of messages whose keys are deleted (spec "Message keys").
    init(file: String = "packets.bin", naming: Naming? = nil) {
        self.naming = naming ?? (file == "packets.bin" ? .first : .id)
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appendingPathComponent(file)
        limit = file == "history.bin" ? History.maxSealed : Packet.maxCipher
        // Protocol v0.5: older packets were sealed with v0.4 keys that no phone uses any more (and no longer decode).
        if file == "packets.bin" && !UserDefaults.standard.bool(forKey: "storeV05") {
            try? FileManager.default.removeItem(at: url)
            UserDefaults.standard.set(true, forKey: "storeV05")
        }
        excludeFromBackup() // a file kept by an earlier version too
    }

    /// The store stays on this phone: never in an iCloud or computer backup (PRIVACY.md, "What stays on your phone").
    /// Set again after each rewrite, which replaces the file.
    private func excludeFromBackup() {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        var u = url, v = URLResourceValues()
        v.isExcludedFromBackup = true
        try? u.setResourceValues(v)
    }

    /// Calls `body` with every stored packet, in the order they were stored, reading 1 MB at a time. Any thread; may
    /// run while packets are appended (a torn last record is ignored).
    func forEach(_ body: (Packet) -> Void) {
        guard let h = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? h.close() }
        Self.records(h, limit) { _, p in if let p { body(p) } }
    }

    /// Like `forEach`, with the name each packet goes by (`Naming`).
    func forEachNamed(_ body: (Packet, String) -> Void) {
        guard let h = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? h.close() }
        var seen = Set<String>()
        Self.records(h, limit) { _, p in if let p { body(p, name(p, &seen)) } }
    }

    /// `seen`: the ids of the records before this one.
    private func name(_ p: Packet, _ seen: inout Set<String>) -> String {
        switch naming {
        case .id: return p.id
        case .key: return StoreCap.name(p, first: false)
        case .first: return StoreCap.name(p, first: seen.insert(p.id).inserted)
        }
    }

    /// Removes the packets that go by these names (`Naming`) by writing the others to a new file that then replaces this
    /// one, under the lock, so packets appended meanwhile are kept.
    func remove(_ ids: Set<String>) {
        guard !ids.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        guard let h = try? FileHandle(forReadingFrom: url) else { return }
        defer { try? h.close() }
        let tmp = url.appendingPathExtension("new")
        guard FileManager.default.createFile(atPath: tmp.path, contents: nil), let out = try? FileHandle(forWritingTo: tmp) else { return }
        var pending = Data(), seen = Set<String>()
        Self.records(h, limit) { record, p in
            guard let p, !ids.contains(name(p, &seen)) else { return } // unreadable records go too
            pending.append(record)
            if pending.count >= Self.piece { try? out.write(contentsOf: pending); pending = Data() }
        }
        try? out.write(contentsOf: pending)
        try? out.close()
        if Foundation.rename(tmp.path, url.path) != 0 { try? FileManager.default.removeItem(at: tmp) }
        excludeFromBackup()
    }

    /// Raises the ttl of stored packets in place: `ttls` is `MeshRouter.key` → the ttl of a copy that came with more
    /// hops left. One pass over the file, under the lock. Nothing is added, so the store cap still counts every record.
    func raise(_ ttls: [String: Int]) {
        guard !ttls.isEmpty else { return }
        let ids = Set(ttls.keys.map { String($0.prefix(16)) }) // a key starts with the packet id: only those records are hashed
        lock.lock(); defer { lock.unlock() }
        guard let h = try? FileHandle(forUpdating: url) else { return }
        defer { try? h.close() }
        var at: UInt64 = 0, found: [(at: UInt64, ttl: UInt8)] = []
        Self.records(h, limit) { record, p in
            if let p, ids.contains(p.id), let ttl = ttls[MeshRouter.key(p)], ttl > p.ttl, ttl <= Packet.maxTtl {
                found.append((at + 4 + UInt64(Packet.headerSize) - 1, UInt8(ttl))) // the ttl is the last byte of the header
            }
            at += UInt64(record.count)
        }
        for f in found {
            do { try h.seek(toOffset: f.at); try h.write(contentsOf: Data([f.ttl])) } catch { return }
        }
    }

    func append(_ p: Packet) {
        guard p.cipher.count <= limit else { return } // the reader would stop at it, and lose every record after it
        let e = p.encode()
        let rec = Data([UInt8(e.count >> 24 & 0xFF), UInt8(e.count >> 16 & 0xFF), UInt8(e.count >> 8 & 0xFF), UInt8(e.count & 0xFF)]) + e
        lock.lock(); defer { lock.unlock() }
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd(); try? h.write(contentsOf: rec)
        } else {
            try? rec.write(to: url)
            excludeFromBackup()
        }
    }

    /// Each whole record (length prefix included) and its packet, or nil if it doesn't decode. Stops at a bad length.
    private static func records(_ h: FileHandle, _ limit: Int, _ body: (Data, Packet?) -> Void) {
        var buf: [UInt8] = []
        while let more = try? h.read(upToCount: piece), !more.isEmpty {
            buf.append(contentsOf: more)
            var i = 0
            while i + 4 <= buf.count {
                let n = Int(buf[i]) << 24 | Int(buf[i + 1]) << 16 | Int(buf[i + 2]) << 8 | Int(buf[i + 3])
                guard n > 0, n <= Packet.headerSize + limit else { return } // damaged: ignore the rest
                guard i + 4 + n <= buf.count else { break }                             // the rest comes with the next piece
                let record = Data(buf[i..<(i + 4 + n)])
                body(record, Packet.decode(record.dropFirst(4), limit: limit))
                i += 4 + n
            }
            buf.removeFirst(i)
        }
    }
}
