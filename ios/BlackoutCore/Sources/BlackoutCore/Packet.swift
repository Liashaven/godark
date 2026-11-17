import Foundation

/// How a packet is padded (spec "Padding"): `.size` up to the next listed size, `.full` to the largest, `.none` only for test vectors.
public enum Pad: Sendable { case none, size, full }

/// Unit carried over the network, compact enough to fit in a LoRa packet. Relays see only the id, timestamp, and remaining hops.
/// Wire format: spec/FORMAT.md (shared with the Android app).
public struct Packet: Equatable, Sendable {
    public static let marker: UInt8 = 0xB3 // 0xB2 = v0.3–0.4 (PBKDF2 keys, device ids), 0xB3 = v0.5
    public static let headerSize = 18
    public static let maxCipher = 16_000
    public static let maxTtl = 64
    /// The whole-packet sizes everything is padded to. 163 and 233 are the LoRa limits, so short packets still fit.
    public static let sizes = [163, 233, 512, 1024, 2048, 4096, 8192, headerSize + maxCipher]
    /// What sealing adds around the body: packet header, IV, signature, tag.
    public static let overhead = headerSize + 12 + 64 + 16

    /// Bytes of plaintext padding for a sealed packet that would otherwise be `size` bytes long.
    public static func padding(_ size: Int, _ pad: Pad) -> Int {
        switch pad {
        case .none: return 0
        case .full: return max(0, headerSize + maxCipher - size)
        case .size: return (sizes.first { $0 >= size } ?? size) - size
        }
    }

    /// 16 lowercase hex chars (8 random bytes).
    public let id: String
    /// Sender's clock, milliseconds since 1970-01-01 UTC.
    public let ts: Int64
    /// Hops left.
    public let ttl: Int
    public let cipher: Data

    public init(id: String, ts: Int64, ttl: Int, cipher: Data) {
        self.id = id; self.ts = ts; self.ttl = ttl; self.cipher = cipher
    }

    public func encode() -> Data {
        var out = Data([Packet.marker])
        out.append(Hex.decode(id))
        withUnsafeBytes(of: UInt64(bitPattern: ts).bigEndian) { out.append(contentsOf: $0) }
        out.append(UInt8(truncatingIfNeeded: ttl))
        out.append(cipher)
        return out
    }

    public func withTtl(_ t: Int) -> Packet { Packet(id: id, ts: ts, ttl: t, cipher: cipher) }

    /// A new id whose first 2 bytes are the mailbox (spec/FORMAT.md, "Mailboxes"), the other 6 random.
    public static func newId(mailbox: UInt16) -> String {
        String(format: "%04x", mailbox) + newId().dropFirst(4)
    }

    /// The mailbox of any packet id.
    public static func mailbox(of id: String) -> UInt16 { UInt16(id.prefix(4), radix: 16) ?? 0 }

    public static func newId() -> String {
        var g = SystemRandomNumberGenerator() // cryptographically secure on Apple platforms
        return Hex.encode(Data((0..<8).map { _ in UInt8.random(in: .min ... .max, using: &g) }))
    }

    /// `limit`: the largest cipher taken. Only a store of this phone's own copies (`History.maxSealed`) takes more than a packet.
    public static func decode(_ raw: Data, limit: Int = maxCipher) -> Packet? {
        let b = [UInt8](raw)
        guard b.count > headerSize, b.count <= headerSize + limit, b[0] == marker else { return nil }
        let ttl = Int(b[17])
        guard ttl <= maxTtl else { return nil }
        let ts = b[9..<17].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        return Packet(id: Hex.encode(Data(b[1..<9])), ts: Int64(bitPattern: ts), ttl: ttl, cipher: Data(b[headerSize...]))
    }
}

enum Hex {
    private static let digits = Array("0123456789abcdef".utf8)
    static func encode(_ d: Data) -> String {
        var out = [UInt8](); out.reserveCapacity(d.count * 2)
        for b in d { out.append(digits[Int(b >> 4)]); out.append(digits[Int(b & 15)]) }
        return String(decoding: out, as: UTF8.self)
    }
    static func decode(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex), i < s.endIndex {
            d.append(UInt8(s[i..<j], radix: 16) ?? 0); i = j
        }
        return d
    }
}
