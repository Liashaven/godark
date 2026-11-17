import Foundation

/// Hand-encoded subset of the Meshtastic protocol (ToRadio/FromRadio), same as the Android Meshtastic.kt.
/// Field numbers come from the Meshtastic protobufs (mesh.proto, portnums.proto).
public enum Meshtastic {
    public static let payloadMax = 233
    static let privateApp: UInt64 = 256   // PortNum.PRIVATE_APP
    static let broadcast: UInt32 = 0xFFFF_FFFF
    static let hopLimit: UInt64 = 3

    public static func fits(_ p: Packet) -> Bool { p.encode().count <= payloadMax }

    public static func varint(_ value: UInt64) -> Data {
        var out = Data(), x = value
        while x >= 0x80 { out.append(UInt8(x & 0x7F) | 0x80); x >>= 7 }
        out.append(UInt8(x))
        return out
    }
    private static func varintField(_ f: Int, _ v: UInt64) -> Data { varint(UInt64(f << 3)) + varint(v) }
    private static func bytesField(_ f: Int, _ b: Data) -> Data { varint(UInt64(f << 3 | 2)) + varint(UInt64(b.count)) + b }
    private static func fixed32Field(_ f: Int, _ v: UInt32) -> Data {
        varint(UInt64(f << 3 | 5)) + Data([UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 24 & 0xFF)])
    }

    /// ToRadio.want_config_id: asks the radio to send its configuration, ending with config_complete_id == nonce.
    public static func wantConfig(_ nonce: UInt32) -> Data { varintField(3, UInt64(nonce)) }

    /// ToRadio.packet: a broadcast MeshPacket on channel 0 carrying `payload` on PRIVATE_APP.
    public static func toRadioPacket(_ payload: Data, packetId: UInt32) -> Data {
        let data = varintField(1, privateApp) + bytesField(2, payload)                         // Data
        let packet = fixed32Field(2, broadcast) + bytesField(4, data) + fixed32Field(6, packetId) + varintField(9, hopLimit) // MeshPacket
        return bytesField(1, packet)
    }

    private enum Malformed: Error { case truncated }

    /// Calls `on(field, varintValue, bytes)` for each field; bytes is non-nil for length-delimited fields.
    private static func walk(_ b: [UInt8], _ on: (Int, UInt64, [UInt8]?) -> Void) throws {
        var i = 0
        func readVarint() throws -> UInt64 {
            var r: UInt64 = 0, shift: UInt64 = 0
            while true {
                guard i < b.count, shift < 64 else { throw Malformed.truncated }
                let x = b[i]; i += 1
                r |= UInt64(x & 0x7F) << shift
                if x & 0x80 == 0 { return r }
                shift += 7
            }
        }
        while i < b.count {
            let tag = try readVarint(), field = Int(tag >> 3)
            switch tag & 7 {
            case 0: on(field, try readVarint(), nil)
            case 1: guard i + 8 <= b.count else { throw Malformed.truncated }; i += 8
            case 2:
                guard let n = Int(exactly: try readVarint()), n >= 0, n <= b.count - i else { throw Malformed.truncated }
                on(field, 0, Array(b[i..<(i + n)])); i += n
            case 5: guard i + 4 <= b.count else { throw Malformed.truncated }; i += 4
            default: return
            }
        }
    }

    public static func fieldBytes(_ b: Data, _ field: Int) -> Data? {
        var r: Data?
        try? walk([UInt8](b)) { f, _, x in if f == field, let x { r = Data(x) } }
        return r
    }

    public struct FromRadio: Equatable {
        public let payload: Data?           // our packet, if this was a PRIVATE_APP MeshPacket
        public let configComplete: UInt64?  // config_complete_id
    }

    public static func parseFromRadio(_ b: Data) -> FromRadio {
        var payload: Data?, done: UInt64?
        do {
            try walk([UInt8](b)) { f, v, x in
                if f == 7 { done = v }
                if f == 2, let x, let decoded = fieldBytes(Data(x), 4) { // FromRadio.packet -> MeshPacket.decoded
                    var port: UInt64 = 0
                    try? walk([UInt8](decoded)) { pf, pv, _ in if pf == 1 { port = pv } }
                    if port == privateApp { payload = fieldBytes(decoded, 2) }
                }
            }
        } catch { return FromRadio(payload: nil, configComplete: nil) }
        return FromRadio(payload: payload, configComplete: done)
    }
}

/// LoRa has very little bandwidth: only recent messages that fit, one at a time. The packets this phone wrote go
/// first, and a packet it only passes on never takes the place of one of them. Same rules as the Android LoraQueue.
public final class LoraQueue: @unchecked Sendable { // state guarded by `lock`
    public static let maxAgeMs: Int64 = 30 * 60_000
    public static let intervalMs: Int64 = 20_000
    public static let maxQueue = 20
    private let now: () -> Int64
    private let lock = NSLock()
    private var q: [Packet] = []
    private var own: [Packet] = [] // written on this phone
    private var sent: [String] = [] // MeshRouter.key, as the router tells packets apart: junk under an id can't keep the real packet off the radio
    private var sentSet = Set<String>()
    private var last: Int64 = 0

    private let maxBytes: Int

    public init(maxBytes: Int = Meshtastic.payloadMax, now: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) {
        self.maxBytes = maxBytes; self.now = now
    }

    /// `mine`: this very packet was written on this phone.
    public func offer(_ p: Packet, mine: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        guard p.ts >= now() - Self.maxAgeMs, p.encode().count <= maxBytes else { return }
        let k = MeshRouter.key(p)
        guard sentSet.insert(k).inserted else { return }
        sent.append(k)
        if sent.count > 1000 { sentSet.remove(sent.removeFirst()) }
        // Full: the oldest packet passed on makes room. With only own packets waiting, the oldest of them does, for another own one.
        if q.count + own.count >= Self.maxQueue {
            if !q.isEmpty { q.removeFirst() } else if mine { own.removeFirst() } else { return }
        }
        if mine { own.append(p) } else { q.append(p) }
    }

    public func next() -> Packet? {
        lock.lock(); defer { lock.unlock() }
        guard !(q.isEmpty && own.isEmpty), now() - last >= Self.intervalMs else { return nil }
        last = now()
        return own.isEmpty ? q.removeFirst() : own.removeFirst()
    }
}
