import Foundation

/// Bluetooth LE link protocol (spec/FORMAT.md, "Bluetooth LE"). Pure logic, same as the Android BleProtocol.kt.
public enum BleProtocol {
    public static let rx = UUID(uuidString: "33826aba-0bb0-4dfe-9c1a-86e48726ed62")!  // central writes
    public static let tx = UUID(uuidString: "94eb2c34-0e66-4bea-864c-d02a7694a3d5")!  // peripheral notifies
    public static let version: UInt8 = 1
    public static let helloType: UInt8 = 1
    public static let packetType: UInt8 = 2
    static let maxNodeId = 64

    public enum StreamError: Error { case badType(UInt8), badLength(Int) }

    /// The same for every Blackout device: all of them relay for each other, whatever their group.
    public static let service = UUID(uuidString: "bec33cd5-a64e-4e1a-b8c1-868db67d0df3")!

    public static func frame(_ type: UInt8, _ payload: Data) -> Data {
        Data([type, UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)]) + payload
    }

    public static func hello(nodeId: String) -> Data { frame(helloType, Data([version]) + Data(nodeId.utf8)) }

    /// Node id from a HELLO payload, or nil if the version or id is not acceptable.
    public static func parseHello(_ payload: Data) -> String? {
        let b = [UInt8](payload)
        guard b.count >= 2, b[0] == version, b.count - 1 <= maxNodeId, b.dropFirst().allSatisfy({ (0x20...0x7e).contains($0) }) else { return nil }
        return String(decoding: b.dropFirst(), as: UTF8.self)
    }

    /// Largest chunk for a link: what the stack allows, but never above 512 (maximum attribute value length).
    public static func chunkSize(maxLength: Int) -> Int { min(max(maxLength, 20), 512) }

    /// Pieces of at most `size` bytes, each sent as one write or one notification.
    public static func chunks(_ frame: Data, size: Int) -> [Data] {
        stride(from: 0, to: frame.count, by: size).map { frame.subdata(in: $0..<min($0 + size, frame.count)) }
    }

    /// Of two links to the same node, true means keep the one where this device is the central.
    public static func keepMyCentralLink(myId: String, remoteId: String) -> Bool {
        Array(myId.utf8).lexicographicallyPrecedes(Array(remoteId.utf8))
    }

    /// Two links made less than this apart were made at the same moment: the two phones dialed each other.
    public static let sameTimeMs: Int64 = 10_000
    /// What this phone does about a link whose node id another of its links already carries.
    public enum Twin: Sendable { case bothStay, closeNew, closeOld }
    /// A second link with a node id this phone already has a link with (spec "Duplicate links"). Two phones that
    /// dialed each other at the same moment keep the link the smaller node id dialed. Otherwise the link that is there
    /// stays. What happens to the new one depends on who made it: a link this phone dialed is closed, the phone is
    /// linked already. A link the other side dialed stays beside the first one, unless it comes from the same device:
    /// node ids prove nothing, so it may be the real phone, and the link that was there first the one that only says
    /// its id. If the two do lead to one phone, that phone closes the link it dialed.
    /// `newCentral`, `oldCentral`: this phone dialed that link. `apartMs`: the time between the making of the two.
    /// `sameDevice`: both have the same Bluetooth identifier (one radio connection, used in both directions).
    /// Same as Android's BleProtocol.twin.
    public static func twin(myId: String, remoteId: String, newCentral: Bool, oldCentral: Bool, apartMs: Int64, sameDevice: Bool) -> Twin {
        if newCentral != oldCentral && apartMs < sameTimeMs { // dialed each other at the same moment
            return newCentral == keepMyCentralLink(myId: myId, remoteId: remoteId) ? .closeOld : .closeNew
        }
        if newCentral { return apartMs < sameTimeMs ? .closeOld : .closeNew } // dialed twice in a moment: the newer; else it is linked already
        return sameDevice ? .closeNew : .bothStay
    }

    /// A link whose other side sends no HELLO this long after the link opened is closed (spec "Limits").
    public static let helloWait: TimeInterval = 10
    /// A central link still being set up this long after dialing is closed.
    public static let setupWait: TimeInterval = 30
    /// Re-sync and HELLO answers to a repeated HELLO, at most once per this per link (spec "Restarts").
    public static let repeatMs: Int64 = 60_000

    /// A repeated HELLO with the same node id (spec "Restarts"): whether to answer with HELLO, and whether to send the
    /// link every stored packet again. Each at most once a minute; the re-sync only when the link's queue is empty.
    /// The first repeat is always answered, so a restarted app learns who it is linked to. Same as Android's HelloGate.
    public struct HelloGate: Sendable {
        private var answeredAt = Int64.min / 2
        private var resyncedAt = Int64.min / 2
        public init() {}
        public mutating func repeated(nowMs: Int64, queueEmpty: Bool) -> (answer: Bool, resync: Bool) {
            let answer = nowMs - answeredAt >= repeatMs
            if answer { answeredAt = nowMs }
            let resync = queueEmpty && nowMs - resyncedAt >= repeatMs
            if resync { resyncedAt = nowMs }
            return (answer, resync)
        }
    }

    public static let maxQueueBytes = 1 << 20  // 1 MiB: about a minute of Bluetooth LE
    public static let maxQueueFrames = 1_000
    private static let head = 3                // a frame's type and length
    /// What a link tells the router its queue takes (`MeshRouter.peerUp`): under the queue's own limits, so HELLOs fit too.
    public static let roomBytes = maxQueueBytes - (1 << 16)
    public static let roomPackets = maxQueueFrames / 2

    /// Frames waiting to go out on one link, cut into chunks as they are sent. Over `maxBytes` or `maxFrames`, the
    /// oldest PACKET frames not yet started are dropped (the neighbour gets stored packets again on its next link);
    /// HELLO frames are never dropped. The router fills the queue only as far as it has room (`roomBytes`, `freed`),
    /// so in normal use nothing is dropped here. Same as Android's Outbox.
    public struct Outbox: Sendable {
        private var frames: [(data: Data, hello: Bool)] = []
        private var pos = 0          // bytes of the first frame already sent
        private var peeked = 0       // length of the chunk handed out by peek()
        private let maxBytes: Int, maxFrames: Int
        public private(set) var bytes = 0
        private var freedBytes = 0, freedPackets = 0 // PACKET frames that left the queue since freed()
        public var isEmpty: Bool { frames.isEmpty }
        public var count: Int { frames.count }
        public init(maxBytes: Int = BleProtocol.maxQueueBytes, maxFrames: Int = BleProtocol.maxQueueFrames) {
            self.maxBytes = maxBytes; self.maxFrames = maxFrames
        }

        public mutating func add(_ frame: Data, hello: Bool = false) {
            frames.append((frame, hello)); bytes += frame.count
            while bytes > maxBytes || frames.count > maxFrames {
                // the first frame may be half sent: never cut a frame in the middle of the stream
                let start = pos > 0 || peeked > 0 ? 1 : 0
                guard start < frames.count, let i = frames[start...].firstIndex(where: { !$0.hello }) else { break }
                let gone = frames.remove(at: i).data.count
                bytes -= gone; freedBytes += gone - BleProtocol.head; freedPackets += 1
            }
        }
        /// The room that opened since the last call, for `MeshRouter.room`: the bytes of the packets (without the frame
        /// header) that went out whole or were dropped, and how many they were.
        public mutating func freed() -> (bytes: Int, packets: Int) {
            defer { freedBytes = 0; freedPackets = 0 }
            return (freedBytes, freedPackets)
        }
        /// The next chunk of at most `size` bytes, without taking it: call `commit()` once it went out.
        public mutating func peek(_ size: Int) -> Data? {
            guard let f = frames.first?.data else { return nil }
            let end = min(pos + size, f.count)
            peeked = end - pos
            return f.subdata(in: (f.startIndex + pos)..<(f.startIndex + end))
        }
        public mutating func commit() {
            guard let f = frames.first?.data else { return }
            pos += peeked; peeked = 0
            if pos >= f.count {
                let hello = frames.removeFirst().hello
                bytes -= f.count; pos = 0
                if !hello { freedBytes += f.count - BleProtocol.head; freedPackets += 1 }
            }
        }
        public mutating func clear() { frames = []; bytes = 0; pos = 0; peeked = 0; freedBytes = 0; freedPackets = 0 }
    }

    /// Rebuilds frames from chunks. Throws on a malformed stream: the caller disconnects.
    public struct Reader {
        private var buf: [UInt8] = []
        public init() {}
        public mutating func feed(_ chunk: Data) throws -> [(type: UInt8, payload: Data)] {
            buf += chunk
            var out: [(type: UInt8, payload: Data)] = []
            var i = 0
            while buf.count - i >= 3 {
                let type = buf[i], len = Int(buf[i + 1]) << 8 | Int(buf[i + 2])
                let max: Int
                switch type {
                case helloType: max = 1 + maxNodeId
                case packetType: max = Packet.headerSize + Packet.maxCipher
                default: throw StreamError.badType(type)
                }
                guard (1...max).contains(len) else { throw StreamError.badLength(len) }
                guard buf.count - i - 3 >= len else { break }
                out.append((type, Data(buf[(i + 3)..<(i + 3 + len)])))
                i += 3 + len
            }
            buf.removeFirst(i)
            return out
        }
    }
}
