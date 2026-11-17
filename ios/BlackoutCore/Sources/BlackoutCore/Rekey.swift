import Foundation

/// A rekey's payload, the 4th field after the type byte (spec/DESIGN-v0.6-groups.md, "New key"): a new epoch, its
/// maker's signing key, the admins, whose join request it answers, and the epoch secret sealed for each member.
/// Type 0x05 is a `removal`: `answers` is then the person removed, and each sealed part also holds the group's new code.
/// Same bytes as Android's Rekey (Core.kt).
public struct Rekey: Equatable, Sendable {
    public static let type: UInt8 = 6, removalType: UInt8 = 7 // 4 and 5 were the shape without a separate member list
    public static let partsPerPacket = 10
    private static let maxCode = 200 // bytes
    public let epoch: Int64, made: Int64, maker: Data, admins: [String], answers: String?, removal: Bool
    public let parts: [(id: String, box: Data)]
    /// Everyone in the new epoch. `parts` can hold only some of them: a big group's key is split over several packets.
    public let members: [String]

    public init(epoch: Int64, made: Int64, maker: Data, admins: [String], answers: String?, parts: [(id: String, box: Data)], removal: Bool = false, members: [String]? = nil) {
        self.epoch = epoch; self.made = made; self.maker = maker; self.admins = admins; self.answers = answers; self.parts = parts; self.removal = removal
        self.members = members ?? parts.map(\.id)
    }

    /// How many packets a new key for `n` members travels in. Only three counts exist, so the number says little about the group's size.
    public static func packets(_ n: Int) -> Int { n <= partsPerPacket ? 1 : n <= 3 * partsPerPacket ? 3 : 10 }

    /// `items` spread evenly over that many packets.
    public static func split<T>(_ items: [T]) -> [[T]] {
        let k = packets(items.count)
        return (0..<k).map { i in items.enumerated().filter { $0.offset % k == i }.map(\.element) }
    }

    public static func == (a: Rekey, b: Rekey) -> Bool { a.encode() == b.encode() }

    public func encode() -> Data {
        var d = Data([removal ? Self.removalType : Self.type])
        func be(_ v: Int64) { withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) } }
        be(epoch); be(made); d.append(maker)
        d.append(UInt8(admins.count)); admins.forEach { d.append(Hex.decode($0)) }
        d.append(answers.map(Hex.decode) ?? Data(count: 8))
        d.append(UInt8(members.count >> 8)); d.append(UInt8(members.count & 0xff)); members.forEach { d.append(Hex.decode($0)) }
        d.append(UInt8(parts.count >> 8)); d.append(UInt8(parts.count & 0xff))
        for p in parts { d.append(Hex.decode(p.id)); d.append(UInt8(p.box.count >> 8)); d.append(UInt8(p.box.count & 0xff)); d.append(p.box) }
        return d
    }

    public static func decode(_ e: Data) -> Rekey? {
        let b = [UInt8](e); var i = 0
        func take(_ n: Int) -> [UInt8]? { guard i + n <= b.count else { return nil }; defer { i += n }; return Array(b[i..<(i + n)]) }
        func int64() -> Int64? { take(8).map { $0.reduce(Int64(0)) { $0 << 8 | Int64($1) } } }
        // The counts are checked as they are read: this runs before the signature is checked, on a packet anyone with the
        // code can seal, and a list as long as the packet allows would cost far more to read than it did to write.
        guard let t = take(1)?.first, t == type || t == removalType, let epoch = int64(), let made = int64(), let maker = take(33), let na = take(1),
              Int(na[0]) <= Keyring.maxMembers else { return nil }
        var admins: [String] = []
        for _ in 0..<Int(na[0]) { guard let a = take(8) else { return nil }; admins.append(Hex.encode(Data(a))) }
        guard let ans = take(8), let nm = take(2), Int(nm[0]) << 8 | Int(nm[1]) <= Keyring.maxMembers else { return nil }
        var members: [String] = []
        for _ in 0..<(Int(nm[0]) << 8 | Int(nm[1])) { guard let m = take(8) else { return nil }; members.append(Hex.encode(Data(m))) }
        guard let np = take(2), Int(np[0]) << 8 | Int(np[1]) <= partsPerPacket else { return nil }
        var parts: [(String, Data)] = []
        for _ in 0..<(Int(np[0]) << 8 | Int(np[1])) {
            guard let id = take(8), let n = take(2), let box = take(Int(n[0]) << 8 | Int(n[1])) else { return nil }
            parts.append((Hex.encode(Data(id)), Data(box)))
        }
        guard i == b.count, whole(members, parts.map(\.0)) else { return nil }
        let a = Hex.encode(Data(ans))
        if t == removalType && a == "0000000000000000" { return nil }
        return Rekey(epoch: epoch, made: made, maker: Data(maker), admins: admins, answers: a == "0000000000000000" ? nil : a, parts: parts, removal: t == removalType, members: members)
    }

    /// True if a packet that lists `members` carries parts for exactly the people one packet of that key holds (`split`):
    /// all of them up to `partsPerPacket` members, else every 3rd or 10th. Every phone can check this, so a maker can't
    /// list someone and quietly give them no part: only an admin may leave a member out, and has to say so.
    public static func whole(_ members: [String], _ parts: [String]) -> Bool { split(members).contains(parts) }

    /// What is sealed for each member: the epoch secret, then after a removal the group's new code.
    public static func box(_ secret: Data, code: String?) -> Data { secret + Data((code ?? "").utf8) }

    /// The secret and new code from an opened part, or nil if it isn't the right shape: anyone with the code can write one.
    public static func unbox(_ plain: Data, removal: Bool) -> (secret: Data, code: String?)? {
        guard plain.count >= 32, plain.count <= 32 + maxCode, (plain.count > 32) == removal else { return nil }
        let secret = Data(plain.prefix(32))
        guard removal else { return (secret, nil) }
        guard let code = String(data: Data(plain.dropFirst(32)), encoding: .utf8),
              Invite.isGeneratedCode(code) else { return nil } // a removal can't move the group to a code that can be guessed
        return (secret, code)
    }

    /// HPKE info for a group's rekeys: binds the sealed secret to the door it travels through.
    public static func info(_ groupId: String) -> Data { Data("darkproof-rekey-v1".utf8) + Hex.decode(groupId) }
    /// HPKE aad for one member's part: binds it to this packet and this member.
    public static func aad(_ packetId: String, _ member: String) -> Data { Hex.decode(packetId) + Hex.decode(member) }
}
