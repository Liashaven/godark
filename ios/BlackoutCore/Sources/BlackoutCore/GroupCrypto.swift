import Foundation
import CryptoKit
import Scrypt

public struct Message: Equatable, Sendable {
    public let id: String
    public let ts: Int64
    public let sender: String
    public let name: String
    public let text: String
    /// Sent on the Public channel (spec/FORMAT.md), readable by everyone.
    public let isPublic: Bool
    /// A small JPEG photo (spec/FORMAT.md, "Photos"), or nil.
    public let photo: Data?
    /// The code of the saved group whose key opened it (nil for Public messages). Not sent on the wire.
    public var group: String?
    /// false: the sender's public key isn't known yet, so its signature couldn't be checked (spec "Signatures").
    public var verified = true

    public init(id: String, ts: Int64, sender: String, name: String, text: String, isPublic: Bool = false, photo: Data? = nil,
                group: String? = nil) {
        self.id = id; self.ts = ts; self.sender = sender; self.name = name; self.text = text; self.isPublic = isPublic
        self.photo = photo; self.group = group
    }

    /// The same message with another sender: on this phone, its own messages carry the device id (Engine).
    public func withSender(_ s: String) -> Message {
        var m = Message(id: id, ts: ts, sender: s, name: name, text: text, isPublic: isPublic, photo: photo, group: group)
        m.verified = verified
        return m
    }

    /// The same message under another id: the name its packet goes by on this phone when another packet had its id first (`StoreCap.name`).
    public func withId(_ i: String) -> Message {
        var m = Message(id: i, ts: ts, sender: sender, name: name, text: text, isPublic: isPublic, photo: photo, group: group)
        m.verified = verified
        return m
    }
}

public enum GroupCryptoError: Error { case fieldTooLong, badIv, badSignature }

/// Photos ride in a 4th plaintext field that older readers skip (spec/FORMAT.md, "Photos").
public enum Photo {
    /// Type byte of a JPEG attachment.
    public static let jpeg: UInt8 = 0x01
    /// Most JPEG bytes in one message, so the whole packet stays under `Packet.maxCipher`.
    public static let maxBytes = 14_000
    /// The text older apps show for a photo without a caption.
    public static let placeholder = "📷 Photo"

    /// "📷 Photo" or "📷 <caption>".
    public static func text(caption: String) -> String {
        let c = caption.trimmingCharacters(in: .whitespacesAndNewlines)
        return c.isEmpty ? placeholder : "📷 \(c)"
    }

    /// The caption of a photo message's text, or "" for none.
    public static func caption(_ text: String) -> String {
        guard text != placeholder else { return "" }
        return text.hasPrefix("📷 ") ? String(text.dropFirst(2)) : text
    }
}

/// Group encryption: everyone who knows the group code can read and write; relays without it cannot. See spec/FORMAT.md.
public final class GroupCrypto: Sendable {
    /// Code of the Public channel: everyone knows it, so anyone can read and post (spec/FORMAT.md).
    public static let publicCode = "blackout-public"
    private let key: SymmetricKey
    /// The group's relay mailbox (spec/FORMAT.md, "Mailboxes"): receipts share it, so members get them too.
    public let mailbox: UInt16

    public init(code: String) {
        let k = GroupCrypto.deriveKey(code)
        key = SymmetricKey(data: k); mailbox = GroupCrypto.deriveMailbox(k)
    }
    private init(key: SymmetricKey, mailbox: UInt16) { self.key = key; self.mailbox = mailbox }

    /// First 2 bytes of HMAC-SHA256(group key, "darkproof-relay-mailbox-v1").
    public static func deriveMailbox(_ groupKey: Data) -> UInt16 {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("darkproof-relay-mailbox-v1".utf8), using: SymmetricKey(data: groupKey))
        let b = Array(mac)
        return UInt16(b[0]) << 8 | UInt16(b[1])
    }

    /// The group's delivery-receipt key (spec/FORMAT.md, "Delivery receipts"). Apps that don't know receipts can't
    /// open them with the group or public key, so they relay them without showing them.
    public func receipts() -> GroupCrypto {
        GroupCrypto(key: SymmetricKey(data: key.withUnsafeBytes { GroupCrypto.deriveReceiptKey(Data($0)) }), mailbox: mailbox)
    }

    /// The group's introduction key (spec/FORMAT.md, "Introductions").
    public func intros() -> GroupCrypto {
        GroupCrypto(key: SymmetricKey(data: key.withUnsafeBytes { GroupCrypto.deriveIntroKey(Data($0)) }), mailbox: mailbox)
    }

    /// The door's rekey key (spec/DESIGN-v0.6-groups.md, "New key"): new epoch secrets travel sealed with it.
    public func rekeys() -> GroupCrypto {
        let k = key.withUnsafeBytes { HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data($0)), info: Data("darkproof-rekey-v1".utf8), outputByteCount: 32) }
        return GroupCrypto(key: k, mailbox: mailbox)
    }

    /// HKDF-SHA256 of the group key, no salt, info "darkproof-intro-v1", 32 bytes.
    public static func deriveIntroKey(_ groupKey: Data) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: groupKey), info: Data("darkproof-intro-v1".utf8),
                               outputByteCount: 32).withUnsafeBytes { Data($0) }
    }

    /// A group's keys from a 32-byte epoch secret instead of a code (spec/DESIGN-v0.6-groups.md, "Keys").
    public static func fromSecret(_ secret: Data) -> GroupCrypto {
        precondition(secret.count == 32)
        return GroupCrypto(key: SymmetricKey(data: secret), mailbox: deriveMailbox(secret))
    }

    /// The group's id, from the key its code makes: it stays the same when the group's code or epoch changes
    /// (spec/DESIGN-v0.6-groups.md), so member keys, saved public keys and checked people hang off it.
    public func groupId() -> String {
        Hex.encode(Data(HMAC<SHA256>.authenticationCode(for: Data("darkproof-group-id-v1".utf8), using: key)).prefix(16))
    }

    /// HMAC-SHA256(key, "darkproof-sig-context-v1"): ties signatures to this key (spec "Signatures").
    private var context: Data { Data(HMAC<SHA256>.authenticationCode(for: Data("darkproof-sig-context-v1".utf8), using: key)) }

    /// Names this key without revealing it, e.g. for the Keychain entry of the member key: half the context, in hex.
    public var tag: String { Hex.encode(context.prefix(16)) }

    /// What a packet's signature covers: tag, context, id, ts, body.
    public func signed(id: String, ts: Int64, body: Data) -> Data {
        var d = Data("darkproof-sig-v1".utf8)
        d.append(context); d.append(Hex.decode(id))
        withUnsafeBytes(of: ts.bigEndian) { d.append(contentsOf: $0) }
        d.append(body)
        return d
    }

    /// What the signature of a packet sealed with a message key covers (spec "Message keys"): a tag of its own, context, id,
    /// ts, the sender's position and the message number, body. Every member holds every member's message keys: were the
    /// position and number left out, one of them could seal someone's signed message again under that person's unused
    /// numbers, and each phone that checked the signature would delete the key of a message not written yet. The tag keeps
    /// the signature from being moved to or from a packet sealed with the epoch's key.
    public func signed(index: Int, counter: Int, id: String, ts: Int64, body: Data) -> Data {
        var d = Data("darkproof-sig-mk-v1".utf8)
        d.append(context); d.append(Hex.decode(id))
        withUnsafeBytes(of: ts.bigEndian) { d.append(contentsOf: $0) }
        d.append(contentsOf: GroupCrypto.header(index, counter)); d.append(body)
        return d
    }

    /// The 3 bytes that say which sender's which message a packet is: the position, then the number, big-endian.
    private static func header(_ index: Int, _ counter: Int) -> [UInt8] { [UInt8(index & 255), UInt8(counter >> 8 & 255), UInt8(counter & 255)] }

    /// An opened packet: the message, its signature, SHA-256 of what it signs, and the raw 4th field. Not checked yet.
    public struct Opened: Sendable {
        public let message: Message
        public let signature: Data
        public let digest: Data
        public let extra: Data?
        /// The message key that opened it, if one did.
        public var leaf: Leaf? = nil
        /// Names what a signature check of this packet is about: its id, and what it signs together with the signature.
        /// Packets that share an id differ in it, unless they are the same signed message sealed again (`KeyWait`).
        public var key: String {
            var h = SHA256()
            h.update(data: digest); h.update(data: signature)
            return message.id + ":" + h.finalize().prefix(16).map { String(format: "%02x", $0) }.joined()
        }
        /// Names the message this packet carries: its id and what was signed, without the signature. The same signed
        /// message sealed again has the same mark, and so has one whose signature was rewritten (every ECDSA signature
        /// has a twin that checks too): a chat shows it once, however many packets bring it (`StoreCap.name`).
        public var mark: String { String(message.id.prefix(16)) + ":" + Hex.encode(Data(digest.prefix(8))) }
    }

    private func headerMask(_ iv: Data) -> [UInt8] { Array(HMAC<SHA256>.authenticationCode(for: Data("darkproof-header-v1".utf8) + iv, using: key)) }

    /// Which sender's which message a packet says it is (spec "Message keys"): 3 bytes after the IV, readable with this key.
    public func header(_ p: Packet) -> (index: Int, counter: Int)? {
        guard p.cipher.count >= 12 + 3 + 16 else { return nil }
        let c = [UInt8](p.cipher), m = headerMask(Data(c[0..<12]))
        return (Int(c[12] ^ m[0]), Int(c[13] ^ m[1]) << 8 | Int(c[14] ^ m[2]))
    }

    /// Seals a message with its own key `mk`: message `counter` of the sender at `index` in the epoch's member list.
    public func seal(messageKey mk: Data, index: Int, counter: Int, id: String, ts: Int64, sender: String, name: String, text: String, photo: Data? = nil,
                     iv: Data? = nil, pad: Pad = .size, sign: (Data) throws -> Data) throws -> Data {
        var body = Data()
        var fields = [sender, name, text].map { Data($0.utf8) }
        if let photo {
            guard photo.count <= Photo.maxBytes else { throw GroupCryptoError.fieldTooLong }
            fields.append(Data([Photo.jpeg]) + photo)
        }
        for b in fields {
            guard b.count <= 0xFFFF else { throw GroupCryptoError.fieldTooLong }
            body.append(UInt8(b.count >> 8)); body.append(UInt8(b.count & 0xFF)); body.append(b)
        }
        body.append(Data(count: Packet.padding(Packet.overhead + 3 + body.count, pad)))
        let sig = try sign(signed(index: index, counter: counter, id: id, ts: ts, body: body))
        guard sig.count == 64 else { throw GroupCryptoError.badSignature }
        if let iv, iv.count != 12 { throw GroupCryptoError.badIv }
        let nonce = try iv.map { try AES.GCM.Nonce(data: $0) } ?? AES.GCM.Nonce()
        let h = GroupCrypto.header(index, counter)
        let box = try AES.GCM.seal(sig + body, using: SymmetricKey(data: mk), nonce: nonce, authenticating: GroupCrypto.aad(id, ts) + Data(h))
        let ivData = Data(nonce), m = headerMask(ivData)
        return ivData + Data([h[0] ^ m[0], h[1] ^ m[1], h[2] ^ m[2]]) + box.ciphertext + box.tag
    }

    /// Opens a message sealed with its own key. Its time is taken from the blurred header, or `at` when the packet is local.
    public func open(messageKey mk: Data, index: Int, counter: Int, _ p: Packet, at: Int64? = nil) -> Opened? {
        guard p.cipher.count >= 12 + 3 + 16 else { return nil }
        let ts = at ?? realTime(p.ts, p.cipher)
        let body = Data(p.cipher.dropFirst(15))
        guard let n = try? AES.GCM.Nonce(data: Data(p.cipher.prefix(12))), let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: body.dropLast(16), tag: body.suffix(16)),
              let plain = try? AES.GCM.open(box, using: SymmetricKey(data: mk), authenticating: GroupCrypto.aad(p.id, ts) + Data(GroupCrypto.header(index, counter))) else { return nil }
        return parsed(p.id, ts, plain) { self.signed(index: index, counter: counter, id: p.id, ts: ts, body: $0) }
    }

    /// `covered`: what the signature covers, given the body; nil for a packet sealed with this key itself.
    private func parsed(_ id: String, _ ts: Int64, _ plain: Data, covered: ((Data) -> Data)? = nil) -> Opened? {
        guard plain.count >= 64 + 6 else { return nil }
        let body = Data(plain.dropFirst(64))
        var r = FieldReader(bytes: [UInt8](body))
        guard let sender = r.next(), let name = r.next(), let text = r.next() else { return nil }
        let extra = r.nextBytes().flatMap { $0.isEmpty ? nil : $0 } // padding reads as an empty field
        var photo: Data?
        if let a = extra, a.first == Photo.jpeg, a.count > 1, a.count - 1 <= Photo.maxBytes { photo = Data(a.dropFirst()) }
        let m = Message(id: id, ts: ts, sender: sender, name: name, text: text, photo: photo) // other bytes are ignored
        return Opened(message: m, signature: Data(plain.prefix(64)), digest: Data(SHA256.hash(data: covered?(body) ?? signed(id: id, ts: ts, body: body))),
                      extra: extra.map { Data($0) })
    }

    /// HKDF-SHA256 of the group key, no salt, info "darkproof-receipt-v1", 32 bytes.
    public static func deriveReceiptKey(_ groupKey: Data) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: groupKey), info: Data("darkproof-receipt-v1".utf8),
                               outputByteCount: 32).withUnsafeBytes { Data($0) }
    }

    private static let cacheLock = NSLock()
    nonisolated(unsafe) private static var cache: [String: Data] = [:] // guarded by cacheLock

    /// scrypt (N 32768, r 8, p 1) over the UTF-8 bytes of the NFC-normalized group code. Each code is derived once
    /// (it takes 32 MiB and tens of milliseconds); then it comes from memory.
    public static func deriveKey(_ code: String) -> Data {
        let pw = code.precomposedStringWithCanonicalMapping
        if let k = cacheLock.withLock({ cache[pw] }) { return k }
        let k = Scrypt.derive(password: Data(pw.utf8), salt: Data("darkproof-group-v2".utf8), n: 32768, r: 8, p: 1, length: 32)
        cacheLock.withLock { cache[pw] = k }
        return k
    }

    /// Seals a signed packet: `sign` gets the signed message and returns r ‖ s. `photo` or `extra` is the 4th field.
    /// Returns IV (12) + ciphertext + tag (16). `iv` is random in normal use; tests pass a fixed one. Zero bytes after the
    /// fields pad the packet (`pad`): they are encrypted and signed, and readers ignore them, so relays can't tell a
    /// short message from a long one or count a group's members from the size of a new key.
    public func seal(id: String, ts: Int64, sender: String, name: String, text: String, photo: Data? = nil, extra: Data? = nil,
                     iv: Data? = nil, pad: Pad = .size, sign: (Data) throws -> Data) throws -> Data {
        var body = Data()
        var fields = [sender, name, text].map { Data($0.utf8) }
        if let photo {
            guard photo.count <= Photo.maxBytes else { throw GroupCryptoError.fieldTooLong }
            fields.append(Data([Photo.jpeg]) + photo)
        } else if let extra { fields.append(extra) }
        for b in fields {
            guard b.count <= 0xFFFF else { throw GroupCryptoError.fieldTooLong }
            body.append(UInt8(b.count >> 8)); body.append(UInt8(b.count & 0xFF)); body.append(b)
        }
        body.append(Data(count: Packet.padding(Packet.overhead + body.count, pad)))
        let sig = try sign(signed(id: id, ts: ts, body: body))
        guard sig.count == 64 else { throw GroupCryptoError.badSignature }
        if let iv, iv.count != 12 { throw GroupCryptoError.badIv }
        let nonce = try iv.map { try AES.GCM.Nonce(data: $0) } ?? AES.GCM.Nonce()
        let box = try AES.GCM.seal(sig + body, using: key, nonce: nonce, authenticating: GroupCrypto.aad(id, ts))
        return box.combined! // never nil with a 12-byte nonce
    }

    public static let timeWindow: Int64 = 1 << 20 // ms, about 17 minutes

    private func timeMask(_ cipher: Data) -> Int64 {
        var iv = Data(cipher.prefix(12)); iv.append(Data(count: 12 - iv.count))
        let m = Array(HMAC<SHA256>.authenticationCode(for: Data("darkproof-time-v1".utf8) + iv, using: key))
        return (Int64(m[0]) << 16 | Int64(m[1]) << 8 | Int64(m[2])) & (Self.timeWindow - 1)
    }

    /// The time to put in the clear header of a packet sealed at `ts` (spec "Times"): up to 35 minutes back, and only this key can tell the real one.
    public func hideTime(_ ts: Int64, _ cipher: Data) -> Int64 { (ts & ~(Self.timeWindow - 1)) - Self.timeWindow + ((ts & (Self.timeWindow - 1)) ^ timeMask(cipher)) }
    private func realTime(_ wire: Int64, _ cipher: Data) -> Int64 { (wire & ~(Self.timeWindow - 1)) + Self.timeWindow + ((wire & (Self.timeWindow - 1)) ^ timeMask(cipher)) }

    /// nil if the packet was sealed with another key or was tampered with. The signature is not checked here. A
    /// packet's `Message.ts` is the real time; a packet whose header wasn't blurred (test vectors) opens too.
    public func openSigned(_ p: Packet) -> Opened? { openAt(p, realTime(p.ts, p.cipher)) ?? openAt(p, p.ts) }

    private func openAt(_ p: Packet, _ ts: Int64) -> Opened? {
        guard let box = try? AES.GCM.SealedBox(combined: p.cipher),
              let plain = try? AES.GCM.open(box, using: key, authenticating: GroupCrypto.aad(p.id, ts)) else { return nil }
        return parsed(p.id, ts, plain)
    }

    /// The message without checking its signature: tests and debug tools only.
    public func open(_ p: Packet) -> Message? { openSigned(p)?.message }

    private static func aad(_ id: String, _ ts: Int64) -> Data { Data("\(id)|\(ts)".utf8) }
}

/// Reads text fields: 2-byte big-endian length, then standard UTF-8.
private struct FieldReader {
    let bytes: [UInt8]
    var i = 0
    mutating func next() -> String? { nextBytes().map { String(decoding: $0, as: UTF8.self) } }

    mutating func nextBytes() -> [UInt8]? {
        guard i + 2 <= bytes.count else { return nil }
        let n = Int(bytes[i]) << 8 | Int(bytes[i + 1])
        guard i + 2 + n <= bytes.count else { return nil }
        defer { i += 2 + n }
        return Array(bytes[(i + 2)..<(i + 2 + n)])
    }
}
