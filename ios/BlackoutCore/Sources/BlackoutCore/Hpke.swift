import Foundation
import CryptoKit

/// HPKE (RFC 9180), base mode, single shot, with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM: seals a group
/// secret for one member's encryption key (spec/DESIGN-v0.6-groups.md). Written from CryptoKit's primitives because
/// CryptoKit's own HPKE needs iOS 17; the tests check it against that one on the Mac. Same as Android's Hpke.kt.
public enum Hpke {
    static let suiteKem = Data("KEM".utf8) + be16(0x0010)
    static let suite = Data("HPKE".utf8) + be16(0x0010) + be16(0x0001) + be16(0x0002)
    /// Size of the encapsulated key (an uncompressed P-256 point) at the start of every sealed box.
    public static let encSize = 65
    static let pskId = Data("darkproof-mlkem768-v1".utf8)

    /// enc (65 bytes) ‖ ciphertext ‖ tag (16). `ephemeral` is random in normal use; test vectors fix it. `psk`: PSK mode, for `Hybrid`.
    public static func seal(_ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey, info: Data, aad: Data,
                            ephemeral: P256.KeyAgreement.PrivateKey = .init(), psk: Data? = nil) throws -> Data {
        let dh = try ephemeral.sharedSecretFromKeyAgreement(with: recipient).withUnsafeBytes { Data($0) }
        let enc = ephemeral.publicKey.x963Representation
        let (key, nonce) = schedule(sharedSecret(dh, enc + recipient.x963Representation), info, psk)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
        return enc + box.ciphertext + box.tag
    }

    /// The plaintext, or nil if it wasn't sealed for this key (or with this info and aad), or was changed.
    public static func open(_ sealed: Data, with recipient: P256.KeyAgreement.PrivateKey, info: Data, aad: Data, psk: Data? = nil) -> Data? {
        open(sealed, to: recipient.publicKey, agree: { try recipient.sharedSecretFromKeyAgreement(with: $0) }, info: info, aad: aad, psk: psk)
    }

    /// The same, for a private key that never leaves the secure chip: `agree` does the key agreement there.
    public static func open(_ sealed: Data, to recipient: P256.KeyAgreement.PublicKey, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret,
                            info: Data, aad: Data, psk: Data? = nil) -> Data? {
        guard sealed.count >= encSize + 16 else { return nil }
        let enc = Data(sealed.prefix(encSize)), body = Data(sealed.dropFirst(encSize))
        guard let pkE = try? P256.KeyAgreement.PublicKey(x963Representation: enc),
              let dh = try? agree(pkE).withUnsafeBytes({ Data($0) }) else { return nil }
        let (key, nonce) = schedule(sharedSecret(dh, enc + recipient.x963Representation), info, psk)
        guard let n = try? AES.GCM.Nonce(data: nonce),
              let box = try? AES.GCM.SealedBox(nonce: n, ciphertext: body.dropLast(16), tag: body.suffix(16)) else { return nil }
        return try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    /// DHKEM ExtractAndExpand: the KEM shared secret from the DH result and enc ‖ pkR.
    private static func sharedSecret(_ dh: Data, _ kemContext: Data) -> Data {
        let prk = labeledExtract(suiteKem, Data(), "eae_prk", dh)
        return labeledExpand(suiteKem, prk, "shared_secret", kemContext, 32)
    }

    /// The key schedule, base mode or (with `psk`) PSK mode: AEAD key and base nonce; the single message uses sequence number 0.
    private static func schedule(_ shared: Data, _ info: Data, _ psk: Data?) -> (Data, Data) {
        let context = Data([psk == nil ? 0 : 1]) + labeledExtract(suite, Data(), "psk_id_hash", psk == nil ? Data() : pskId) + labeledExtract(suite, Data(), "info_hash", info)
        let secret = labeledExtract(suite, shared, "secret", psk ?? Data())
        return (labeledExpand(suite, secret, "key", context, 32), labeledExpand(suite, secret, "base_nonce", context, 12))
    }

    private static func labeledExtract(_ suite: Data, _ salt: Data, _ label: String, _ ikm: Data) -> Data {
        extract(salt, Data("HPKE-v1".utf8) + suite + Data(label.utf8) + ikm)
    }

    private static func labeledExpand(_ suite: Data, _ prk: Data, _ label: String, _ info: Data, _ length: Int) -> Data {
        expand(prk, be16(UInt16(length)) + Data("HPKE-v1".utf8) + suite + Data(label.utf8) + info, length)
    }

    /// HKDF-Extract (RFC 5869); an empty salt means 32 zero bytes.
    private static func extract(_ salt: Data, _ ikm: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt.isEmpty ? Data(count: 32) : salt)))
    }

    /// HKDF-Expand (RFC 5869).
    private static func expand(_ prk: Data, _ info: Data, _ length: Int) -> Data {
        var out = Data(), t = Data(), i: UInt8 = 1
        while out.count < length {
            t = Data(HMAC<SHA256>.authenticationCode(for: t + info + Data([i]), using: SymmetricKey(data: prk)))
            out += t; i += 1
        }
        return out.prefix(length)
    }

    private static func be16(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
}

/// ML-KEM-768 (FIPS 203), from CryptoKit.
public enum MlKem {
    public static let publicSize = 1184, cipherSize = 1088

    /// A new key: its public half and the 64-byte seed it comes from.
    public static func newKey() -> (pub: Data, seed: Data)? {
        guard let k = try? MLKEM768.PrivateKey.generate() else { return nil }
        return (k.publicKey.rawRepresentation, k.seedRepresentation)
    }

    public static func publicKey(seed: Data) -> Data? {
        guard let k = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil) else { return nil }
        return k.publicKey.rawRepresentation
    }

    /// The cipher and shared secret for this public key, or nil if it isn't a valid one.
    public static func encapsulate(_ pub: Data) -> (cipher: Data, shared: Data)? {
        guard let k = try? MLKEM768.PublicKey(rawRepresentation: pub), let r = try? k.encapsulate() else { return nil }
        return (r.encapsulated, r.sharedSecret.withUnsafeBytes { Data($0) })
    }

    public static func decapsulate(seed: Data, cipher: Data) -> Data? {
        guard let k = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil),
              let s = try? k.decapsulate(cipher) else { return nil }
        return s.withUnsafeBytes { Data($0) }
    }
}

/// A new epoch secret sealed so that breaking it needs both P-256 and ML-KEM-768 (spec "Sealing for one member"): the
/// ML-KEM shared secret is HPKE's pre-shared key (RFC 9180, mode_psk). There is no plain mode: a box without ML-KEM is refused.
public enum Hybrid {
    public enum Failure: Error { case badKey }
    private static let smallest = MlKem.cipherSize + Hpke.encSize + 16

    public static func seal(_ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey, pq: Data, info: Data, aad: Data) throws -> Data {
        guard let kem = MlKem.encapsulate(pq) else { throw Failure.badKey }
        return kem.cipher + (try Hpke.seal(plaintext, to: recipient, info: info, aad: aad, psk: kem.shared))
    }

    /// `seed`: the recipient's ML-KEM key. Nil result: not sealed for these keys, or changed.
    public static func open(_ sealed: Data, to recipient: P256.KeyAgreement.PublicKey, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret,
                            seed: Data?, info: Data, aad: Data) -> Data? {
        guard sealed.count >= smallest, let seed, let shared = MlKem.decapsulate(seed: seed, cipher: Data(sealed.prefix(MlKem.cipherSize))) else { return nil }
        return Hpke.open(Data(sealed.dropFirst(MlKem.cipherSize)), to: recipient, agree: agree, info: info, aad: aad, psk: shared)
    }
}
