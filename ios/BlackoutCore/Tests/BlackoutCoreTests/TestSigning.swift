import Foundation
import CryptoKit
@testable import BlackoutCore

/// A throwaway member key for tests that only need packets to be signed by someone (spec "Signatures").
enum TestKeys {
    static let key = P256.Signing.PrivateKey()
    static var pub: Data { key.publicKey.compressedRepresentation }
}

extension GroupCrypto {
    /// seal() signed with `TestKeys`, for tests written before signatures.
    func seal(id: String, ts: Int64, sender: String, name: String, text: String, photo: Data? = nil, iv: Data? = nil) throws -> Data {
        try seal(id: id, ts: ts, sender: sender, name: name, text: text, photo: photo, extra: nil, iv: iv) { try MemberKey.sign(TestKeys.key, $0) }
    }
}
