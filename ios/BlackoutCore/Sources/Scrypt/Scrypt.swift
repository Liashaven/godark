import Foundation
import CryptoKit

/// scrypt (RFC 7914), the memory-hard step that turns a group code into the group key (spec/FORMAT.md,
/// "Encryption"). Memory-hard means each guess of a code costs an attacker 32 MiB and real time, not just CPU.
public enum Scrypt {
    private static let lock = NSLock() // one derivation at a time, so at most one 32 MiB table is alive

    public static func derive(password: Data, salt: Data, n: Int, r: Int, p: Int, length: Int) -> Data {
        precondition(n > 1 && n & (n - 1) == 0 && r > 0 && p > 0, "bad scrypt parameters")
        lock.lock(); defer { lock.unlock() }
        let words = 32 * r // 32-bit words in one 128·r-byte block
        var b = pbkdf2(password, salt, length: p * 128 * r)
        var x = [UInt32](repeating: 0, count: words)
        var y = [UInt32](repeating: 0, count: words)
        var v = [UInt32](repeating: 0, count: words * n)
        for i in 0..<p {
            b.withUnsafeBytes { raw in
                for k in 0..<words { x[k] = UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: (i * words + k) * 4, as: UInt32.self)) }
            }
            x.withUnsafeMutableBufferPointer { xp in
                y.withUnsafeMutableBufferPointer { yp in
                    v.withUnsafeMutableBufferPointer { vp in
                        for j in 0..<n {
                            (vp.baseAddress! + j * words).update(from: xp.baseAddress!, count: words)
                            blockMix(xp, yp, r)
                        }
                        let mask = UInt32(n - 1)
                        for _ in 0..<n {
                            let j = Int(xp[(2 * r - 1) * 16] & mask)
                            let row = vp.baseAddress! + j * words
                            for k in 0..<words { xp[k] ^= row[k] }
                            blockMix(xp, yp, r)
                        }
                    }
                }
            }
            b.withUnsafeMutableBytes { raw in
                for k in 0..<words { raw.storeBytes(of: x[k].littleEndian, toByteOffset: (i * words + k) * 4, as: UInt32.self) }
            }
        }
        return pbkdf2(password, b, length: length)
    }

    /// BlockMix with Salsa20/8 (RFC 7914 §4): [b] is replaced by the result; [t] is scratch space of the same size.
    private static func blockMix(_ b: UnsafeMutableBufferPointer<UInt32>, _ t: UnsafeMutableBufferPointer<UInt32>, _ r: Int) {
        var x = [UInt32](repeating: 0, count: 16)
        for k in 0..<16 { x[k] = b[(2 * r - 1) * 16 + k] }
        for i in 0..<(2 * r) {
            for k in 0..<16 { x[k] ^= b[i * 16 + k] }
            salsa8(&x)
            // Even blocks go to the first half, odd ones to the second.
            let out = (i % 2 == 0 ? i / 2 : r + i / 2) * 16
            for k in 0..<16 { t[out + k] = x[k] }
        }
        b.baseAddress!.update(from: t.baseAddress!, count: 32 * r)
    }

    private static func salsa8(_ b: inout [UInt32]) {
        var x = b
        @inline(__always) func rotl(_ a: UInt32, _ n: UInt32) -> UInt32 { (a << n) | (a >> (32 - n)) }
        for _ in 0..<4 {
            x[4] ^= rotl(x[0] &+ x[12], 7);  x[8] ^= rotl(x[4] &+ x[0], 9)
            x[12] ^= rotl(x[8] &+ x[4], 13); x[0] ^= rotl(x[12] &+ x[8], 18)
            x[9] ^= rotl(x[5] &+ x[1], 7);   x[13] ^= rotl(x[9] &+ x[5], 9)
            x[1] ^= rotl(x[13] &+ x[9], 13); x[5] ^= rotl(x[1] &+ x[13], 18)
            x[14] ^= rotl(x[10] &+ x[6], 7); x[2] ^= rotl(x[14] &+ x[10], 9)
            x[6] ^= rotl(x[2] &+ x[14], 13); x[10] ^= rotl(x[6] &+ x[2], 18)
            x[3] ^= rotl(x[15] &+ x[11], 7); x[7] ^= rotl(x[3] &+ x[15], 9)
            x[11] ^= rotl(x[7] &+ x[3], 13); x[15] ^= rotl(x[11] &+ x[7], 18)
            x[1] ^= rotl(x[0] &+ x[3], 7);   x[2] ^= rotl(x[1] &+ x[0], 9)
            x[3] ^= rotl(x[2] &+ x[1], 13);  x[0] ^= rotl(x[3] &+ x[2], 18)
            x[6] ^= rotl(x[5] &+ x[4], 7);   x[7] ^= rotl(x[6] &+ x[5], 9)
            x[4] ^= rotl(x[7] &+ x[6], 13);  x[5] ^= rotl(x[4] &+ x[7], 18)
            x[11] ^= rotl(x[10] &+ x[9], 7); x[8] ^= rotl(x[11] &+ x[10], 9)
            x[9] ^= rotl(x[8] &+ x[11], 13); x[10] ^= rotl(x[9] &+ x[8], 18)
            x[12] ^= rotl(x[15] &+ x[14], 7); x[13] ^= rotl(x[12] &+ x[15], 9)
            x[14] ^= rotl(x[13] &+ x[12], 13); x[15] ^= rotl(x[14] &+ x[13], 18)
        }
        for i in 0..<16 { b[i] = b[i] &+ x[i] }
    }

    /// PBKDF2-HMAC-SHA256 with one iteration, as scrypt uses it.
    static func pbkdf2(_ password: Data, _ salt: Data, length: Int) -> Data {
        let key = SymmetricKey(data: password)
        var out = Data(capacity: length)
        var block: UInt32 = 1
        while out.count < length {
            var msg = salt
            msg.append(contentsOf: [UInt8(block >> 24), UInt8(block >> 16 & 0xff), UInt8(block >> 8 & 0xff), UInt8(block & 0xff)])
            out.append(contentsOf: HMAC<SHA256>.authenticationCode(for: msg, using: key))
            block += 1
        }
        return out.prefix(length)
    }
}
