package it.blackout.mesh

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * scrypt (RFC 7914), the memory-hard step that turns a group code into the group key (spec/FORMAT.md,
 * "Encryption"). Memory-hard means each guess of a code costs an attacker 32 MiB and real time, not just CPU.
 * The same code as ios/BlackoutCore/Sources/Scrypt/Scrypt.swift.
 */
object Scrypt {
    /** One derivation at a time, so at most one 32 MiB table is alive. */
    @Synchronized
    fun derive(password: ByteArray, salt: ByteArray, n: Int, r: Int, p: Int, length: Int): ByteArray {
        require(n > 1 && n and (n - 1) == 0 && r > 0 && p > 0) { "bad scrypt parameters" }
        val words = 32 * r // 32-bit words in one 128·r-byte block
        val b = pbkdf2(password, salt, p * 128 * r)
        val x = IntArray(words); val t = IntArray(words); val v = IntArray(words * n); val s = IntArray(16); val w = IntArray(16)
        for (i in 0 until p) {
            for (k in 0 until words) x[k] = le(b, (i * words + k) * 4)
            for (j in 0 until n) { System.arraycopy(x, 0, v, j * words, words); blockMix(x, t, r, s, w) }
            for (c in 0 until n) {
                val j = x[(2 * r - 1) * 16] and (n - 1)
                val row = j * words
                for (k in 0 until words) x[k] = x[k] xor v[row + k]
                blockMix(x, t, r, s, w)
            }
            for (k in 0 until words) { val o = (i * words + k) * 4; val q = x[k]
                b[o] = q.toByte(); b[o + 1] = (q ushr 8).toByte(); b[o + 2] = (q ushr 16).toByte(); b[o + 3] = (q ushr 24).toByte() }
        }
        return pbkdf2(password, b, length)
    }

    private fun le(b: ByteArray, o: Int) =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    /** BlockMix with Salsa20/8 (RFC 7914 §4): [b] is replaced by the result; [t], [x] and [w] are scratch space. */
    private fun blockMix(b: IntArray, t: IntArray, r: Int, x: IntArray, w: IntArray) {
        System.arraycopy(b, (2 * r - 1) * 16, x, 0, 16)
        for (i in 0 until 2 * r) {
            for (k in 0 until 16) x[k] = x[k] xor b[i * 16 + k]
            salsa8(x, w)
            System.arraycopy(x, 0, t, (if (i % 2 == 0) i / 2 else r + i / 2) * 16, 16) // even blocks first, then odd
        }
        System.arraycopy(t, 0, b, 0, 32 * r)
    }

    private fun salsa8(b: IntArray, x: IntArray) {
        System.arraycopy(b, 0, x, 0, 16)
        repeat(4) {
            x[4] = x[4] xor Integer.rotateLeft(x[0] + x[12], 7); x[8] = x[8] xor Integer.rotateLeft(x[4] + x[0], 9)
            x[12] = x[12] xor Integer.rotateLeft(x[8] + x[4], 13); x[0] = x[0] xor Integer.rotateLeft(x[12] + x[8], 18)
            x[9] = x[9] xor Integer.rotateLeft(x[5] + x[1], 7); x[13] = x[13] xor Integer.rotateLeft(x[9] + x[5], 9)
            x[1] = x[1] xor Integer.rotateLeft(x[13] + x[9], 13); x[5] = x[5] xor Integer.rotateLeft(x[1] + x[13], 18)
            x[14] = x[14] xor Integer.rotateLeft(x[10] + x[6], 7); x[2] = x[2] xor Integer.rotateLeft(x[14] + x[10], 9)
            x[6] = x[6] xor Integer.rotateLeft(x[2] + x[14], 13); x[10] = x[10] xor Integer.rotateLeft(x[6] + x[2], 18)
            x[3] = x[3] xor Integer.rotateLeft(x[15] + x[11], 7); x[7] = x[7] xor Integer.rotateLeft(x[3] + x[15], 9)
            x[11] = x[11] xor Integer.rotateLeft(x[7] + x[3], 13); x[15] = x[15] xor Integer.rotateLeft(x[11] + x[7], 18)
            x[1] = x[1] xor Integer.rotateLeft(x[0] + x[3], 7); x[2] = x[2] xor Integer.rotateLeft(x[1] + x[0], 9)
            x[3] = x[3] xor Integer.rotateLeft(x[2] + x[1], 13); x[0] = x[0] xor Integer.rotateLeft(x[3] + x[2], 18)
            x[6] = x[6] xor Integer.rotateLeft(x[5] + x[4], 7); x[7] = x[7] xor Integer.rotateLeft(x[6] + x[5], 9)
            x[4] = x[4] xor Integer.rotateLeft(x[7] + x[6], 13); x[5] = x[5] xor Integer.rotateLeft(x[4] + x[7], 18)
            x[11] = x[11] xor Integer.rotateLeft(x[10] + x[9], 7); x[8] = x[8] xor Integer.rotateLeft(x[11] + x[10], 9)
            x[9] = x[9] xor Integer.rotateLeft(x[8] + x[11], 13); x[10] = x[10] xor Integer.rotateLeft(x[9] + x[8], 18)
            x[12] = x[12] xor Integer.rotateLeft(x[15] + x[14], 7); x[13] = x[13] xor Integer.rotateLeft(x[12] + x[15], 9)
            x[14] = x[14] xor Integer.rotateLeft(x[13] + x[12], 13); x[15] = x[15] xor Integer.rotateLeft(x[14] + x[13], 18)
        }
        for (i in 0 until 16) b[i] += x[i]
    }

    /** PBKDF2-HMAC-SHA256 with one iteration, as scrypt uses it. */
    private fun pbkdf2(password: ByteArray, salt: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // SecretKeySpec refuses an empty key (RFC test vector). HMAC pads keys with zero bytes, so one zero byte is the same key.
        mac.init(SecretKeySpec(password.takeIf { it.isNotEmpty() } ?: ByteArray(1), "HmacSHA256"))
        val out = ByteArray(length)
        var block = 1; var o = 0
        while (o < length) {
            mac.update(salt); mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            val u = mac.doFinal()
            System.arraycopy(u, 0, out, o, minOf(32, length - o)); o += 32; block++
        }
        return out
    }
}
