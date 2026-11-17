package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.security.KeyPair

/** HPKE against the shared vector (kind: hpke), which the iPhone tests check against Apple's own HPKE. */
class HpkeTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val v: Map<String, String> = File("../spec/test-vectors.txt").readText().split(Regex("\n\\s*\n"))
        .map { b -> b.lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { it.substringBefore(": ") to it.substringAfter(": ") } }
        .first { it["kind"] == "hpke" }

    @Test fun sealsAndOpensTheSharedVector() {
        val rPub = P256.fromUncompressed(unhex(v["recipient_public"]!!))!!
        val r = KeyPair(rPub, P256.privateKey(unhex(v["recipient_private"]!!)))
        // The ephemeral public key is the enc at the start of the sealed box.
        val e = KeyPair(P256.fromUncompressed(unhex(v["sealed"]!!).copyOf(Hpke.ENC_SIZE))!!, P256.privateKey(unhex(v["ephemeral_private"]!!)))
        val sealed = Hpke.seal(unhex(v["plaintext"]!!), rPub, unhex(v["info"]!!), unhex(v["aad"]!!), e)
        assertEquals(v["sealed"], hex(sealed))
        assertArrayEquals(unhex(v["plaintext"]!!), Hpke.open(sealed, r, unhex(v["info"]!!), unhex(v["aad"]!!)))
        assertNull(Hpke.open(sealed, r, "other".toByteArray(), unhex(v["aad"]!!)))           // wrong info: no
        assertNull(Hpke.open(sealed, P256.newKeyPair(), unhex(v["info"]!!), unhex(v["aad"]!!))) // wrong key: no
        assertNull(Hpke.open(sealed.copyOf().also { it[70] = (it[70] + 1).toByte() }, r, unhex(v["info"]!!), unhex(v["aad"]!!))) // changed: no
    }

    @Test fun randomRoundTripAndBadPoints() {
        val r = P256.newKeyPair()
        assertArrayEquals("secret".toByteArray(), Hpke.open(Hpke.seal("secret".toByteArray(), r.public, byteArrayOf(1), byteArrayOf(2)), r, byteArrayOf(1), byteArrayOf(2)))
        assertNull(P256.fromUncompressed(ByteArray(65).also { it[0] = 4; it[64] = 1 })) // not on the curve
    }
}
