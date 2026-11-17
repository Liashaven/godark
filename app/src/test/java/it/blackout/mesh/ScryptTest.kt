package it.blackout.mesh

import org.junit.Assert.assertEquals
import org.junit.Test

/** scrypt against RFC 7914 §12; the group-key parameters are checked in FormatVectorsTest (kind: kdf). */
class ScryptTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test fun rfcVectors() {
        assertEquals("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            hex(Scrypt.derive(ByteArray(0), ByteArray(0), 16, 1, 1, 64)))
        assertEquals("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            hex(Scrypt.derive("password".toByteArray(), "NaCl".toByteArray(), 1024, 8, 16, 64)))
    }

    @Test fun groupKeyTiming() {
        val t = System.nanoTime()
        Scrypt.derive("blackout-test-1".toByteArray(), "darkproof-group-v2".toByteArray(), 32768, 8, 1, 32)
        println("scrypt N=32768 r=8 p=1: ${(System.nanoTime() - t) / 1_000_000} ms")
    }
}
