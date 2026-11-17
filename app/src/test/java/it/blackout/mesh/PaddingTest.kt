package it.blackout.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Spec "Padding": relays and anyone reading them see only a few packet sizes. The iPhone tests use the same table. */
class PaddingTest {
    private val crypto = GroupCrypto.fromSecret(ByteArray(32) { 7 })
    private val id = "0123456789abcdef"
    private val member = "aabbccddeeff0011"

    private fun packet(text: String, photo: ByteArray? = null, extra: ByteArray? = null, pad: Pad = Pad.SIZE) =
        Packet(id, 1_000L, 16, crypto.seal(id, 1_000L, member, "Ann", text, photo, extra, pad = pad) { TestKeys.sign(it) })

    @Test fun thePaddingAmountsAreTheSameOnBothPlatforms() {
        for ((size, expected) in listOf(1 to 162, 163 to 0, 164 to 69, 233 to 0, 234 to 278, 512 to 0, 513 to 511, 1024 to 0,
            1025 to 1023, 4097 to 4095, 8193 to 7825, 16018 to 0, 16019 to 0))
            assertEquals("size $size", expected, Packet.padding(size, Pad.SIZE))
        assertEquals(15_018, Packet.padding(1000, Pad.FULL)); assertEquals(0, Packet.padding(16_018, Pad.FULL))
        assertEquals(0, Packet.padding(1000, Pad.NONE))
    }

    @Test fun messagesOfDifferentLengthsAreTheSameSize() {
        assertEquals(setOf(163), (0..20).map { packet("x".repeat(it)).encode().size }.toSet())
        assertEquals(setOf(512), (200..300).map { packet("x".repeat(it)).encode().size }.toSet())
    }

    @Test fun everySizeIsOneOfTheListedSizes() {
        for (n in listOf(0, 50, 100, 150, 400, 900, 2000, 3900, 7000, 12_000))
            assertTrue("text of $n", packet("y".repeat(n)).encode().size in Packet.SIZES)
    }

    @Test fun aPaddedPacketOpensAndItsSignatureChecks() {
        val o = crypto.openSigned(packet("hello"))!!
        assertEquals("hello", o.message.text); assertNull(o.extra); assertNull(o.message.photo)
        assertTrue(P256.verify(TestKeys.pair.public, o.digest, o.signature))
    }

    @Test fun oneByteOfPaddingIsIgnored() {
        // 110 overhead + 2+16 + 2+3 + 2+n = 163 - 1 when n = 27: one byte of padding, too short to read as a field.
        val p = packet("x".repeat(27))
        assertEquals(163, p.encode().size)
        val o = crypto.openSigned(p)!!
        assertEquals(27, o.message.text.length); assertNull(o.extra)
    }

    @Test fun theFourthFieldSurvivesPadding() {
        val extra = ByteArray(99) { 2 }; val photo = ByteArray(5_000) { 3 }
        assertArrayEquals(extra, crypto.openSigned(packet("", extra = extra))!!.extra)
        val withPhoto = packet("cap", photo = photo)
        assertEquals(8192, withPhoto.encode().size)
        assertArrayEquals(photo, crypto.openSigned(withPhoto)!!.message.photo)
    }

    @Test fun shortPacketsStillFitTheRadios() {
        assertTrue(MeshCore.fits(packet("I'm safe"))); assertTrue(Meshtastic.fits(packet("x".repeat(70))))
    }

    @Test fun fullPaddingIsAlwaysTheLargestSize() {
        for (n in listOf(0, 500, 9000)) assertEquals(16_018, packet("z".repeat(n), pad = Pad.FULL).encode().size)
    }

    @Test fun anUnpaddedPacketStillOpens() {
        assertEquals("old", crypto.openSigned(packet("old", pad = Pad.NONE))!!.message.text)
    }
}
