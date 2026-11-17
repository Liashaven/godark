package it.blackout.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import kotlin.concurrent.thread

/** Blurred times and one Tor circuit per group (spec "Times", "Tor"). The iPhone tests have the same time cases. */
class PrivacyTest {
    private val crypto = GroupCrypto.fromSecret(ByteArray(32) { 7 }); private val id = "0123456789abcdef"; private val real = 1_794_000_123_456L
    private fun sealed(ts: Long = real) = crypto.seal(id, ts, "aabbccddeeff0011", "Ann", "hi") { TestKeys.sign(it) }

    @Test fun theHeaderShowsAnEarlierTimeAndTheKeyGivesTheRealOne() {
        val c = sealed(); val wire = crypto.hideTime(real, c)
        assertTrue(wire < real); assertTrue(real - wire < 2 * GroupCrypto.TIME_WINDOW)
        val o = crypto.openSigned(Packet(id, wire, 16, c))!!
        assertEquals(real, o.message.ts)
        assertTrue(P256.verify(TestKeys.pair.public, o.digest, o.signature))
    }

    @Test fun twoMessagesSentTogetherDontShowIt() {
        val wires = (0 until 20).map { crypto.hideTime(real, sealed()) }.toSet()
        assertTrue("got ${wires.size}", wires.size > 15)
    }

    @Test fun anotherKeyCantOpenIt() {
        val c = sealed(); assertNull(GroupCrypto.fromSecret(ByteArray(32) { 8 }).openSigned(Packet(id, crypto.hideTime(real, c), 16, c)))
    }

    @Test fun changingTheHeaderTimeIsDetected() {
        val c = sealed(); assertNull(crypto.openSigned(Packet(id, crypto.hideTime(real, c) + 1, 16, c)))
    }

    @Test fun anEventIsDatedAtMostSeventeenMinutesBack() {
        for (n in listOf(1_794_000_000L, 1_794_000_513L, 1_794_001_023L)) { val b = Nostr.blurred(n); assertTrue(b <= n); assertTrue(n - b < 1024); assertEquals(0, b % 1024) }
        assertTrue(Nostr.SINCE_MARGIN_S > 1024)
    }

    @Test fun eachUserNameReachesTorAndHostNamesGoThroughIt() {
        val server = ServerSocket(0)
        val seen = java.util.Collections.synchronizedList(ArrayList<Pair<String, String>>())
        val t = thread {
            repeat(2) {
                server.accept().use { s ->
                    val i = java.io.DataInputStream(s.getInputStream()); val o = s.getOutputStream()
                    i.readFully(ByteArray(3)); o.write(byteArrayOf(5, 2))
                    i.readByte(); val user = String(ByteArray(i.readUnsignedByte()).also(i::readFully)); i.readFully(ByteArray(i.readUnsignedByte())); o.write(byteArrayOf(1, 0))
                    i.readFully(ByteArray(4)); val host = String(ByteArray(i.readUnsignedByte()).also(i::readFully)); i.readFully(ByteArray(2))
                    o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    seen += user to host
                }
            }
        }
        for (user in listOf("groupa", "groupb")) {
            val addr = java.net.InetSocketAddress(Socks5.noDns.lookup("relay.example").first(), 443)
            Socks5.factory(server.localPort, user).createSocket().use { it.connect(addr, 5_000) }
        }
        t.join(5_000)
        assertEquals(listOf("groupa" to "relay.example", "groupb" to "relay.example"), seen.toList())
    }

    @Test fun aRefusedConnectionIsAnError() {
        val out = java.io.ByteArrayOutputStream()
        val answer = byteArrayOf(5, 2, 1, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0)
        val failed = runCatching { Socks5.handshake(answer.inputStream(), out, "relay.example", 443, "a") }.isFailure
        assertTrue(failed); assertFalse(out.size() == 0); assertNotEquals(0, out.size())
    }
}
