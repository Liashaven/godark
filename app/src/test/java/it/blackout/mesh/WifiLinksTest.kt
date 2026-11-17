package it.blackout.mesh

import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/** Runs the Wi-Fi network links over real loopback TCP sockets, wired to real MeshRouter and GroupCrypto. */
class WifiLinksTest {
    private class Node(code: String, id: String) {
        val crypto = GroupCrypto(code)
        val got = CopyOnWriteArrayList<Packet>()
        lateinit var router: MeshRouter
        val wifi = WifiLinks(id, { router }, {})
        init { router = MeshRouter({ peer, p -> wifi.send(peer, p) }, { got += it }) }
        fun say(text: String): Packet {
            val id = Packet.newId(); val ts = System.currentTimeMillis()
            return Packet(id, ts, 16, crypto.seal(id, ts, "dev-$text", "Node", text)).also(router::publish)
        }
    }
    private val nodes = ArrayList<Node>()
    private fun node(code: String, id: String) = Node(code, id).also { nodes += it }
    @After fun tearDown() = nodes.forEach { it.wifi.stop() }

    private fun waitFor(what: String, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + 15_000
        while (!cond()) { if (System.currentTimeMillis() > end) fail("timed out: $what"); Thread.sleep(20) }
    }

    @Test fun relaysAcrossTcpChainAndOnlyGroupCanRead() {
        val a = node("group-code", "node-a"); val relay = node("other-code", "node-r"); val c = node("group-code", "node-c")
        val pa = a.wifi.listen(0); val pr = relay.wifi.listen(0)
        relay.wifi.connectManually("127.0.0.1", pa); c.wifi.connectManually("127.0.0.1", pr)
        waitFor("links") { a.wifi.linkCount() == 1 && relay.wifi.linkCount() == 2 && c.wifi.linkCount() == 1 }
        assertEquals(setOf("node-r"), a.wifi.nodes())                // the HELLO tells who is on the other end

        val sent = a.say("hello over wi-fi")
        waitFor("delivery to c") { c.got.isNotEmpty() }
        assertEquals("hello over wi-fi", c.crypto.open(c.got.single())!!.text)
        assertEquals(sent.id, relay.got.single().id)                 // the relay stored and forwarded it...
        assertNull(relay.crypto.open(relay.got.single()))            // ...but cannot read it
        assertTrue(a.got.isEmpty())                                  // no echo back to the sender

        val reply = c.say("reply")
        waitFor("reply to a") { a.got.isNotEmpty() }
        assertEquals(reply.id, a.got.single().id)
    }

    @Test fun manualAddressRetriesUntilListenerAppearsThenDeliversStoredMessage() {
        val a = node("group-code", "node-a"); val b = node("group-code", "node-b")
        val port = ServerSocket(0).use { it.localPort }
        b.wifi.connectManually("127.0.0.1", port)                      // nothing listening yet: first attempt fails
        a.say("written while offline")
        waitFor("retrying") { b.wifi.statusLine().contains("retrying") }
        a.wifi.listen(port)
        waitFor("delivery after redial") { b.got.isNotEmpty() }
        assertEquals("written while offline", b.crypto.open(b.got.single())!!.text)
    }

    @Test fun aNewLinkFromTheSameNodeReplacesTheOld() {
        val a = node("group-code", "node-a"); val b = node("group-code", "node-b")
        val port = a.wifi.listen(0)
        b.wifi.dial("127.0.0.1", port)
        waitFor("first link") { a.wifi.linkCount() == 1 }
        b.wifi.dial("127.0.0.1", port)                                 // e.g. b restarted and dialed again
        waitFor("second dial handled") { b.wifi.linkCount() == 2 || a.router.peerCount() == 1 }
        Thread.sleep(300)
        waitFor("one link left") { a.wifi.linkCount() == 1 && a.router.peerCount() == 1 }
        val sent = b.say("after reconnect")
        waitFor("delivery") { a.got.any { it.id == sent.id } }
    }

    /** Both phones dial each other at once (e.g. both typed the other's address): both keep the link "node-a" dialed. */
    @Test fun dialingEachOtherAtOnceLeavesOneLink() {
        val a = node("group-code", "node-a"); val b = node("group-code", "node-b")
        val pa = a.wifi.listen(0); val pb = b.wifi.listen(0)
        a.wifi.dial("127.0.0.1", pb); b.wifi.dial("127.0.0.1", pa)
        waitFor("one link each") { a.wifi.linkCount() == 1 && b.wifi.linkCount() == 1 && a.router.peerCount() == 1 && b.router.peerCount() == 1 }
        Thread.sleep(500)
        assertEquals(1, a.wifi.linkCount()); assertEquals(1, b.wifi.linkCount())
        val sent = b.say("over the one link left")
        waitFor("delivery") { a.got.any { it.id == sent.id } }
    }

    @Test fun linksWithoutHelloOrToItselfAreClosed() {
        val a = node("group-code", "node-a")
        val port = a.wifi.listen(0)
        Socket("127.0.0.1", port).use { s ->                         // a packet frame instead of a HELLO
            val out = DataOutputStream(s.getOutputStream()); out.writeInt(3); out.write(byteArrayOf(1, 2, 3)); out.flush()
            val inp = DataInputStream(s.getInputStream())
            inp.readFully(ByteArray(inp.readInt()))                   // a's own HELLO comes first...
            assertEquals(-1, inp.read())                              // ...then a closes the link
        }
        Socket("127.0.0.1", port).use { s ->                         // a HELLO with a's own node id
            val hello = "DPW1node-a".toByteArray()
            val out = DataOutputStream(s.getOutputStream()); out.writeInt(hello.size); out.write(hello); out.flush()
            val inp = DataInputStream(s.getInputStream())
            inp.readFully(ByteArray(inp.readInt()))
            assertEquals(-1, inp.read())
        }
        assertEquals(0, a.wifi.linkCount())
    }

    /**
     * A device at another address on the network sends a HELLO with node-x's id and then stays idle. When the real link
     * to node-x dropped, that link stood in for node-x, and node-a never dialed the address its user had typed again
     * (audit of 2026-11). The other address is 127.0.0.2 where the computer has it, else the IPv6 loopback.
     */
    @Test fun aLinkThatOnlyClaimsAPhonesIdDoesNotStopThisPhoneFromDialingIt() {
        val a = node("group-code", "node-a"); val x = node("group-code", "node-x")
        val pa = a.wifi.listen(0); val px = x.wifi.listen(0)
        a.wifi.connectManually("127.0.0.1", px)
        waitFor("real link") { a.wifi.linkCount() == 1 && x.wifi.linkCount() == 1 }
        assertTrue(a.wifi.linkedAt("node-x", "127.0.0.1"))

        val claim = listOf("127.0.0.2" to "127.0.0.1", "::1" to "::1").firstNotNullOfOrNull { (from, to) ->
            val s = Socket()
            try { s.bind(java.net.InetSocketAddress(java.net.InetAddress.getByName(from), 0)); s.connect(java.net.InetSocketAddress(to, pa), 5_000); s }
            catch (_: java.io.IOException) { s.close(); null }
        }
        org.junit.Assume.assumeTrue("this computer has no second loopback address", claim != null)
        claim!!.use { s ->
            val inp = DataInputStream(s.getInputStream()); val out = DataOutputStream(s.getOutputStream())
            inp.readFully(ByteArray(inp.readInt()))                   // node-a's HELLO
            val hello = "DPW1node-x".toByteArray()
            out.writeInt(hello.size); out.write(hello); out.flush()   // "I am node-x", then nothing more
            waitFor("the claiming link is taken, beside the real one") { a.wifi.linkCount() == 2 }

            x.wifi.stop()                                             // the real link drops...
            waitFor("real link gone") { a.wifi.linkCount() == 1 && x.wifi.linkCount() == 0 && x.wifi.port == 0 }
            assertEquals(setOf("node-x"), a.wifi.nodes())            // the claim is all that is left under that id
            assertFalse(a.wifi.linkedAt("node-x", "127.0.0.1"))      // and it doesn't count for the typed address
            waitFor("node-x listens again on its port") { x.wifi.listen(px) == px } // ...and node-x is back
            val sent = a.say("while someone claims to be node-x")
            waitFor("node-a dialed the typed address again") { x.wifi.linkCount() == 1 && x.got.any { it.id == sent.id } }
            assertEquals(2, a.wifi.linkCount())                      // the idle link is still there, and stopped nothing
            Thread.sleep(6_000)                                       // one more redial period: the real link is counted, so no third link
            assertEquals(2, a.wifi.linkCount()); assertEquals(1, x.wifi.linkCount())
        }
    }

    @Test fun stopClosesEverything() {
        val a = node("group-code", "node-a"); val b = node("group-code", "node-b")
        b.wifi.connectManually("127.0.0.1", a.wifi.listen(0))
        waitFor("link") { a.wifi.linkCount() == 1 && b.wifi.linkCount() == 1 }
        a.wifi.stop()
        waitFor("links closed") { a.wifi.linkCount() == 0 && b.wifi.linkCount() == 0 && a.wifi.port == 0 }
        assertEquals(0, a.router.peerCount())
    }
}
