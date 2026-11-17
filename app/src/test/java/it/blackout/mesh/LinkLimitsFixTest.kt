package it.blackout.mesh

import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CopyOnWriteArrayList

/**
 * What a nearby device can make a phone's local links do (audit of 2026-11): the router's limits count per sender and
 * not per connection, a slow link gets the store in pieces, and the Wi-Fi link places can't be taken by one device.
 * The same router, queue and rule tests are in the iPhone's LinkLimitsFixTests.
 */
class LinkLimitsFixTest {
    private fun id(i: Int) = "%016x".format(i)
    private fun pkt(i: Int, t: Long, n: Int = 1, ttl: Int = 16) = Packet(id(i), t, ttl, ByteArray(n))

    // ---- the router: one allowance per sender, however many links it opens ----

    // Four links from one address, two packets each, emptied an 8-packet store of everything the phone carried.
    @Test fun linksOfOneSenderShareOneShareOfTheStore() {
        val sent = HashSet<String>(); val t = System.currentTimeMillis()
        val r = MeshRouter({ _, p -> sent += p.id }, { }, maxStored = 8)
        r.receive("good", pkt(0xa1, t))
        for (l in 1..4) { r.peerUp("wifi:fake$l#$l", "wifi:@10.0.0.9"); repeat(2) { r.receive("wifi:fake$l#$l", pkt(1000 + l * 10 + it, t)) } }
        // ... and the same device coming back under new link ids
        for (l in 5..30) { r.peerDown("wifi:fake${l - 4}#${l - 4}"); r.peerUp("wifi:fake$l#$l", "wifi:@10.0.0.9"); repeat(2) { r.receive("wifi:fake$l#$l", pkt(1000 + l * 10 + it, t)) } }
        sent.clear(); r.peerUp("new")
        assertTrue("the first link's packet is still here", id(0xa1) in sent)
        assertEquals(8, sent.size)
    }

    // Without an address to go by (Bluetooth addresses are free to change), links are told apart only by their ids.
    // What they bring, all together, still can't push out what this phone wrote.
    @Test fun anyNumberOfLinksCantPushOutThisPhonesOwnPackets() {
        val sent = HashSet<String>(); val t = System.currentTimeMillis()
        val r = MeshRouter({ _, p -> sent += p.id }, { }, maxStored = 8)
        r.publish(pkt(0xa1, t)); r.publish(pkt(0xa2, t))
        for (l in 1..40) repeat(2) { r.receive("ble:$l", pkt(1000 + l * 10 + it, t)) }
        sent.clear(); r.peerUp("new")
        assertTrue("this phone's own packets are still here", id(0xa1) in sent && id(0xa2) in sent)
        assertEquals("and the newest of what the links brought", 8, sent.size)
        assertTrue(id(1000 + 40 * 10 + 1) in sent)
    }

    // The phone's own packets keep at most half against the others: a phone that writes a lot still passes on.
    @Test fun aPhoneThatWritesALotStillCarriesForItsNeighbours() {
        val sent = HashSet<String>(); val t = System.currentTimeMillis()
        val r = MeshRouter({ _, p -> sent += p.id }, { }, maxStored = 8)
        for (i in 1..20) r.publish(pkt(i, t))
        for (l in 1..4) r.receive("ble:$l", pkt(100 + l, t))            // four neighbours, one packet each
        sent.clear(); r.peerUp("new")
        assertTrue((1..4).all { id(100 + it) in sent })
        assertEquals(setOf(17, 18, 19, 20).map(::id).toSet(), sent.filter { it < id(100) }.toSet())
    }

    @Test fun closingALinkDoesNotStartANewMinute() {
        var t = 1_000_000L; val got = ArrayList<String>()
        val r = MeshRouter({ _, _ -> }, { got += it.id }, now = { t }, maxPerMinute = 3)
        r.peerUp("a"); for (i in 1..3) r.receive("a", pkt(i, t))
        r.peerDown("a"); r.peerUp("a"); for (i in 4..6) r.receive("a", pkt(i, t))
        assertEquals("the link came back within its minute", 3, got.size)
        // two links at once from one address, and a third after both closed: one allowance
        r.peerUp("wifi:x#1", "wifi:@10.0.0.9"); r.peerUp("wifi:y#2", "wifi:@10.0.0.9")
        r.receive("wifi:x#1", pkt(11, t)); r.receive("wifi:y#2", pkt(12, t)); r.receive("wifi:x#1", pkt(13, t)); r.receive("wifi:y#2", pkt(14, t))
        r.peerDown("wifi:x#1"); r.peerDown("wifi:y#2"); r.peerUp("wifi:z#3", "wifi:@10.0.0.9"); r.receive("wifi:z#3", pkt(15, t))
        assertEquals(6, got.size)
        r.peerUp("wifi:w#4", "wifi:@10.0.0.7"); r.receive("wifi:w#4", pkt(16, t))
        assertEquals("another address isn't held up", 7, got.size)
        t += 60_000; r.receive("a", pkt(6, t)); r.receive("wifi:z#3", pkt(15, t))
        assertEquals("a minute later both go on", 9, got.size)
    }

    // ---- the router: packets from before a restart aren't this phone's own ----

    @Test fun restoredPacketsGiveWayLikeOneSendersPackets() {
        val sent = HashSet<String>(); val t = System.currentTimeMillis()
        val r = MeshRouter({ _, p -> sent += p.id }, { }, maxStored = 8)
        r.restore((1..8).map { pkt(500 + it, t + 60_000) })              // saved before the restart, dated ahead
        for (i in 1..4) r.receive("good", pkt(0xa0 + i, t))
        sent.clear(); r.peerUp("new")
        assertTrue("all the link brought is kept", (1..4).all { id(0xa0 + it) in sent })
        assertEquals("with the newest from before the restart", (5..8).map { id(500 + it) }.toSet(), sent.filter { it > id(0xff) }.toSet())
        // ...and they don't count as written here: what links bring pushes them out before this phone's own packets
        val own = MeshRouter({ _, p -> sent += p.id }, { }, maxStored = 8)
        own.restore((1..6).map { pkt(500 + it, t) }); own.publish(pkt(0xb1, t))
        for (l in 1..20) own.receive("ble:$l", pkt(2000 + l, t))
        sent.clear(); own.peerUp("new")
        assertTrue(id(0xb1) in sent); assertTrue(sent.none { it in (1..6).map { i -> id(500 + i) } })
    }

    // ---- a slow link takes the store in pieces ----

    /** A Bluetooth link's send queue, drained the way BleLink does: one chunk at a time, reporting the room that opens. */
    private class SlowLink(val name: String) {
        val out = BleProtocol.Outbox(); val reader = BleProtocol.Reader(); val got = ArrayList<Packet>()
        var worst = 0
        lateinit var router: MeshRouter
        fun send(p: Packet) { out.add(BleProtocol.frame(BleProtocol.PACKET, p.encode())); worst = maxOf(worst, out.bytes); freed() }
        private fun freed() { val (b, n) = out.freed(); if (n > 0) router.room(name, b, n) }
        /** Sends up to [chunks] chunks; false when the queue is empty. */
        fun pump(chunks: Int = Int.MAX_VALUE): Boolean {
            repeat(chunks) {
                val c = out.peek(509) ?: return false
                out.commit(); reader.feed(c).forEach { (_, raw) -> got += Packet.decode(raw)!! }
                freed()
            }
            return !out.isEmpty
        }
    }
    private fun slow(maxStored: Int = 500, perMinute: Int = 0): Pair<MeshRouter, SlowLink> {
        val l = SlowLink("ble:1")
        val r = MeshRouter({ peer, p -> if (peer == l.name) l.send(p) }, { }, maxStored = maxStored, maxPerMinute = perMinute)
        l.router = r
        return r to l
    }

    // Sixty-six large packets, stored last, were all a Bluetooth neighbour ever got: the queue dropped the rest.
    @Test fun aSlowLinkGetsTheWholeStoreOldestFirst() {
        val t = System.currentTimeMillis(); val (r, l) = slow()
        for (i in 1..434) r.publish(pkt(i, t, 182))                        // the messages this phone carries
        for (i in 1..66) r.receive("junk", pkt(10_000 + i, t, 16_000))     // a neighbour's large packets, stored last
        r.peerUp(l.name, null, BleProtocol.ROOM_BYTES, BleProtocol.ROOM_PACKETS)
        while (l.pump(50)) { }
        assertEquals((1..434).map(::id) + (1..66).map { id(10_000 + it) }, l.got.map { it.id })
        assertTrue("the queue never went over its limit, so nothing was dropped", l.worst <= BleProtocol.MAX_QUEUE_BYTES)
        assertEquals(15, l.got.first().ttl)
    }

    @Test fun aSlowLinkGetsNewPacketsInTurnAndNothingTwice() {
        val t = System.currentTimeMillis(); val (r, l) = slow()
        for (i in 1..200) r.receive("wifi:a#1", pkt(i, t, 16_000))         // more than the queue holds
        r.receive(l.name, pkt(900, t))                                     // what the link brought itself doesn't go back
        r.peerUp(l.name, null, BleProtocol.ROOM_BYTES, BleProtocol.ROOM_PACKETS)
        l.pump(40)
        r.publish(pkt(901, t)); r.receive("wifi:a#1", pkt(902, t))         // new while the link is still behind
        assertTrue(l.got.none { it.id == id(901) })
        while (l.pump(50)) { }
        assertEquals((1..200).map(::id) + listOf(id(901), id(902)), l.got.map { it.id })
        // caught up: a new packet goes at once, and a link that is no slower than before loses nothing
        r.publish(pkt(903, t)); l.pump()
        assertEquals(id(903), l.got.last().id)
        // a copy with more hops of a packet it has goes again; one it hasn't had yet goes once, with the higher ttl
        val n = l.got.size
        r.receive("wifi:b#2", pkt(904, t, ttl = 3)); l.pump()
        r.receive("wifi:c#3", pkt(904, t, ttl = 9)); l.pump()
        assertEquals(listOf(2, 8), l.got.drop(n).map { it.ttl })
        // a repeated HELLO (BleLink): everything stored goes again, in pieces as before
        val before = l.got.size
        r.peerUp(l.name); while (l.pump(50)) { }
        assertEquals("all but the one it brought itself", 204, l.got.size - before)
        assertTrue(l.worst <= BleProtocol.MAX_QUEUE_BYTES)
        // when the link closes, the router forgets its place
        r.peerDown(l.name); r.publish(pkt(905, t)); r.room(l.name, 1 shl 20, 100)
        assertFalse(l.pump())
    }

    @Test fun theQueueReportsTheRoomThatOpens() {
        val q = BleProtocol.Outbox(maxBytes = 100, maxFrames = 10)
        q.add(BleProtocol.hello("node"), hello = true)
        q.add(BleProtocol.frame(BleProtocol.PACKET, ByteArray(30))); q.add(BleProtocol.frame(BleProtocol.PACKET, ByteArray(40)))
        assertEquals(0 to 0, q.freed())
        while (q.count > 2) { q.peek(20); q.commit() }                    // the HELLO went out: no packet room
        assertEquals(0 to 0, q.freed())
        while (q.count > 1) { q.peek(20); q.commit() }
        assertEquals(30 to 1, q.freed()); assertEquals(0 to 0, q.freed())
        q.add(BleProtocol.frame(BleProtocol.PACKET, ByteArray(60)))        // over the cap: the oldest unsent packet is dropped
        assertEquals(40 to 1, q.freed())
        q.clear(); assertEquals(0 to 0, q.freed())
        assertTrue(BleProtocol.ROOM_BYTES + 3 * BleProtocol.ROOM_PACKETS + 1024 <= BleProtocol.MAX_QUEUE_BYTES)
        assertTrue(BleProtocol.ROOM_PACKETS < BleProtocol.MAX_QUEUE_FRAMES && BleProtocol.ROOM_PACKETS >= 500)
    }

    // ---- Bluetooth: whoever says a phone's node id first doesn't keep that phone out ----

    @Test fun aLaterLinkTheOtherSideDialedStaysBesideTheFirst() {
        val both = BleProtocol.Twin.BOTH_STAY; val new = BleProtocol.Twin.CLOSE_NEW; val old = BleProtocol.Twin.CLOSE_OLD
        fun twin(me: String, them: String, newCentral: Boolean, oldCentral: Boolean, apart: Long, same: Boolean = false) =
            BleProtocol.twin(me, them, newCentral, oldCentral, apart, same)
        // Someone linked first under the real phone's id. When the real phone dials, its link stays: whatever the two
        // ids, and whether the first link was dialed by this phone or by the other side. (It used to be closed.)
        for ((me, them) in listOf("aaaa" to "bbbb", "bbbb" to "aaaa")) for (oldCentral in listOf(true, false)) for (apart in listOf(10_000L, 3_600_000L))
            assertEquals(both, twin(me, them, newCentral = false, oldCentral = oldCentral, apart = apart))
        assertEquals(both, twin("aaaa", "bbbb", false, false, 0))           // two that dialed in at the same moment: neither is closed for the other
        // Over the same radio connection it is the same device: the phone is linked already, as before.
        assertEquals(new, twin("aaaa", "bbbb", false, true, 20_000, same = true))
        // A link this phone dialed to a phone it is linked to already is closed, as before...
        assertEquals(new, twin("aaaa", "bbbb", true, false, 10_000)); assertEquals(new, twin("bbbb", "aaaa", true, true, 10_000))
        assertEquals(old, twin("aaaa", "bbbb", true, true, 500))
        // ...and two phones that dialed each other at the same moment keep the link the smaller id dialed, as before.
        assertEquals(old, twin("aaaa", "bbbb", true, false, 500)); assertEquals(new, twin("aaaa", "bbbb", false, true, 500))
        assertEquals(new, twin("bbbb", "aaaa", true, false, 500)); assertEquals(old, twin("bbbb", "aaaa", false, true, 500))
        // The honest case, the other phone dials 20 s later: here both stay, there the phone closes the one it dialed.
        assertEquals(both, twin("aaaa", "bbbb", false, true, 20_000)); assertEquals(new, twin("bbbb", "aaaa", true, false, 20_000))
    }

    // ---- who gets a place, and which addresses are local ----

    @Test fun oneAddressCantTakeEveryPlace() {
        val room = LinkLimits.ROOM; val full = LinkLimits.FULL
        fun g(held: List<String>, a: String, max: Int = 4, per: Int = 2) = LinkLimits.giveWay(held, a, max, per)
        assertEquals(room, g(emptyList(), "x")); assertEquals(room, g(listOf("x", "y"), "x"))
        assertEquals("its own oldest makes room", 1, g(listOf("y", "x", "x"), "x"))
        assertEquals("the address with the most gives up its oldest", 1, g(listOf("a", "x", "b", "x"), "c"))
        assertEquals(0, g(listOf("a", "x", "a", "x"), "c"))
        assertEquals("nobody holds more than one: the caller decides", full, g(listOf("a", "b", "c", "d"), "e"))
        // 40 connections from one address that say nothing leave room for everyone else
        val held = ArrayList<String>()
        repeat(40) { val i = LinkLimits.giveWay(held, "10.0.0.9", LinkLimits.WAITING, LinkLimits.WAITING_PER_ADDRESS); if (i >= 0) held.removeAt(i); held += "10.0.0.9" }
        assertEquals(LinkLimits.WAITING_PER_ADDRESS, held.size)
        assertEquals(room, LinkLimits.giveWay(held, "10.0.0.7", LinkLimits.WAITING, LinkLimits.WAITING_PER_ADDRESS))
    }

    @Test fun onlyLocalAddressesCountAsTheLocalNetwork() {
        fun a(s: String) = InetAddress.getByName(s).address                 // literals only: nothing is looked up
        for (s in listOf("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.43.1", "169.254.7.7", "fe80::1", "fd12:3456::1", "::ffff:192.168.1.5"))
            assertTrue(s, LinkLimits.local(a(s)))
        for (s in listOf("8.8.8.8", "172.32.0.1", "192.169.1.1", "100.64.0.1", "127.0.0.1", "::1", "::", "0.0.0.0", "2001:4860:4860::8888", "::ffff:8.8.8.8"))
            assertFalse(s, LinkLimits.local(a(s)))
        // a network with public addresses: the same network as this phone's end of the connection
        assertTrue(LinkLimits.local(a("2001:db8:1:2::99"), a("2001:db8:1:2::5"))); assertFalse(LinkLimits.local(a("2001:db8:1:3::99"), a("2001:db8:1:2::5")))
        assertTrue(LinkLimits.local(a("44.1.2.3"), a("44.1.2.200"))); assertFalse(LinkLimits.local(a("44.1.3.3"), a("44.1.2.200")))
        assertFalse(LinkLimits.local(a("127.0.0.1"), a("127.0.0.1")))
        assertFalse(LinkLimits.local(ByteArray(5)))
        assertTrue(WifiLinks.onLan(InetAddress.getByName("192.168.1.7"))); assertFalse(WifiLinks.onLan(InetAddress.getByName("203.0.113.9")))
        assertFalse(WifiLinks.onLan(InetAddress.getByName("127.0.0.1")))
    }

    // ---- Nearby links have their own names ----

    @Test fun aNearbyEndpointCantBeTakenForARadioOrTheRelays() {
        for (name in listOf(LoraLink.PEER, MeshCoreLink.PEER, NostrLink.PEER, "ble:1", "wifi:x#1")) {
            val peer = NearbyPeers.peer(name)
            assertNotEquals(name, peer); assertTrue(NearbyPeers.owns(peer)); assertEquals(name, NearbyPeers.endpoint(peer))
            assertFalse(NostrLink.owns(peer)); assertFalse(peer.startsWith(BleLink.PREFIX)); assertFalse(WifiLinks.owns(peer))
        }
        assertFalse(NearbyPeers.owns(LoraLink.PEER)); assertFalse(NearbyPeers.owns(NostrLink.PEER))
        // what MeshService does for an endpoint with the radio's name no longer takes the radio's place in the router
        val sent = ArrayList<String>(); val t = System.currentTimeMillis()
        val r = MeshRouter({ peer, _ -> sent += peer }, { })
        r.peerUp(LoraLink.PEER); r.peerUp(NearbyPeers.peer(LoraLink.PEER)); r.peerDown(NearbyPeers.peer(LoraLink.PEER))
        assertEquals(1, r.peerCount()); r.publish(pkt(1, t))
        assertEquals(listOf(LoraLink.PEER), sent)
    }

    // ---- Wi-Fi links over loopback ----

    private class Node(id: String, perMinute: Int = 0, local: (InetAddress) -> Boolean = { true }) {
        val got = CopyOnWriteArrayList<Packet>()
        val router: MeshRouter = MeshRouter({ peer, p -> wifi.send(peer, p) }, { got += it }, maxPerMinute = perMinute)
        val wifi: WifiLinks = WifiLinks(id, { router }, {}, local)
    }
    private val nodes = ArrayList<Node>(); private val open = ArrayList<java.io.Closeable>()
    private fun node(id: String, perMinute: Int = 0, local: (InetAddress) -> Boolean = { true }) = Node(id, perMinute, local).also { nodes += it }
    @After fun tearDown() { nodes.forEach { it.wifi.stop() }; open.forEach { runCatching { it.close() } } }
    private fun waitFor(what: String, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + 15_000
        while (!cond()) { if (System.currentTimeMillis() > end) fail("timed out: $what"); Thread.sleep(20) }
    }
    /** A raw client; with [node] it says HELLO, and then it never reads. */
    private fun raw(port: Int, node: String? = null): Socket = Socket("127.0.0.1", port).also { s ->
        open += s
        if (node != null) { val hello = "DPW1$node".toByteArray(); DataOutputStream(s.getOutputStream()).run { writeInt(hello.size); write(hello); flush() } }
    }
    private fun frame(p: Packet): ByteArray = java.io.ByteArrayOutputStream().also { DataOutputStream(it).run { val b = p.encode(); writeInt(b.size); write(b) } }.toByteArray()

    @Test fun aStoppedPhoneCompletesNoDial() {
        val a = node("node-a"); val b = node("node-b")
        val port = a.wifi.listen(0)
        b.wifi.stop(); b.wifi.dial("127.0.0.1", port)
        Thread.sleep(700)
        assertEquals(0, b.wifi.linkCount()); assertEquals(0, b.router.peerCount()); assertEquals(0, a.wifi.linkCount())
        b.wifi.listen(0); b.wifi.dial("127.0.0.1", port)                  // turned on again: it links as before
        waitFor("link after turning on again") { a.wifi.linkCount() == 1 && b.wifi.linkCount() == 1 }
    }

    @Test fun theFullTotalQueueClosesTheLinksThatStoppedReading() {
        val a = node("node-a"); val b = node("node-b")
        val port = a.wifi.listen(0)
        b.wifi.dial("127.0.0.1", port)
        waitFor("b linked") { a.wifi.linkCount() == 1 }
        for (i in 1..4) raw(port, "silent-$i")
        waitFor("silent links") { a.wifi.linkCount() == 5 }
        val t = System.currentTimeMillis()
        for (i in 1..700) { a.router.publish(Packet(id(i), t, 16, ByteArray(16_000))); if (i % 20 == 0) Thread.sleep(5) }
        waitFor("a link that stopped reading is closed") { a.wifi.linkCount() < 5 }
        assertTrue("b, which kept reading, is still linked", "node-b" in a.wifi.nodes())
        assertEquals(1, b.wifi.linkCount())
        val last = a.router.let { r -> Packet(id(9_999), t, 16, ByteArray(200)).also(r::publish) }
        waitFor("and still gets packets") { b.got.any { it.id == last.id } }
    }

    @Test fun onlyEightDiscoveredDevicesAreDialedAtOnce() {
        val a = node("node-a")
        val servers = (1..40).map { ServerSocket(0).also { open += it } }  // they accept (in the backlog) and say nothing
        servers.forEach { a.wifi.dial("127.0.0.1", it.localPort) }
        Thread.sleep(700)
        val dials = Thread.getAllStackTraces().keys.count { it.name == "wifi-dial" && it.isAlive }
        assertTrue("at most 8 dials at once, but $dials", dials in 1..LinkLimits.DIALS)
    }

    @Test fun connectionsThatSayNothingCantKeepARealPhoneOut() {
        val a = node("node-a"); val b = node("node-b")
        val port = a.wifi.listen(0)
        val silent = (1..60).map { raw(port) }                             // more than every place for a connection
        Thread.sleep(500)
        b.wifi.dial("127.0.0.1", port)
        waitFor("the real phone links") { a.wifi.linkCount() == 1 && b.wifi.linkCount() == 1 }
        val stillOpen = silent.count { s ->
            s.soTimeout = 300
            val inp = DataInputStream(s.getInputStream())
            try { inp.readFully(ByteArray(inp.readInt())); inp.read() != -1 } catch (_: SocketTimeoutException) { true } catch (_: java.io.IOException) { false }
        }
        assertTrue("one address keeps at most 4 connections waiting, but $stillOpen", stillOpen <= LinkLimits.WAITING_PER_ADDRESS)
    }

    @Test fun oneAddressHoldsEightLinksAndOneAllowance() {
        val a = node("node-a", perMinute = 5)
        val port = a.wifi.listen(0)
        val clients = (1..12).map { raw(port, "fake-$it") }               // one device, twelve node ids
        waitFor("the links settle at eight") { a.wifi.linkCount() == LinkLimits.PER_ADDRESS }
        Thread.sleep(300)
        assertEquals(LinkLimits.PER_ADDRESS, a.wifi.linkCount()); assertEquals(LinkLimits.PER_ADDRESS, a.router.peerCount())
        // three new packets on each connection (four of them are closed by now)
        val t = System.currentTimeMillis()
        clients.forEachIndexed { c, s -> try { val o = s.getOutputStream(); repeat(3) { o.write(frame(pkt(5000 + c * 10 + it, t, 120))) }; o.flush() } catch (_: java.io.IOException) { } }
        Thread.sleep(700)
        assertEquals("all its links together get one link's packets a minute", 5, a.got.size)
    }

    @Test fun onlyTheLocalNetworkIsDialedOrLetIn() {
        val a = node("node-a", local = WifiLinks::onLan)                  // the rule the app uses: loopback is not the local network
        val port = a.wifi.listen(0)
        raw(port).let { s ->
            s.soTimeout = 5_000
            assertEquals("closed without a HELLO", -1, try { s.getInputStream().read() } catch (_: java.net.SocketException) { -1 })
        }
        assertEquals(0, a.wifi.linkCount())
        val fixture = ServerSocket(0).also { open += it }; fixture.soTimeout = 700
        a.wifi.dial("127.0.0.1", fixture.localPort)                        // as if a DNS-SD answer named this address
        assertThrows(SocketTimeoutException::class.java) { fixture.accept() }
        a.wifi.connectManually("127.0.0.1", fixture.localPort)             // an address the user typed is dialed, wherever it is
        fixture.soTimeout = 5_000
        fixture.accept().use { s -> val inp = DataInputStream(s.getInputStream()); val hello = ByteArray(inp.readInt()).also(inp::readFully); assertEquals("DPW1node-a", String(hello)) }
    }
}
