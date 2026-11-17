package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * Whoever hands a phone the first copy of a packet must not decide what happens to the real one: found in the
 * 2026-11-13 audit. Each of these failed before its fix; the iPhone's FirstCopyTests check the same. Dummy keys only.
 */
class FirstCopyTest {
    private val now = 1_800_000_000_000L
    private val anna = "1111111111111111"; private val ben = "2222222222222222"
    private fun pid(i: Int) = "%016x".format(i)
    private fun pkt(id: String, ttl: Int, fill: Int = 0x55) = Packet(id, now, ttl, ByteArray(98) { fill.toByte() })

    /** A router with the limits MeshEngine gives it. [sent]: "peer ttl" of everything passed on. */
    private class Rig(now: Long, perMinute: Int = MeshRouter.LINK_PER_MINUTE) {
        val got = ArrayList<Packet>(); val sent = ArrayList<String>(); val raised = ArrayList<Int>()
        val r = MeshRouter({ peer, p -> sent += "$peer ${p.ttl}" }, { got += it }, { now }, minCipher = MeshRouter.MIN_SEALED,
            maxPerMinute = perMinute, unlimited = { it == "nostr" }, raised = { raised += it.ttl })
    }

    // ---- The header time is part of what a packet is: a copy with another time can't be opened ----

    @Test fun theKeyCoversTheIdTheHeaderTimeAndTheContentButNotTheTtl() {
        val p = pkt("00000000000000a1", 16)
        assertEquals("00000000000000a1:4d9c1a2194a8e806", MeshRouter.key(p)) // SHA-256 of ts (8 bytes, big-endian), then cipher
        assertEquals(MeshRouter.key(p), MeshRouter.key(p.withTtl(3)))
        assertEquals("00000000000000a1:85b5782718fe85c3", MeshRouter.key(Packet(p.id, p.ts - 1, 16, p.cipher)))
        assertNotEquals(MeshRouter.key(p), MeshRouter.key(pkt(p.id, 16, 0x56)))
        assertNotEquals(MeshRouter.key(p), MeshRouter.key(pkt("00000000000000a2", 16)))
    }

    @Test fun aCopyOfAGroupMessageWithAnotherHeaderTimeDoesNotStopTheRealOne() {
        val secret = ByteArray(32) { 9 }
        val writer = Keyring.Epoch.fresh(6, now - 3_600_000L, secret, listOf(anna, ben), listOf(anna))
        val reader = Keyring.Epoch.fresh(6, now - 3_600_000L, secret, listOf(anna, ben), listOf(anna))
        val id = "%04x".format(writer.group.mailbox) + "000000000001"; val t = now - 5_000L
        val cipher = writer.group.sealWith(writer.messageKeys!!.key(1, 0)!!, 1, 0, id, t, ben, "Ben", "dummy text") { TestKeys.sign(it) }
        val real = Packet(id, writer.group.hideTime(t, cipher), 16, cipher); val copy = Packet(id, real.ts - 1, 16, cipher)
        fun text(p: Packet) = reader.open(p)?.message?.text
        assertNull("the copy can't be opened", text(copy))

        val x = Rig(now); x.r.peerUp("ble:next")
        x.r.receive("ble:attacker", copy); x.r.receive("ble:honest", real); x.r.receive("nostr", real)
        assertEquals("the copy, then the real packet once", listOf(copy.ts, real.ts), x.got.map { it.ts })
        assertEquals(listOf(null, "dummy text"), x.got.map(::text))
        assertEquals("both are passed on", listOf("ble:next 15", "ble:next 15"), x.sent)
    }

    @Test fun aCopyOfAChannelPacketWithAnotherHeaderTimeDoesNotStopTheRealOne() {
        // The sealing of receipts, introductions, new keys and Public messages. The copy comes from the relays first.
        val g = GroupCrypto.fromSecret(ByteArray(32) { 7 })
        val id = "%04x".format(g.mailbox) + "000000000002"; val t = now - 5_000L
        val cipher = g.seal(id, t, ben, "Ben", "dummy text 2")
        val real = Packet(id, g.hideTime(t, cipher), 16, cipher); val copy = Packet(id, real.ts - 1, 16, cipher)
        assertNull(g.open(copy))
        val x = Rig(now)
        x.r.receive("nostr", copy); x.r.receive("ble:honest", real)
        assertEquals(listOf(null, "dummy text 2"), x.got.map { g.open(it)?.text })
    }

    @Test fun afterARestartTheStoredCopyDoesNotStopTheRealPacket() {
        val g = GroupCrypto.fromSecret(ByteArray(32) { 7 })
        val id = "%04x".format(g.mailbox) + "000000000003"; val t = now - 5_000L
        val cipher = g.seal(id, t, ben, "Ben", "dummy text 3")
        val real = Packet(id, g.hideTime(t, cipher), 16, cipher); val copy = Packet(id, real.ts - 1, 16, cipher)
        val x = Rig(now)
        x.r.restore(listOf(copy), listOf(MeshRouter.key(copy))) // what MeshEngine.start gives the router
        x.r.receive("ble:honest", real)
        assertEquals(listOf("dummy text 3"), x.got.map { g.open(it)?.text })
        x.r.receive("ble:honest", copy)
        assertEquals("the stored copy is not shown again", 1, x.got.size)
    }

    // ---- The ttl isn't authenticated: the copy with the most hops left decides, not the first ----

    /** What the linked peer, the relays and a peer that links later get when only the real copy arrives. */
    private val passedOn = listOf("ble:b 15", "nostr 15", "ble:c 15")

    @Test fun aCopyThatCameFirstWithTtl1DoesNotStopThePacketFromBeingPassedOn() {
        val x = Rig(now); x.r.peerUp("ble:b"); x.r.peerUp("nostr")
        x.r.receive("ble:x", pkt(pid(1), 1)); assertTrue(x.sent.isEmpty())
        x.r.receive("ble:y", pkt(pid(1), 16)); x.r.peerUp("ble:c")
        assertEquals(passedOn, x.sent)
        assertEquals("shown once", listOf(1), x.got.map { it.ttl })
        assertEquals("the engine is told to save the higher ttl", listOf(16), x.raised)
    }

    @Test fun aCopyThatCameFirstFromTheRelaysWithTtl0DoesNotStopThePacketFromBeingPassedOn() {
        val x = Rig(now); x.r.peerUp("ble:b")
        x.r.receive("nostr", pkt(pid(2), 0)); x.r.receive("ble:y", pkt(pid(2), 16)); x.r.peerUp("ble:c")
        assertEquals(listOf("ble:b 15", "ble:c 15"), x.sent); assertEquals(1, x.got.size)
    }

    @Test fun afterARestartAStoredTtl1CopyIsStillRaised() {
        val x = Rig(now); val stored = pkt(pid(3), 1)
        x.r.restore(listOf(stored), listOf(MeshRouter.key(stored))); x.r.peerUp("ble:d")
        x.r.receive("ble:y", pkt(pid(3), 16))
        assertEquals(listOf("ble:d 15"), x.sent); assertTrue("not shown again", x.got.isEmpty()); assertEquals(listOf(16), x.raised)
    }

    @Test fun aCopyWithTheSameOrFewerHopsIsStillIgnored() {
        val x = Rig(now); x.r.peerUp("ble:b")
        x.r.receive("ble:x", pkt(pid(4), 9)); x.r.receive("ble:y", pkt(pid(4), 9)); x.r.receive("ble:y", pkt(pid(4), 3)); x.r.receive("ble:b", pkt(pid(4), 8))
        assertEquals(listOf("ble:b 8"), x.sent); assertTrue(x.raised.isEmpty()); assertEquals(1, x.got.size)
        x.r.receive("ble:y", pkt(pid(4), 64)) // above 16 counts as 16
        x.r.receive("ble:x", pkt(pid(4), 40)) // and 16 again is not higher
        assertEquals(listOf("ble:b 8", "ble:b 15"), x.sent); assertEquals(listOf(16), x.raised)
    }

    @Test fun passingOnAgainCountsInTheLinksPace() {
        val x = Rig(now, perMinute = 3); x.r.peerUp("ble:b")
        for (ttl in 2..6) x.r.receive("ble:x", pkt(pid(5), ttl)) // one new packet and two raises, then the link is over its share
        assertEquals(listOf("ble:b 1", "ble:b 2", "ble:b 3"), x.sent)
        x.r.receive("ble:y", pkt(pid(5), 6))                     // another link isn't held up
        x.r.receive("nostr", pkt(pid(5), 7))                     // nor are the relays, which have their own limit
        assertEquals(listOf("ble:b 1", "ble:b 2", "ble:b 3", "ble:b 5", "ble:b 6"), x.sent)
    }

    @Test fun aLowTtlCopyGivenToACarrierDoesNotCutOffThePhonesBehindIt() {
        val n = CoreTest.Net(); listOf("a", "b", "c", "d").forEach(n::add); n.link("a", "b"); n.link("b", "c"); n.link("c", "d")
        val real = Packet(pid(6), System.currentTimeMillis(), 16, byteArrayOf(1))
        n.nodes["b"]!!.receive("attacker", real.withTtl(1)) // b reads it, but would never pass it on
        n.nodes["a"]!!.publish(real); n.pump()
        for (node in listOf("b", "c", "d")) assertEquals(node, listOf(real.id), n.got[node])
    }

    // ---- The LoRa queue tells packets apart as the router does ----

    @Test fun junkUnderAnIdDoesNotKeepTheRealPacketOffTheRadio() {
        var t = now; val q = LoraQueue({ t })
        q.offer(pkt(pid(7), 16, 7))  // junk under the id
        q.offer(pkt(pid(7), 16, 9))  // the real packet
        q.offer(pkt(pid(7), 15, 9))  // the real packet again, one hop later: not sent twice
        assertEquals(7, q.next()!!.cipher[0].toInt()); t += LoraQueue.INTERVAL_MS
        assertEquals(9, q.next()!!.cipher[0].toInt()); t += LoraQueue.INTERVAL_MS
        assertNull(q.next())
    }

    /** The router hands packets for the radio peer to a queue, as MeshEngine.route and LoraLink.offer do. */
    private fun overTheRadio(maxBytes: Int, radio: String, arrivals: List<Pair<String, Packet>>): List<Int?> {
        var t = now; val q = LoraQueue({ t }, maxBytes)
        val r = MeshRouter({ peer, p -> if (peer == radio) q.offer(p) }, { }, { t }, minCipher = MeshRouter.MIN_SEALED,
            maxPerMinute = MeshRouter.LINK_PER_MINUTE, unlimited = { it == "nostr" })
        r.peerUp(radio)
        for ((link, p) in arrivals) r.receive(link, p)
        return (1..3).map { q.next()?.cipher?.get(0)?.toInt().also { t += LoraQueue.INTERVAL_MS } }
    }

    @Test fun junkSentFirstUnderAnIdIsFollowedByTheRealPacketOnBothRadios() {
        val junk = Packet("a8d00000000000c1", now, 16, ByteArray(100) { 7 }); val real = Packet(junk.id, now - 5 * 60_000L, 16, ByteArray(100) { 9 })
        val arrivals = listOf("nearby:attacker" to junk, "nearby:honest" to real)
        assertEquals(listOf(7, 9, null), overTheRadio(Meshtastic.PAYLOAD_MAX, "lora", arrivals))
        assertEquals(listOf(7, 9, null), overTheRadio(MeshCore.PAYLOAD_MAX, "meshcore", arrivals))
        assertEquals(listOf(9, 7, null), overTheRadio(Meshtastic.PAYLOAD_MAX, "lora", arrivals.reversed()))
    }

    @Test fun aPacketPassedOnAgainWithMoreHopsGoesOverTheRadioOnce() {
        val p = pkt(pid(8), 5)
        assertEquals(listOf(0x55, null, null), overTheRadio(Meshtastic.PAYLOAD_MAX, "lora", listOf("ble:x" to p, "ble:y" to p.withTtl(16))))
    }
}
