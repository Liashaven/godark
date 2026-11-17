package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/** Attacks found in the 2026-11-08 assessment. Each of these failed before its fix; the iPhone's RelayAttackTests check the same. */
class RelayAttackTest {
    private val now = 1_800_000_000_000L
    private val hour = 3_600_000L
    private fun pid(i: Int) = "%016x".format(i)
    private fun pkt(id: String, fill: Int = 0x55) = Packet(id, now, 16, ByteArray(98) { fill.toByte() })
    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"; private val dan = "4444444444444444"
    private fun ring() = Keyring().also { it.add(Keyring.Epoch(5, now - hour * 200, ByteArray(32) { 5 }, listOf(anna, ben, cara), listOf(anna))) }
    private var n = 0
    private fun box(): ByteArray { n++; return ByteArray(32) { i -> (n shr (i % 3 * 8)).toByte() } }
    private fun taken(r: Keyring, k: Rekey, maker: String, at: Long = now) = r.take(k, maker, anna, "door", false, null, at) { box() } is Keyring.Taken.Added
    private fun key(epoch: Long, made: Long, members: List<String>, answers: String? = null) = Rekey(epoch, made, ByteArray(33), listOf(anna), answers, members.map { it to ByteArray(1) })

    // One hostile relay, or any peer, could use up the copies allowed per id and so stop the real packet on every other path.
    @Test fun junkUnderAnIdNeverStopsTheRealPacketFromAnotherLink() {
        val got = ArrayList<Packet>()
        val r = MeshRouter({ _, _ -> }, { got += it }, { now }, minCipher = 98, maxPerMinute = 3000, unlimited = { it == "nostr" })
        val id = pid(1)
        for (i in 1..200) r.receive("nostr", pkt(id, i))
        r.receive("ble:neighbour", pkt(id, 0xFF))
        assertEquals(1, got.count { it.cipher[0] == 0xFF.toByte() })
    }

    // A member could date keys as they liked and so make as many as they wanted.
    @Test fun aMemberCantMakeUnlimitedKeysByBackdatingThem() {
        val r = ring()
        val below = (1..100).count { i -> taken(r, key(4, now - hour * i, listOf(anna)), ben) }
        assertTrue("below the current epoch: $below", below <= 4)
        val other = ring(); val all = listOf(anna, ben, cara)
        val above = (1..40).count { i -> taken(other, key(other.current().number + 1, now - hour * (i + 1), all), ben) }
        assertTrue("above the current epoch: $above", above <= 4)
        assertEquals("a key an hour later is taken again", true, taken(other, key(other.current().number + 1, now + hour * 2, all), ben, now + hour * 2))
    }

    @Test fun onlyAnAdminLetsSomeoneIn() {
        val r = ring(); val all = listOf(anna, ben, cara)
        assertFalse(taken(r, key(r.current().number + 1, now, all + dan, answers = dan), ben))
        assertTrue(taken(r, key(r.current().number + 1, now, all + dan, answers = dan), anna))
    }

    @Test fun anExistingMembersIdDoesntMakeAKeyAJoinAndEscapeTheLimit() {
        val r = ring(); val all = listOf(anna, ben, cara)
        val added = (1..40).count { i -> taken(r, key(r.current().number + 1, now - hour * (i + 1), all, answers = cara), ben) }
        assertTrue("taken: $added", added <= 4)
    }

    // A plain member could name themselves admin in a key numbered below the current one, then remove the group's creator.
    private fun forge(r: Keyring, me: String): Keyring.Taken {
        val x = "%016x".format(0xC1L)
        r.take(Rekey(4, now, ByteArray(33), listOf(ben), x, listOf(cara to ByteArray(1), anna to ByteArray(1), x to ByteArray(1))), ben, me, "door", false, null, now) { box() }
        return r.take(Rekey(5, now, ByteArray(33), listOf(ben), anna, listOf(ben to ByteArray(1), cara to ByteArray(1)), removal = true), ben, me, "door", false, null, now) { ByteArray(32) { 9 } + "ATTK-ATTK-ATTK-ATTK".toByteArray() }
    }

    @Test fun aMemberCantMakeThemselvesAdminWithAKeyBelowTheCurrentOne() {
        val forCara = ring(); assertSame(Keyring.Taken.Ignored, forge(forCara, cara))
        assertEquals(listOf(anna), forCara.current().admins)
        assertSame("the creator stays in", Keyring.Taken.Ignored, forge(ring(), anna))
    }

    @Test fun aKeyBelowTheCurrentOneCantBeUsedToLeavePeopleOut() {
        val r = ring(); val x = "%016x".format(0xC2L)
        taken(r, Rekey(4, now - hour, ByteArray(33), listOf(anna), x, listOf(anna to ByteArray(1), x to ByteArray(1))), ben)
        assertNull(r.admit(Rekey(5, now, ByteArray(33), listOf(anna), null, listOf(anna to ByteArray(1), x to ByteArray(1))), ben, null, now))
    }

    @Test fun aKeyBelowTheCurrentOneStillOpensOldMessagesButListsNobody() {
        val r = ring(); val x = "%016x".format(0xC3L)
        assertTrue(taken(r, key(4, now - hour, listOf(anna, x), answers = x), ben))
        val late = r.all().first { it.number == 4L }
        assertTrue(late.members.isEmpty()); assertEquals(listOf(anna), late.admins); assertEquals(5L, r.current().number)
        assertNull("someone listed only there is still a stranger to it", r.admit(key(4, now, listOf(anna)), x, null, now))
    }

    @Test fun aRealAdminCanStillRemoveAfterAKeyArrivedLate() {
        val r = ring(); val x = "%016x".format(0xC4L)
        assertTrue(taken(r, key(4, now - hour, listOf(anna, x), answers = x), ben)) // before the removal: the epoch before it exists, read-only
        val removal = Rekey(5, now, ByteArray(33), listOf(anna), cara, listOf(anna to ByteArray(1), ben to ByteArray(1)), removal = true)
        assertNotNull(r.admit(removal, anna, null, now))
    }

    // Found when these fixes were attacked: a removal that arrives late can become current, so it must keep its members.
    @Test fun aLateRemovalThatBecomesCurrentKeepsItsMembers() {
        val r = ring(); val all = listOf(anna, ben, cara)
        assertTrue(taken(r, key(7, now, all), ben))
        val removal = Rekey(6, now, ByteArray(33), listOf(anna), cara, listOf(anna to ByteArray(1), ben to ByteArray(1)), removal = true)
        val t = r.take(removal, anna, ben, "door", false, null, now) { ByteArray(32) { 6 } + "NNNN-GGGG-KKKK-ZZZZ".toByteArray() }
        assertTrue(t is Keyring.Taken.Added && t.moveTo != null)
        assertEquals(6L, r.current().number); assertEquals(listOf(anna, ben), r.current().members)
    }

    @Test fun aRelayThatDropsTheLinkDoesntGetANewShare() {
        val pace = RelayPace(); val t = 1_800_000_000L
        val first = CatchUp("r", RelaySince(), pace = pace)
        repeat(Nostr.RELAY_PER_MINUTE) { assertTrue(first.allow(t)) }
        assertFalse(CatchUp("r", RelaySince(), pace = pace).allow(t + 5))
    }

    // Each relay link has its own limit, and what went over it is fetched again.
    @Test fun aRelayOverItsShareIsCutOffAndItsCatchUpIsNotMarkedDone() {
        val s = RelaySince(); val c = CatchUp("r", s); val t = 1_800_000_000L
        c.add(listOf(0x1234))
        val req = c.next(t)!!
        repeat(Nostr.RELAY_PER_MINUTE) { assertTrue(c.allow(t)) }
        assertFalse(c.allow(t))
        assertNull(c.end(req.subId, true, t))
        assertNull("the saved start must not move", s.get("r", 0x1234))
        assertTrue("a new minute", c.allow(t + 60))
    }

    @Test fun anotherRelaysLinkKeepsItsOwnShare() {
        val a = CatchUp("a", RelaySince()); val b = CatchUp("b", RelaySince()); val t = 1_800_000_000L
        repeat(Nostr.RELAY_PER_MINUTE + 1) { a.allow(t) }
        assertFalse(a.allow(t)); assertTrue(b.allow(t))
    }

    // WsFrameGuard: a long message is refused from its header, before any of it is kept.
    private val upgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".toByteArray()
    private fun header(op: Int, fin: Boolean, len: Long): ByteArray {
        val b0 = (if (fin) 0x80 else 0) or op
        return when {
            len < 126 -> byteArrayOf(b0.toByte(), len.toByte())
            len < 65536 -> byteArrayOf(b0.toByte(), 126, (len shr 8).toByte(), len.toByte())
            else -> byteArrayOf(b0.toByte(), 127) + ByteArray(8) { i -> (len shr (56 - i * 8)).toByte() }
        }
    }
    private fun feed(g: WsFrameGuard, vararg parts: ByteArray) = parts.forEach { g.look(it, 0, it.size) }
    private fun fails(block: () -> Unit) = try { block(); false } catch (_: java.io.IOException) { true }

    // Two interim answers made OkHttp 4.12 throw on a thread where it ended the app; a relay has no reason to send any.
    @Test fun anythingButAnUpgradeEndsTheLink() {
        for (answer in listOf("HTTP/1.1 100 Continue\r\n\r\n", "HTTP/1.1 103 Hints\r\nLink: x\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "\r\n", "nonsense\n\n"))
            assertTrue(answer, fails { feed(WsFrameGuard(), answer.toByteArray()) })
    }

    // OkHttp takes all of these answers as a successful upgrade, so the guard has to as well, or it would never look at the frames.
    @Test fun headersEndingInBareLineFeedsAreStillAnAnswer() {
        val g = WsFrameGuard(); feed(g, "HTTP/1.1 101\nUpgrade: websocket\n\n".toByteArray())
        assertTrue(fails { feed(g, header(1, true, 1L shl 30)) })
    }

    @Test fun aMixOfLineEndingsIsStillAnAnswer() {
        val g = WsFrameGuard(); feed(g, "HTTP/1.1 101 x\r\nA: b\n\r\n".toByteArray())
        assertTrue(fails { feed(g, header(1, true, 1L shl 30)) })
    }

    @Test fun theIcyStatusLineCounts() {
        val g = WsFrameGuard(); feed(g, "ICY 101 x\r\n\r\n".toByteArray())
        assertTrue(fails { feed(g, header(1, true, 1L shl 30)) })
    }

    @Test fun aLoneCarriageReturnLineIsNotTheEndOfTheHeaders() {
        val g = WsFrameGuard(); feed(g, "HTTP/1.1 101 x\r\n\r\r\nA: b\r\n\r\n".toByteArray())
        feed(g, header(1, true, 10), ByteArray(10))
        assertTrue(fails { feed(g, header(1, true, 1L shl 30)) })
    }

    @Test fun anAnswerThatNeverEndsFails() {
        val g = WsFrameGuard(); val line = "A: ".toByteArray() + ByteArray(1024) { 'x'.code.toByte() } + "\r\n".toByteArray()
        assertTrue(fails { repeat(1000) { feed(g, line) } })
    }

    @Test fun aHeaderClaimingAHugeMessageFailsAtOnce() {
        val g = WsFrameGuard(); feed(g, upgrade)
        assertTrue(fails { feed(g, header(1, true, 1L shl 30)) })
    }

    @Test fun aHeaderWithANegativeLengthFails() {
        val g = WsFrameGuard(); feed(g, upgrade)
        assertTrue(fails { feed(g, byteArrayOf(0x81.toByte(), 127) + ByteArray(8) { -1 }) })
    }

    @Test fun fragmentsCantAddUpToMoreThanTheLimit() {
        val g = WsFrameGuard(max = 1000); feed(g, upgrade)
        feed(g, header(1, false, 600), ByteArray(600))
        assertTrue(fails { feed(g, header(0, false, 600)) })
    }

    @Test fun normalTrafficPassesHoweverItIsCutUp() {
        val stream = upgrade + header(1, true, 300) + ByteArray(300) + header(9, true, 5) + ByteArray(5) + header(1, false, 70_000) + ByteArray(70_000) +
            header(10, true, 0) + header(0, true, 70_000) + ByteArray(70_000) + header(1, true, 0) + header(1, true, 900_000) + ByteArray(900_000)
        for (chunk in listOf(1, 3, 7, 1024, stream.size)) {
            val g = WsFrameGuard()
            var i = 0
            while (i < stream.size) { val n = minOf(chunk, stream.size - i); g.look(stream, i, n); i += n }
        }
    }

    @Test fun oneMessageAfterAnotherStartsCountingAgain() {
        val g = WsFrameGuard(max = 1000); feed(g, upgrade)
        repeat(5) { feed(g, header(1, true, 900), ByteArray(900)) }
    }

    @Test fun messagesMaskedByMistakeAreStillMeasured() {
        val g = WsFrameGuard(max = 1000); feed(g, upgrade)
        assertTrue(fails { feed(g, byteArrayOf(0x81.toByte(), (126 or 0x80).toByte(), 0x7F, 0x7F, 1, 2, 3, 4)) })
    }

    @Test fun deepJsonFromARelayIsRefused() {
        for (deep in listOf("{\"a\":".repeat(200_000), "[".repeat(200_000))) {
            assertNull(Nostr.ok(deep)); assertNull(Nostr.end(deep)); assertNull(Nostr.received(deep))
        }
    }
}
