package it.blackout.mesh

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

/**
 * The relay outbox, the catch-up, the LoRa queue, the Everyone store and the Everyone introduction (audit of 2026-11).
 * Each test of a rule in the outbox, the catch-up and the LoRa queue failed before its fix; the iPhone's
 * RelayLimitsFixTests check the same. Dummy packets and mailboxes only; no socket, no relay.
 *
 * NostrLink, RelayScope and MeshEngine need Android, so the tests run the rules they are made of ([RelayOutbox],
 * [CatchUp], [RelaySince], [MeshRouter.source], [LoraQueue], [StoreCap.everyone], [PublicIntro]); [Phone] and [link]
 * wire them the way MeshEngine.route and RelayScope's message handler do.
 */
class RelayLimitsFixTest {
    private val t0 = 1_800_000_000_000L
    private fun pkt(id: String, fill: Int, ts: Long = t0 - 1_000, size: Int = MeshRouter.MIN_SEALED, ttl: Int = 15) = Packet(id, ts, ttl, ByteArray(size) { fill.toByte() })
    private fun outbox(sent: Collection<String> = emptyList()) = RelayOutbox(sent, now = { t0 }, jitter = { 0L })

    /** The router's relay and radio peers, wired to an outbox and a LoRa queue the way MeshEngine.route does it. */
    private class Phone(val now: () -> Long) {
        val mine = HashSet<String>()                                  // ids of packets written on this phone
        val outbox = RelayOutbox(now = now, jitter = { 0L })
        val radio = LoraQueue(now)
        val offered = ArrayList<Pair<Boolean, String>>()              // what the relay peer was told: mine, from
        lateinit var router: MeshRouter
        init {
            router = MeshRouter({ peer, p ->
                val from = router.source(p); val own = from == "" && p.id in mine
                if (peer == NostrLink.PEER) { offered += own to (from ?: ""); outbox.offer(p, own, from ?: "") }
                if (peer == LoraLink.PEER) radio.offer(p, own)
            }, { }, now, minCipher = MeshRouter.MIN_SEALED)
        }
    }

    // ---- 1. The outbox tells packets apart by id, time and content, never by id alone ----

    // Any neighbour could send another packet under the id of one this phone wrote. It took the real one's place in
    // the queue, went up instead of it, and its acceptance made the real one count as sent, also after a restart.
    @Test fun anotherPacketUnderTheIdOfAnOwnOneNeitherTakesItsPlaceNorCountsAsIt() {
        val phone = Phone { t0 }
        phone.router.peerUp(NostrLink.PEER); phone.router.peerUp("ble:neighbour")
        val real = pkt("a8d00000000000e1", 1, ttl = 16)
        phone.mine += real.id; phone.router.publish(real)
        repeat(5) { phone.router.receive("ble:neighbour", pkt(real.id, 10 + it, ts = t0 - 500)) }
        // Only the packet this phone wrote is its own; the others are a link's, whatever id they carry.
        assertEquals(listOf(true to "") + List(5) { false to "ble:neighbour" }, phone.offered)
        val o = phone.outbox
        val (first, own) = o.next(bridged = false)!!
        assertEquals(1, first.cipher[0].toInt()); assertTrue(own)
        assertNull("the others wait with the packets passed on", o.next(bridged = false))
        o.posted("ev-real", first, own, setOf("r"))
        // While the real one is in flight, the others are still looked up and posted like anyone's.
        val batch = o.toCheck(50); assertEquals(5, batch.size)
        assertEquals(emptyList<String>(), o.checked(batch))
        val (other, otherOwn) = o.next(bridged = true)!!; assertFalse(otherOwn)
        o.posted("ev-other", other, otherOwn, setOf("r"))
        assertNull("a relay taking someone else's packet is no \"Sent\" for this phone's message", o.answer("r", Nostr.Ok("ev-other", true, "")))
        assertTrue(o.isSent(other)); assertFalse(o.isSent(real))
        assertEquals(real.id, o.answer("r", Nostr.Ok("ev-real", true, "")))
        assertTrue(o.isSent(real))
    }

    @Test fun aPacketThatWentUpFirstUnderAnIdDoesNotStopTheRealOne() {
        val real = pkt("a8d00000000000e2", 1, ttl = 16); val fake = pkt(real.id, 2, ts = t0 - 500)
        val o = outbox()
        o.offer(fake, mine = false, from = "ble:x")
        o.checked(o.toCheck(50))
        val (p, own) = o.next(bridged = true)!!; o.posted("ev1", p, own, setOf("r"))
        o.offer(real, mine = true)                                          // was dropped: "its id is in flight"
        assertEquals(1, o.next(bridged = false)?.first?.cipher?.get(0)?.toInt())
        o.answer("r", Nostr.Ok("ev1", true, ""))
        o.offer(real, mine = true)                                          // was dropped: "its id is sent"
        assertEquals(1, o.next(bridged = false)?.first?.cipher?.get(0)?.toInt())

        // The saved list names the very packet, so after a restart too only that one counts as sent.
        val saved = o.sentList(); assertEquals(listOf(MeshRouter.key(fake)), saved)
        val restarted = outbox(saved)
        restarted.offer(fake, mine = false); assertEquals(0, restarted.queued())
        restarted.offer(real, mine = true); assertEquals(1, restarted.queued())
        // What an older build saved by id alone stands for no packet: the real one is looked up or posted again.
        val upgraded = outbox(listOf(real.id))
        upgraded.offer(real, mine = true); assertEquals(1, upgraded.queued()); assertFalse(upgraded.isSent(real.id))
    }

    @Test fun twoPacketsUnderOneIdBothWaitAndARelaysCopyOfOneSaysNothingAboutTheOther() {
        val real = pkt("beef00000000c001", 1); val fake = pkt(real.id, 2)
        val o = outbox()
        o.offer(real, mine = false, from = "ble:a"); o.offer(fake, mine = false, from = "ble:b")
        assertEquals("neither replaces the other", 2, o.queued())
        val batch = o.toCheck(50); assertEquals(2, batch.size)
        o.fromRelay(fake)                                                   // the relays have the other packet only
        o.checked(batch)
        assertEquals(listOf(1), generateSequence { o.next(bridged = true)?.first?.cipher?.get(0)?.toInt() }.toList())

        // A relay that sends the real packet and then another under its id: the real one still counts as there.
        val again = outbox()
        again.offer(real, mine = false)
        val asked = again.toCheck(50)
        again.fromRelay(real.withTtl(3)); again.fromRelay(fake)
        again.checked(asked)
        assertNull("not posted a second time", again.next(bridged = true)); assertTrue(again.isSent(real))
    }

    @Test fun theRouterSaysWhereThisVeryPacketCameFrom() {
        val r = MeshRouter({ _, _ -> }, { }, { t0 }, minCipher = MeshRouter.MIN_SEALED)
        val own = pkt("a8d00000000000e3", 1, ttl = 16); val other = pkt(own.id, 2); val board = pkt("957600000000e004", 3, ttl = 16)
        assertNull(r.source(own))
        r.publish(own); r.receive("wifi:n", other); r.publish(board, "board")
        assertEquals("", r.source(own)); assertEquals("", r.source(own.withTtl(3)))
        assertEquals("another packet under the id is the link's", "wifi:n", r.source(other))
        assertEquals("board", r.source(board))
        // After a restart: what the phone held is its own or unknown (""), unless the caller knows a relay brought it.
        val again = MeshRouter({ _, _ -> }, { }, { t0 }, minCipher = MeshRouter.MIN_SEALED)
        again.restore(listOf(own, board)) { if (it == MeshRouter.key(board)) NostrLink.PEER else "" }
        assertEquals("", again.source(own)); assertEquals(NostrLink.PEER, again.source(board)); assertNull(again.source(other))
    }

    // ---- 2. Catch-up: junk in a mailbox neither ends it early nor makes the phone skip what it didn't fetch ----

    private val box = 0xa8d0
    private fun frame(sub: String, created: Long, content: String) = JSONArray().put("EVENT").put(sub).put(JSONObject()
        .put("id", "0".repeat(64)).put("pubkey", "1".repeat(64)).put("created_at", created).put("kind", Nostr.KIND)
        .put("tags", JSONArray().put(JSONArray().put("t").put(Nostr.tag(box)))).put("content", content).put("sig", "2".repeat(128))).toString()
    private fun content(p: Packet) = Base64.getEncoder().encodeToString(p.encode())

    /** An honest relay with these stored events (date in seconds, content): it answers a REQ with the newest 500 of the window. */
    private fun answer(events: List<Pair<Long, String>>, r: CatchUp.Req): List<String> =
        events.filter { it.first >= r.since && (r.until == null || it.first <= r.until!!) }.sortedByDescending { it.first }.take(Nostr.PAGE)
            .map { frame(r.subId, it.first, it.second) }

    /** One link to the relay: catches [mailbox] up as RelayScope does. Returns the REQs sent and the packets that arrived. */
    private fun link(events: List<Pair<Long, String>>, since: RelaySince, now: Long, mailbox: Int = box): Pair<List<CatchUp.Req>, List<Packet>> {
        val cu = CatchUp("wss://r", since); cu.add(listOf(mailbox))
        val reqs = ArrayList<CatchUp.Req>(); val got = ArrayList<Packet>()
        var req = cu.next(now)
        while (req != null) {
            reqs += req
            for (text in answer(events, req)) { cu.frame(text); Nostr.received(text)?.let { got += it.packet } }
            req = cu.end(req.subId, true, now)
        }
        return reqs to got
    }

    private val nowS = 1_800_000_000L
    private val real = Packet("a8d0000000000001", (nowS - 50_000) * 1000, 15, ByteArray(MeshRouter.MIN_SEALED) { 1 })

    @Test fun readsTheDateOfAnyEvent() {
        val d = Nostr.dated(frame("cu7", 123, "x"))!!
        assertEquals("cu7", d.subId); assertEquals(123L, d.createdAt)
        assertNull(Nostr.received(frame("cu7", 123, "x")))                  // no packet in it
        assertNull(Nostr.dated("""["EOSE","cu7"]""")); assertNull(Nostr.dated("""["EVENT","cu7"]""")); assertNull(Nostr.dated("nonsense"))
    }

    // 500 events with the mailbox's tag and content that is no packet used to count as an empty page: the catch-up
    // ended there, and the saved start moved past the real event below them.
    @Test fun aPageOfEventsThatCarryNoPacketIsStillAFullPage() {
        val events = listOf(nowS - 50_000 to content(real)) + (0 until Nostr.PAGE).map { nowS - 40_000 + it to "x" }
        val since = RelaySince(); since.advance("wss://r", box, nowS - 60_000)
        val (reqs, got) = link(events, since, nowS)
        assertEquals(2, reqs.size); assertEquals(nowS - 40_000, reqs[1].until)
        assertEquals(listOf(real.id), got.map { it.id })
        assertEquals(nowS, since.get("wss://r", box)); assertNull(since.owed("wss://r", box))
    }

    // 2,000 junk packets used up the four pages; the catch-up counted as done, and no later link asked for anything older.
    @Test fun aCatchUpThatStopsAtItsPageLimitOwesTheRestToTheNextLinks() {
        val junk = (0 until 2_500).map { nowS - 40_000 + it to content(Packet("a8d0%012x".format(1000 + it), (nowS - 40_000 + it) * 1000, 15, ByteArray(MeshRouter.MIN_SEALED) { 9 })) }
        val events = junk + (nowS - 50_000 to content(real))
        var since = RelaySince(); since.advance("wss://r", box, nowS - 60_000)
        val (first, got) = link(events, since, nowS)
        assertEquals(Nostr.MAX_PAGES, first.size); assertFalse(got.any { it.id == real.id })
        assertEquals("new events are asked from here, as before", nowS, since.get("wss://r", box))
        val owed = since.owed("wss://r", box)!!
        assertEquals(nowS - 60_000 - Nostr.SINCE_MARGIN_S, owed.first)       // everything since the old start…
        assertEquals(first.last().since, owed.first); assertTrue(owed.second < first.last().until!!) // …that is older than the last page

        since = RelaySince(since.save())                                    // the app restarts in between
        assertEquals(owed, since.owed("wss://r", box))
        val (second, more) = link(events, since, nowS + 600)
        assertTrue("no more REQs than a link may send", second.size <= Nostr.MAX_PAGES)
        assertNull(second[0].until); assertEquals(nowS - Nostr.SINCE_MARGIN_S, second[0].since) // first what is new
        assertEquals(owed.first, second[1].since); assertEquals(owed.second, second[1].until)   // then what was left out
        assertTrue("the real event is fetched", more.any { it.id == real.id })
        assertNull("nothing is owed any more", since.owed("wss://r", box))
        assertEquals(nowS + 600, since.get("wss://r", box))
        assertEquals(1, link(events, since, nowS + 1_200).first.size)        // caught up: one REQ, as always
    }

    @Test fun aDeeperFloodIsReadFurtherOnEveryLink() {
        val junk = (0 until 5_000).map { nowS - 40_000 + it to "x" }
        val events = junk + (nowS - 50_000 to content(real))
        val since = RelaySince(); since.advance("wss://r", box, nowS - 60_000)
        var links = 0; var fetched = false; var last = Long.MAX_VALUE
        while (!fetched && links < 10) {
            val (reqs, got) = link(events, since, nowS + links * 600L); links++
            assertTrue(reqs.size <= Nostr.MAX_PAGES)
            fetched = got.any { it.id == real.id }
            if (!fetched) { val until = since.owed("wss://r", box)!!.second; assertTrue("each link gets further", until < last); last = until }
        }
        assertTrue(fetched); assertEquals(4, links)                          // 4 pages, then 3 older ones on each later link: the 11th isn't full
        assertNull(since.owed("wss://r", box))
    }

    @Test fun theEveryoneChannelStaysOnePageAndWhatIsOwedIsNeverOlderThanSevenDays() {
        val everyone = (0 until 600).map { nowS - 1_000 + it to "x" }
        val since = RelaySince()
        val (reqs, _) = link(everyone, since, nowS, Nostr.PUBLIC_MAILBOX)
        assertEquals(1, reqs.size); assertEquals(nowS, since.get("wss://r", Nostr.PUBLIC_MAILBOX))
        assertNull("one page by design: nothing is owed", since.owed("wss://r", Nostr.PUBLIC_MAILBOX))

        since.owe("wss://r", box, nowS - 9 * 86_400, nowS - 8 * 86_400)      // left out over a week ago: relays no longer keep it
        assertEquals(1, link(emptyList(), since, nowS).first.size)
        assertNull(since.owed("wss://r", box))
        since.owe("wss://r", box, nowS - 8 * 86_400, nowS - 86_400)          // partly older: asked from 7 days back
        val part = link(emptyList(), since, nowS).first
        assertEquals(2, part.size); assertEquals(nowS - Nostr.KEEP_S, part[1].since); assertEquals(nowS - 86_400, part[1].until)
    }

    @Test fun whatIsOwedIsSavedWithTheStartsAndOlderSavedListsStillRead() {
        val s = RelaySince("wss://a|a8d0=100,wss://b|0794=7")                // as saved before this change
        assertEquals(100L, s.get("wss://a", 0xa8d0)); assertNull(s.owed("wss://a", 0xa8d0)); assertFalse(s.changed)
        s.owe("wss://a", 0xa8d0, 40, 90); assertTrue(s.changed)
        assertEquals("wss://a|a8d0=100,wss://b|0794=7,wss://a|a8d0|from=40,wss://a|a8d0|until=90", s.save())
        val t = RelaySince(s.save())
        assertEquals(40L to 90L, t.owed("wss://a", 0xa8d0)); assertNull(t.owed("wss://b", 0x0794)); assertEquals(100L, t.get("wss://a", 0xa8d0))
        t.owe("wss://a", 0xa8d0, 40, 90); assertFalse("nothing moved", t.changed)
        t.owe("wss://a", 0xa8d0, 40, 40); assertTrue(t.changed)             // nothing left
        assertNull(t.owed("wss://a", 0xa8d0)); assertEquals("wss://a|a8d0=100,wss://b|0794=7", t.save())
    }

    // ---- 3. The queues for packets passed on are bounded in bytes ----

    // 5,000 + 2,000 packets of 16 KB: a neighbour could park over 100 MB in memory.
    @Test fun theQueuesForPacketsPassedOnAreBoundedInBytes() {
        val o = outbox(); val big = ByteArray(Packet.MAX_CIPHER) { 7 }; val one = 18L + big.size
        var n = 0
        fun flood(count: Int) = repeat(count) { o.offer(Packet("beef%012x".format(n), t0 - 3_600_000 + n, 15, big), mine = false, from = "wifi:x"); n++ }
        flood(3_000)
        assertEquals("as many as fit in the budget", (RelayOutbox.QUEUE_BYTES / one).toInt(), o.queued())
        assertTrue(o.queuedBytes() <= RelayOutbox.QUEUE_BYTES)              // was 48 MB
        repeat(60) { o.checked(o.toCheck(50)); flood(100) }                 // looked up, not found: they wait to be posted
        assertTrue(o.queuedBytes() <= 2 * RelayOutbox.QUEUE_BYTES)          // the two queues together
        assertTrue(o.queuedBytes() > RelayOutbox.QUEUE_BYTES)               // and both are in use

        val small = outbox()                                                // short packets: the counts are the limit, as before
        for (i in 0 until RelayOutbox.CANDIDATES_MAX + 100) small.offer(pkt("beef%012x".format(i), 9, ts = t0 - 60_000 + i), mine = false)
        assertEquals(RelayOutbox.CANDIDATES_MAX, small.queued())
    }

    // ---- 5. This phone's older messages have their own way up, and the links that brought the rest take turns ----

    // A message written without internet is over 40 minutes old by the time the relays link. It waited behind every
    // packet with a later date, and the date is whatever the packet's maker wrote, up to 10 minutes ahead.
    @Test fun aNeighboursForwardDatedPacketsDoNotGoBeforeThisPhonesOlderMessage() {
        val o = outbox()
        val own = pkt("a8d00000000000f1", 1, ts = t0 - 41 * 60_000L, ttl = 16)
        o.offer(own, mine = true)
        assertNull("older than 40 minutes: looked up first", o.next(bridged = false))
        for (i in 0 until 60) o.offer(pkt("beef%012x".format(i), 9, ts = t0 + 9 * 60_000L + i), mine = false, from = "ble:loud")
        val batch = o.toCheck(50)
        assertEquals("looked up before anything passed on", own.id, batch[0].id)
        o.checked(batch)
        val (p, mine) = o.next(bridged = false)!!                           // and posted with the own packets, at their pace
        assertEquals(own.id, p.id); assertTrue(mine)
    }

    @Test fun aBurstOfForwardDatedPacketsDoesNotPushThisPhonesOlderMessageOut() {
        val o = outbox()
        val own = pkt("a8d00000000000f2", 1, ts = t0 - 41 * 60_000L, ttl = 16)
        o.offer(own, mine = true)
        val c = ByteArray(MeshRouter.MIN_SEALED) { 9 }
        for (i in 0 until RelayOutbox.CANDIDATES_MAX + RelayOutbox.MISSING_MAX + 50) o.offer(Packet("beef%012x".format(i), t0 + 9 * 60_000L + i, 15, c), mine = false, from = "ble:loud")
        assertEquals(RelayOutbox.CANDIDATES_MAX, o.queued())
        assertEquals(own.id, o.toCheck(50)[0].id)
    }

    @Test fun theLinksThatBroughtPacketsTakeTurns() {
        val o = outbox()
        for (i in 0 until 200) o.offer(pkt("beef%012x".format(i), 9, ts = t0 + 9 * 60_000L + i), mine = false, from = "ble:loud")
        val quiet = (0 until 3).map { pkt("cafe%012x".format(it), 5, ts = t0 - 30 * 60_000L - it) }
        quiet.forEach { o.offer(it, mine = false, from = "wifi:quiet") }
        val batch = o.toCheck(50)
        assertTrue("the quiet link's packets are looked up in the first batch", batch.map { it.id }.containsAll(quiet.map { it.id }))
        assertEquals(50, batch.size)
        o.checked(batch)
        assertEquals(listOf("beef", "cafe", "beef", "cafe", "beef", "cafe", "beef"), (1..7).map { o.next(bridged = true)!!.first.id.take(4) })
        // A packet from a link not seen before waits one turn, not for the whole queue of the loud one.
        o.offer(pkt("f00d00000000c001", 6, ts = t0 - 20 * 60_000L), mine = false, from = "nearby:new")
        o.checked(o.toCheck(50))
        assertTrue("f00d" in (1..2).map { o.next(bridged = true)!!.first.id.take(4) })
    }

    @Test fun aFullQueueTakesFromTheLinkThatHoldsMoreThanAQuarter() {
        val o = outbox()
        val quiet = (0 until 100).map { pkt("cafe%012x".format(it), 5, ts = t0 - 3_600_000L - it) }
        quiet.forEach { o.offer(it, mine = false, from = "wifi:quiet") }
        val c = ByteArray(MeshRouter.MIN_SEALED) { 9 }
        for (i in 0 until RelayOutbox.CANDIDATES_MAX + 500) o.offer(Packet("beef%012x".format(i), t0 + 9 * 60_000L + i, 15, c), mine = false, from = "ble:loud")
        assertEquals(RelayOutbox.CANDIDATES_MAX, o.queued())
        val waiting = generateSequence { o.toCheck(50).takeIf { it.isNotEmpty() } }.flatten().map { it.id }.toList()
        assertEquals("none of the quiet link's older packets was pushed out", 100, waiting.count { it.startsWith("cafe") })
        assertEquals(RelayOutbox.CANDIDATES_MAX - 100, waiting.count { it.startsWith("beef") })
        assertTrue("the loud link's own oldest made room", "beef%012x".format(0) !in waiting)
    }

    // ---- 6. The LoRa queue sends this phone's own packets first ----

    // 20 packets passed on after it pushed the phone's own message out of the queue for good, and it showed "Sent".
    @Test fun packetsPassedOnDoNotPushThisPhonesOwnMessageOutOfTheRadioQueue() {
        var t = t0; val q = LoraQueue({ t })
        q.offer(Packet("00000000000000f0", t, 16, ByteArray(10))); assertNotNull(q.next()) // the 20 s until the next one are running
        val own = Packet("00000000000000a1", t, 16, ByteArray(10))
        q.offer(own, mine = true)
        for (i in 0 until 3 * LoraQueue.MAX_QUEUE) q.offer(Packet("00000000000001%02x".format(i), t, 15, ByteArray(10)))
        t += LoraQueue.INTERVAL_MS
        assertEquals("the phone's own goes first", own.id, q.next()!!.id)
        val after = generateSequence { t += LoraQueue.INTERVAL_MS; q.next()?.id }.toList()
        assertEquals("then the newest that fit, in the order they came", (41 until 60).map { "00000000000001%02x".format(it) }, after)
    }

    @Test fun theRadioQueueKeepsItsOwnPacketsWhenFull() {
        var t = t0; val q = LoraQueue({ t })
        val own = (0 until LoraQueue.MAX_QUEUE + 2).map { Packet("00000000000002%02x".format(it), t, 16, ByteArray(10)) }
        own.take(LoraQueue.MAX_QUEUE).forEach { q.offer(it, mine = true) }
        q.offer(Packet("00000000000000b1", t, 15, ByteArray(10)))            // full of own packets: one passed on isn't taken
        own.drop(LoraQueue.MAX_QUEUE).forEach { q.offer(it, mine = true) }   // more own ones: the oldest own make room
        val aired = generateSequence { t += LoraQueue.INTERVAL_MS; q.next()?.id }.toList()
        assertEquals(own.drop(2).map { it.id }, aired)
    }

    @Test fun theRouterFeedsTheRadioQueueAndOnlyThePhonesOwnPacketGoesFirst() {
        var t = t0; val phone = Phone { t }
        phone.router.peerUp(LoraLink.PEER); phone.router.peerUp("ble:n")
        val own = pkt("00000000000000a2", 1, ts = t0, ttl = 16)
        for (i in 0 until 5) phone.router.receive("ble:n", pkt("00000000000003%02x".format(i), 9, ts = t0))
        phone.router.receive("ble:n", pkt(own.id, 8, ts = t0))               // another packet under the id it is about to use
        phone.mine += own.id; phone.router.publish(own)
        for (i in 5 until 40) phone.router.receive("ble:n", pkt("00000000000003%02x".format(i), 9, ts = t0))
        val first = phone.radio.next()!!
        assertEquals(own.id, first.id); assertEquals(1, first.cipher[0].toInt())
    }

    // ---- 7. The Everyone store: one sender can't push everyone else out ----

    private fun held(prefix: String, n: Int, from: Long, own: Boolean = false, holder: (Int) -> String) =
        (0 until n).map { StoreCap.Held("$prefix%05d".format(it), from + it, holder(it), own) }

    // The newest 2,000 stayed, whoever sent them: 2,000 packets from one key emptied the channel and every place in it.
    @Test fun oneSenderCantPushEveryoneElseOutOfTheEveryoneStore() {
        val honest = held("h", 300, 1_000) { "sender-${it % 60}" }           // 60 people, 5 packets each, all older
        val flood = held("f", 2_500, 10_000) { "flooder" }
        val drop = StoreCap.everyone(honest + flood, 2_000)
        assertEquals((0 until 800).map { "f%05d".format(it) }, drop)         // only the flooder's, its oldest first
        assertEquals(emptyList<String>(), StoreCap.everyone(honest + flood.take(1_700), 2_000)) // at the cap: nothing goes
        // The same for a flood of introductions, and for packets whose sender can't be checked: each counts as one holder.
        val intros = held("i", 3_000, 10_000) { "introductions" }; val unknown = held("u", 3_000, 20_000) { "not verified" }
        val gone = StoreCap.everyone(honest + intros + unknown, 2_000).toSet()
        assertEquals(4_300, gone.size); assertTrue(gone.none { it.startsWith("h") })
        assertEquals(850, intros.count { it.id !in gone }); assertEquals(850, unknown.count { it.id !in gone })
    }

    @Test fun theEveryoneStoreKeepsThisPhonesOwnAndOtherwiseTheNewest() {
        // No sender over a quarter: the oldest go, as before.
        val many = held("m", 2_100, 1_000) { "sender-${it % 700}" }
        assertEquals((0 until 100).map { "m%05d".format(it) }, StoreCap.everyone(many, 2_000))
        // A sender over a quarter gives up its oldest until it is down to a quarter; then the oldest of all go.
        val honest = held("h", 1_800, 1_000) { "sender-${it % 600}" }; val flood = held("f", 2_500, 10_000) { "flooder" }
        val drop = StoreCap.everyone(honest + flood, 2_000).toSet()
        assertEquals(2_300, drop.size)
        assertEquals(500, flood.count { it.id !in drop }); assertEquals(1_500, honest.count { it.id !in drop })
        assertTrue((0 until 300).all { "h%05d".format(it) in drop })
        // This phone's own packets, the oldest of all here, stay while anything else can go.
        val own = held("o", 50, 10, own = true) { "me" }
        val kept = StoreCap.everyone(own + many, 2_000)
        assertEquals(150, kept.size); assertTrue(kept.none { it.startsWith("o") })
        assertEquals(listOf("o00000", "o00001"), StoreCap.everyone(own, 48))  // only own left: the oldest of them
    }

    // ---- 8. The Everyone introduction goes out only for someone who posts there ----

    @Test fun aPhoneIntroducesItselfOnEveryoneOnlyWhenItsUserPostsThere() {
        val now = t0; val day = 24 * 3_600_000L
        assertFalse("never posted: nothing at app start", PublicIntro.wanted(writing = false, lastOwnPost = null, now = now))
        assertTrue("writing now", PublicIntro.wanted(writing = true, lastOwnPost = null, now = now))
        assertTrue("a post of theirs is still shown", PublicIntro.wanted(false, now - 6 * day, now))
        assertFalse("their last post is gone", PublicIntro.wanted(false, now - 7 * day, now))
    }
}
