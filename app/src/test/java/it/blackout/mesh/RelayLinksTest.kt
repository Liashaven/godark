package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * What a relay or a neighbour could learn about which groups a phone is in, and two races between the relay links and
 * the Internet and Tor switches (audit of 2026-11). Each of these failed before its fix. The iPhone's RelayLinksTests
 * check the same rules, except the two races, which only Android had. Dummy packets and mailboxes only; no socket.
 *
 * NostrLink and RelayScope need Android and sockets, so the tests run the rules they are made of ([Nostr.subId],
 * [Nostr.takes], [Nostr.scope], [MeshRouter], [FromRelays], [LinkSets], [RelaySockets]); [Phone] wires them the way
 * RelayScope's message handler, NostrLink.route and MeshEngine.route do.
 */
class RelayLinksTest {
    private val now = System.currentTimeMillis()
    private val groupOne = 0x6a44; private val groupTwo = 0x1b2c
    private val scopes = linkedMapOf("group-one" to listOf(groupOne), "group-two" to listOf(groupTwo), "" to listOf(Nostr.PUBLIC_MAILBOX))
    /** 98 junk bytes with two hops left: the phone that gets it offers it on once, and no phone after it. */
    private fun junk(id: String, fill: Int, ts: Long = now) = Packet(id, ts, 2, ByteArray(MeshRouter.MIN_SEALED) { fill.toByte() })

    private class Phone(val boxes: Map<String, List<Int>>, saved: String = "", restored: List<Packet> = emptyList()) {
        val delivered = ArrayList<String>()
        val toRelays = ArrayList<String>()              // what the router offered the relay peer
        val mine = HashSet<String>()                    // ids of packets written on this phone
        val fromRelays = FromRelays(saved)
        val outbox = boxes.keys.associateWith { RelayOutbox(jitter = { 0L }) } // one for each link set
        val router: MeshRouter = MeshRouter({ peer, p ->
            if (peer == NostrLink.PEER) { toRelays += p.id; outbox.getValue(Nostr.scope(p.id, p.id in mine, boxes)).offer(p, p.id in mine) }
        }, { delivered += it.id }, minCipher = MeshRouter.MIN_SEALED)
        init { router.restore(restored, restored.map(MeshRouter::key)) { if (it in fromRelays) NostrLink.PEER else "" } }

        /** A relay sends [p] on a link of [scope]'s link set, while that set's lookup names [asked]. */
        fun relaySends(scope: String, p: Packet, asked: Set<String> = emptySet()) {
            if (!Nostr.takes(p, boxes.getValue(scope), asked)) return
            if (router.receive(NostrLink.PEER, p)) fromRelays.add(p)
        }
        fun queued() = outbox.mapValues { it.value.queued() }
    }
    private fun nothingQueued(p: Phone) = p.boxes.keys.associateWith { 0 }

    // ---- the subscription id ----

    // The ids were the phone's clock in base 36: on the links of one phone they were microseconds apart.
    @Test fun aSubscriptionIdSaysNothingAboutThePhoneOrItsOtherLinkSets() {
        val ids = (1..50).map { Nostr.subId("live") }
        assertTrue(ids.all { it.startsWith("live") && it.length == 4 + 16 && it.drop(4).all { c -> c in '0'..'9' || c in 'a'..'f' } })
        val values = ids.map { it.drop(4).toULong(16) }.sorted()
        assertEquals(50, values.toSet().size)
        // Ids made one after another, as NostrLink.resubscribe makes them for every link set, are nowhere near each other.
        assertTrue(values.zipWithNext().all { (a, b) -> b - a > (1uL shl 32) })
        // Read the way the audit read them, as a base 36 number, none is this phone's clock.
        val clocks = listOf(System.nanoTime(), System.currentTimeMillis())
        for (id in ids + Nostr.subId("have")) {
            val v = id.drop(4).toLongOrNull(36) ?: continue
            assertTrue(clocks.none { kotlin.math.abs(v - it) < 3_600_000_000_000L })
        }
        assertNotEquals(Nostr.subId("have"), Nostr.subId("have"))
    }

    // ---- what a link set takes ----

    @Test fun aLinkSetTakesOnlyPacketsOfItsOwnMailboxesAndAnswersToItsLookup() {
        val own = junk("6a4400000000c001", 1); val other = junk("1b2c00000000c002", 2); val foreign = junk("beef00000000c003", 3)
        assertTrue(Nostr.takes(own, listOf(groupOne), emptySet()))
        assertFalse(Nostr.takes(other, listOf(groupOne), emptySet()))   // another group of this phone
        assertFalse(Nostr.takes(foreign, listOf(groupOne), emptySet())) // nobody's here
        assertFalse(Nostr.takes(own, listOf(Nostr.PUBLIC_MAILBOX), emptySet()))
        assertTrue(Nostr.takes(foreign, listOf(Nostr.PUBLIC_MAILBOX), setOf(foreign.id))) // the Everyone links asked for it
        assertFalse(Nostr.takes(foreign, listOf(Nostr.PUBLIC_MAILBOX), setOf(other.id)))
    }

    // A relay sent junk on group one's link; after the links came back it was looked up and posted on the Everyone
    // links, or on group two's when its id began with group two's mailbox. The relay then knew all three were one phone.
    @Test fun whatARelaySendsOnOneGroupsLinkIsNeverNamedOnAnotherLinkSet() {
        val phone = Phone(scopes)
        phone.router.peerUp(NostrLink.PEER)
        val a = junk("beef00000000c301", 0x41) // mailbox beef: none of this phone's
        val b = junk("1b2c00000000c302", 0x42) // mailbox 1b2c: group two's
        val c = junk("6a4400000000c304", 0x44) // group one's own mailbox: this one the link takes
        listOf(a, b, c).forEach { phone.relaySends("group-one", it) }
        assertEquals(listOf(c.id), phone.delivered)
        phone.router.peerDown(NostrLink.PEER); phone.router.peerUp(NostrLink.PEER) // every relay link lost, then one is back
        assertEquals(emptyList<String>(), phone.toRelays)
        assertEquals(nothingQueued(phone), phone.queued())
    }

    // The phone gave its newest stored packets back to the router at start with no word on where they came from, and
    // the router offered all of them to the relays.
    @Test fun afterARestartWhatTheRelaysBroughtStillDoesntGoBackUp() {
        val first = Phone(scopes)
        first.router.peerUp(NostrLink.PEER)
        val one = junk("6a4400000000c305", 0x45); val two = junk("1b2c00000000c306", 0x46); val all = junk("957600000000c307", 0x47)
        first.relaySends("group-one", one); first.relaySends("group-two", two); first.relaySends("", all)
        val neighbours = junk("beef00000000c308", 0x48)
        first.router.receive("ble:neighbour", neighbours)
        assertEquals(listOf(one.id, two.id, all.id, neighbours.id), first.delivered)
        val stored = listOf(one, two, all, neighbours)

        val second = Phone(scopes, first.fromRelays.save(), stored) // the restart
        assertEquals(emptyList<String>(), second.delivered)         // nothing is shown twice
        second.router.peerUp(NostrLink.PEER)
        assertEquals(listOf(neighbours.id), second.toRelays)        // bridging goes on; what the relays sent is named on no link
        assertEquals(mapOf("group-one" to 0, "group-two" to 0, "" to 1), second.queued())

        // A phone that kept nothing about where its packets came from bridges them all, as before: nothing else holds them back.
        val forgot = Phone(scopes, "", stored)
        forgot.router.peerUp(NostrLink.PEER)
        assertEquals(stored.map { it.id }, forgot.toRelays)
    }

    @Test fun whatCameFromTheRelaysIsRememberedByPacketTimeSoAFloodCantPushItOut() {
        val f = FromRelays(max = 3)
        val kept = (1..3).map { junk("6a44%012x".format(it), it, now + it) }
        kept.forEach(f::add)
        assertTrue(f.changed)
        // After a restart the phone passes on its newest packets. Any number of older ones doesn't push those out of here.
        repeat(200) { f.add(junk("6a44%012x".format(1000 + it), it, now - 1000 - it)) }
        assertEquals(3, f.size()); assertTrue(kept.all { MeshRouter.key(it) in f })
        f.add(junk("6a440000000000ff", 9, now + 10))              // a newer one takes the place of the oldest
        assertFalse(MeshRouter.key(kept[0]) in f); assertTrue(MeshRouter.key(kept[2]) in f)
        val again = FromRelays(f.save(), 3)
        assertFalse(again.changed); assertEquals(3, again.size()); assertTrue(MeshRouter.key(kept[1]) in again)
        assertFalse(MeshRouter.key(kept[1].let { Packet(it.id, it.ts, it.ttl, ByteArray(98) { 0x7f }) }) in again) // junk under its id is another packet
        assertEquals(0, FromRelays("nonsense,=5,x=y,").size())
    }

    // ---- which link set a packet goes up on ----

    // The link set was picked by the first 2 bytes of the packet id, which its sender chooses: a neighbour's junk that
    // began with a group's mailbox was posted with that group's key, the key of the phone's own messages there.
    @Test fun aNeighboursPacketGoesUpWithTheEveryoneLinksWhateverMailboxItNames() {
        val boxes = linkedMapOf("group-one" to listOf(groupOne), "" to listOf(Nostr.PUBLIC_MAILBOX))
        assertEquals("", Nostr.scope("6a4400000000c201", false, boxes))
        assertEquals("", Nostr.scope("beef00000000c202", false, boxes))
        assertEquals("group-one", Nostr.scope("6a4400000000c203", true, boxes)) // this phone's own
        assertEquals("", Nostr.scope("957600000000c204", true, boxes))          // its own Everyone message
        assertEquals("", Nostr.scope("beef00000000c205", true, boxes))

        val phone = Phone(boxes)
        phone.router.peerUp(NostrLink.PEER); phone.router.peerUp("wifi:neighbour")
        val test = junk("6a4400000000c201", 0x51)    // begins with the mailbox of the phone's group
        val control = junk("beef00000000c202", 0x52) // a mailbox the phone doesn't have
        phone.router.receive("wifi:neighbour", test); phone.router.receive("wifi:neighbour", control)
        val own = Packet("6a4400000000c203", now, 16, ByteArray(MeshRouter.MIN_SEALED) { 0x53 })
        phone.mine += own.id; phone.router.publish(own)
        assertEquals(listOf(test.id, control.id, own.id), phone.toRelays) // all three still go up: bridging works
        // Both of the neighbour's packets wait on the Everyone links, so they go up under one key, like on a phone without the group.
        assertEquals(setOf(test.id, control.id), phone.outbox.getValue("").toCheck(50).map { it.id }.toSet())
        // The group's links carry only what this phone wrote there.
        val groups = phone.outbox.getValue("group-one")
        assertEquals(1, groups.queued()); assertEquals(own.id, groups.next(bridged = true)?.first?.id)
        assertEquals(0, groups.queued())
    }

    // ---- the router: nothing goes back to the link that brought it ----

    @Test fun aLinkThatComesBackDoesntGetWhatItBroughtButEveryOtherLinkDoes() {
        val sent = ArrayList<String>()
        val r = MeshRouter({ peer, p -> sent += "$peer ${p.id} ttl ${p.ttl}" }, { }, { now })
        val p = junk("6a4400000000c401", 1)
        r.peerUp(NostrLink.PEER)
        assertTrue(r.receive(NostrLink.PEER, p)); assertFalse(r.receive(NostrLink.PEER, p)) // new only once
        r.peerDown(NostrLink.PEER); r.peerUp(NostrLink.PEER)
        assertEquals(emptyList<String>(), sent)
        r.peerUp("ble:a")
        assertEquals(listOf("ble:a ${p.id} ttl 1"), sent)
        // Restored as brought by the relays: the same.
        val again = MeshRouter({ peer, p2 -> sent += "$peer ${p2.id} ttl ${p2.ttl}" }, { }, { now })
        sent.clear(); again.peerUp(NostrLink.PEER)
        again.restore(listOf(p), listOf(MeshRouter.key(p))) { NostrLink.PEER }
        again.peerDown(NostrLink.PEER); again.peerUp(NostrLink.PEER); again.peerUp("ble:a")
        assertEquals(listOf("ble:a ${p.id} ttl 1"), sent)
    }

    // What comes back after a restart is the newest packets, whoever brought them. If knowing that a relay brought a
    // packet made it go first, like the packets of a link that holds too many, an older relay packet that a flood had
    // pushed out of [FromRelays] would stay instead, with nothing to say it came from a relay, and go back up.
    @Test fun afterARestartTheNewestPacketsComeBackWhoeverBroughtThem() {
        val sent = ArrayList<String>()
        val r = MeshRouter({ peer, p -> sent += "$peer ${p.id}" }, { }, { now }, maxStored = 4)
        val old = (1..2).map { junk("6a44%012x".format(it), it, now - 10_000 + it) }      // forgotten: no word on who brought them
        val newer = (1..4).map { junk("6a44%012x".format(100 + it), it, now - 1_000 + it) } // known to be from the relays
        val relayed = newer.map(MeshRouter::key).toSet()
        r.restore(old + newer, emptyList()) { if (it in relayed) NostrLink.PEER else "" }
        r.peerUp(NostrLink.PEER)
        assertEquals(emptyList<String>(), sent)
        r.peerUp("ble:a")
        assertEquals(newer.map { "ble:a ${it.id}" }, sent)
        r.receive("ble:b", old[0]); assertEquals(4, sent.size) // the older ones were still marked as seen: not taken as new
    }

    // The first copy's ttl still doesn't decide how far a packet goes: a copy another link brought with more hops left
    // goes to the first link as well, when it comes back.
    @Test fun aCopyWithMoreHopsFromAnotherLinkGoesToTheFirstLinkToo() {
        val sent = ArrayList<String>()
        val r = MeshRouter({ peer, p -> sent += "$peer ${p.id} ttl ${p.ttl}" }, { }, { now })
        val p = junk("6a4400000000c402", 2)
        r.receive("ble:a", p); r.peerDown("ble:a")
        assertFalse(r.receive("ble:b", p.withTtl(10)))
        r.peerUp("ble:a")
        assertEquals(listOf("ble:a ${p.id} ttl 9"), sent)
    }

    // ---- Android: the Internet and Tor switches ----

    // NostrLink.sync checked that the link ran, read the scopes and only then took the lock: a stop() in between
    // (the Internet or Tor switch) emptied the map, and sync then made and started new link sets in the stopped link,
    // with its old Tor setting, where nothing ever stopped them.
    @Test fun aLinkStoppedDuringAResubscribeGetsNoNewLinkSets() {
        val made = CopyOnWriteArrayList<String>(); val started = CopyOnWriteArrayList<String>()
        val sets = LinkSets<String>({ id -> "set of '$id'".also { made += it } }, { started += it })
        val two = linkedMapOf("group" to listOf(0x1111), "" to listOf(Nostr.PUBLIC_MAILBOX))
        assertNull("not started yet", sets.sync { two })
        sets.start()
        assertEquals(emptyList<String>(), sets.sync { two })
        assertEquals(2, sets.all().size); assertEquals(made.toList(), started.toList()); assertEquals(two, sets.boxes)

        val reading = CountDownLatch(1); val goOn = CountDownLatch(1)
        var result: List<String>? = emptyList()
        val resubscribe = thread { result = sets.sync { reading.countDown(); goOn.await(5, TimeUnit.SECONDS); two + ("new group" to listOf(0x2222)) } }
        assertTrue(reading.await(5, TimeUnit.SECONDS))
        assertEquals(2, sets.stop().size) // the switch: the caller stops these two
        goOn.countDown(); resubscribe.join(5_000)
        assertNull(result)                // the resubscribe found the link stopped
        assertEquals(0, sets.all().size); assertEquals(2, made.size); assertEquals(2, started.size)
        assertNull(sets["new group"]); assertNull(sets[""])

        sets.start() // a link that is started again works as before
        assertEquals(emptyList<String>(), sets.sync { mapOf("" to listOf(Nostr.PUBLIC_MAILBOX)) })
        assertEquals(listOf("set of ''"), sets.all())
        assertEquals(listOf("set of ''"), sets.sync { emptyMap() }) // a scope that is gone: the caller stops its link set
    }

    // With Tor, a loss while no relay was open started a Tor check and also scheduled the usual reconnect. Both then
    // connected the same relay; the second socket replaced the first in the map, and the first stayed open, untracked:
    // stop() didn't close it, and the router still took what it sent.
    @Test fun aLinkSetHasOneSocketForEachRelayAndHandlesNothingFromAnyOther() {
        val sockets = RelaySockets<Any>()
        val afterTorCheck = Any()
        assertTrue(sockets.connect("wss://relay.example") { afterTorCheck })
        var opened = 0
        assertFalse(sockets.connect("wss://relay.example") { opened++; Any() }) // the reconnect that was scheduled as well
        assertEquals(0, opened); assertEquals(1, sockets.size())
        assertTrue(sockets.tracks("wss://relay.example", afterTorCheck))
        val stray = Any()
        assertFalse(sockets.tracks("wss://relay.example", stray)); assertFalse(sockets.lost("wss://relay.example", stray))
        val other = Any()
        assertTrue(sockets.connect("wss://other.example") { other })              // another relay has its own
        assertTrue(sockets.lost("wss://other.example", other))
        assertTrue(sockets.connect("wss://other.example") { Any() })              // after a loss the relay is linked again
        assertEquals(2, sockets.close().size)                                     // stop(): every socket is handed back to be closed
        assertFalse(sockets.tracks("wss://relay.example", afterTorCheck))         // nothing it still sends is handled
        assertFalse(sockets.connect("wss://relay.example") { opened++; Any() })   // and a reconnect that was still waiting opens nothing
        assertEquals(0, opened); assertEquals(0, sockets.size())
    }

    // A callback of a new socket can run before connect() has returned. It waits until the socket is tracked.
    @Test fun aSocketIsTrackedBeforeItsCallbacksAreAnswered() {
        val sockets = RelaySockets<Any>(); val socket = Any()
        val opening = CountDownLatch(1); var tracked: Boolean? = null
        var callback: Thread? = null
        sockets.connect("wss://relay.example") {
            callback = thread { opening.countDown(); tracked = sockets.tracks("wss://relay.example", socket) }
            opening.await(5, TimeUnit.SECONDS); Thread.sleep(50)
            socket
        }
        callback!!.join(5_000)
        assertEquals(true, tracked)
    }
}
