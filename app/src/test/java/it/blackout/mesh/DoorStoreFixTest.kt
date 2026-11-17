package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * What someone who only holds a group's code, or an ordinary member, can do to other phones' stored messages and keys:
 * found in the 2026-11-13 audit. The iPhone's DoorStoreFixTests check the same. Dummy keys only.
 */
class DoorStoreFixTest {
    private val hour = 3600_000L; private val day = 24 * hour; private val now = 1_000 * day
    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"; private val dan = "4444444444444444"
    private val all = listOf(anna, ben, cara)
    private fun secret(b: Int) = ByteArray(32) { (b * 31 + it).toByte() }
    private fun id(i: Int) = "%016x".format(0xF0000 + i)
    /** A new key from the member whose signing key is [by] bytes; a part is opened by handing its box back. */
    private fun key(n: Long, made: Long, s: Int, members: List<String> = all) =
        Rekey(n, made, ByteArray(33), listOf(anna), null, members.map { it to Rekey.box(secret(s), null) })
    /** Epoch [n], a day old: Anna (admin), Ben and Cara. */
    private fun ring(n: Long = 5) = Keyring().also { it.add(Keyring.Epoch.fresh(n, now - day, secret(n.toInt()), all, listOf(anna), taken = now - day)) }

    // ---- 1. Door packets: anyone with the code can write them, so they are not the group's own ----

    @Test fun aFloodThroughTheDoorNeverPushesAMessageOut() {
        val kept = (1..200).map { StoreCap.Entry("m$it", 1_000L + it, 300, StoreCap.Kind.GROUP) } +
            (1..5).map { StoreCap.Entry("p$it", 1_000L + it, 300, StoreCap.Kind.PUBLIC) } + (1..5).map { StoreCap.Entry("u$it", 1_000L + it, 300, StoreCap.Kind.UNREADABLE) }
        // Forged new keys of the largest size, dated newest: enough to fill the whole store.
        val forged = (1..2_881).map { StoreCap.Entry("f$it", 9_000L + it, 16_018, StoreCap.Kind.DOOR) }
        val gone = StoreCap.overflow(kept + forged).toSet()
        assertTrue("only door packets go", gone.all { it.startsWith("f") })
        assertTrue(forged.filter { it.id !in gone }.sumOf { it.size.toLong() } <= StoreCap.DOOR_BYTES)
        assertTrue("the oldest of them first", "f1" in gone && "f2881" !in gone)
        // The smallest introductions, more of them than the store holds packets.
        val small = (1..21_001).map { StoreCap.Entry("i$it", 9_000L + it, 181, StoreCap.Kind.DOOR) }
        val gone2 = StoreCap.overflow(kept + small).toSet()
        assertTrue(gone2.all { it.startsWith("i") }); assertEquals(StoreCap.DOOR_COUNT, small.size - gone2.size)
        // Classed like the group's own packets, as they were, the same flood removed every message.
        assertTrue(StoreCap.overflow(kept + forged.map { StoreCap.Entry(it.id, it.ts, it.size, StoreCap.Kind.GROUP) }).count { it.startsWith("m") } == 200)
    }

    @Test fun doorPacketsWithinTheirRoomGoAfterJunkAndBeforeMessages() {
        val e = listOf(StoreCap.Entry("g1", 1, 100, StoreCap.Kind.GROUP), StoreCap.Entry("d1", 2, 100, StoreCap.Kind.DOOR), StoreCap.Entry("p1", 3, 100, StoreCap.Kind.PUBLIC),
            StoreCap.Entry("u1", 4, 100, StoreCap.Kind.UNREADABLE), StoreCap.Entry("d2", 5, 100, StoreCap.Kind.DOOR))
        assertEquals(emptyList<String>(), StoreCap.overflow(e, maxBytes = 500, maxCount = 5))
        assertEquals(listOf("u1", "d1", "d2", "p1"), StoreCap.overflow(e, maxBytes = 100, maxCount = 5))
        assertEquals("their own room first", listOf("d1"), StoreCap.overflow(e, maxBytes = 10_000, maxCount = 5, doorCount = 1))
        assertEquals(listOf("d1", "d2", "u1"), StoreCap.overflow(e, maxBytes = 200, maxCount = 5, doorBytes = 0))
        assertFalse(StoreCap.doorFull(2 * StoreCap.DOOR_COUNT, 2 * StoreCap.DOOR_BYTES))
        assertTrue(StoreCap.doorFull(2 * StoreCap.DOOR_COUNT + 1, 0)); assertTrue(StoreCap.doorFull(1, 2 * StoreCap.DOOR_BYTES + 1))
    }

    @Test fun whoWroteADoorPacketDecidesItsClass() {
        val r = ring()
        assertTrue(r.inGroup(ben)); assertFalse("someone who only holds the code", r.inGroup(dan))
        assertFalse("a phone still joining knows nobody", Keyring().inGroup(anna))
        // Anna removes Cara: the epoch before still lists her, but what she sends through a door is no longer the group's.
        r.add(Keyring.Epoch.fresh(6, now, secret(6), listOf(anna, ben), listOf(anna), "AAAA-AAAA-AAAA-AAAA", "d1", cara, anna, 0, now))
        assertFalse(r.inGroup(cara)); assertTrue(cara in r.everyone()); assertTrue(r.inGroup(ben))
        assertEquals(StoreCap.Kind.GROUP, StoreCap.door(mine = false, member = r.inGroup(ben)))
        assertEquals(StoreCap.Kind.DOOR, StoreCap.door(mine = false, member = r.inGroup(cara)))
        assertEquals(StoreCap.Kind.DOOR, StoreCap.door(mine = false, member = r.inGroup(dan)))
        assertEquals("a phone's own request to join stays", StoreCap.Kind.GROUP, StoreCap.door(mine = true, member = false))
    }

    // ---- 2. Join requests: a made-up key costs nothing ----

    /** What the engines do with a checked introduction: keep its key or not ([Joining.keeps]). */
    private class Directory(val me: String, val members: Set<String>, val now: Long) {
        val known = LinkedHashMap<String, Long>(); var declined = setOf<String>()
        fun asking() = Joining.asking(known, members, declined, me, now)
        fun arrive(id: String, at: Long): Boolean {
            if (id !in known && !Joining.keeps(id, asking(), members, me)) return false
            known[id] = at; return true
        }
    }

    @Test fun aFloodOfMadeUpKeysCannotCrowdOutARealRequest() {
        val d = Directory(anna, setOf(anna, ben), now); val real = id(0)
        assertTrue(d.arrive(real, now - hour))
        // 500 made-up keys, dated as far back as a packet can be so as to sort first.
        assertEquals(Joining.MAX_ASKING - 1, (1..500).count { d.arrive(id(it), now - 6 * day) })
        assertEquals(Joining.MAX_ASKING, d.asking().size); assertTrue("the real request is still there", real in d.asking())
        assertEquals("nothing more is saved", Joining.MAX_ASKING, d.known.size)
        assertTrue("a member's key is always kept", d.arrive(ben, now)); assertFalse(ben in d.asking())
        assertTrue("and a request that is already there can be updated", d.arrive(real, now))
        // Turning one down makes room for one more; so does a request that is a week old.
        d.declined = setOf(id(1)); assertTrue(d.arrive(id(600), now)); assertFalse(d.arrive(id(601), now))
        d.known[id(2)] = now - 8 * day; assertFalse(id(2) in d.asking()); assertTrue(d.arrive(id(602), now))
        assertEquals(Joining.MAX_ASKING, d.asking().size)
    }

    @Test fun moreRequestsThanTheRoomSavedEarlierAreNotAllShown() {
        val known = (1..300).associate { id(it) to now - it * 1_000L }
        val shown = Joining.asking(known, setOf(anna), emptySet(), anna, now)
        assertEquals(Joining.MAX_ASKING, shown.size); assertEquals(id(300), shown.first())
        assertEquals(emptyList<String>(), Joining.asking(known, known.keys, emptySet(), anna, now))
    }

    @Test fun joinAlertsComeAtMostOnceAMinute() {
        assertTrue(Joining.alertDue(0, now)); assertFalse(Joining.alertDue(now - 59_000, now)); assertTrue(Joining.alertDue(now - 60_000, now))
        assertTrue("a clock set back doesn't silence them", Joining.alertDue(now + hour, now))
    }

    // ---- 3. Stored new keys are read again at every start ----

    @Test fun aDeletedEpochDoesNotComeBackFromItsStoredNewKey() {
        val t0 = now; val r = ring()
        val six = key(6, t0, 6); val seven = key(7, t0 + day, 7)
        assertTrue(r.take(six, anna, ben, "door", false, null, t0) { it } is Keyring.Taken.Added)
        assertTrue(r.take(seven, anna, ben, "door", false, null, t0 + day) { it } is Keyring.Taken.Added)
        assertEquals(listOf(5L, 6L), r.expire(t0 + 9 * day).map { it.number }.sorted())
        var opened = 0
        assertTrue(r.take(six, anna, ben, "door", false, null, t0 + 9 * day) { opened++; it } is Keyring.Taken.Ignored)
        assertEquals("the part isn't even opened", 0, opened); assertEquals(listOf(7L), r.all().map { it.number })
        // A phone that no longer knows which parts it opened refuses it too: the epoch is past its week.
        val again = Keyring().also { it.add(Keyring.Epoch.fresh(7, t0 + day, secret(7), all, listOf(anna), by = anna, taken = t0 + day)) }
        assertTrue(again.take(six, anna, ben, "door", false, null, t0 + 9 * day) { opened++; it } is Keyring.Taken.Ignored)
        assertEquals(0, opened)
    }

    @Test fun aKeyThatArrivesLateWithinItsWeekIsStillTaken() {
        // A phone that was away gets epoch 7 first and then 6: it reads what was written with 6 for another week.
        val r = ring()
        assertTrue(r.take(key(7, now - 2 * day, 7), anna, ben, "door", false, null, now) { it } is Keyring.Taken.Added)
        val t = r.take(key(6, now - 6 * day, 6), anna, ben, "door", false, null, now + hour) { it }
        assertTrue(t is Keyring.Taken.Added); assertEquals(7L, r.current().number); assertTrue(r.all().any { it.number == 6L && it.messageKeys != null })
        assertTrue(r.expire(now + 6 * day).isEmpty()); assertEquals(listOf(5L, 6L), r.expire(now + 8 * day).map { it.number }.sorted())
    }

    @Test fun aPartIsOpenedOnceAlsoAfterARestart() {
        val r = ring(); val six = key(6, now, 6); var opened = 0
        assertFalse(r.partsToSave())
        assertTrue(r.take(six, anna, ben, "door", false, null, now) { opened++; it } is Keyring.Taken.Added)
        assertTrue(r.partsToSave()); assertFalse(r.partsToSave()); assertEquals(1, r.openedParts().size)
        repeat(5) { assertTrue(r.take(six, anna, ben, "door", false, null, now + it) { opened++; it } is Keyring.Taken.Ignored) }
        assertEquals("read again from the store: not opened again", 1, opened)
        // After a restart the engine gives the keyring its epochs and the parts it opened.
        val next = Keyring().also { k -> r.all().forEach(k::add); k.restoreParts(r.openedParts()) }
        assertTrue(next.take(six, anna, ben, "door", false, null, now + hour) { opened++; it } is Keyring.Taken.Ignored); assertEquals(1, opened)
        // The same box in someone else's key is another part: one secret can travel in two keys.
        assertTrue(next.take(key(6, now + 1, 6), cara, ben, "door", false, null, now + hour) { opened++; it } is Keyring.Taken.Added); assertEquals(2, opened)
        assertNotEquals(Keyring.partMark(ByteArray(40), anna, six), Keyring.partMark(ByteArray(40), ben, six))
    }

    // ---- 4. One id, several packets ----

    @Test fun thePacketStoredFirstUnderAnIdGoesByItAndTheOthersByTheirKey() {
        val a = Packet("00000000000000a1", now, 16, ByteArray(98) { 1 }); val b = Packet(a.id, now, 16, ByteArray(98) { 2 })
        assertEquals(a.id, StoreCap.name(a, first = true)); assertEquals(MeshRouter.key(b), StoreCap.name(b, first = false))
        assertNotEquals(StoreCap.name(a, false), StoreCap.name(b, false)); assertEquals(StoreCap.name(b, false), StoreCap.name(b.withTtl(3), false))
        assertEquals(a.id, StoreCap.packetId(StoreCap.name(b, false))); assertEquals(a.id, StoreCap.packetId(a.id))
    }

    @Test fun theSameSignedMessageHasOneMarkAndAnotherMessageUnderItsIdAnother() {
        val g = GroupCrypto.fromSecret(ByteArray(32) { 7 }); val id = "%04x".format(g.mailbox) + "000000000009"; val t = 1_800_000_000_000L
        fun open(text: String, iv: Int, sender: String = ben) = g.seal(id, t, sender, "Ben", text, iv = ByteArray(12) { iv.toByte() }).let { g.openSigned(Packet(id, g.hideTime(t, it), 16, it))!! }
        val first = open("dummy text", 1); val again = open("dummy text", 2); val other = open("another text", 3); val others = open("dummy text", 4, cara)
        assertNotEquals("two packets", first.key, again.key)
        assertEquals("one message, sealed and signed again", first.mark, again.mark)
        assertNotEquals(first.mark, other.mark); assertNotEquals(first.mark, others.mark)
        assertTrue(first.mark.startsWith("$id:")); assertEquals(33, first.mark.length)
    }

    // ---- 5. The 64 epochs a phone holds ----

    @Test fun aMembersOldKeysDoNotPushOutTheEpochsBefore() {
        val r = Keyring()
        for (n in 5L..7L) r.add(Keyring.Epoch.fresh(n, now - (8 - n) * day, secret(n.toInt()), all, listOf(anna), taken = now - (8 - n) * day))
        // Ben, a member: keys numbered below the current epoch, dated an hour apart, four an hour as they arrive.
        for (i in 1..70) r.take(key(6, now - i * hour, 100 + i), ben, anna, "door", false, null, now + i * 16 * 60_000L) { it }
        assertEquals("the group's own epochs stay", listOf(5L, 6L, 7L), r.all().filter { it.members.isNotEmpty() }.map { it.number }.sorted())
        assertEquals("one maker has only a few kept to read with", 4, r.all().count { it.members.isEmpty() && it.by == ben })
        assertEquals(7L, r.current().number)
    }

    @Test fun aFullKeyringDropsWhatIsKeptOnlyToReadWithFirst() {
        val r = Keyring()
        for (n in 1L..60L) r.add(Keyring.Epoch(n, now, secret(n.toInt()), all, listOf(anna)))
        // Keys kept only to read with, from many makers, numbered above most of the group's own.
        for (i in 1..10) r.add(Keyring.Epoch(59, now, secret(100 + i), emptyList(), listOf(anna), by = id(i)))
        assertEquals(64, r.all().size); assertEquals((1L..60L).toList(), r.all().filter { it.members.isNotEmpty() }.map { it.number }.sorted())
        // With nothing of that kind left to drop, the lowest goes, as before.
        val full = Keyring(); for (n in 1L..70L) full.add(Keyring.Epoch(n, now, secret(n.toInt()), all, listOf(anna)))
        assertEquals((7L..70L).toList(), full.all().map { it.number }.sorted())
    }

    // ---- 6. Parts that don't open ----

    @Test fun partsThatDoNotOpenAreTriedOnlyAFewTimesAnHour() {
        val r = ring(); var tries = 0
        // Ben, a member, sends 50 keys whose part for this phone is garbage: each try is a key agreement in secure hardware.
        val got = (1..50).map { r.take(key(6, now, 200 + it), ben, anna, "door", false, null, now + it) { tries++; null } }
        assertEquals(4, tries); assertTrue("each still counts as a key this phone was left out of", got.all { it is Keyring.Taken.LeftOut })
        // Another member's key is tried, and opens.
        assertTrue(r.take(key(6, now, 300), cara, anna, "door", false, null, now + 60) { tries++; it } is Keyring.Taken.Added); assertEquals(5, tries)
        // An hour later Ben's are tried again.
        r.take(key(7, now + hour, 301), ben, anna, "door", false, null, now + hour + 100) { tries++; null }; assertEquals(6, tries)
    }

    @Test fun aPhoneStillJoiningStopsTryingWhateverTheMaker() {
        // With a typed code anyone who holds it can send a first key, each under a key pair made for it.
        val r = Keyring(); var tries = 0
        for (i in 1..200) r.take(Rekey(1, now, ByteArray(33), listOf(id(i)), dan, listOf(id(i), dan).map { it to ByteArray(40) }), id(i), dan, "door", false, null, now + i) { tries++; null }
        assertEquals(16, tries); assertNull(r.currentOrNull())
        // An hour later the key that lets it in is opened.
        assertTrue(r.take(Rekey(6, now + hour, ByteArray(33), listOf(anna), dan, (all + dan).map { it to Rekey.box(secret(9), null) }), anna, dan, "door", false, null, now + hour + 300) { tries++; it } is Keyring.Taken.Added)
    }

    // ---- 7. "That phone is behind" ----

    @Test fun aKeyDatedFarAheadIsNotFromAPhoneThatFellBehind() {
        val r = ring(7)
        assertFalse("no key made later could ever be newer than this", r.behind(Rekey(6, now + 400 * day, ByteArray(33), emptyList(), null, emptyList()), ben, now))
        assertFalse(r.behind(key(6, now + 11 * 60_000L, 1), ben, now))
        assertFalse("not from someone who isn't in", r.behind(key(6, now, 1), dan, now))
        assertFalse("made before the current epoch", r.behind(key(6, now - 2 * day, 1), ben, now))
        assertTrue("clocks differ by minutes", r.behind(key(6, now + 9 * 60_000L, 1), ben, now))
    }

    @Test fun oneMemberIsAnsweredOnceAnHour() {
        val r = ring(7)
        assertTrue(r.behind(key(6, now - 60_000, 1), ben, now))
        assertFalse((2..50).any { r.behind(key(6, now - 60_000 + it, it), ben, now + it * 1_000L) })
        assertTrue("another member's phone can be behind too", r.behind(key(6, now - 60_000, 60), cara, now + 60_000))
        assertTrue("an hour later Ben's is answered again", r.behind(key(6, now + hour, 61), ben, now + hour))
    }

    // ---- 8. Reading a new key before its signature is checked ----

    @Test fun aNewKeyThatListsTooManyIsNotRead() {
        val key33 = ByteArray(33); val many = (1..101).map(::id)
        assertNull("101 members", Rekey.decode(Rekey(6, 1, key33, listOf(anna), null, Rekey.split(many)[0].map { it to ByteArray(1) }, false, many).encode()))
        assertNull("101 admins", Rekey.decode(Rekey(6, 1, key33, many, null, listOf(anna to ByteArray(1))).encode()))
        assertNull("11 parts", Rekey.decode(Rekey(6, 1, key33, listOf(anna), null, many.take(11).map { it to ByteArray(1) }).encode()))
        // As many member ids as a packet holds, and parts that all name the last one: not even the lists are read.
        val huge = Rekey(6, 1, key33, listOf(anna), null, (1..700).map { id(990) to ByteArray(0) }, false, (1..990).map(::id))
        assertNull(Rekey.decode(huge.encode()))
    }

    @Test fun theLargestGroupsKeyIsStillRead() {
        val hundred = (1..100).map(::id)
        for (some in Rekey.split(hundred)) {
            val r = Rekey.decode(Rekey(6, 1, ByteArray(33) { 3 }, hundred, hundred[99], some.map { it to ByteArray(40) { 9 } }, false, hundred).encode())!!
            assertEquals(hundred, r.members); assertEquals(hundred, r.admins); assertEquals(some, r.parts.map { it.first }); assertEquals(hundred[99], r.answers)
        }
        assertEquals("ids read as lowercase hex", "00000000000f0001", Rekey.decode(Rekey(6, 1, ByteArray(33), listOf(id(1)), null, listOf(id(1) to ByteArray(1))).encode())!!.members[0])
        assertEquals("fedcba9876543210", Rekey.decode(Rekey(6, 1, ByteArray(33), listOf("fedcba9876543210"), null, listOf("fedcba9876543210" to ByteArray(1))).encode())!!.admins[0])
    }
}
