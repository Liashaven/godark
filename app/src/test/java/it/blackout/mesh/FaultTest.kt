package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * Simulated phones running the real decision code ([Keyring.take]), given the same new keys in every order
 * (spec/DESIGN-v0.6-groups.md, step 6). The iPhone's FaultTests check the same cases.
 */
class FaultTest {
    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"
    private val dan = "4444444444444444"; private val eve = "5555555555555555"
    private val all = listOf(anna, ben, cara, dan)
    private val now = 1_000_000_000_000L; private val hour = 3600_000L

    private fun secret(b: Int) = ByteArray(32) { b.toByte() }

    private class Pkt(val r: Rekey, val maker: String, val door: String)

    /** Number [n], by [by], sealed for [members], through code [door]. [removes]: a removal to the new code [code]. */
    private fun pkt(n: Long, by: String, members: List<String>, door: String, s: Int, removes: String? = null, code: String? = null,
                    admins: List<String> = listOf(anna, ben), answers: String? = removes, made: Long = now - 100 * hour + n * hour) =
        Pkt(Rekey(n, made, ByteArray(33), admins.filter { it in members }, answers, members.map { it to Rekey.box(secret(s), code) }, removes != null), by, door)

    /** A phone as the engines run one: it reads the store again after every new epoch, oldest first. */
    private inner class Phone(val me: String, admins: List<String> = listOf(anna, ben), joined: Boolean = true) {
        val ring = Keyring().also { if (joined) it.add(Keyring.Epoch(5, now - 200 * hour, secret(99), all, admins)) }
        var door = "d1"; val old = ArrayList<String>(); var removedAt: Pair<Long, Int>? = null; var removedBy: String? = null
        var leftOut: Keyring.Taken.LeftOut? = null
        private val seen = ArrayList<Pkt>()
        fun get(p: Pkt) { seen += p; if (tryIt(p)) settle() }
        private fun tryIt(p: Pkt): Boolean {
            if (p.door != door && p.door !in old) return false
            return when (val t = ring.take(p.r, p.maker, me, p.door, p.door != door, removedAt, now, removedBy = removedBy) { it }) {
                is Keyring.Taken.Added -> { if (t.back) { removedAt = null; removedBy = null }; t.moveTo?.let { if (it != door) { old.add(0, door); door = it } }; true }
                is Keyring.Taken.Removed -> { removedAt = t.number to t.rank; removedBy = t.by; false }
                is Keyring.Taken.LeftOut -> { leftOut = t; false }
                else -> false
            }
        }
        private fun settle() { do { var again = false; for (p in seen.sortedBy { it.r.made }) if (tryIt(p)) again = true } while (again) }
    }

    private fun <T> orders(l: List<T>): List<List<T>> = if (l.size < 2) listOf(l) else l.indices.flatMap { i -> orders(l - l[i]).map { listOf(l[i]) + it } }
    private fun phoneAfter(me: String, ps: List<Pkt>) = Phone(me).also { p -> ps.forEach(p::get) }

    @Test fun twoAdminsRemovingDifferentPeopleAtOnce() {
        val a = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA"); val b = pkt(6, ben, listOf(anna, ben, dan), "d1", 2, cara, "BBBB-BBBB-BBBB-BBBB")
        for (o in orders(listOf(a, b))) {
            for (me in listOf(anna, ben)) phoneAfter(me, o).let { p ->
                assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertEquals(dan, p.ring.current().removes); assertEquals(listOf(cara), p.ring.stillToRemove()); assertNull(p.removedAt)
            }
            phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertNull(it.removedAt) } // told first by the removal that lost: undone
            assertNotNull(phoneAfter(dan, o).removedAt)
            // An admin's phone finishes it: Cara goes too, and the group moves again.
            val finish = pkt(7, anna, listOf(anna, ben), "AAAA-AAAA-AAAA-AAAA", 3, cara, "AAAA-AAAA-AAAA-AAA2")
            for (me in listOf(anna, ben)) phoneAfter(me, o + finish).let { assertEquals("AAAA-AAAA-AAAA-AAA2", it.door); assertTrue(it.ring.stillToRemove().isEmpty()) }
            assertNotNull(phoneAfter(cara, o + finish).removedAt)
        }
    }

    @Test fun adminsRemovingEachOther() {
        val a = pkt(6, anna, listOf(anna, cara, dan), "d1", 1, ben, "AAAA-AAAA-AAAA-AAAA"); val b = pkt(6, ben, listOf(ben, cara, dan), "d1", 2, anna, "BBBB-BBBB-BBBB-BBBB")
        for (o in orders(listOf(a, b))) {
            for (me in listOf(anna, cara, dan)) phoneAfter(me, o).let { p ->
                assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertNull(p.removedAt); assertTrue(p.ring.stillToRemove().isEmpty()); assertFalse(p.ring.removedBefore(anna, now))
            }
            assertNotNull(phoneAfter(ben, o).removedAt)
        }
    }

    @Test fun aRemovedAdminCantComeBackLater() {
        val out = pkt(6, anna, listOf(anna, cara, dan), "d1", 1, ben, "AAAA-AAAA-AAAA-AAAA")
        val join = pkt(7, anna, listOf(anna, cara, dan, eve), "AAAA-AAAA-AAAA-AAAA", 2, admins = listOf(anna), answers = eve)
        val rival = pkt(6, ben, listOf(ben, cara, dan), "d1", 3, anna, "BBBB-BBBB-BBBB-BBBB")
        phoneAfter(cara, listOf(out, join, rival)).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(7L, it.ring.current().number); assertFalse(it.ring.removedBefore(anna, now)) }
        // Nor by picking a higher number, nor with an ordinary new key through the old door.
        phoneAfter(cara, listOf(out, join, pkt(8, ben, listOf(ben, cara, dan), "d1", 4, anna, "BBBB-BBBB-BBBB-BBBB"))).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(7L, it.ring.current().number) }
        phoneAfter(cara, listOf(out, pkt(7, ben, all, "d1", 5))).let { assertEquals(6L, it.ring.current().number) }
    }

    /** The first dummy secret from 4 up whose epoch sorts before the one made from [s]: whoever makes a key picks its secret, and so its hash. */
    private fun lowerThan(s: Int) = (4..99).first { hashOf(it).compareTo(hashOf(s)) < 0 }
    private fun hashOf(b: Int) = Keyring.Epoch.fresh(1, 0, secret(b), listOf(ben), emptyList()).hash

    @Test fun aRemovedAdminWhoLearnsTheNewCodeDecidesNothing() {
        val a = "AAAA-AAAA-AAAA-AAAA"
        val out = pkt(6, anna, listOf(anna, cara, dan), "d1", 1, ben, a)
        val rival = pkt(6, ben, listOf(ben, cara, dan), "d1", 3, anna, "BBBB-BBBB-BBBB-BBBB")           // allowed through the old door; it loses
        val crossed = pkt(6, dan, all, "d1", 2)                                                         // a member's key that crossed the removal
        val key = pkt(7, ben, listOf(ben, cara, dan), a, 4, admins = listOf(ben))
        val removal = pkt(7, ben, listOf(ben, cara, dan), a, 5, anna, "BBBB-BBBB-BBBB-BBB2", admins = listOf(ben))
        // Either of those still lists him as an admin. Through the new door his next key is refused all the same.
        for (held in listOf(listOf(out, rival), listOf(crossed, out))) for (next in listOf(key, removal)) for (o in orders(held + next)) for (me in listOf(cara, anna)) phoneAfter(me, o).let { p ->
            assertEquals(a, p.door); assertEquals(6L, p.ring.current().number); assertEquals(anna, p.ring.current().by)
            assertFalse(p.ring.removedBefore(anna, now)); assertNull(p.removedAt)
        }
        // Nor does the admin list he wrote in his rival removal give anyone else a say.
        val list = pkt(6, ben, listOf(ben, cara, dan), "d1", 3, anna, "BBBB-BBBB-BBBB-BBBB", admins = listOf(ben, dan))
        assertEquals(6L, phoneAfter(cara, listOf(out, list, pkt(7, dan, listOf(cara, dan), a, 8, admins = listOf(dan)))).ring.current().number)
        // A removal he numbers below his own, to have it judged against an epoch in which he still was an admin, is refused too.
        val p = Phone(cara).also { it.ring.add(Keyring.Epoch(4, now - 300 * hour, secret(98), all, listOf(anna, ben))) }
        p.get(out)
        for (door in listOf("d1", a)) p.get(pkt(5, ben, listOf(anna, ben, cara), door, 6, dan, "CCCC-CCCC-CCCC-CCCC"))
        assertFalse(p.ring.removedBefore(dan, now)); assertTrue(p.ring.stillToRemove().isEmpty()); assertEquals(a, p.door)
    }

    @Test fun aLateKeyThroughTheOldDoorCantRaiseARemovedAdminsSeniority() {
        val a = "AAAA-AAAA-AAAA-AAAA"
        for (admins in listOf(listOf(dan, anna, ben), listOf(anna, ben))) {                             // Anna removes Ben, who is listed after her
            val key = pkt(6, anna, all, "d1", 1, admins = admins); val out = pkt(7, anna, listOf(anna, cara, dan), "d1", 2, ben, a, admins = admins)
            val late = pkt(6, ben, all, "d1", 3, admins = listOf(ben))                                  // kept only to read with, and it names him alone
            val rival = pkt(7, ben, listOf(ben, cara, dan), "d1", lowerThan(2), anna, "BBBB-BBBB-BBBB-BBBB", admins = listOf(ben))
            for (me in listOf(cara, anna)) Phone(me, admins).also { p -> listOf(key, out, late, rival).forEach(p::get) }.let { p ->
                assertEquals(admins.indexOf(ben), p.ring.rank(rival.r, ben))
                assertEquals(a, p.door); assertEquals(anna, p.ring.current().by); assertFalse(p.ring.removedBefore(anna, now)); assertNull(p.removedAt)
            }
        }
    }

    @Test fun aLateRivalRemovalByAnAdminRemovedSinceCountsForNothing() {
        val a = "AAAA-AAAA-AAAA-AAAA"; val a2 = "AAAA-AAAA-AAAA-AAA2"
        // Anna removes Dan (6), then Ben (7). Ben still knows the code from before 6, when he was an admin.
        fun check(me: String, admins: List<String>, named: String) {
            val r1 = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, a, admins = admins); val r2 = pkt(7, anna, listOf(anna, cara), a, 2, ben, a2, admins = admins)
            val p = Phone(me, admins); listOf(r1, r2).forEach(p::get)
            p.get(pkt(6, ben, listOf(anna, ben, cara) - named, "d1", 3, named, "CCCC-CCCC-CCCC-CCCC", admins = listOf(ben)))
            assertTrue(p.ring.stillToRemove().isEmpty()); assertEquals(a2, p.door); assertEquals(7L, p.ring.current().number) // no admin's phone finishes it
            // Nor does the admin list he wrote in it make him senior: his rival to his own removal still loses, whatever its hash.
            p.get(pkt(7, ben, listOf(ben, cara), a, lowerThan(2), anna, "BBBB-BBBB-BBBB-BBBB", admins = listOf(ben)))
            assertEquals(a2, p.door); assertEquals(anna, p.ring.current().by); assertFalse(p.ring.removedBefore(anna, now)); assertNull(p.removedAt)
        }
        check(anna, listOf(anna, ben), cara); check(cara, listOf(anna, ben, cara), anna)
    }

    @Test fun aJuniorAdminsRivalRemovalDoesntStopTheSeniorOne() { // Ben's removal of Anna lost to hers of Dan; she can still remove him, and then his counts for nothing
        val r1 = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA"); val b = pkt(6, ben, listOf(ben, cara, dan), "d1", 2, anna, "BBBB-BBBB-BBBB-BBBB")
        val r2 = pkt(7, anna, listOf(anna, cara), "AAAA-AAAA-AAAA-AAAA", 3, ben, "AAAA-AAAA-AAAA-AAA2")
        for (o in orders(listOf(r1, b, r2))) phoneAfter(cara, o).let { p ->
            assertEquals("AAAA-AAAA-AAAA-AAA2", p.door); assertEquals(ben, p.ring.current().removes); assertTrue(p.ring.stillToRemove().isEmpty()); assertFalse(p.ring.removedBefore(anna, now))
        }
    }

    @Test fun theCreatorOverrulesANewerAdmin() {
        val out = pkt(6, ben, listOf(ben, cara, dan), "d1", 1, anna, "BBBB-BBBB-BBBB-BBBB")
        val join = pkt(7, cara, listOf(ben, cara, dan, eve), "BBBB-BBBB-BBBB-BBBB", 2, admins = listOf(ben), answers = eve)
        val rival = pkt(6, anna, listOf(anna, cara, dan), "d1", 3, ben, "AAAA-AAAA-AAAA-AAAA")
        for (o in orders(listOf(out, join, rival))) phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(6L, it.ring.current().number); assertEquals(ben, it.ring.current().removes) }
    }

    @Test fun aRemovalBuiltOnOneThatLost() { // Ben removes Dan, then Anna through his new code, while Anna's rival removal was on its way
        val junior = pkt(6, ben, listOf(anna, ben, cara), "d1", 1, dan, "BBBB-BBBB-BBBB-BBBB")
        val next = pkt(7, ben, listOf(ben, cara), "BBBB-BBBB-BBBB-BBBB", 2, anna, "BBBB-BBBB-BBBB-BBB2")
        val senior = pkt(6, anna, listOf(anna, ben, cara), "d1", 3, dan, "AAAA-AAAA-AAAA-AAAA")
        for (o in orders(listOf(junior, next, senior))) phoneAfter(cara, o).let { assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(6L, it.ring.current().number) }
    }

    @Test fun aSeniorAdminsRemovalNumberedBelowAJuniorOnesStillWins() { // Ben, whom Anna is removing, gets a key and then his removal of her to a phone first
        val a = "AAAA-AAAA-AAAA-AAAA"; val b = "BBBB-BBBB-BBBB-BBBB"
        val ben6 = pkt(6, ben, all, "d1", 1); val ben7 = pkt(7, ben, listOf(ben, cara, dan), "d1", 2, anna, b)
        val anna6 = pkt(6, anna, listOf(anna, cara, dan), "d1", 3, ben, a)
        for (o in orders(listOf(ben6, ben7, anna6))) {
            for (me in listOf(cara, dan, anna)) phoneAfter(me, o).let { p ->
                assertEquals(a, p.door); assertEquals(6L, p.ring.current().number); assertEquals(anna, p.ring.current().by); assertEquals(listOf(anna), p.ring.current().admins)
                assertTrue(p.ring.removedBefore(ben, now)); assertFalse(p.ring.removedBefore(anna, now)); assertNull(p.removedAt)
            }
            assertNotNull(phoneAfter(ben, o).removedAt)                                               // his own phone is told, in every order
        }
        val first = phoneAfter(cara, listOf(ben6, ben7))
        assertEquals(b, first.door); assertNotNull(first.ring.admit(anna6.r, anna, "d1", now))        // through what is now an old door, numbered below the removal followed out of it
        // A member his higher-numbered removal named is back in when hers, which keeps them, arrives.
        val out7 = pkt(7, ben, listOf(anna, ben, cara), "d1", 2, dan, b)
        for (o in orders(listOf(ben6, out7, anna6))) phoneAfter(dan, o).let { assertNull(it.removedAt); assertEquals(a, it.door); assertEquals(6L, it.ring.current().number) }
        // Only seniority does that. A junior admin can't number a removal below a senior one's to undo it, and nobody overrules themselves.
        val key = pkt(6, anna, all, "d1", 4); val out = pkt(7, anna, listOf(anna, ben, cara), "d1", 5, dan, a)
        val late = pkt(6, ben, listOf(ben, cara, dan), "d1", 6, anna, b); val own = pkt(6, anna, listOf(anna, cara, dan), "d1", 7, ben, "CCCC-CCCC-CCCC-CCCC")
        for (me in listOf(cara, dan)) for (o in orders(listOf(late, own))) phoneAfter(me, listOf(key, out) + o).let { p ->
            assertEquals(me == dan, p.removedAt != null); assertEquals(if (me == dan) "d1" else a, p.door)
            if (me == cara) { assertEquals(7L, p.ring.current().number); assertFalse(p.ring.removedBefore(anna, now)); assertFalse(p.ring.removedBefore(ben, now)) }
        }
    }

    @Test fun aSecretSentOnInAnotherKeyDoesntShutOutTheKeyItCameFrom() {
        val a = "AAAA-AAAA-AAAA-AAAA"
        val removal = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, a)                           // Anna removes Dan
        // Cara, who isn't an admin, got its secret in her part and sends it on in a key of her own: numbered the same, above or below.
        for (n in listOf(6L, 7L, 4L)) for (o in orders(listOf(pkt(n, cara, all, "d1", 1), removal))) phoneAfter(ben, o).let { p ->
            assertEquals(a, p.door); assertEquals(6L, p.ring.current().number); assertEquals(anna, p.ring.current().by); assertEquals(dan, p.ring.current().removes)
            assertFalse(dan in p.ring.current().members); assertTrue(p.ring.removedBefore(dan, now)); assertSame(p.ring.current(), p.ring.lastMove())
        }
        // The same goes for an admin's key that lets someone in.
        val join = pkt(6, anna, all + eve, "d1", 2, answers = eve)
        for (o in orders(listOf(pkt(6, cara, all, "d1", 2), join))) phoneAfter(ben, o).let { assertEquals(anna, it.ring.current().by); assertTrue(eve in it.ring.current().members) }
        // Either key read again changes nothing.
        val p = phoneAfter(ben, listOf(pkt(6, cara, all, "d1", 1), removal)); val held = p.ring.all().size
        assertEquals(2, p.ring.all().count { it.number == 6L })
        p.get(removal); p.get(pkt(6, cara, all, "d1", 1)); assertEquals(held, p.ring.all().size)
    }

    @Test fun aMembersKeyCantUndoAnAdminsChoiceToLetSomeoneIn() {
        val join = pkt(6, anna, all + eve, "d1", 1, answers = eve)                                     // Anna lets Eve in
        val rival = pkt(6, cara, all, "d1", lowerThan(1))                                              // Cara, not an admin: the same number, without Eve, and a hash that sorts first
        for (o in orders(listOf(join, rival))) for (me in listOf(anna, ben, dan)) phoneAfter(me, o).let { p ->
            assertEquals(6L, p.ring.current().number); assertEquals(anna, p.ring.current().by); assertTrue(eve in p.ring.current().members)
            assertEquals(2, p.ring.all().count { it.number == 6L })                                   // hers is kept, to read what she wrote with it
        }
        // Eve's phone, still joining, has only Anna's key to go by. A member's key that lists the same people can't take it either.
        val same = pkt(6, cara, all + eve, "d1", lowerThan(1), made = now - 90 * hour)
        for (o in orders(listOf(rival, same))) Phone(eve, joined = false).also { p -> (listOf(join) + o).forEach(p::get) }.let { assertEquals(anna, it.ring.current().by) }
        // Two keys from members who aren't admins still settle by the hash, as before.
        val other = pkt(6, dan, all, "d1", 1)
        for (o in orders(listOf(rival, other))) assertEquals(cara, phoneAfter(ben, o).ring.current().by)
    }

    @Test fun aKeyThatListsSomeoneWithoutAPartTheyCanOpen() {
        fun fromDan(parts: List<Pair<String, ByteArray>>, members: List<String> = all) = Rekey(6, now - 94 * hour, ByteArray(33), listOf(anna, ben), null, parts, false, members)
        val good = Rekey.box(secret(1), null)
        // No part for Cara: every phone can see that, and refuses the key as it comes off the wire.
        assertNull(Rekey.decode(fromDan(listOf(anna, ben, dan).map { it to good }).encode()))
        assertNotNull(Rekey.decode(fromDan(all.map { it to good }).encode()))
        // A bigger group's key goes in several packets: each has to hold exactly its share of the parts.
        val many = (1..25).map { "%016x".format(it) }; val shares = Rekey.split(many)
        for (share in shares) assertNotNull(Rekey.decode(fromDan(share.map { it to good }, many).encode()))
        assertNull(Rekey.decode(fromDan(shares[1].drop(1).map { it to good }, many).encode()))        // one of its people left out
        assertNull(Rekey.decode(fromDan((many - many[4]).map { it to good }, many).encode()))         // everyone but one, in a single packet
        // A part that doesn't open: only Cara's phone can tell. The others take the key and write with it.
        val spoiled = Pkt(Rekey.decode(fromDan(all.map { it to if (it == cara) ByteArray(5) else good }).encode())!!, dan, "d1")
        val phones = all.map { me -> Phone(me).also { it.get(spoiled) } }; val hers = phones[2]
        for (p in phones - hers) { assertEquals(6L, p.ring.current().number); assertTrue(cara in p.ring.current().members); assertNull(p.leftOut) }
        val out = hers.leftOut!!
        assertEquals(5L, hers.ring.current().number); assertEquals(6L, out.number); assertEquals(Int.MAX_VALUE, out.rank)
        // Her phone asks its way back as the engines do, like one that was away: with its own next key. It has Dan's number, so the hash decides.
        fun agreed() = phones.map { it.ring.current().id }.toSet().size == 1
        val lost = pkt(6, cara, all, "d1", (4..99).first { hashOf(it) > hashOf(1) })
        phones.forEach { it.get(lost) }
        assertFalse(agreed()); assertEquals(dan, phones[0].ring.current().by); assertEquals(cara, hers.ring.current().by)
        hers.leftOut = null; hers.get(spoiled); assertNotNull(hers.leftOut)                           // read again from the store: still the key the others follow
        // So an hour later it makes one more, numbered above both, and everyone moves to it.
        val back = pkt(7, cara, all, "d1", 7)
        phones.forEach { it.get(back) }
        assertTrue(agreed()); for (p in phones) { assertEquals(7L, p.ring.current().number); assertEquals(cara, p.ring.current().by) }
        hers.leftOut = null; hers.get(spoiled); assertNull(hers.leftOut)                              // read again: it is below her epoch now
        // When her first key sorts before Dan's, that one already settles it.
        val lucky = all.map { me -> Phone(me).also { it.get(spoiled); it.get(pkt(6, cara, all, "d1", lowerThan(1))) } }
        assertEquals(1, lucky.map { it.ring.current().id }.toSet().size); assertEquals(cara, lucky[0].ring.current().by)
        // Not answered: a key numbered below the current epoch, one that an admin's key of the same number beats whatever the hashes, or a removal, which only an admin can make.
        val late = Phone(cara).also { it.get(pkt(7, anna, all, "d1", 8)); it.get(spoiled) }; assertNull(late.leftOut)
        val beaten = Phone(cara).also { it.get(pkt(6, anna, all, "d1", 8)); it.get(spoiled) }; assertNull(beaten.leftOut)
        val gone = Rekey(6, now - 94 * hour, ByteArray(33), listOf(anna), dan, listOf(anna, ben, cara).map { it to if (it == cara) ByteArray(5) else Rekey.box(secret(9), "AAAA-AAAA-AAAA-AAAA") }, true)
        assertNull(Phone(cara).also { it.get(Pkt(gone, anna, "d1")) }.leftOut)
    }

    @Test fun newKeysInEveryOrder() {
        val ps = listOf(pkt(6, anna, all, "d1", 1), pkt(7, ben, all, "d1", 2), pkt(8, anna, all + eve, "d1", 3, answers = eve),
            pkt(9, anna, listOf(anna, ben, cara, eve), "d1", 4, dan, "AAAA-AAAA-AAAA-AAAA"), pkt(10, ben, listOf(anna, ben, cara, eve), "AAAA-AAAA-AAAA-AAAA", 5))
        val first = phoneAfter(cara, ps)
        assertEquals(10L, first.ring.current().number); assertEquals("AAAA-AAAA-AAAA-AAAA", first.door)
        for (o in orders(ps)) phoneAfter(cara, o).let { assertEquals(first.ring.current().hash, it.ring.current().hash); assertEquals("AAAA-AAAA-AAAA-AAAA", it.door); assertEquals(first.ring.all().size, it.ring.all().size) }
    }

    @Test fun aPhoneAwayForTenDays() {
        // Only the latest key is still around, made by someone who isn't an admin.
        val p = phoneAfter(cara, listOf(pkt(12, dan, all, "d1", 1)))
        assertEquals(12L, p.ring.current().number); assertEquals(listOf(anna, ben), p.ring.current().admins)
        // The group is at 12; the phone that is behind makes its own key, numbered below. Members spot it.
        val group = phoneAfter(anna, listOf(pkt(12, dan, all, "d1", 1)))
        val mine = pkt(6, cara, all, "d1", 2, made = now)
        assertTrue(group.ring.behind(mine.r, cara))
        group.get(mine); assertEquals(12L, group.ring.current().number)                      // kept to read with, nothing changes
        // The answer brings it back.
        val back = phoneAfter(cara, listOf(mine, pkt(13, anna, all, "d1", 3, made = now + 1)))
        assertEquals(13L, back.ring.current().number)
    }

    @Test fun aPhoneAwayWhenSomeoneWasRemovedHasToWaitForTheMissingKeys() {
        val r = pkt(8, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA")
        val p = phoneAfter(cara, listOf(r)); assertEquals("d1", p.door)                       // it can't follow: epoch 7 isn't here
        p.get(pkt(6, anna, all, "d1", 2)); assertEquals("d1", p.door)
        p.get(pkt(7, anna, all, "d1", 3)); assertEquals("AAAA-AAAA-AAAA-AAAA", p.door)                      // when it comes, the removal is read again
    }

    @Test fun aRemovedPhoneGetsNowhere() {
        val out = pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA")
        val p = phoneAfter(cara, listOf(out))
        p.get(pkt(7, dan, all, "d1", 2))                                                       // a new key through the old door
        p.get(pkt(7, dan, listOf(cara), "d1", 3, anna, "DDDD-DDDD-DDDD-DDDD"))                              // not an admin
        assertEquals("AAAA-AAAA-AAAA-AAAA", p.door); assertEquals(6L, p.ring.current().number)
        assertTrue(p.ring.removedBefore(dan, now)); assertFalse(p.ring.removedBefore(cara, now))
        // The removed phone stays out, even if rekeys keep coming past it.
        val d = phoneAfter(dan, listOf(out)); assertNotNull(d.removedAt)
        d.get(pkt(7, anna, listOf(anna, ben, cara), "AAAA-AAAA-AAAA-AAAA", 4)); assertEquals(5L, d.ring.current().number)
    }

    @Test fun someoneRemovedAddsNoKeys() {
        val a = "AAAA-AAAA-AAAA-AAAA"
        val p = phoneAfter(cara, listOf(pkt(6, anna, listOf(anna, ben, cara), "d1", 1, dan, a)))  // Anna removed Dan: the group moved on from d1
        val before = p.ring.all().size
        // Dan still has the old code, and epoch 5, which lists him, stays for a week. A key numbered below his removal, with a
        // secret and a date he chose, would be kept to read with: he could write with it once the removal itself has expired.
        p.get(pkt(5, dan, listOf(dan, cara), "d1", 3, made = now))
        p.get(pkt(4, dan, all, "d1", 4, made = now - 2 * hour))
        assertEquals(before, p.ring.all().size); assertTrue(p.ring.all().none { it.by == dan })
        // Nor through the current door, should he learn the new code, whatever its number.
        p.get(pkt(7, anna, listOf(anna, ben, cara), a, 5)); p.get(pkt(8, anna, listOf(anna, ben, cara), a, 6)); p.get(pkt(9, anna, listOf(anna, ben, cara), a, 7))
        assertEquals(9L, p.ring.current().number)
        p.get(pkt(8, dan, listOf(dan, cara), a, 8, made = now - 4 * hour)); p.get(pkt(5, dan, listOf(dan, cara), a, 9, made = now - 6 * hour))
        assertTrue(p.ring.all().none { it.by == dan })
        // A member's late key through the old door is still kept to read with.
        val held = p.ring.all().size
        p.get(pkt(5, ben, all, "d1", 10)); assertEquals(held + 1, p.ring.all().size)
    }

    @Test fun aNameInAKeyKeptForReadingLetsNobodyWrite() {
        // A member's key numbered below the current epoch is kept to read with, whatever member list it carries.
        val p = phoneAfter(cara, listOf(pkt(6, anna, all, "d1", 1)))
        p.get(pkt(4, dan, listOf(dan, cara, eve), "d1", 2))                                    // it lists Eve, whom nobody let in
        val planted = p.ring.all().first { it.by == dan }
        assertTrue(planted.members.isEmpty()); assertTrue(planted.lists(eve))                   // so it opens what is sealed under her id
        assertTrue(p.ring.shutOut(eve, now, had = false)); assertTrue(p.ring.shutOut(eve, now, had = true)) // but nothing under it is shown
        for (m in all) assertFalse(p.ring.shutOut(m, now, had = false))
        assertFalse(Keyring().shutOut(eve, now, had = false))                                   // the Public channel has no epochs: anyone writes there
    }

    @Test fun aStrangerWithAnOldCodeCantFillThePhoneWithKeys() {
        val p = phoneAfter(cara, listOf(pkt(6, anna, all, "d1", 1), pkt(7, anna, listOf(anna, ben, cara), "d1", 2, dan, "AAAA-AAAA-AAAA-AAAA")))
        val before = p.ring.all().size
        p.get(pkt(3, eve, listOf(cara), "d1", 3)); assertEquals(before, p.ring.all().size)      // late, through the old door, from someone who never was in
        p.get(pkt(3, ben, all, "d1", 4)); assertEquals(before + 1, p.ring.all().size)           // from a member: kept to read with
    }

    @Test fun manyRivalsInRandomOrders() {
        val rnd = java.util.Random(42); val admins = listOf(anna, ben, cara)
        fun sha(b: Int) = java.security.MessageDigest.getInstance("SHA-256").digest(secret(b)).joinToString("") { "%02x".format(it) }
        repeat(300) { round ->
            val makers = admins.shuffled(rnd).take(2 + rnd.nextInt(2))              // each admin at most once: a phone numbers its own one after the other
            val rivals = makers.mapIndexed { i, by -> val t = (all - by)[rnd.nextInt(3)]; Triple(pkt(6, by, all - t, "d1", 10 + i, t, "CCCC-CCCC-CCCC-CCC${i + 2}", admins = admins), by, i) }
            val winner = rivals.minWith(compareBy({ admins.indexOf(it.second) }, { sha(10 + it.third) }))
            for (me in all) {
                val p = Phone(me, admins); rivals.map { it.first }.shuffled(rnd).forEach(p::get)
                if (winner.first.r.answers == me) assertNotNull("round $round", p.removedAt)
                else { assertNull("round $round", p.removedAt); assertEquals("round $round", "CCCC-CCCC-CCCC-CCC${winner.third + 2}", p.door) }
            }
        }
    }

    @Test fun crippledRekeysDoNothing() {
        val good = pkt(6, anna, all, "d1", 1, dan, "AAAA-AAAA-AAAA-AAAA").r.encode(); val rnd = java.util.Random(7)
        for (n in good.indices) assertNull(Rekey.decode(good.copyOf(n)))
        repeat(3000) { val b = good.copyOf(); repeat(1 + rnd.nextInt(6)) { b[rnd.nextInt(b.size)] = rnd.nextInt(256).toByte() }; Rekey.decode(b) }
        repeat(1000) { val b = ByteArray(rnd.nextInt(300)).also(rnd::nextBytes); Rekey.decode(b) }
    }
}
