package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/** Keyring (spec/DESIGN-v0.6-groups.md, "Keys"); the iPhone's KeyringTests check the same cases. */
class KeyringTest {
    private fun secret(b: Int) = ByteArray(32) { b.toByte() }
    private fun hash(b: Int) = java.security.MessageDigest.getInstance("SHA-256").digest(secret(b)).joinToString("") { "%02x".format(it) }

    @Test fun currentIsTheHighestEpochThenTheSmallestHash() {
        val r = Keyring()
        assertTrue(r.add(Keyring.Epoch(1, 1_000, secret(1))))
        assertFalse(r.add(Keyring.Epoch(1, 2_000, secret(1)))) // the same secret twice: kept once
        r.add(Keyring.Epoch(2, 3_000, secret(2))); r.add(Keyring.Epoch(2, 3_000, secret(3)))
        val winner = if (hash(2) < hash(3)) hash(2) else hash(3)
        assertEquals(2L, r.current().number); assertEquals(winner, r.current().hash)
        assertEquals(3, r.all().size); assertSame(r.current(), r.all().first())
    }

    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"; private val dan = "4444444444444444"
    private fun rekey(epoch: Long, members: List<String>, admins: List<String> = listOf(anna), removes: String? = null, made: Long = 1, answers: String? = removes) =
        Rekey(epoch, made, ByteArray(33), admins, answers, members.map { it to ByteArray(1) }, removes != null)
    /** Epoch 5: Anna (admin), Ben and Cara. */
    private fun ring() = Keyring().also { it.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna))) }

    @Test fun onlyAdminsLeavePeopleOut() {
        assertNull(ring().admit(rekey(6, listOf(anna, ben)), ben, null))
        assertEquals(listOf(anna), ring().admit(rekey(6, listOf(anna, ben)), anna, null))
    }

    @Test fun theCodeAloneDoesntLetAnyoneIn() {
        val members = listOf(anna, ben, cara, dan)
        assertNull(ring().admit(rekey(6, members), dan, null, now = 2))                       // someone not in yet, adding themselves
        assertNull(ring().admit(rekey(6, members, admins = listOf(dan)), dan, null, now = 2)) // and claiming to be the admin
        assertNull(ring().admit(rekey(6, members, answers = dan), ben, null, now = 2))        // a member can't add them either
        assertEquals(listOf(anna), ring().admit(rekey(6, members, answers = dan), anna, null, now = 2)) // an admin can
        assertEquals(listOf(anna, ben), ring().admit(rekey(6, members, admins = listOf(anna, ben)), anna, null))
    }

    @Test fun onlyAdminsRemoveAndTheRemovedPersonMustBeGone() {
        val left = listOf(anna, ben)
        assertNull(ring().admit(rekey(6, left, removes = cara), ben, null))
        assertEquals(listOf(anna), ring().admit(rekey(6, left, removes = cara), anna, null))
        assertNull(ring().admit(rekey(6, left + cara, removes = cara), anna, null))
    }

    @Test fun aPhoneStillJoiningTakesTheFirstRekey() {
        assertEquals(listOf(dan), Keyring().admit(rekey(6, listOf(dan), admins = listOf(dan)), dan, null))
        assertNull(Keyring().admit(rekey(6, listOf(dan), admins = listOf(dan), removes = cara), dan, "old"))
    }

    @Test fun aPhoneStillJoiningTakesNoKeyOnceARemovalWentPast() {
        val eve = "5555555555555555"; val annaKey = ByteArray(33) { 1 }; val benKey = ByteArray(33) { 2 }
        val pins = Invite.pin(annaKey) + Invite.pin(benKey)                                  // an invite made while Anna and Ben were the admins
        val first = Rekey(1, 2, benKey, listOf(ben), eve, listOf(ben, eve).map { it to Rekey.box(secret(2), null) })
        fun take(r: Keyring, k: Rekey, by: String) = r.take(k, by, eve, "d1", false, null, 10, Invite.allows(pins, k.maker)) { it }
        assertTrue(take(Keyring(), first, ben) is Keyring.Taken.Added)                        // until then, either of them lets it in
        val r = Keyring()
        val removal = Rekey(6, 1, annaKey, listOf(anna), ben, listOf(anna, cara).map { it to Rekey.box(secret(1), "AAAA-AAAA-AAAA-AAAA") }, true)
        assertTrue(take(r, removal, anna) is Keyring.Taken.Closed); assertTrue(r.closed)
        // Ben still has the old code and answers the request himself. The invite names him, but its code no longer works.
        assertTrue(take(r, first, ben) is Keyring.Taken.Ignored); assertNull(r.currentOrNull())
        assertTrue(take(Keyring().also { it.closed = true }, first, ben) is Keyring.Taken.Ignored) // nor after a restart: the engine saved it
        // A removal from someone the invite doesn't name closes nothing.
        val other = Keyring(); val zed = ByteArray(33) { 9 }
        assertTrue(take(other, Rekey(6, 1, zed, listOf(dan), ben, listOf(dan).map { it to Rekey.box(secret(3), "AAAA-AAAA-AAAA-AAAA") }, true), dan) is Keyring.Taken.Ignored)
        assertFalse(other.closed); assertTrue(take(other, first, ben) is Keyring.Taken.Added)
    }

    @Test fun seniorityIsReadFromEpochsWithAMemberList() {
        val r = Keyring(); r.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben)))
        r.add(Keyring.Epoch(6, 1, secret(6), listOf(anna, ben, cara), listOf(anna, ben)))
        for (n in 4L..5L) r.add(Keyring.Epoch(n, 1, secret(n.toInt() + 3), emptyList(), listOf(ben), by = ben)) // kept only to read with: their admins are whatever their maker wrote
        assertEquals(1, r.rank(rekey(6, listOf(anna)), ben)); assertEquals(0, r.rank(rekey(6, listOf(anna)), anna))
        assertEquals(1, r.rank(rekey(5, listOf(anna)), ben))                                  // only such an epoch before it: the current epoch's list
        assertEquals(Int.MAX_VALUE, r.rank(rekey(9, listOf(anna)), anna))                     // none before it
    }

    @Test fun lateEpochsAreOnlyForReading() {
        val r = ring(); r.add(Keyring.Epoch(9, 1, secret(9), listOf(anna, ben, cara, dan), listOf(anna)))
        assertNotNull(r.admit(rekey(3, listOf(ben)), ben, null))
        assertEquals(9L, r.current().number)
    }

    @Test fun throughAnOldDoorOnlyARivalRemovalCounts() {
        val r = ring()
        r.add(Keyring.Epoch(6, 1, secret(6), listOf(anna, ben), listOf(anna), "new", "old", cara, anna))
        assertNotNull(r.admit(rekey(6, listOf(anna, cara), removes = ben), anna, "old"))         // made from the same epoch
        assertNull(r.admit(rekey(6, listOf(anna, cara)), anna, "old"))                           // not a removal
        assertNull(r.admit(rekey(7, listOf(anna, cara), removes = ben), anna, "old"))            // past it
        assertNull(r.admit(rekey(6, listOf(anna, cara), removes = ben), anna, "another"))        // through some other door
        assertNull(r.admit(rekey(6, listOf(anna, ben, cara), removes = dan), cara, "old"))       // not an admin
    }

    @Test fun aRemovalBeatsAnythingElseOfTheSameNumber() {
        for ((a, b) in listOf(1 to 2, 2 to 1, 3 to 4, 4 to 3)) {
            val r = Keyring()
            r.add(Keyring.Epoch(6, 1, secret(a), listOf(anna, ben, cara), listOf(anna)))
            r.add(Keyring.Epoch(6, 1, secret(b), listOf(anna, ben), listOf(anna), "new", "old", cara, anna))
            assertEquals(cara, r.current().removes); assertSame(r.current(), r.lastMove())
        }
    }

    @Test fun theMostSeniorAdminsRemovalWinsWhateverTheHash() {
        for ((a, b) in listOf(1 to 2, 2 to 1, 3 to 4, 4 to 3)) for (seniorFirst in listOf(true, false)) {
            val r = Keyring()
            val senior = Keyring.Epoch(6, 1, secret(a), listOf(anna, cara), listOf(anna), "code-a", "old", ben, anna, 0)
            val junior = Keyring.Epoch(6, 1, secret(b), listOf(ben, cara), listOf(ben), "code-b", "old", anna, ben, 1)
            (if (seniorFirst) listOf(senior, junior) else listOf(junior, senior)).forEach { r.add(it) }
            assertSame(senior, r.current()); assertSame(senior, r.lastMove()); assertTrue(r.won(senior)); assertFalse(r.won(junior))
        }
    }

    @Test fun rankIsThePlaceInTheAdminList() {
        val r = Keyring(); r.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben)))
        assertEquals(0, r.rank(rekey(6, listOf(anna)), anna)); assertEquals(1, r.rank(rekey(6, listOf(anna)), ben))
        assertEquals(Int.MAX_VALUE, r.rank(rekey(6, listOf(anna)), cara))
    }

    @Test fun aRemovalThatLostSilencesNobody() {
        val r = ring()
        r.add(Keyring.Epoch(6, 500, secret(6), listOf(anna, cara), listOf(anna), "code-a", "old", ben, anna, 0))
        r.add(Keyring.Epoch(6, 500, secret(7), listOf(ben, cara), listOf(ben), "code-b", "old", anna, ben, 1))
        assertTrue(r.removedBefore(ben, 501)); assertFalse(r.removedBefore(anna, 501))
        assertTrue(r.shutOut(ben, 1, had = false)); assertFalse(r.shutOut(anna, 1, had = false)); assertFalse(r.shutOut(anna, 501, had = true))
    }

    @Test fun aRemovalCantPickAHigherNumberToGetAhead() {
        assertNull(ring().admit(rekey(9, listOf(anna, cara), removes = ben), anna, null)) // this phone has no epoch 8
        assertNotNull(ring().admit(rekey(6, listOf(anna, cara), removes = ben), anna, null))
    }

    @Test fun outrankedOnlyByAMoreSeniorRemovalOfTheSameNumber() {
        val r = Keyring(); r.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben)))
        assertFalse(r.outranked(rekey(6, listOf(ben, cara), removes = anna), ben))
        r.add(Keyring.Epoch(6, 1, secret(6), listOf(anna, cara), listOf(anna), "code-a", "old", ben, anna, 0))
        assertTrue(r.outranked(rekey(6, listOf(ben, cara), removes = anna), ben))    // Anna is listed before Ben
        assertFalse(r.outranked(rekey(6, listOf(anna, cara), removes = ben), anna))  // and not before herself
    }

    @Test fun aKeyDatedLongAgoCantExpireTheOnesBeforeItEarly() {
        val day = 24 * 3600_000L; val r = Keyring()
        r.add(Keyring.Epoch(1, 20 * day, secret(1))); r.add(Keyring.Epoch(2, 0, secret(2)))
        assertTrue(r.expire(21 * day).isEmpty())                        // epoch 1 was made a day ago, whatever epoch 2 says
    }

    @Test fun aMembersKeyDatedLongAgoNeitherExpiresOlderEpochsNorMakesTheWeeklyKeyDue() {
        val day = 24 * 3600_000L; val hour = 3600_000L; val now = 1000 * day; val two = listOf(anna, ben)
        // Anna's phone: epoch 1 is 8 days old, epoch 2 replaced it an hour ago.
        fun r() = Keyring().also { it.add(Keyring.Epoch.fresh(1, now - 8 * day, secret(1), two, listOf(anna), by = anna)); it.add(Keyring.Epoch.fresh(2, now - hour, secret(2), two, listOf(anna), by = anna)) }
        fun bens(made: Long) = Rekey.decode(Rekey(3, made, ByteArray(33), listOf(anna), null, two.map { it to ByteArray(1) }).encode())!!
        assertTrue(r().expire(now).isEmpty())
        for (made in listOf(now - 60_000, 0L)) {                                              // Ben, who isn't an admin, dates his key a minute ago, or in 1970
            val ring = r()
            assertTrue(ring.take(bens(made), ben, anna, "door", false, null, now) { secret(3) } is Keyring.Taken.Added)
            val cur = ring.current(); assertEquals(3L, cur.number); assertEquals(made, cur.made); assertEquals(now, cur.taken)
            assertTrue("dated $made", ring.expire(now).isEmpty()); assertEquals(listOf(1L, 2L, 3L), ring.all().map { it.number }.sorted())
            assertFalse(Keyring.weeklyDue(cur.since, now, 0)); assertFalse(Keyring.overdue(cur.since, now))
            assertTrue(Keyring.weeklyDue(cur.since, now + 7 * day, 0))                        // a week after it got here
            assertEquals(listOf(1L), ring.expire(now - hour + 7 * day + 1).map { it.number }) // a week after epoch 2 replaced it, as without Ben's key
        }
        val saved = Keyring.Epoch(4, 5 * day, secret(4)); assertEquals(5 * day, saved.taken); assertEquals(5 * day, saved.since) // saved before phones noted the arrival: its date
    }

    @Test fun theSameSecretInAnotherKeyIsAnotherEpoch() {
        val r = Keyring(); val five = Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben)); r.add(five)
        assertFalse(r.add(Keyring.Epoch(5, 9, secret(5), listOf(anna), listOf(anna))))                         // the same key read again: kept once
        assertTrue(r.add(Keyring.Epoch(6, 2, secret(5), listOf(anna, ben, cara), listOf(anna, ben), by = cara))) // its secret in a key of Cara's: held beside it
        assertTrue(r.add(Keyring.Epoch(6, 2, secret(5), listOf(anna, ben), listOf(anna), "new", "old", cara, anna, 0))) // and in a removal of Anna's, which wins
        assertFalse(r.add(Keyring.Epoch(6, 3, secret(5), emptyList(), listOf(anna), by = cara)))               // Cara's again, kept only to read with: still one
        assertEquals(3, r.all().size); assertTrue(r.all().any { it === five }); assertEquals(cara, r.current().removes)
        assertEquals(3, r.all().map { it.id }.toSet().size); assertEquals(1, r.all().map { it.hash }.toSet().size)
        // Of two keys with one secret, number and standing, the maker's id decides, whichever came first.
        for (order in listOf(listOf(ben, cara), listOf(cara, ben))) {
            val k = Keyring(); order.forEach { k.add(Keyring.Epoch(6, 2, secret(5), listOf(anna, ben, cara), listOf(anna), by = it)) }
            assertEquals(ben, k.current().by)
        }
    }

    @Test fun anAdminsKeyComesBeforeAMembersOfTheSameNumber() {
        val r = Keyring(); r.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben)))
        assertEquals(Keyring.BY_ADMIN, r.standing(rekey(6, listOf(anna, ben, cara)), ben)); assertEquals(Int.MAX_VALUE, r.standing(rekey(6, listOf(anna, ben, cara)), cara))
        assertEquals(1, r.standing(rekey(6, listOf(anna, cara), removes = ben), ben))                          // a removal keeps its maker's place
        assertEquals(Keyring.BY_ADMIN, r.standing(rekey(9, listOf(anna, ben, cara)), anna))                    // no epoch 8 here: the current one says who is an admin, as for admit
        assertEquals(Keyring.BY_ADMIN, Keyring().standing(rekey(6, listOf(dan), admins = listOf(anna)), anna)) // still joining: the key's own list
        assertEquals(Int.MAX_VALUE, Keyring().standing(rekey(6, listOf(dan), admins = listOf(anna)), cara))
        for ((a, b) in listOf(1 to 2, 2 to 1, 3 to 4, 4 to 3)) for (adminFirst in listOf(true, false)) {
            val k = Keyring()
            val admins = Keyring.Epoch(6, 1, secret(a), listOf(anna, ben, cara, dan), listOf(anna), by = anna, rank = Keyring.BY_ADMIN)
            val members = Keyring.Epoch(6, 1, secret(b), listOf(anna, ben, cara), listOf(anna), by = cara)
            (if (adminFirst) listOf(admins, members) else listOf(members, admins)).forEach { k.add(it) }
            assertSame(admins, k.current()); assertTrue(k.won(admins)); assertFalse(k.won(members))
            k.add(Keyring.Epoch(6, 1, secret(9), listOf(anna, ben), listOf(anna), "new", "old", cara, ben, 1)); assertEquals(cara, k.current().removes) // a removal still beats both
        }
    }

    @Test fun theWeeklyKeyWaitsForAWeekAndThisPhonesDelay() {
        val day = 24 * 3600_000L; val hour = 3600_000L
        assertFalse(Keyring.weeklyDue(0, 7 * day - 1, 0))
        assertTrue(Keyring.weeklyDue(0, 7 * day, 0))
        assertFalse(Keyring.weeklyDue(0, 7 * day + 2 * hour, 3 * hour))
        assertTrue(Keyring.weeklyDue(0, 7 * day + 3 * hour, 3 * hour))
        assertFalse(Keyring.overdue(0, 7 * day + 6 * hour - 1)); assertTrue(Keyring.overdue(0, 7 * day + 6 * hour))
    }

    @Test fun oneRekeyPerMemberPerHour() {
        val hour = 3600_000L; val everyone = listOf(anna, ben, cara); val now = 100 * hour
        fun r() = ring().also { it.add(Keyring.Epoch(6, 50 * hour, secret(6), everyone, listOf(anna), by = ben)) }
        assertNull(r().admit(rekey(7, everyone, made = 50 * hour + 1), ben, null, now))            // Ben again, within the hour
        assertNotNull(r().admit(rekey(7, everyone, made = 51 * hour), ben, null, now))             // an hour later
        assertNotNull(r().admit(rekey(7, everyone, made = 50 * hour + 1), cara, null, now))        // someone else
        assertNotNull(r().let { it.add(Keyring.Epoch(7, 50 * hour, secret(7), everyone, listOf(anna), by = anna)); it.admit(rekey(8, everyone, made = 50 * hour + 1), anna, null, now) }) // admins may act again
        assertNull(r().admit(rekey(7, everyone + dan, made = 51 * hour, answers = dan), ben, null, now))  // a member can't let someone in
    }

    @Test fun nonsenseNumbersAndTimesAndHugeGroupsAreRefused() {
        val now = 1_000_000_000L; val everyone = listOf(anna, ben, cara)
        for (bad in listOf(0L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, (1L shl 53) + 1)) {
            assertNull(ring().admit(rekey(bad, everyone), anna, null, now)); assertNull(Keyring().admit(rekey(bad, everyone), anna, null, now))
        }
        assertNull(ring().admit(rekey(1006, everyone), anna, null, now))                           // too far ahead of epoch 5
        assertNotNull(ring().admit(rekey(1005, everyone), anna, null, now))
        assertNull(ring().admit(rekey(6, everyone, made = now + 10 * 60_000 + 1), anna, null, now)) // would put off the weekly key
        assertNull(ring().admit(rekey(6, everyone, made = -1), anna, null, now))
        val many = (1..101).map { "%016x".format(it) }
        assertNull(ring().admit(rekey(6, many), anna, null, now)); assertNotNull(ring().admit(rekey(6, many.take(99) + anna), anna, null, now))
    }

    @Test fun someoneInNoEpochCantMakeAKey() {
        val hour = 3600_000L; val now = 100 * hour; val everyone = listOf(anna, ben, cara); val r = ring()
        repeat(8) { assertNull("key $it", r.admit(rekey(6, everyone + dan, made = now), "%016x".format(100 + it), null, now)) }
        assertNull(r.admit(rekey(6, everyone, made = now), "%016x".format(200), null, now))         // even leaving the members as they are
        assertNotNull(r.admit(rekey(6, everyone, made = now - 2 * hour), ben, null, now))           // a member can
    }

    @Test fun aFloodOfKeysCantGrowTheRingForever() {
        val r = Keyring()
        for (n in 1L..200L) r.add(Keyring.Epoch(n, n, ByteArray(32) { i -> (n shr (i % 8)).toByte() }))
        assertEquals(64, r.all().size); assertEquals(200L, r.current().number); assertEquals(137L, r.all().minOf { it.number })
    }

    @Test fun theEpochBeforeIsPickedTheSameWayOnBothApps() {
        // Two rivals numbered 5, added in either order: the winner's members decide.
        val hash = listOf(1, 2).sortedBy { hash(it) }
        for (order in listOf(hash, hash.reversed())) {
            val r = Keyring()
            order.forEach { b -> r.add(Keyring.Epoch(5, 1, secret(b), if (b == hash[0]) listOf(anna, ben) else listOf(anna, ben, cara), listOf(anna))) }
            r.add(Keyring.Epoch(7, 1, secret(9), listOf(anna, ben, cara), listOf(anna)))
            assertNotNull(r.admit(rekey(6, listOf(anna, ben), made = 100), ben, null, now = 200)) // keeps everyone in the winner of epoch 5
        }
    }

    @Test fun aPhoneThatMissedKeysIsSpotted() {
        val r = Keyring(); r.add(Keyring.Epoch(9, 1000, secret(9), listOf(anna, ben), listOf(anna)))
        assertTrue(r.behind(rekey(4, listOf(ben), made = 2000), ben))
        assertFalse(r.behind(rekey(9, listOf(ben), made = 2000), ben))                             // the same number: two phones at once, nobody is behind
        assertFalse(r.behind(rekey(4, listOf(ben), made = 500), ben))                              // made before our epoch: a late packet
        assertFalse(r.behind(rekey(4, listOf(cara), made = 2000), cara))                           // not in the group
        assertFalse(r.behind(rekey(4, listOf(ben), made = 2000, removes = cara), ben))             // a removal is its own thing
    }

    @Test fun whatsAboveARemovalGoesAndTheRemovedStaySilent() {
        val r = ring(); r.add(Keyring.Epoch(6, 500, secret(6), listOf(anna, ben), listOf(anna), "new", "old", cara, anna)); r.add(Keyring.Epoch(8, 1, secret(8)))
        r.dropAbove(6); assertEquals(6L, r.current().number)
        assertFalse(r.removedBefore(cara, 500)); assertTrue(r.removedBefore(cara, 501)); assertFalse(r.removedBefore(ben, 501))
    }

    @Test fun oldEpochsGoButNeverTheCurrentOne() {
        val day = 24 * 3600_000L; val r = Keyring()
        r.add(Keyring.Epoch(1, 0, secret(1))); r.add(Keyring.Epoch(2, 6 * day, secret(2)))
        assertTrue(r.expire(8 * day).isEmpty())                         // replaced 2 days ago: a message written on its last day can still come
        assertEquals(listOf(1L), r.expire(14 * day).map { it.number })  // replaced more than 7 days ago
        assertEquals(listOf(2L), r.all().map { it.number })
        assertTrue(r.expire(30 * day).isEmpty())                        // the current one stays, however old
        assertNotNull(r.current().group.mailbox)
    }

    @Test fun whatLostGoesWithTheEpochThatBeatIt() {
        val day = 24 * 3600_000L; val r = ring()
        r.add(Keyring.Epoch(6, 1 * day, secret(6), listOf(anna, cara), listOf(anna), "code-a", "old", ben, anna, 0)) // Anna removes Ben
        r.add(Keyring.Epoch(6, 5 * day, secret(7), listOf(ben, cara), listOf(ben), "code-b", "old", anna, ben, 1))   // his rival removal lost; he dated it later
        r.add(Keyring.Epoch(7, 2 * day, secret(8), listOf(anna, cara), listOf(anna)))
        assertEquals(listOf(5L, 6L, 6L), r.expire(10 * day).map { it.number }.sorted())       // or it would be the only removal numbered 6 left, and so the one that won
        assertFalse(r.removedBefore(anna, 10 * day)); assertTrue(r.stillToRemove().isEmpty())
    }

    @Test fun groupIdIsStableAndKeysComeFromTheSecret() {
        assertEquals(GroupCrypto("test-group-1").groupId(), GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).groupId())
        assertEquals(GroupCrypto("test-group-1").mailbox, GroupCrypto.fromSecret(GroupCrypto.deriveKey("test-group-1")).mailbox)
        assertNotEquals(GroupCrypto("test-group-1").groupId(), GroupCrypto("test-group-2").groupId())
        assertEquals("ccb162da8b97168602926c8bb8f8f4c6", GroupCrypto("test-group-1").groupId()) // Python: HMAC(key, "darkproof-group-id-v1")
    }
}
