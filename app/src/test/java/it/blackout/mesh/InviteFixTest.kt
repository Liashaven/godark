package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * Invites, group codes and joining (spec/FORMAT.md, "Invites", "Accepting a new key", "Removals and the code"); the
 * iPhone's InviteFixTests check the same cases. Ids, keys and codes are made up.
 */
class InviteFixTest {
    private val anna = "1111111111111111"; private val ben = "2222222222222222"; private val cara = "3333333333333333"; private val zed = "9999999999999999"
    private val annaKey = ByteArray(33) { 1 }; private val benKey = ByteArray(33) { 2 }; private val zedKey = ByteArray(33) { 9 }
    private val code = "AAAA-BBBB-CCCC-DDDD"; private val other = "HHHH-HHHH-HHHH-HHHH"
    private fun secret(b: Int) = ByteArray(32) { b.toByte() }

    @Test fun aLinkReadLaterDoesNotChangeTheAdminsAPendingJoinTrusts() {
        // The user says Join to an invite that names Anna: from then on only she can let this phone in.
        var saved = Invite.joinPins(emptyMap(), emptyList(), code, Invite.pin(annaKey))
        assertEquals(mapOf(code to Invite.pin(annaKey)), saved)
        // The phone now has the code. A second link for it, naming someone else, is read or even said yes to: nothing changes.
        saved = Invite.joinPins(saved, listOf(code), code, Invite.pin(zedKey))
        assertTrue(Invite.allows(saved.getValue(code), annaKey)); assertFalse(Invite.allows(saved.getValue(code), zedKey))
        assertEquals(saved, Invite.joinPins(saved, listOf(code), code, ""))                  // nor does typing the code again drop them
        // Joining other groups, however many, never pushes them out while the group is saved.
        var groups = listOf(code)
        for (i in 0 until 40) { val c = "KKKK-KKKK-KKKK-KK%02d".format(i); saved = Invite.joinPins(saved, groups, c, Invite.pin(zedKey)); groups = groups + c }
        assertEquals(Invite.pin(annaKey), saved[code]); assertEquals(41, saved.size)
        // What was kept for a code that is no longer saved goes; a typed code names nobody.
        saved = Invite.joinPins(saved, listOf(other), "MMMM-MMMM-MMMM-MMMM", "")
        assertTrue(saved.isEmpty())
        assertEquals(emptyMap<String, String>(), Invite.joinPins(mapOf(code to Invite.pin(zedKey)), emptyList(), code, "")) // left over from before: not trusted for a typed code
    }

    @Test fun noPinsNameNobody() {
        val pins = Invite.pin(annaKey) + Invite.pin(benKey)
        assertTrue(Invite.names(pins, annaKey)); assertTrue(Invite.names(pins, benKey)); assertFalse(Invite.names(pins, zedKey))
        assertTrue(Invite.allows("", zedKey)); assertFalse(Invite.names("", zedKey))
    }

    @Test fun aRemovalFromSomeoneWhoOnlyHasTheCodeClosesNoPendingJoin() {
        fun removal(key: ByteArray, by: String) = Rekey(6, 1, key, listOf(by), ben, listOf(by to Rekey.box(secret(3), code)), true)
        fun take(r: Keyring, k: Rekey, by: String, pins: String) =
            r.take(k, by, cara, "d1", false, null, 10, Invite.allows(pins, k.maker), named = Invite.names(pins, k.maker)) { it }
        // A typed code, or a link that names nobody: nothing tells an admin's removal from one signed by anyone who has the code.
        val typed = Keyring()
        assertSame(Keyring.Taken.Ignored, take(typed, removal(zedKey, zed), zed, "")); assertFalse(typed.closed)
        assertSame(Keyring.Taken.Ignored, take(typed, removal(annaKey, anna), anna, "")); assertFalse(typed.closed)
        val first = Rekey(1, 2, annaKey, listOf(anna), cara, listOf(anna, cara).map { it to Rekey.box(secret(2), null) })
        assertTrue(take(typed, first, anna, "") is Keyring.Taken.Added)                      // so the group can still let it in
        // An invite that names Anna: her removal closes it, one from somebody it doesn't name closes nothing.
        val pins = Invite.pin(annaKey); val invited = Keyring()
        assertSame(Keyring.Taken.Ignored, take(invited, removal(zedKey, zed), zed, pins)); assertFalse(invited.closed)
        assertSame(Keyring.Taken.Closed, take(invited, removal(annaKey, anna), anna, pins)); assertTrue(invited.closed)
    }

    @Test fun onlyAnAdminsRemovalTellsAPhoneComingBackThatTheGroupMovedOn() {
        val r = Keyring().also { it.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna))) }
        fun removal(by: String) = Rekey(9, 2, ByteArray(33), listOf(by), ben, listOf(by to Rekey.box(secret(6), code)), true)
        assertFalse(r.movedOn(removal(zed), zed))                                            // someone who only has the code
        assertFalse(r.movedOn(removal(cara), cara))                                          // a member who isn't an admin
        assertTrue(r.movedOn(removal(anna), anna))
        assertFalse(r.movedOn(Rekey(9, 2, ByteArray(33), listOf(anna), null, listOf(anna to ByteArray(1))), anna)) // not a removal
        assertFalse(Keyring().movedOn(removal(anna), anna))                                  // no epoch: the invite's admins decide (take)
        // An admin a removal took out says nothing either, even if the list still has them.
        val two = Keyring().also { it.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna, ben))) }
        two.add(Keyring.Epoch(6, 2, secret(6), listOf(anna, cara), listOf(anna, ben), code, "d1", ben, anna, 0))
        assertFalse(two.movedOn(removal(ben), ben)); assertTrue(two.movedOn(removal(anna), anna))
    }

    @Test fun aRemovalCannotMoveAGroupOntoTheCodeOfAnotherSavedGroup() {
        fun ring() = Keyring().also { it.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, ben, cara), listOf(anna))) }
        val removal = Rekey(6, 2, ByteArray(33), listOf(anna), ben, listOf(anna, cara).map { it to Rekey.box(secret(6), other) }, true)
        val r = ring()
        assertSame(Keyring.Taken.Ignored, r.take(removal, anna, cara, "d1", false, null, 10, inUse = listOf(other)) { it })
        assertEquals(5L, r.current().number); assertNull(r.lastMove())                       // nothing was added: the group stays where it is
        val free = ring().take(removal, anna, cara, "d1", false, null, 10, inUse = listOf("JJJJ-JJJJ-JJJJ-JJJJ")) { it }
        assertEquals(other, (free as Keyring.Taken.Added).moveTo)                            // a code no other group here has is followed as before
        // A phone still joining with a typed code takes the first key that includes it, but not onto another group's code.
        val first = Rekey(1, 2, ByteArray(33), listOf(zed), ben, listOf(zed, cara).map { it to Rekey.box(secret(7), other) }, true)
        val joining = Keyring()
        assertSame(Keyring.Taken.Ignored, joining.take(first, zed, cara, "d1", false, null, 10, inUse = listOf(other)) { it })
        assertNull(joining.currentOrNull()); assertFalse(joining.closed)
    }

    /** Holds today without a change; kept so that both apps go on agreeing (a code one accepted and the other refused would split the group). */
    @Test fun aGeneratedCodeEndsWhereItEnds() {
        assertTrue(Invite.isGeneratedCode(code)); assertNotNull(Rekey.unbox(Rekey.box(secret(1), code), true))
        for (tail in listOf("\n", "\r\n", "\r", "\u0085", " ", " ", "\u000B", "\u000C", " ")) {
            assertFalse(Invite.isGeneratedCode(code + tail)); assertFalse(Invite.isGeneratedCode(tail + code))
            assertNull(Rekey.unbox(Rekey.box(secret(1), code + tail), true))
        }
    }

    /**
     * Holds today without a change. A second set of keys made from a code the group has moved on from would call that
     * code the current door (the engines no longer make one: MeshEngine.keys). Even so, someone a removal took out adds
     * nothing through it.
     */
    @Test fun someoneRemovedAddsNothingThroughTheOldDoorEvenIfItIsTakenForTheCurrentOne() {
        val ring = Keyring().also { it.add(Keyring.Epoch(5, 1, secret(5), listOf(anna, cara, zed), listOf(anna, zed))) }
        val removal = Rekey(6, 2, ByteArray(33), listOf(anna), zed, listOf(anna, cara).map { it to Rekey.box(secret(6), code) }, true)
        assertTrue(ring.take(removal, anna, cara, "old", false, null, 10) { it } is Keyring.Taken.Added)
        val same = Rekey(6, 3, ByteArray(33), listOf(zed), null, listOf(zed, cara).map { it to Rekey.box(secret(7), null) })
        assertSame(Keyring.Taken.Ignored, ring.take(same, zed, cara, "old", false, null, 10) { it })
        val next = Rekey(7, 4, ByteArray(33), listOf(zed), null, listOf(zed, cara).map { it to Rekey.box(secret(8), null) })
        assertSame(Keyring.Taken.Ignored, ring.take(next, zed, cara, "old", false, null, 10) { it })
        assertEquals(6L, ring.current().number); assertEquals(listOf(anna), ring.current().admins)
    }
}
