package it.blackout.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Encryption keys that change every week, codes that can't be guessed, and the longer person check. Same cases on the iPhone. */
class KeyChangesTest {
    private val day = 24 * 3_600_000L

    @Test fun aKeyIsReplacedAfterAWeek() {
        val l = listOf(EncSchedule.Entry(0, 1_000L))
        assertFalse(EncSchedule.due(l, 1_000L + 7 * day - 1)); assertTrue(EncSchedule.due(l, 1_000L + 7 * day))
        assertTrue(EncSchedule.due(emptyList(), 0L))
    }

    @Test fun theNewKeyBecomesCurrentAndTheOldOneIsMarked() {
        val l = EncSchedule.rotated(listOf(EncSchedule.Entry(0, 1_000L)), 9_000L)
        assertEquals(listOf(EncSchedule.Entry(0, 1_000L, 9_000L), EncSchedule.Entry(1, 9_000L)), l)
    }

    @Test fun aReplacedKeyIsDeletedAfterTwoWeeksAndTheCurrentOneNever() {
        val l = listOf(EncSchedule.Entry(0, 0L, day), EncSchedule.Entry(1, day))
        assertEquals(emptyList<EncSchedule.Entry>(), EncSchedule.expired(l, day + 14 * day - 1))
        assertEquals(listOf(l[0]), EncSchedule.expired(l, day + 14 * day))
        assertEquals(listOf(l[0]), EncSchedule.expired(l, day + 1000 * day))
    }

    @Test fun onlyTheNewestKeysAreEverKept() {
        val l = (0 until 12).map { EncSchedule.Entry(it, it * 1L, if (it == 11) 0L else it + 1L) }
        val left = l - EncSchedule.expired(l, 12L).toSet()
        assertEquals(8, left.size); assertEquals(11, left.last().n)
    }

    @Test fun theScheduleIsSavedAndJunkIsIgnored() {
        val l = listOf(EncSchedule.Entry(0, 5L, 9L), EncSchedule.Entry(1, 9L))
        assertEquals(l, EncSchedule.parse(EncSchedule.save(l)))
        assertEquals(emptyList<EncSchedule.Entry>(), EncSchedule.parse("nonsense,1:2,a:b:c"))
    }

    @Test fun anOlderIntroductionDoesntReplaceAKey() {
        assertTrue(EncSchedule.isNewer(100L, 101L)); assertFalse(EncSchedule.isNewer(100L, 100L)); assertFalse(EncSchedule.isNewer(100L, 99L))
    }

    @Test fun aRemovalCantMoveTheGroupToACodeThatCanBeGuessed() {
        val secret = ByteArray(32) { 1 }
        assertNotNull(Rekey.unbox(Rekey.box(secret, "K7QF-2M9X-PA4T-W8RJ"), true))
        for (weak in listOf("short", "password123", "k7qf-2m9x-pa4t-w8rj", "K7QF-2M9X-PA4T-W8R")) assertNull(weak, Rekey.unbox(Rekey.box(secret, weak), true))
    }

    @Test fun thePersonCheckHasSixteenEmojiFromTheFirst96Bits() {
        val pub = ByteArray(33) { 2 }
        val ix = P256.emoji(pub)
        assertEquals(16, ix.size); assertTrue(ix.all { it in 0..63 })
        val h = java.security.MessageDigest.getInstance("SHA-256").digest("darkproof-person-emoji-v1".toByteArray() + pub)
        val bits = h.copyOf(12).joinToString("") { (it.toInt() and 0xFF).toString(2).padStart(8, '0') }
        assertEquals(bits.chunked(6).map { it.toInt(2) }, ix)
    }

    @Test fun theEmojiGoEightToALine() {
        assertEquals(2, Fingerprint.emojiLines(P256.emoji(ByteArray(33) { 2 })).lines().size)
    }
}
