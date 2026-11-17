package it.blackout.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the phone keeps, and for how long: copies of messages go with their epoch (spec "This phone's copy"), and an
 * alert doesn't outlive its message (spec "Alerts"). Same cases as the iPhone's StoredDataFixTests.
 */
class StoredDataFixTest {
    private val anna = "1111111111111111"; private val ben = "2222222222222222"
    private val group = "00112233445566778899aabbccddeeff"
    private val key = ByteArray(32) { 3 }
    private val day = 24 * 3_600_000L

    private fun epoch(n: Long, made: Long, secret: Int) = Keyring.Epoch.fresh(n, made, ByteArray(32) { secret.toByte() }, listOf(anna, ben), listOf(anna))

    /** Ben's message [i] in epoch [e], opened with its message key, and this phone's copy of it naming [named]. */
    private fun copy(e: Keyring.Epoch, i: Int, named: String = e.id): History.Saved {
        val id = "6a4400000000000$i"; val ts = e.made + 1_000
        val c = e.group.sealWith(e.messageKeys!!.key(1, i)!!, 1, i, id, ts, ben, "Ben", "message $i") { TestKeys.sign(it) }
        val o = e.open(Packet(id, e.group.hideTime(ts, c), 16, c))!!
        return History.open(key, id, History.seal(key, id, group, named, o, 1, i))!!
    }

    @Test fun aCopyGoesWithTheEpochThatWasDeleted() {
        val ring = Keyring(); val one = epoch(1, 0, 1); val two = epoch(2, day, 2)
        ring.add(one); ring.add(two)
        val old = copy(one, 1); val new = copy(two, 2)
        val gone = ring.expire(day + 8 * day)
        assertEquals(listOf(one), gone)
        assertTrue(History.goesWith(old, gone, ring.all()))
        assertFalse(History.goesWith(new, gone, ring.all()))
    }

    @Test fun nothingGoesWhileNoEpochIsDeleted() {
        val ring = Keyring(); val one = epoch(1, 0, 1); val two = epoch(2, day, 2)
        ring.add(one); ring.add(two)
        val gone = ring.expire(day + 6 * day)
        assertTrue(gone.isEmpty())
        assertFalse(History.goesWith(copy(one, 1), gone, ring.all()))
    }

    @Test fun anOldCopyNamingItsEpochByHashGoesOnlyIfNoHeldEpochHasThatHash() {
        val one = epoch(1, 0, 1); val again = epoch(3, 2 * day, 1) // the same secret, sent again under another number
        val old = copy(one, 1, named = one.hash)
        assertTrue(History.goesWith(old, listOf(one), listOf(epoch(2, day, 2))))
        assertFalse(History.goesWith(old, listOf(one), listOf(again))) // still shown with that one
    }

    @Test fun aCopyOfAnotherEpochIsLeftAlone() {
        val one = epoch(1, 0, 1); val two = epoch(2, day, 2)
        assertFalse(History.goesWith(copy(two, 3), listOf(one), listOf(two)))
    }

    @Test fun anAlertGoesAWeekAfterItsMessagesDate() {
        val now = 1_794_000_000_000L
        assertEquals(AlertLife.WEEK_MS, AlertLife.timeout(now, now))
        assertEquals(AlertLife.WEEK_MS - 3 * day, AlertLife.timeout(now - 3 * day, now)) // arrived three days late
        assertEquals(60_000L, AlertLife.timeout(now - 9 * day, now)) // arrived after its week: a minute
        assertEquals(AlertLife.WEEK_MS, AlertLife.timeout(now + 600_000, now)) // dated ahead: a week at most
    }
}
