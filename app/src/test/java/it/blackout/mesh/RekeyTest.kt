package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/** Rekey payloads (spec/DESIGN-v0.6-groups.md, "New key"): encoding, and a member opening only their own part. */
class RekeyTest {
    @Test fun roundTripAndOnlyMyPart() {
        val gid = GroupCrypto("test-group-1").groupId(); val pid = "6a44000000000009"
        val anna = P256.newKeyPair(); val ben = P256.newKeyPair()
        val annaId = "1111111111111111"; val benId = "2222222222222222"
        val secret = ByteArray(32) { 7 }
        val parts = listOf(annaId to anna, benId to ben).map { (id, kp) -> id to Hpke.seal(secret, kp.public, Rekey.info(gid), Rekey.aad(pid, id)) }
        val r = Rekey(3, 1_794_000_000_000, TestKeys.pub, listOf(annaId), benId, parts)
        val back = Rekey.decode(r.encode())!!
        assertEquals(3L, back.epoch); assertEquals(1_794_000_000_000, back.made); assertArrayEquals(TestKeys.pub, back.maker)
        assertEquals(listOf(annaId), back.admins); assertEquals(benId, back.answers); assertEquals(listOf(annaId, benId), back.members)
        val benPart = back.parts.first { it.first == benId }.second
        assertArrayEquals(secret, Hpke.open(benPart, ben, Rekey.info(gid), Rekey.aad(pid, benId)))
        assertNull(Hpke.open(benPart, anna, Rekey.info(gid), Rekey.aad(pid, benId)))   // Anna can't open Ben's part
        assertNull(Hpke.open(benPart, ben, Rekey.info(gid), Rekey.aad(pid, annaId)))   // nor can it be moved to another member
        assertNull(Rekey.decode(r.encode() + byteArrayOf(0)))                          // trailing bytes: no
        assertNull(Rekey(1, 1, TestKeys.pub, emptyList(), null, emptyList()).encode().let { Rekey.decode(it)?.answers })
    }

    @Test fun rekeysTravelAtTheDoorWithTheirOwnKey() {
        val door = GroupCrypto("test-group-1")
        assertEquals(door.mailbox, door.rekeys().mailbox)
        val id = Packet.newId(door.mailbox)
        val p = Packet(id, 1, 16, door.rekeys().seal(id, 1, "c482f374ea24d954", "Anna", "", extra = Rekey(1, 1, TestKeys.pub, emptyList(), null, emptyList()).encode()) { TestKeys.sign(it) })
        assertNull(door.open(p)); assertNull(door.intros().open(p)) // not a message, not an introduction
        assertEquals(Rekey.TYPE, door.rekeys().openSigned(p)!!.extra!![0])
    }

    @Test fun removalCarriesItsTypeAndTheNewCode() {
        val r = Rekey(4, 9, TestKeys.pub, listOf("1111111111111111"), "3333333333333333", listOf("1111111111111111" to ByteArray(3)), removal = true)
        val back = Rekey.decode(r.encode())!!
        assertTrue(back.removal); assertEquals("3333333333333333", back.answers); assertEquals(Rekey.REMOVAL, r.encode()[0])
        // A removal has to say who went.
        assertNull(Rekey.decode(Rekey(4, 9, TestKeys.pub, emptyList(), null, emptyList(), removal = true).encode()))
        val secret = ByteArray(32) { 7 }
        val (s, code) = Rekey.unbox(Rekey.box(secret, "K7QF-2M9X-PA4T-W8RJ"), true)!!
        assertArrayEquals(secret, s); assertEquals("K7QF-2M9X-PA4T-W8RJ", code)
        assertNull(Rekey.unbox(Rekey.box(secret, null), false)!!.second)
        // Anyone with the code can seal a part: wrong shapes are refused, not trusted.
        assertNull(Rekey.unbox(ByteArray(31), false)); assertNull(Rekey.unbox(ByteArray(33), false)); assertNull(Rekey.unbox(ByteArray(32), true))
        assertNull(Rekey.unbox(ByteArray(32 + 201), true))
        assertNull(Rekey.unbox(ByteArray(32) + byteArrayOf(0xFF.toByte()), true)) // not UTF-8: refused on both apps, or the group would split
    }

    @Test fun rekeyBytesMatchTheIphone() { // the iPhone's RekeyTests.testRekeyBytesMatchAndroid expects the same hex
        val r = Rekey(1, 2, ByteArray(33), listOf("0102030405060708"), null, listOf("1111111111111111" to ByteArray(3)))
        assertEquals("06" + "0000000000000001" + "0000000000000002" + "00".repeat(33) + "01" + "0102030405060708" + "0000000000000000" +
            "0001" + "1111111111111111" + "0001" + "1111111111111111" + "0003" + "000000", r.encode().joinToString("") { "%02x".format(it) })
    }
}
