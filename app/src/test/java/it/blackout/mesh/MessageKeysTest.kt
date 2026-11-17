package it.blackout.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Per-message keys (spec "Message keys"). The vector was made by the iPhone's code, so these also check that both apps agree. */
class MessageKeysTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val v = File("../spec/test-vectors.txt").readText().split(Regex("\n\\s*\n"))
        .map { b -> b.lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { it.substringBefore(": ") to it.substringAfter(": ") } }
        .first { it["kind"] == "message-key" }
    private val anna = "1111111111111111"; private val ben = "2222222222222222"
    private val secret = ByteArray(32) { 9 }
    private val id = "6a44000000000009"; private val ts = 1_794_000_123_456L
    private fun keys() = MessageKeys.of(secret, listOf(anna, ben))

    @Test fun matchesTheSharedVector() {
        val s = unhex(v["secret"]!!); val members = listOf(v["member_0"]!!, v["member_1"]!!)
        val outer = MessageKeys.outer(s); assertEquals(v["outer"], hex(outer))
        val g = GroupCrypto.fromSecret(outer); assertEquals(v["mailbox"]!!.toInt(), g.mailbox)
        val mk = MessageKeys.of(s, members).key(1, 5)!!; assertEquals(v["key_1_5"], hex(mk))
        val t = v["ts"]!!.toLong()
        val c = g.sealWith(mk, 1, 5, v["id"]!!, t, v["sender"]!!, v["name"]!!, v["text"]!!, iv = unhex(v["iv"]!!)) { unhex(v["signature"]!!) }
        assertEquals(v["cipher"], hex(c)); assertEquals(v["wire_ts"]!!.toLong(), g.hideTime(t, c))
        val p = Packet(v["id"]!!, v["wire_ts"]!!.toLong(), 16, unhex(v["cipher"]!!))
        assertEquals(1 to 5, g.header(p))
        val o = g.openWith(mk, 1, 5, p)!!
        assertEquals(v["text"], o.message.text); assertEquals(t, o.message.ts); assertEquals(v["sender"], o.message.sender)
        // What the signature covers: the position and number too, under a tag of its own.
        assertEquals(hex(java.security.MessageDigest.getInstance("SHA-256").digest(unhex(v["signed_message"]!!))), hex(o.digest))
    }

    @Test fun aDeletedKeyIsGoneAndTheOthersStay() {
        val k = keys(); val before = (0..9).map { k.key(1, it)!! }
        k.forget(1, 4)
        assertNull(k.key(1, 4))
        for (i in (0..9) - 4) assertArrayEquals("key $i", before[i], k.key(1, i))
    }

    @Test fun keysCanBeDeletedInAnyOrder() {
        val k = keys(); val whole = keys(); val order = (0 until 300).shuffled(java.util.Random(5))
        order.take(150).forEach { k.forget(0, it) }
        order.take(150).forEach { assertNull(k.key(0, it)) }
        order.drop(150).forEach { assertArrayEquals(whole.key(0, it), k.key(0, it)) }
    }

    @Test fun eachSenderHasItsOwnKeys() { assertTrue(!keys().key(0, 0)!!.contentEquals(keys().key(1, 0)!!)) }

    @Test fun deletingOneSendersKeyLeavesTheOthers() { val k = keys(); k.forget(0, 3); assertNotNull(k.key(1, 3)) }

    @Test fun whatWasDeletedStaysDeletedAfterARestart() {
        val k = keys(); k.forget(1, 7); k.takeNext(); k.takeNext()
        val back = MessageKeys.decode(k.encode())!!
        assertNull(back.key(1, 7)); assertArrayEquals(keys().key(1, 8), back.key(1, 8)); assertEquals(2, back.takeNext()); assertEquals(listOf(anna, ben), back.members)
    }

    @Test fun numbersOutsideTheTreeHaveNoKey() { assertNull(keys().key(0, 65_536)); assertNull(keys().key(0, -1)); assertNull(keys().key(5, 0)) }

    @Test fun whenTheNumbersRunOutThereIsNoNext() {
        val k = MessageKeys.decode(keys().encode().also { java.nio.ByteBuffer.wrap(it).putInt(SenderTree.LEAVES) })!!
        assertNull(k.takeNext())
    }

    private fun epoch() = Keyring.Epoch.fresh(6, 1, secret, listOf(anna, ben), listOf(anna))
    private fun sealedBy(e: Keyring.Epoch, n: Int, at: Long = ts, sign: (ByteArray) -> ByteArray = { TestKeys.sign(it) }): Packet {
        val c = e.group.sealWith(e.messageKeys!!.key(1, n)!!, 1, n, id, at, ben, "Ben", "message $n", sign = sign)
        return Packet(id, e.group.hideTime(at, c), 16, c)
    }
    private fun signedByBen(o: GroupCrypto.Opened) = P256.verify(TestKeys.pair.public, o.digest, o.signature)

    @Test fun twoPhonesWithTheSameSecretReadEachOther() {
        val o = epoch().open(sealedBy(epoch(), 2))!!
        assertEquals("message 2", o.message.text); assertEquals(ts, o.message.ts); assertEquals(2, o.leaf!!.counter); assertEquals(1, o.leaf!!.index)
    }

    @Test fun oncDeletedTheEpochCantOpenThePacketAgain() {
        val e = epoch(); val p = sealedBy(epoch(), 2)
        e.open(p)!!.leaf!!.forget()
        assertNull(e.open(p))
    }

    @Test fun openingAloneDoesntDeleteTheKey() {
        // A member could forge a packet under someone else's number; the key goes only after the signature has checked.
        val e = epoch(); val forged = sealedBy(epoch(), 3) { ByteArray(64) }
        assertNotNull(e.open(forged)); assertNotNull(e.messageKeys!!.key(1, 3))
    }

    @Test fun aMemberCantUseUpSomeoneElsesKey() {
        // Ben seals under Anna's position and number and signs as himself: the signature would check, so it must not open.
        val e = epoch(); val g = epoch().group
        val c = g.sealWith(epoch().messageKeys!!.key(0, 7)!!, 0, 7, id, ts, ben, "Ben", "not Anna") { TestKeys.sign(it) }
        assertNull(e.open(Packet(id, g.hideTime(ts, c), 16, c)))
        assertNotNull(e.messageKeys!!.key(0, 7))
    }

    @Test fun aSignedMessageCantBeSealedAgainUnderAnotherNumber() {
        // Every member holds every member's message keys. One of them reads Ben's message number 2 and seals its body and
        // signature again under Ben's unused number 9. If that signature checked, phones would delete Ben's key 9, and
        // what he later writes under it could no longer be opened.
        val e = epoch(); val insider = epoch()
        val first = insider.open(sealedBy(epoch(), 2))!!
        assertTrue(signedByBen(first))
        val c = insider.group.sealWith(insider.messageKeys!!.key(1, 9)!!, 1, 9, id, ts, ben, "Ben", "message 2") { first.signature }
        val again = e.open(Packet(id, insider.group.hideTime(ts, c), 16, c))
        assertTrue(again == null || !signedByBen(again))
        assertNotNull(e.messageKeys!!.key(1, 9))
    }

    @Test fun aSignatureDoesntMoveBetweenTheEpochKeyAndAMessageKey() {
        // Unpadded, both kinds of packet have the same body: only what is signed around it tells them apart.
        val e = epoch(); val g = epoch().group; val keys = epoch().messageKeys!!
        val own = g.sealWith(keys.key(1, 2)!!, 1, 2, id, ts, ben, "Ben", "hello", pad = Pad.NONE) { TestKeys.sign(it) }
        val first = epoch().open(Packet(id, g.hideTime(ts, own), 16, own))!!
        assertTrue(signedByBen(first))
        val shared = g.seal(id, ts, ben, "Ben", "hello", pad = Pad.NONE) { first.signature }
        assertFalse(signedByBen(e.open(Packet(id, g.hideTime(ts, shared), 16, shared))!!))
        // The other way round, it would use up a number: Ben's message under the epoch's key, sealed again under his number 9.
        val plain = g.seal(id, ts, ben, "Ben", "hello", pad = Pad.NONE) { TestKeys.sign(it) }
        val second = e.open(Packet(id, g.hideTime(ts, plain), 16, plain))!!
        assertTrue(signedByBen(second))
        val moved = g.sealWith(keys.key(1, 9)!!, 1, 9, id, ts, ben, "Ben", "hello", pad = Pad.NONE) { second.signature }
        assertFalse(signedByBen(e.open(Packet(id, g.hideTime(ts, moved), 16, moved))!!))
    }

    @Test fun theEpochKeyOpensOnlyWhatItsMembersWrote() {
        // Every member holds the epoch's key, and so does someone removed since. Sealed with it, a packet under an id
        // nobody was let in with would be shown as "not verified yet", with any name: it must not open.
        val g = epoch().group; val madeUp = "3333333333333333"
        fun sealed(sender: String) = g.seal(id, ts, sender, "Anna", "I need help") { ByteArray(64) }.let { Packet(id, g.hideTime(ts, it), 16, it) }
        assertNull(epoch().open(sealed(madeUp)))
        assertNull(epoch().forReadingOnly().open(sealed(madeUp)))
        assertNull(Keyring.Epoch(6, 1, MessageKeys.outer(secret), listOf(anna, ben), listOf(anna)).open(sealed(madeUp))) // an epoch from before message keys
        // A member whose numbers ran out writes with the epoch's key: that still opens, also in an epoch kept only to read with.
        for (e in listOf(epoch(), epoch().forReadingOnly(), Keyring.Epoch(6, 1, MessageKeys.outer(secret), listOf(anna, ben), listOf(anna)))) {
            val o = e.open(sealed(ben))!!
            assertEquals(ben, o.message.sender); assertNull(o.leaf)
            assertNotNull(e.open(sealed("web-$ben")))
        }
    }

    @Test fun aReceiptCountsOnlyFromSomeoneInTheEpoch() {
        val rc = epoch().receipts; val rid = "6a4400000000000b"
        fun receipt(sender: String) = rc.seal(rid, ts, sender, "Anna", id) { ByteArray(64) }.let { Packet(rid, rc.hideTime(ts, it), 16, it) }
        assertNull(epoch().openReceipt(receipt("3333333333333333")))
        assertNull(epoch().forReadingOnly().openReceipt(receipt("3333333333333333")))
        assertEquals(ben, epoch().openReceipt(receipt(ben))!!.message.sender)
        assertNotNull(epoch().forReadingOnly().openReceipt(receipt(anna)))
        assertNull(epoch().openReceipt(sealedBy(epoch(), 1)))                    // a message isn't a receipt
    }

    @Test fun whatSomeoneRemovedWritesIsShownOnlyIfThisPhoneHadItBefore() {
        // Ben was removed at ts. Phones go on reading with epoch 6, whose keys he has, for another week.
        val ring = Keyring(); ring.add(epoch())
        ring.add(Keyring.Epoch.fresh(7, ts, ByteArray(32) { 7 }, listOf(anna), listOf(anna), "AAAA-AAAA-AAAA-AAAA", "old", ben, anna, 0))
        // He writes afterwards and dates it a minute before: it opens, the signature is his, and its date says "before".
        val o = ring.all().firstNotNullOf { it.open(sealedBy(epoch(), 2, at = ts - 60_000)) }
        assertTrue(signedByBen(o)); assertFalse(ring.removedBefore(ben, o.message.ts))
        assertTrue(ring.shutOut(ben, o.message.ts, had = false))                 // seen for the first time now: not shown, whatever its date
        assertTrue(ring.shutOut(ben, 0, had = false))
        assertFalse(ring.shutOut(ben, o.message.ts, had = true))                 // this phone had it before the removal came: it stays
        assertFalse(ring.shutOut(ben, ts, had = true)); assertTrue(ring.shutOut(ben, ts + 1, had = true)) // unless it is dated after the removal
        assertFalse(ring.shutOut(anna, ts + 1, had = false))                     // nobody else is touched
    }

    @Test fun aBoardMessageCountsAsThePhonesOwn() {
        val g = epoch().group
        val c = g.sealWith(epoch().messageKeys!!.key(1, 2)!!, 1, 2, id, ts, "web-$ben", "Visitor", "hello") { TestKeys.sign(it) }
        assertNotNull(epoch().open(Packet(id, g.hideTime(ts, c), 16, c))?.leaf)
    }

    @Test fun theEpochSecretIsntKept() { val e = epoch(); assertTrue(!e.secret.contentEquals(secret)); assertArrayEquals(MessageKeys.outer(secret), e.secret) }

    @Test fun aKeyKeptForReadingStillOpens() { val e = epoch().forReadingOnly(); assertNotNull(e.open(sealedBy(epoch(), 1))) }

    @Test fun theCopyKeepsTheMessage() {
        val key = ByteArray(32) { 3 }; val e = epoch(); val o = e.open(sealedBy(epoch(), 4))!!
        val s = History.open(key, id, History.seal(key, id, "00112233445566778899aabbccddeeff", e.hash, o, 1, 4))!!
        assertEquals("message 4", s.opened.message.text); assertEquals(ts, s.opened.message.ts); assertEquals(e.hash, s.epoch)
        assertArrayEquals(o.digest, s.opened.digest); assertArrayEquals(o.signature, s.opened.signature); assertEquals(1, s.index); assertEquals(4, s.counter)
    }

    @Test fun theCopyNeedsItsKeyAndId() {
        val key = ByteArray(32) { 3 }; val e = epoch(); val o = e.open(sealedBy(epoch(), 4))!!
        val b = History.seal(key, id, "00112233445566778899aabbccddeeff", e.hash, o, 1, 4)
        assertNull(History.open(ByteArray(32), id, b)); assertNull(History.open(key, "6a4400000000000a", b))
    }

    @Test fun aMessageFitsTheSmallestSize() { assertEquals(163, sealedBy(epoch(), 0).encode().size) }
}
