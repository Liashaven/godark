package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test

/**
 * Who wrote a message, and what the app shows about that: found in the 2026-11-13 audit. The rules live in the core
 * (KeyWait, Senders, Deliveries, Blocks, Checked, Vouch.key) so that they can be checked here; MeshEngine only calls
 * them. The iPhone's AuthorshipTests check the same. Dummy keys only.
 */
class AuthorshipTest {
    private val now = 1_800_000_000_000L
    private val everyone = GroupCrypto(GroupCrypto.PUBLIC_CODE)
    private fun memberId(k: java.security.KeyPair) = P256.memberId(P256.compress(k.public))
    private fun pid(i: Int) = "%016x".format(i)

    // ---- A waiting signature check belongs to one packet, not to an id ----

    /** F: under T's id, with a signature that doesn't check. G: the same packet id, signed by A. Both open; A's introduction comes next. */
    @Test fun theCheckOfAnotherPacketWithTheSameIdDoesNotReachTheMessageShown() {
        val a = P256.newKeyPair(); val aId = memberId(a); val t = "aaaaaaaaaaaaaaaa"
        val id = Packet.newId(everyone.mailbox)
        val f = everyone.openSigned(Packet(id, now, 16, everyone.seal(id, now, t, "Tina", "forged") { P256.sign(a.private, "another message".toByteArray()) }))!!
        val g = everyone.openSigned(Packet(id, now, 16, everyone.seal(id, now, aId, "A", "real") { P256.sign(a.private, it) }))!!
        assertFalse(P256.verify(a.public, f.digest, f.signature)); assertTrue(P256.verify(a.public, g.digest, g.signature))
        assertNotEquals("one id, two packets", f.key, g.key)

        val w = KeyWait<String, GroupCrypto.Opened>()
        assertTrue(w.message(f.key, Blocks.EVERYONE, t, id, shown = true, f))     // F came first: it is the row shown, not verified
        assertFalse(w.message(g.key, Blocks.EVERYONE, aId, id, shown = false, g)) // the chat has that id already: G is not shown
        assertTrue("G's check must not mark the row that shows F", w.take(Blocks.EVERYONE, aId).isEmpty())
        val forT = w.take(Blocks.EVERYONE, t)                                     // T's own introduction checks F, and F fails
        assertEquals(listOf(id), forT.map { it.row }); assertSame(f, forT.single().item)
        assertEquals(0, w.count(Blocks.EVERYONE))
    }

    /** The other order: T's real message is shown, then a packet with its id and a bad signature. T's introduction must check the real one. */
    @Test fun aLaterPacketWithTheSameIdDoesNotReplaceTheWaitingCheck() {
        val t = P256.newKeyPair(); val tId = memberId(t); val id = Packet.newId(everyone.mailbox)
        val real = everyone.openSigned(Packet(id, now, 16, everyone.seal(id, now, tId, "Tina", "real") { P256.sign(t.private, it) }))!!
        val fake = everyone.openSigned(Packet(id, now, 16, everyone.seal(id, now, tId, "Tina", "fake") { ByteArray(64) { 1 } }))!!
        val w = KeyWait<String, GroupCrypto.Opened>()
        assertTrue(w.message(real.key, Blocks.EVERYONE, tId, id, shown = true, real))
        assertFalse(w.message(fake.key, Blocks.EVERYONE, tId, id, shown = false, fake))
        val got = w.take(Blocks.EVERYONE, tId)
        assertSame(real, got.single().item)
        assertTrue(P256.verify(t.public, got.single().item.digest, got.single().item.signature))
    }

    @Test fun aReceiptAndAMessageWithOnePacketIdBothWait() {
        val w = KeyWait<String, String>(); val id = pid(1); val sender = "1111111111111111"
        assertTrue(w.message("$id:m", "g", sender, id, shown = true, "message"))
        assertTrue(w.receipt("$id:r", "g", sender, "receipt"))
        assertFalse("the same receipt, read again from the store", w.receipt("$id:r", "g", sender, "receipt"))
        assertEquals(listOf("message", "receipt"), w.take("g", sender).map { it.item })
    }

    @Test fun aRowMadeAgainFromAnotherPacketDropsWhatWaitedForTheOldOne() {
        val w = KeyWait<String, String>(); val id = pid(2)
        w.message("$id:old", "g", "1111111111111111", id, shown = true, "old")
        w.message("$id:new", "g", "2222222222222222", id, shown = true, "new") // the old row left the chat, a new one was made
        assertTrue(w.take("g", "1111111111111111").isEmpty())
        assertEquals(listOf("new"), w.take("g", "2222222222222222").map { it.item })
    }

    // ---- The waiting list: the Public channel can't use up a group's room, and it empties ----

    @Test fun everyoneMessagesFromSendersNeverIntroducedLeaveTheGroupsRoomAlone() {
        val w = KeyWait<String, Int>(); val member = "1111111111111111"
        for (i in 0 until 5_000) assertTrue(w.message("${pid(i)}:x", Blocks.EVERYONE, "%016x".format(0xf000 + i), pid(i), shown = true, i))
        assertEquals(KeyWait.MAX, w.count(Blocks.EVERYONE))
        // A group message that arrives before its sender's introduction still waits, and is checked when it comes.
        assertTrue(w.message("${pid(9_000)}:x", "group", member, pid(9_000), shown = true, 9_000))
        assertTrue(w.receipt("${pid(9_001)}:x", "group", member, 9_001))
        assertEquals(listOf(9_000, 9_001), w.take("group", member).map { it.item })
        // In the Public channel the newest stay: a full list drops its own oldest.
        assertTrue(w.take(Blocks.EVERYONE, "%016x".format(0xf000)).isEmpty())
        assertEquals(listOf(4_999), w.take(Blocks.EVERYONE, "%016x".format(0xf000 + 4_999)).map { it.item })
    }

    @Test fun whatWaitedForARowThatLeftTheChatGoesWithIt() {
        val w = KeyWait<String, Int>(max = 3)
        for (i in 0 until 3) w.message("${pid(i)}:x", "g", "1111111111111111", pid(i), shown = true, i)
        w.forget(listOf(pid(0), pid(1), "0000000000000fff"))
        assertEquals(1, w.count("g"))
        assertEquals(listOf(2), w.take("g", "1111111111111111").map { it.item })
        assertEquals(0, w.count("g"))
    }

    @Test fun aWifiBoardPostWaitsForItsHostPhonesKey() {
        val w = KeyWait<String, String>(); val host = "1111111111111111"
        w.message("${pid(3)}:x", Blocks.EVERYONE, "web-$host", pid(3), shown = true, "board post")
        assertEquals(listOf("board post"), w.take(Blocks.EVERYONE, host).map { it.item })
    }

    // ---- Nothing received may pass for written on this phone ----

    @Test fun aSenderThatIsThisPhonesOwnMarkIsRefused() {
        val me = "0123456789abcdef"; val device = "7c0d995b-2c4" // the shape of a device id: 12 characters of a UUID
        assertNull(Senders.shown(device, me, device))
        assertNull("whatever shape the saved mark has", Senders.shown("1111111111111111", me, "1111111111111111"))
        assertEquals("only this phone's member id becomes its mark", device, Senders.shown(me, me, device))
        assertEquals("2222222222222222", Senders.shown("2222222222222222", me, device))
        assertEquals("web-$me", Senders.shown("web-$me", me, device)) // a Wi-Fi board post is someone else's
    }

    @Test fun aSenderHasToBeAMemberId() {
        val me = "0123456789abcdef"; val device = "7c0d995b-2c4"
        for (bad in listOf("", "alice", "7c0d995b-2c5", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "web-", "web-web-0123456789abcdef", " 0123456789abcdef", "0123456789abcdeg"))
            assertNull(bad, Senders.shown(bad, me, device))
        assertTrue(Senders.isMemberId(memberId(P256.newKeyPair())))
    }

    /** What the engine does with it: the Public channel opens a packet whose sender is the phone's mark, and the rule turns it away. */
    @Test fun aPublicPacketUnderThisPhonesMarkOpensButIsNotShown() {
        val device = "7c0d995b-2c4"; val stranger = P256.newKeyPair(); val id = Packet.newId(everyone.mailbox)
        val o = everyone.openSigned(Packet(id, now, 16, everyone.seal(id, now, device, "Stranger", "hello") { P256.sign(stranger.private, it) }))!!
        assertEquals(device, o.message.sender)
        assertNull(Senders.shown(o.message.sender, memberId(P256.newKeyPair()), device))
    }

    // ---- Receipts: bound to their group, limited, and only for messages written here ----

    private fun receipt(sender: String, name: String, ts: Long, ids: List<String>) = Message("r$sender$ts", ts, sender, name, Receipt.text(ids))

    @Test fun aReceiptFromAnotherGroupConfirmsNothing() {
        val d = Deliveries(); val inA = pid(0xa1)
        d.sent("group-a", inA)
        d.add("group-b", receipt("3333333333333333", "Grandma Rosa", 100, listOf(inA))) // a member of B lists an id seen on the air
        assertTrue(d.readers(inA).isEmpty())
        d.add("group-a", receipt("4444444444444444", "Lucia", 200, listOf(inA)))
        assertEquals(listOf("Lucia"), d.readers(inA).map { it.name })
    }

    @Test fun aReceiptCountsAtMost200Ids() {
        val many = (0 until 935).map(::pid) // what fits in one packet
        assertEquals(many.take(200), Receipt.ids(Receipt.text(many)))
        val d = Deliveries(); many.forEach { d.sent("g", it) }
        d.add("g", receipt("3333333333333333", "Marco", 100, many))
        assertEquals(200, many.count { d.readers(it).isNotEmpty() })
    }

    @Test fun idsThatAreNoMessageOfThisPhoneTakeNoMemory() {
        val d = Deliveries(); val mine = pid(1)
        d.sent("g", mine)
        for (i in 0 until 200) d.add("g", receipt("3333333333333333", "Marco", 100L + i, (0 until 200).map { pid(1_000 + 200 * i + it) }))
        val table = Deliveries::class.java.getDeclaredField("byMessage").apply { isAccessible = true }.get(d) as Map<*, *>
        assertTrue("${table.size} ids kept", table.isEmpty())
        d.add("g", receipt("3333333333333333", "Marco", 100, listOf(pid(5), mine)))
        assertEquals(setOf(mine), table.keys)
        d.forget(listOf(mine)) // the message left the store
        assertTrue(table.isEmpty())
        d.add("g", receipt("3333333333333333", "Marco", 100, listOf(mine)))
        assertTrue(d.readers(mine).isEmpty())
    }

    // ---- Blocking: per channel, and only a checked sender ----

    @Test fun aBlockMadeInEveryoneDoesNotHideAGroupMember() {
        val bea = "5555555555555555"; val group = "0f0e0d0c0b0a09080706050403020100"
        val troll = Message(pid(1), now, bea, "Troll", "spam", public = true)                // posted under Bea's group id
        assertTrue(Blocks.canBlock(troll, "7c0d995b-2c4"))
        val blocked = setOf(Blocks.key(Blocks.EVERYONE, troll.sender))
        assertTrue(Blocks.hides(blocked, Blocks.EVERYONE, bea))
        assertFalse("Bea's check-ins and calls for help in the group stay", Blocks.hides(blocked, group, bea))
        assertFalse(Blocks.hides(setOf(Blocks.key(group, bea)), "another group", bea))
        assertFalse(Blocks.hides(blocked, null, bea))
    }

    @Test fun theSenderOfAnUncheckedMessageCannotBeBlocked() {
        val m = Message(pid(1), now, "5555555555555555", "Troll", "spam", public = true)
        assertFalse(Blocks.canBlock(m.copy(verified = false), "7c0d995b-2c4"))
        assertTrue(Blocks.canBlock(m, "7c0d995b-2c4"))
        assertFalse("not one's own", Blocks.canBlock(m.copy(sender = "7c0d995b-2c4"), "7c0d995b-2c4"))
    }

    @Test fun aBlockSavedBeforeBlocksHadAChannelStillHides() {
        assertTrue(Blocks.hides(setOf("5555555555555555"), "any group", "5555555555555555"))
        assertTrue(Blocks.hides(setOf("5555555555555555"), Blocks.EVERYONE, "5555555555555555"))
        assertFalse(Blocks.hides(setOf("5555555555555555"), Blocks.EVERYONE, "6666666666666666"))
    }

    // ---- A checked person's name: what draws the same matches ----

    @Test fun anInvisibleCharacterDoesNotChangeANameKey() {
        assertEquals(Vouch.key("Anna"), Vouch.key("An\u200Bna"))
        assertEquals(Vouch.key("Anna"), Vouch.key("Anna\u2060"))
        for (c in listOf("\u200B", "\u200C", "\u200D", "\u2060", "\uFEFF", "\u00AD", "\u200E", "\u200F", "\u202E", "\u2066", "\u034F", "\u061C", "\u180E", "\u3164", "\uFFA0", "\uFE0F",
            "\u001F", "\u0000", "\u007F", String(Character.toChars(0xE0061)), String(Character.toChars(0xE0100)))) {
            assertEquals("U+%04X inside".format(c.codePointAt(0)), "marco", Vouch.key("Mar${c}co"))
            assertEquals("U+%04X at the end".format(c.codePointAt(0)), "marco", Vouch.key("Marco$c"))
        }
        for (c in listOf("\u0085", "\u00A0", "\u2003", "\u2028", "\u3000", "\u2800", "\t", "\n")) assertEquals("U+%04X".format(c.codePointAt(0)), "anna maria", Vouch.key("Anna${c}Maria$c"))
    }

    @Test fun compatibilityFormsOfANameMatchIt() {
        assertEquals("jos\u00E9", Vouch.key("Jose\u0301"))             // e + combining accent
        assertEquals("jos\u00E9", Vouch.key("JOS\u00C9"))
        assertEquals("anna", Vouch.key("\uFF21\uFF4E\uFF4E\uFF41")) // full-width letters
        assertEquals("\u00E1nna", Vouch.key("a\u200D\u0301nna"))        // the accent joins its letter once the joiner is gone
        assertEquals("grandma rosa", Vouch.key("  Grandma\tROSA "))
        assertEquals("anna maria", Vouch.key("Anna Maria"))
        assertNotEquals(Vouch.key("Marco"), Vouch.key("Marc\u043E"))  // a look-alike letter is still another name
        for (n in listOf("Anna", "Jose\u0301", "\uFF21nna\u200B", "Grandma  Rosa")) assertEquals(Vouch.key(n), Vouch.key(Vouch.key(n)))
    }

    @Test fun aCheckedPersonsNameWithAnInvisibleCharacterStillWarns() {
        val g = "0f0e0d0c0b0a09080706050403020100"; val anna = "1111111111111111"; val other = "2222222222222222"
        val checked = setOf(Checked.entry(g, anna, "Anna"))
        assertEquals(setOf("$g|$anna|anna"), checked)
        assertTrue(Checked.newKey(checked, g, other, "Anna"))
        assertTrue(Checked.newKey(checked, g, other, "Anna\u200B"))
        assertTrue(Checked.newKey(checked, g, other, "An\u00ADna "))
        assertFalse("her own key", Checked.newKey(checked, g, anna, "Anna\u200B"))
        assertFalse(Checked.newKey(checked, g, other, "Marco"))
        assertFalse("another group", Checked.newKey(checked, "ffffffffffffffffffffffffffffffff", other, "Anna"))
        // An entry saved by an older version keeps the older key; it is matched all the same.
        assertTrue(Checked.newKey(setOf("$g|$anna|anna\uFE0F"), g, other, "Anna"))
        assertTrue(Checked.newKey(setOf("$g|$anna|a|b"), g, other, "A|B"))
        assertFalse(Checked.newKey(setOf("$g|$anna|a|b"), g, other, "B"))
    }

    @Test fun markingAPersonCheckedReplacesTheOlderKeyForTheirName() {
        val g = "0f0e0d0c0b0a09080706050403020100"
        var checked = Checked.marked(emptySet(), g, "1111111111111111", "Anna")
        checked = Checked.marked(checked, g, "3333333333333333", "Marco")
        checked = Checked.marked(checked, g, "2222222222222222", "Anna\u200B") // Anna's new phone, compared again
        assertEquals(setOf("$g|2222222222222222|anna", "$g|3333333333333333|marco"), checked)
        assertFalse(Checked.newKey(checked, g, "2222222222222222", "Anna"))
        assertTrue(Checked.newKey(checked, g, "1111111111111111", "Anna"))
    }
}
