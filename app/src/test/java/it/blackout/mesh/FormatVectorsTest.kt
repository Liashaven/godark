package it.blackout.mesh

import org.junit.Assert.*
import org.junit.Test
import java.io.File

/** Checks the Kotlin implementation byte-for-byte against spec/test-vectors.txt, which the iPhone app also checks. */
class FormatVectorsTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private val vectors: List<Map<String, String>> =
        File("../spec/test-vectors.txt").readText(Charsets.UTF_8).split(Regex("\n\\s*\n")).map { block ->
            block.lines().filter { it.isNotBlank() && !it.startsWith("#") }
                .associate { it.substringBefore(": ") to it.substringAfter(": ") }
        }.filter { it.isNotEmpty() }

    private fun code(v: Map<String, String>) = v["code"] ?: String(unhex(v["code_hex"]!!), Charsets.UTF_8)

    @Test fun vectorFileHasAllKinds() {
        assertEquals(4, vectors.count { it["kind"] == "kdf" }) // includes the Public channel code
        assertEquals(2, vectors.count { it["kind"] == "member" })
        assertEquals(1, vectors.count { it["kind"] == "signed" }); assertEquals(1, vectors.count { it["kind"] == "signed-intro" })
    }

    @Test fun memberIdsAndEmojiMatch() = vectors.filter { it["kind"] == "member" }.forEach { v ->
        val pub = unhex(v["public_key"]!!)
        assertEquals(v["member_id"], P256.memberId(pub))
        assertEquals(v["emoji"], P256.emoji(pub).joinToString(" "))
        assertArrayEquals(pub, P256.compress(P256.decompress(pub)!!)) // decompressing gives the same point back
    }

    @Test fun keyDerivationMatches() = vectors.filter { it["kind"] == "kdf" }.forEach { v ->
        assertEquals(v.toString(), v["key"], hex(GroupCrypto.deriveKey(code(v))))
    }

    private fun checkSigned(v: Map<String, String>, crypto: GroupCrypto) {
        val id = v["id"]!!; val ts = v["ts"]!!.toLong(); val sig = unhex(v["signature"]!!)
        val p = Packet.decode(unhex(v["packet"]!!))!!
        assertEquals(id, p.id); assertEquals(ts, p.ts); assertEquals(16, p.ttl)
        val o = crypto.openSigned(p)!!
        assertEquals(v["member_id"], o.message.sender); assertEquals(v["name"], o.message.name)
        assertArrayEquals(sig, o.signature)
        val pub = P256.decompress(unhex(v["public_key"]!!))!!
        assertTrue(P256.verify(pub, o.digest, o.signature))
        assertFalse(P256.verify(pub, o.digest, sig.copyOf().also { it[63] = (it[63] + 1).toByte() })) // one bit off: no
        assertFalse(P256.verify(P256.newKeyPair().public, o.digest, o.signature))                   // another key: no
        // Sealing the same body with the same signature and IV gives the same bytes.
        val again = crypto.seal(id, ts, o.message.sender, o.message.name, o.message.text, extra = o.extra, iv = unhex(v["iv"]!!), pad = Pad.NONE) { sig }
        assertEquals(v["packet"], hex(Packet(id, ts, 16, again).encode()))
    }

    @Test fun signedMessageMatches() = vectors.filter { it["kind"] == "signed" }.forEach { v ->
        checkSigned(v, GroupCrypto(v["code"]!!))
        assertEquals(v["text"], GroupCrypto(v["code"]!!).open(Packet.decode(unhex(v["packet"]!!))!!)!!.text)
        assertNull(GroupCrypto("wrong-code").open(Packet.decode(unhex(v["packet"]!!))!!))
    }

    @Test fun introductionMatches() = vectors.filter { it["kind"] == "signed-intro" }.forEach { v ->
        assertEquals(v["intro_key"], hex(GroupCrypto.deriveIntroKey(GroupCrypto.deriveKey(v["code"]!!))))
        val intros = GroupCrypto(v["code"]!!).intros()
        checkSigned(v, intros)
        val o = intros.openSigned(Packet.decode(unhex(v["packet"]!!))!!)!!
        assertEquals("02" + v["public_key"], hex(o.extra!!)) // 0x02, then the public key
        assertNull(GroupCrypto(v["code"]!!).open(Packet.decode(unhex(v["packet"]!!))!!)) // not a message
    }

    @Test fun oldV02PacketsAreRejected() {
        val raw = unhex(vectors.first { it["kind"] == "signed" }["packet"]!!).also { it[0] = 0xB1.toByte() }
        assertNull(Packet.decode(raw))
    }
}
