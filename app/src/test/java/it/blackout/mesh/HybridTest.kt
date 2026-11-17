package it.blackout.mesh

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.KeyPair

/**
 * Post-quantum keys and new keys split over packets (spec "Sealing for one member", "New keys"). The vectors were made by
 * Apple's CryptoKit, so these tests also check that BouncyCastle's ML-KEM and this HPKE agree with it.
 */
class HybridTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val vectors = File("../spec/test-vectors.txt").readText().split(Regex("\n\\s*\n"))
        .map { b -> b.lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { it.substringBefore(": ") to it.substringAfter(": ") } }
    private fun of(kind: String) = vectors.first { it["kind"] == kind }

    private val info = "darkproof-rekey-v1".toByteArray(); private val aad = ByteArray(16) { 9 }; private val secret = ByteArray(32) { 7 }
    private val anna = "1111111111111111"; private val ben = "2222222222222222"
    private val now = 1_794_000_000_000L

    @Test fun mlKemAgreesWithApple() {
        val v = of("mlkem"); val seed = unhex(v["seed"]!!)
        val priv = org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters(org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters.ml_kem_768, seed)
        assertEquals(v["public_key"], hex(priv.publicKey))
        assertArrayEquals(unhex(v["shared"]!!), MlKem.decapsulate(seed, unhex(v["cipher"]!!)))
    }

    @Test fun aKeyMadeHereWorks() {
        val (pub, priv) = MlKem.newKey()
        assertEquals(MlKem.PUBLIC_SIZE, pub.size)
        val (cipher, shared) = MlKem.encapsulate(pub)!!
        assertEquals(MlKem.CIPHER_SIZE, cipher.size); assertEquals(32, shared.size)
        assertArrayEquals(shared, MlKem.decapsulate(priv, cipher))
    }

    @Test fun aKeyThatIsntOneIsRefused() { assertNull(MlKem.encapsulate(ByteArray(10))) }

    @Test fun pskModeMatchesTheSharedVector() {
        val v = of("hpke-psk")
        val rPub = P256.fromUncompressed(unhex(v["recipient_public"]!!))!!
        val r = KeyPair(rPub, P256.privateKey(unhex(v["recipient_private"]!!)))
        val e = KeyPair(P256.fromUncompressed(unhex(v["sealed"]!!).copyOf(Hpke.ENC_SIZE))!!, P256.privateKey(unhex(v["ephemeral_private"]!!)))
        val psk = unhex(v["psk"]!!)
        assertEquals(v["sealed"], hex(Hpke.seal(unhex(v["plaintext"]!!), rPub, unhex(v["info"]!!), unhex(v["aad"]!!), e, psk)))
        assertEquals(v["plaintext"], hex(Hpke.open(unhex(v["sealed"]!!), r, unhex(v["info"]!!), unhex(v["aad"]!!), psk)!!))
        assertNull(Hpke.open(unhex(v["sealed"]!!), r, unhex(v["info"]!!), unhex(v["aad"]!!)))              // not without the psk
        assertNull(Hpke.open(unhex(v["sealed"]!!), r, unhex(v["info"]!!), unhex(v["aad"]!!), ByteArray(32))) // nor with another
    }

    @Test fun aHybridBoxOpensWithBothKeys() {
        val r = P256.newKeyPair(); val (pub, priv) = MlKem.newKey()
        val box = Hybrid.seal(secret, r.public, pub, info, aad)!!
        assertEquals(MlKem.CIPHER_SIZE + Hpke.ENC_SIZE + 32 + 16, box.size)
        assertArrayEquals(secret, Hybrid.open(box, r, priv, info, aad))
    }

    @Test fun oneOfTheTwoKeysIsNotEnough() {
        val r = P256.newKeyPair(); val (pub, priv) = MlKem.newKey()
        val box = Hybrid.seal(secret, r.public, pub, info, aad)!!
        assertNull(Hybrid.open(box, P256.newKeyPair(), priv, info, aad))      // right ML-KEM key, wrong P-256 key
        assertNull(Hybrid.open(box, r, MlKem.newKey().second, info, aad))     // right P-256 key, wrong ML-KEM key
        assertNull(Hybrid.open(box, r, null, info, aad))                      // no ML-KEM key at all
    }

    @Test fun aChangedBoxIsRefused() {
        val r = P256.newKeyPair(); val (pub, priv) = MlKem.newKey()
        val box = Hybrid.seal(secret, r.public, pub, info, aad)!!
        for (at in listOf(0, MlKem.CIPHER_SIZE - 1, MlKem.CIPHER_SIZE, box.size - 1))
            assertNull("byte $at", Hybrid.open(box.copyOf().also { it[at] = (it[at] + 1).toByte() }, r, priv, info, aad))
        assertNull(Hybrid.open(box, r, priv, info, ByteArray(16) { 1 }))
    }

    @Test fun plainHpkeIsRefused() {
        val r = P256.newKeyPair()
        assertNull(Hybrid.open(Hpke.seal(secret, r.public, info, aad), r, MlKem.newKey().second, info, aad))
        assertNull(Hybrid.seal(secret, r.public, ByteArray(10), info, aad))
    }

    @Test fun aKeyGoesInOneThreeOrTenPackets() {
        for ((n, k) in listOf(1 to 1, 10 to 1, 11 to 3, 30 to 3, 31 to 10, 100 to 10)) assertEquals("$n members", k, Rekey.packets(n))
    }

    @Test fun splittingKeepsEveryoneAndAtMostTenInAPacket() {
        for (n in listOf(1, 7, 10, 11, 29, 30, 31, 64, 100)) {
            val people = (0 until n).toList(); val packets = Rekey.split(people)
            assertEquals(people, packets.flatten().sorted()); assertTrue(packets.all { it.size <= Rekey.PARTS_PER_PACKET })
        }
    }

    @Test fun theMemberListIsSeparateFromTheParts() {
        val members = (1..11).map { "%016x".format(it) }; val share = Rekey.split(members)[1]           // a key for 11 goes in 3 packets
        val r = Rekey(6, now, ByteArray(33), listOf(members[0]), null, share.map { it to ByteArray(4) }, members = members)
        val back = Rekey.decode(r.encode())!!
        assertEquals(members, back.members); assertEquals(share, back.parts.map { it.first })
        assertEquals(Rekey.TYPE, r.encode()[0])
        // Up to 10 members it is one packet with a part for each: listing someone and giving them none is refused.
        assertNull(Rekey.decode(Rekey(6, now, ByteArray(33), listOf(anna), null, listOf(ben to ByteArray(4)), members = listOf(anna, ben)).encode()))
    }

    @Test fun aPartForSomeoneNotInTheListIsRefused() {
        assertNull(Rekey.decode(Rekey(6, now, ByteArray(33), emptyList(), null, listOf(ben to ByteArray(4)), members = listOf(anna)).encode()))
    }

    @Test fun aPacketWithoutMyPartIsIgnoredAndTheOneWithItCounts() {
        val r = Keyring().also { it.add(Keyring.Epoch(5, now - 200 * 3_600_000L, ByteArray(32) { 5 }, listOf(anna, ben), listOf(anna))) }
        val other = Rekey(6, now, ByteArray(33), listOf(anna), null, listOf(anna to ByteArray(1)), members = listOf(anna, ben))
        assertSame(Keyring.Taken.Ignored, r.take(other, anna, ben, "door", false, null, now) { error("not this phone's part") })
        val mine = Rekey(6, now, ByteArray(33), listOf(anna), null, listOf(ben to ByteArray(1)), members = listOf(anna, ben))
        assertTrue(r.take(mine, anna, ben, "door", false, null, now) { ByteArray(32) { 6 } } is Keyring.Taken.Added)
    }

    @Test fun aPhoneStillJoiningWaitsForItsOwnPacketOfARemoval() {
        val removal = Rekey(6, now, ByteArray(33), listOf(anna), "3333333333333333", listOf(anna to ByteArray(1)), removal = true, members = listOf(anna, ben))
        assertSame(Keyring.Taken.Ignored, Keyring().take(removal, anna, ben, "door", false, null, now) { null })
        val notIn = Rekey(6, now, ByteArray(33), listOf(anna), "3333333333333333", listOf(anna to ByteArray(1)), removal = true, members = listOf(anna))
        assertSame(Keyring.Taken.Closed, Keyring().take(notIn, anna, ben, "door", false, null, now) { null })
    }

    @Test fun aPhoneJoiningFromAnInviteTakesKeysOnlyFromTheAdminsItNames() {
        val key = Rekey(1, now, ByteArray(33), listOf(anna), null, listOf(ben to ByteArray(1)), members = listOf(anna, ben))
        assertSame(Keyring.Taken.Ignored, Keyring().take(key, anna, ben, "door", false, null, now, pinned = false) { ByteArray(32) { 6 } })
        assertTrue(Keyring().take(key, anna, ben, "door", false, null, now, pinned = true) { ByteArray(32) { 6 } } is Keyring.Taken.Added)
    }

    @Test fun someoneTheInviteDoesntNameCantCloseIt() {
        val notIn = Rekey(6, now, ByteArray(33), listOf(anna), "3333333333333333", listOf(anna to ByteArray(1)), removal = true, members = listOf(anna))
        assertSame(Keyring.Taken.Ignored, Keyring().take(notIn, anna, ben, "door", false, null, now, pinned = false) { null })
    }

    @Test fun theInvitesAdminsMatterOnlyWhileJoining() {
        val r = Keyring().also { it.add(Keyring.Epoch(5, now - 200 * 3_600_000L, ByteArray(32) { 5 }, listOf(anna, ben), listOf(anna))) }
        val mine = Rekey(6, now, ByteArray(33), listOf(anna), null, listOf(ben to ByteArray(1)), members = listOf(anna, ben))
        assertTrue(r.take(mine, anna, ben, "door", false, null, now, pinned = false) { ByteArray(32) { 6 } } is Keyring.Taken.Added)
    }

    @Test fun theLargestNewKeyFitsInItsPackets() {
        val members = (0 until 100).map { "%016x".format(it) }; val box = ByteArray(MlKem.CIPHER_SIZE + Hpke.ENC_SIZE + 32 + 19 + 16)
        val packets = Rekey.split(members).map { some -> Rekey(7, 1, ByteArray(33), members, "%016x".format(200), some.map { it to box }, removal = true, members = members) }
        assertEquals(10, packets.size)
        val crypto = GroupCrypto.fromSecret(ByteArray(32) { 1 }); val id = "0123456789abcdef"
        for (r in packets) {
            val p = Packet(id, 1, 16, crypto.seal(id, 1, anna, "n".repeat(200), "", extra = r.encode(), pad = Pad.FULL) { TestKeys.sign(it) })
            assertEquals(16_018, p.encode().size)
            assertNotNull(Rekey.decode(crypto.openSigned(p)!!.extra!!))
        }
        assertFalse(packets.isEmpty())
    }
}
