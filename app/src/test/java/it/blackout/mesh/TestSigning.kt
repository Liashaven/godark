package it.blackout.mesh

import java.security.SecureRandom

/** A throwaway member key for tests that only need packets to be signed by someone (spec "Signatures"). */
object TestKeys {
    val pair by lazy { P256.newKeyPair() }
    val pub by lazy { P256.compress(pair.public) }
    fun sign(msg: ByteArray) = P256.sign(pair.private, msg)
}

/** seal() signed with [TestKeys], for tests written before signatures. */
fun GroupCrypto.seal(id: String, ts: Long, sender: String, name: String, text: String, photo: ByteArray? = null,
                     iv: ByteArray = ByteArray(12).also(SecureRandom()::nextBytes)): ByteArray =
    seal(id, ts, sender, name, text, photo, null, iv) { TestKeys.sign(it) }
