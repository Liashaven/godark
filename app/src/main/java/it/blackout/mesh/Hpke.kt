package it.blackout.mesh

import java.security.KeyPair
import java.security.PublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * HPKE (RFC 9180), base mode, single shot, with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM: seals a group
 * secret for one member's encryption key (spec/DESIGN-v0.6-groups.md). The same as ios/BlackoutCore/Hpke.swift, which
 * the iPhone tests check against Apple's own HPKE; both apps check the shared vector (kind: hpke).
 */
object Hpke {
    const val ENC_SIZE = 65 // the encapsulated key, an uncompressed P-256 point, at the start of every sealed box
    private fun be16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
    private val suiteKem = "KEM".toByteArray() + be16(0x0010)
    private val suite = "HPKE".toByteArray() + be16(0x0010) + be16(0x0001) + be16(0x0002)
    private val PSK_ID = "darkproof-mlkem768-v1".toByteArray()

    /** enc (65 bytes) ‖ ciphertext ‖ tag (16). [ephemeral] is random in normal use; test vectors fix it. [psk]: PSK mode, for [Hybrid]. */
    fun seal(plaintext: ByteArray, to: PublicKey, info: ByteArray, aad: ByteArray, ephemeral: KeyPair = P256.newKeyPair(), psk: ByteArray? = null): ByteArray {
        val enc = P256.uncompressed(ephemeral.public)
        val (key, nonce) = schedule(sharedSecret(dh(ephemeral, to), enc + P256.uncompressed(to)), info, psk)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); c.updateAAD(aad)
        return enc + c.doFinal(plaintext)
    }

    /** The plaintext, or null if it wasn't sealed for this key (or with this info and aad), or was changed. */
    fun open(sealed: ByteArray, recipient: KeyPair, info: ByteArray, aad: ByteArray, psk: ByteArray? = null): ByteArray? = runCatching {
        if (sealed.size < ENC_SIZE + 16) return null
        val enc = sealed.copyOf(ENC_SIZE)
        val pkE = P256.fromUncompressed(enc) ?: return null
        val (key, nonce) = schedule(sharedSecret(dh(recipient, pkE), enc + P256.uncompressed(recipient.public)), info, psk)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); c.updateAAD(aad)
        c.doFinal(sealed, ENC_SIZE, sealed.size - ENC_SIZE)
    }.getOrNull()

    /** A key held in the Keystore has no bytes to read: the Keystore does the key agreement itself. */
    private fun dh(own: KeyPair, other: PublicKey): ByteArray =
        (if (own.private.encoded == null) KeyAgreement.getInstance("ECDH", "AndroidKeyStore") else KeyAgreement.getInstance("ECDH"))
            .run { init(own.private); doPhase(other, true); generateSecret() }

    /** DHKEM ExtractAndExpand: the KEM shared secret from the DH result and enc ‖ pkR. */
    private fun sharedSecret(dh: ByteArray, kemContext: ByteArray): ByteArray =
        labeledExpand(suiteKem, labeledExtract(suiteKem, ByteArray(0), "eae_prk", dh), "shared_secret", kemContext, 32)

    /** The key schedule, base mode or (with [psk]) PSK mode: AEAD key and base nonce; the single message uses sequence number 0. */
    private fun schedule(shared: ByteArray, info: ByteArray, psk: ByteArray?): Pair<ByteArray, ByteArray> {
        val mode: Byte = if (psk == null) 0 else 1
        val context = byteArrayOf(mode) + labeledExtract(suite, ByteArray(0), "psk_id_hash", if (psk == null) ByteArray(0) else PSK_ID) + labeledExtract(suite, ByteArray(0), "info_hash", info)
        val secret = labeledExtract(suite, shared, "secret", psk ?: ByteArray(0))
        return labeledExpand(suite, secret, "key", context, 32) to labeledExpand(suite, secret, "base_nonce", context, 12)
    }

    private fun labeledExtract(suite: ByteArray, salt: ByteArray, label: String, ikm: ByteArray) =
        hmac(if (salt.isEmpty()) ByteArray(32) else salt, "HPKE-v1".toByteArray() + suite + label.toByteArray() + ikm)

    private fun labeledExpand(suite: ByteArray, prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray {
        val full = be16(length) + "HPKE-v1".toByteArray() + suite + label.toByteArray() + info
        var out = ByteArray(0); var t = ByteArray(0); var i = 1
        while (out.size < length) { t = hmac(prk, t + full + byteArrayOf(i.toByte())); out += t; i++ }
        return out.copyOf(length)
    }

    private fun hmac(key: ByteArray, msg: ByteArray) = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(msg) }
}

/** ML-KEM-768 (FIPS 203), from BouncyCastle: Android has none of its own. */
object MlKem {
    const val PUBLIC_SIZE = 1184; const val CIPHER_SIZE = 1088
    private val params = org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters.ml_kem_768

    /** A new key: (public, private). */
    fun newKey(): Pair<ByteArray, ByteArray> {
        val kp = org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator().apply {
            init(org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters(java.security.SecureRandom(), params))
        }.generateKeyPair()
        return (kp.public as org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters).encoded to (kp.private as org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters).encoded
    }

    /** (cipher, shared secret) for this public key, or null if it isn't a valid one. */
    fun encapsulate(public: ByteArray): Pair<ByteArray, ByteArray>? = runCatching {
        val s = org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator(java.security.SecureRandom()).generateEncapsulated(org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters(params, public))
        s.encapsulation to s.secret
    }.getOrNull()

    fun decapsulate(private: ByteArray, cipher: ByteArray): ByteArray? = runCatching {
        org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor(org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters(params, private)).extractSecret(cipher)
    }.getOrNull()
}

/**
 * A new epoch secret sealed so that breaking it needs both P-256 and ML-KEM-768 (spec "Sealing for one member"): the
 * ML-KEM shared secret is HPKE's pre-shared key (RFC 9180, mode_psk). There is no plain mode: a box without ML-KEM is refused.
 */
object Hybrid {
    private const val SMALLEST = MlKem.CIPHER_SIZE + Hpke.ENC_SIZE + 16

    /** Null if [pq] isn't a valid ML-KEM key. */
    fun seal(plaintext: ByteArray, to: PublicKey, pq: ByteArray, info: ByteArray, aad: ByteArray): ByteArray? {
        val kem = MlKem.encapsulate(pq) ?: return null
        return kem.first + Hpke.seal(plaintext, to, info, aad, psk = kem.second)
    }

    /** [pq]: the recipient's ML-KEM private key. Null result: not sealed for these keys, or changed. */
    fun open(sealed: ByteArray, recipient: KeyPair, pq: ByteArray?, info: ByteArray, aad: ByteArray): ByteArray? {
        if (sealed.size < SMALLEST) return null
        val shared = pq?.let { MlKem.decapsulate(it, sealed.copyOf(MlKem.CIPHER_SIZE)) } ?: return null
        return Hpke.open(sealed.copyOfRange(MlKem.CIPHER_SIZE, sealed.size), recipient, info, aad, psk = shared)
    }
}
