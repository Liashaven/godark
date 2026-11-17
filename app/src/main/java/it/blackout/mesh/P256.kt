package it.blackout.mesh

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Member keys and signatures (spec/FORMAT.md, "Member ids", "Signatures", "Person emoji"): P-256 with the phone's own
 * crypto (Conscrypt), so signing and checking are native code. Only point compression is done here.
 */
object P256 {
    private val P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    private val params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun sha256(vararg parts: ByteArray) = MessageDigest.getInstance("SHA-256").run { parts.forEach(::update); digest() }
    private fun bytes32(v: BigInteger): ByteArray = v.toByteArray().let { b -> if (b.size >= 32) b.copyOfRange(b.size - 32, b.size) else ByteArray(32 - b.size) + b }

    /** The 33-byte compressed public key (SEC 1). */
    fun compress(k: PublicKey): ByteArray { val w = (k as ECPublicKey).w; return byteArrayOf(if (w.affineY.testBit(0)) 3 else 2) + bytes32(w.affineX) }

    /** The key of a 33-byte compressed point, or null if it isn't a point on P-256. */
    fun decompress(c: ByteArray): PublicKey? {
        if (c.size != 33 || (c[0].toInt() != 2 && c[0].toInt() != 3)) return null
        val x = BigInteger(1, c.copyOfRange(1, 33)); if (x >= P) return null
        val y2 = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P)
        var y = y2.modPow(P.add(BigInteger.ONE).shiftRight(2), P) // P ≡ 3 (mod 4)
        if (y.multiply(y).mod(P) != y2) return null
        if (y.testBit(0) != (c[0].toInt() == 3)) y = P.subtract(y)
        return runCatching { KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) }.getOrNull()
    }

    private fun onCurve(x: BigInteger, y: BigInteger) = x < P && y < P && y.multiply(y).mod(P) == x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P)

    /** The 65-byte uncompressed point 04 ‖ x ‖ y (HPKE's encoding). */
    fun uncompressed(k: PublicKey): ByteArray { val w = (k as ECPublicKey).w; return byteArrayOf(4) + bytes32(w.affineX) + bytes32(w.affineY) }

    /** The key of a 65-byte uncompressed point, or null if it isn't one on P-256. */
    fun fromUncompressed(u: ByteArray): PublicKey? {
        if (u.size != 65 || u[0].toInt() != 4) return null
        val x = BigInteger(1, u.copyOfRange(1, 33)); val y = BigInteger(1, u.copyOfRange(33, 65))
        if (!onCurve(x, y)) return null
        return runCatching { KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) }.getOrNull()
    }

    /** A private key from its 32-byte scalar (test vectors). */
    fun privateKey(scalar: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(java.security.spec.ECPrivateKeySpec(BigInteger(1, scalar), params))

    /** First 8 bytes of SHA-256(public key), as 16 lowercase hex chars. */
    fun memberId(pub: ByteArray): String = sha256(pub).copyOf(8).joinToString("") { "%02x".format(it) }

    /** The 16 emoji indices of a member's public key: the first 96 bits of the hash, 6 bits each. */
    fun emoji(pub: ByteArray): List<Int> {
        val h = sha256("darkproof-person-emoji-v1".toByteArray(), pub)
        return (0 until 16).map { i ->
            val bit = 6 * i; val at = bit / 8
            ((((h[at].toInt() and 0xFF) shl 8) or (h[at + 1].toInt() and 0xFF)) shr (10 - bit % 8)) and 63
        }
    }

    /** Signs the whole signed message (spec "Signatures") and returns r ‖ s. */
    fun sign(key: PrivateKey, msg: ByteArray): ByteArray =
        fromDer(Signature.getInstance("SHA256withECDSA").run { initSign(key); update(msg); sign() })

    /** Checks r ‖ s against SHA-256 of the signed message ([digest]). */
    fun verify(key: PublicKey, digest: ByteArray, raw: ByteArray): Boolean = raw.size == 64 && runCatching {
        Signature.getInstance("NONEwithECDSA").run { initVerify(key); update(digest); verify(toDer(raw)) }
    }.getOrDefault(false)

    /** A software key pair, for tests and debug messages. */
    fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun toDer(raw: ByteArray): ByteArray {
        fun int(b: ByteArray): ByteArray { var v = b.dropWhile { it == 0.toByte() }.toByteArray(); if (v.isEmpty()) v = byteArrayOf(0); if (v[0] < 0) v = byteArrayOf(0) + v; return byteArrayOf(2, v.size.toByte()) + v }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun fromDer(der: ByteArray): ByteArray {
        var i = 2 // 0x30, length (always < 128 for P-256)
        fun next(): ByteArray { require(der[i] == 2.toByte()); val n = der[i + 1].toInt(); val v = der.copyOfRange(i + 2, i + 2 + n); i += 2 + n; return bytes32(BigInteger(1, v)) }
        return next() + next()
    }
}

/**
 * This phone's member keys, one per group (spec "Member ids"), in the Android Keystore: the private key never leaves
 * it. [tag] identifies the group without revealing its key (GroupCrypto.tag).
 */
object MemberKeys {
    private val cache = HashMap<String, KeyPair>()

    @Synchronized fun forGroup(tag: String): KeyPair = cache.getOrPut(tag) {
        val alias = "darkproof-member-$tag"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.let { return@getOrPut KeyPair(it.certificate.publicKey, it.privateKey) }
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).build())
        }.generateKeyPair()
    }
}

/**
 * Small secrets on this phone (epoch secrets, encryption keys: spec/DESIGN-v0.6-groups.md, "Keys"), encrypted with an
 * AES key that never leaves the Android Keystore, in the app's private preferences.
 */
object Vault {
    private const val ALIAS = "darkproof-vault"

    @Synchronized private fun key(): javax.crypto.SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? javax.crypto.SecretKey)?.let { return it }
        return javax.crypto.KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        }.generateKey()
    }

    /** Saves [data] under [name] (null removes it). */
    fun put(c: android.content.Context, name: String, data: ByteArray?) {
        val prefs = c.getSharedPreferences("vault", 0)
        if (data == null) { prefs.edit().remove(name).apply(); return }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply { init(javax.crypto.Cipher.ENCRYPT_MODE, key()) }
        val out = cipher.iv + cipher.doFinal(data)
        prefs.edit().putString(name, android.util.Base64.encodeToString(out, android.util.Base64.NO_WRAP)).apply()
    }

    fun get(c: android.content.Context, name: String): ByteArray? = runCatching {
        val raw = android.util.Base64.decode(c.getSharedPreferences("vault", 0).getString(name, null) ?: return null, android.util.Base64.NO_WRAP)
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(javax.crypto.Cipher.DECRYPT_MODE, key(), javax.crypto.spec.GCMParameterSpec(128, raw, 0, 12))
        }.doFinal(raw, 12, raw.size - 12)
    }.getOrNull()

    /**
     * This phone's encryption key in group [groupId] (HPKE recipient key), made the first time. From Android 12 the private
     * key is made inside the Keystore and can't be copied off the phone. A key made earlier stays: other members have
     * sealed new keys to it.
     */
    fun encryptionKey(c: android.content.Context, groupId: String): KeyPair {
        get(c, "enc.$groupId")?.let { b ->
            runCatching {
                val n = ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
                val f = KeyFactory.getInstance("EC")
                return KeyPair(f.generatePublic(java.security.spec.X509EncodedKeySpec(b.copyOfRange(2 + n, b.size))),
                    f.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(b.copyOfRange(2, 2 + n))))
            }
        }
        if (android.os.Build.VERSION.SDK_INT >= 31) runCatching { return keystoreEncryptionKey("darkproof-enc-$groupId") }
            .onFailure { DebugTools.log("no Keystore encryption key: $it") }
        val kp = P256.newKeyPair(); val priv = kp.private.encoded
        put(c, "enc.$groupId", byteArrayOf((priv.size ushr 8).toByte(), priv.size.toByte()) + priv + kp.public.encoded)
        return kp
    }

    @androidx.annotation.RequiresApi(31)
    private fun keystoreEncryptionKey(alias: String): KeyPair {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.let { return KeyPair(it.certificate.publicKey, it.privateKey) }
        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).build())
        }.generateKeyPair().also { DebugTools.log("encryption key made in the Keystore") }
    }

    /** Deletes an encryption key for good: what was sealed to it can't be opened any more, on this phone or by anyone who takes it. */
    fun forgetEncryptionKey(c: android.content.Context, groupId: String) {
        put(c, "enc.$groupId", null)
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("darkproof-enc-$groupId") }
    }
}

/**
 * This phone's encryption keys in one group (spec "Sealing for one member"): the newest goes in its introductions, and
 * every key still kept can open what was sealed to it. [EncSchedule] says when one changes. Any thread.
 */
class EncKeys(private val c: android.content.Context, private val groupId: String) {
    private val prefs = c.getSharedPreferences("mesh", 0)
    private var list = EncSchedule.parse(prefs.getString("encs.$groupId", "") ?: "").ifEmpty {
        listOf(EncSchedule.Entry(0, System.currentTimeMillis())).also(::save)
    }
    private val pairs = HashMap<Int, KeyPair>()
    private val pqs = HashMap<Int, Pair<ByteArray, ByteArray>>() // n -> ML-KEM (public, private)

    private fun pq(n: Int) = pqs.getOrPut(n) {
        val b = Vault.get(c, "mlkem.${name(n)}")
        if (b != null && b.size > MlKem.PUBLIC_SIZE) b.copyOf(MlKem.PUBLIC_SIZE) to b.copyOfRange(MlKem.PUBLIC_SIZE, b.size)
        else MlKem.newKey().also { (pub, priv) -> Vault.put(c, "mlkem.${name(n)}", pub + priv) }
    }
    private fun save(l: List<EncSchedule.Entry>) { prefs.edit().putString("encs.$groupId", EncSchedule.save(l)).apply() }
    private fun name(n: Int) = if (n == 0) groupId else "$groupId.$n" // the first key keeps the name older builds gave it
    private fun pair(n: Int) = pairs.getOrPut(n) { Vault.encryptionKey(c, name(n)) }

    /** The newest key, as it goes in an introduction. */
    @Synchronized fun currentPub(): ByteArray = P256.uncompressed(pair(list.last().n).public)

    /** The newest key's ML-KEM half, as it goes in an introduction. */
    @Synchronized fun currentPq(): ByteArray = pq(list.last().n).first

    /** Deletes keys that were replaced long enough ago, and makes a new one when the current one is a week old. True if it did. */
    @Synchronized fun rotateIfDue(now: Long): Boolean {
        val gone = EncSchedule.expired(list, now)
        if (gone.isNotEmpty()) {
            gone.forEach { Vault.forgetEncryptionKey(c, name(it.n)); Vault.put(c, "mlkem.${name(it.n)}", null); pairs.remove(it.n); pqs.remove(it.n) }
            list = list - gone.toSet(); save(list)
            DebugTools.log("deleted ${gone.size} old encryption key(s)")
        }
        if (!EncSchedule.due(list, now)) return false
        list = EncSchedule.rotated(list, now); pair(list.last().n); save(list)
        DebugTools.log("new encryption key ${list.last().n}")
        return true
    }

    /** What was sealed to any key still kept, newest first; null if none opens it. */
    @Synchronized fun open(box: ByteArray, info: ByteArray, aad: ByteArray): ByteArray? =
        list.asReversed().firstNotNullOfOrNull { Hybrid.open(box, pair(it.n), pq(it.n).second, info, aad) }
}
