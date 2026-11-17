package it.blackout.mesh

import java.io.*
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Unit carried over the network, compact enough to fit in a LoRa packet. Relays see only the id, timestamp, and remaining hops.
 * Wire format: spec/FORMAT.md (shared with the iPhone app).
 */
/** How a packet is padded (spec "Padding"): [SIZE] up to the next listed size, [FULL] to the largest, [NONE] only for test vectors. */
enum class Pad { NONE, SIZE, FULL }

class Packet(val id: String, val ts: Long, val ttl: Int, val cipher: ByteArray) {
    fun encode(): ByteArray = ByteArrayOutputStream().also { b ->
        DataOutputStream(b).run {
            writeByte(MAGIC); write(id.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            writeLong(ts); writeByte(ttl); write(cipher)
        }
    }.toByteArray()
    fun withTtl(t: Int) = Packet(id, ts, t, cipher)
    companion object {
        private const val MAGIC = 0xB3 // 0xB1 = v0.2 (Java modified UTF-8), 0xB2 = v0.3–0.4 (PBKDF2 keys, device ids), 0xB3 = v0.5
        private const val HEADER = 18
        const val MAX_CIPHER = 16_000
        /** The whole-packet sizes everything is padded to. 163 and 233 are the LoRa limits, so short packets still fit. */
        val SIZES = intArrayOf(163, 233, 512, 1024, 2048, 4096, 8192, HEADER + MAX_CIPHER)
        /** Bytes of plaintext padding for a sealed packet that would otherwise be [size] bytes long. */
        fun padding(size: Int, pad: Pad): Int = when (pad) {
            Pad.NONE -> 0
            Pad.FULL -> maxOf(0, HEADER + MAX_CIPHER - size)
            Pad.SIZE -> (SIZES.firstOrNull { it >= size } ?: size) - size
        }
        /** What sealing adds around the body: packet header, IV, signature, tag. */
        const val OVERHEAD = HEADER + 12 + 64 + 16
        fun newId(): String = ByteArray(8).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        /** A new id whose first 2 bytes are the [mailbox] (spec/FORMAT.md, "Mailboxes"), the other 6 random. */
        fun newId(mailbox: Int): String = "%04x".format(mailbox and 0xFFFF) + newId().substring(4)
        /** The mailbox of any packet id. */
        fun mailbox(id: String): Int = id.substring(0, 4).toInt(16)
        fun decode(raw: ByteArray): Packet? {
            if (raw.size <= HEADER || raw.size > HEADER + MAX_CIPHER || raw[0] != MAGIC.toByte()) return null
            return try {
                DataInputStream(ByteArrayInputStream(raw, 1, raw.size - 1)).run {
                    val id = ByteArray(8).also { readFully(it) }.joinToString("") { "%02x".format(it) }
                    val ts = readLong(); val ttl = readUnsignedByte()
                    if (ttl > 64) return null
                    Packet(id, ts, ttl, raw.copyOfRange(HEADER, raw.size))
                }
            } catch (_: Exception) { null }
        }
    }
}

/**
 * [public]: sent on the Public channel (spec/FORMAT.md), readable by everyone. [photo]: a small JPEG, or null.
 * [group]: the code of the saved group whose key opened it (null for Public messages). Not sent on the wire.
 */
data class Message(val id: String, val ts: Long, val sender: String, val name: String, val text: String,
                   val public: Boolean = false, val photo: ByteArray? = null, val group: String? = null,
                   /** false: the sender's public key isn't known yet, so its signature couldn't be checked (spec "Signatures"). */
                   val verified: Boolean = true)

class GroupCrypto private constructor(private val keyBytes: ByteArray, mailbox: Int?) {
    constructor(code: String) : this(deriveKey(code), null)
    /** The group's relay mailbox (spec/FORMAT.md, "Mailboxes"): receipts share it, so members get them too. */
    val mailbox: Int = mailbox ?: deriveMailbox(keyBytes)
    private val key = SecretKeySpec(keyBytes, "AES")
    private val rnd = SecureRandom()

    /** The group's delivery-receipt key (spec/FORMAT.md, "Delivery receipts"). */
    fun receipts() = GroupCrypto(deriveReceiptKey(keyBytes), mailbox)

    /** The group's introduction key (spec/FORMAT.md, "Introductions"). */
    fun intros() = GroupCrypto(deriveIntroKey(keyBytes), mailbox)

    /** The door's rekey key (spec/DESIGN-v0.6-groups.md, "New key"): new epoch secrets travel sealed with it. */
    fun rekeys() = GroupCrypto(hkdf(keyBytes, "darkproof-rekey-v1"), mailbox)

    /**
     * The group's id, from the key its code makes: it stays the same when the group's code or epoch changes
     * (spec/DESIGN-v0.6-groups.md), so member keys, saved public keys and checked people hang off it.
     */
    fun groupId(): String = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(keyBytes, "HmacSHA256")); doFinal("darkproof-group-id-v1".toByteArray()) }
        .copyOf(16).joinToString("") { "%02x".format(it) }

    /** HMAC-SHA256(key, "darkproof-sig-context-v1"): ties signatures to this key (spec "Signatures"). */
    private val context: ByteArray = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(keyBytes, "HmacSHA256")); doFinal("darkproof-sig-context-v1".toByteArray()) }

    /** Names this key without revealing it, e.g. for the Keystore alias of the member key: half the context, in hex. */
    val tag: String = context.copyOf(16).joinToString("") { "%02x".format(it) }

    /** What a packet's signature covers: tag, context, id, ts, body. */
    fun signed(id: String, ts: Long, body: ByteArray): ByteArray = ByteArrayOutputStream().also { b ->
        b.write("darkproof-sig-v1".toByteArray()); b.write(context)
        b.write(id.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        DataOutputStream(b).writeLong(ts); b.write(body)
    }.toByteArray()

    /**
     * What the signature of a packet sealed with a message key covers (spec "Message keys"): a tag of its own, context, id,
     * ts, the sender's position and the message number, body. Every member holds every member's message keys: were the
     * position and number left out, one of them could seal someone's signed message again under that person's unused
     * numbers, and each phone that checked the signature would delete the key of a message not written yet. The tag keeps
     * the signature from being moved to or from a packet sealed with the epoch's key.
     */
    fun signedWith(index: Int, counter: Int, id: String, ts: Long, body: ByteArray): ByteArray = ByteArrayOutputStream().also { b ->
        b.write("darkproof-sig-mk-v1".toByteArray()); b.write(context)
        b.write(id.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        DataOutputStream(b).writeLong(ts); b.write(header(index, counter)); b.write(body)
    }.toByteArray()

    /** The 3 bytes that say which sender's which message a packet is: the position, then the number, big-endian. */
    private fun header(index: Int, counter: Int) = byteArrayOf(index.toByte(), (counter ushr 8).toByte(), counter.toByte())

    /**
     * Seals a signed packet: [sign] gets the signed message and returns r ‖ s. [photo] or [extra] is the 4th field.
     * [iv] is random in normal use; tests pass a fixed one to reproduce spec/test-vectors.txt. Zero bytes after the
     * fields pad the packet ([pad]): they are encrypted and signed, and readers ignore them, so relays can't tell a
     * short message from a long one or count a group's members from the size of a new key.
     */
    fun seal(id: String, ts: Long, sender: String, name: String, text: String, photo: ByteArray? = null, extra: ByteArray? = null,
             iv: ByteArray = ByteArray(12).also(rnd::nextBytes), pad: Pad = Pad.SIZE, sign: (ByteArray) -> ByteArray): ByteArray {
        require(photo == null || photo.size <= Photo.MAX_BYTES) { "photo too big" }
        val fields = ByteArrayOutputStream().also { b ->
            b.putStr(sender); b.putStr(name); b.putStr(text)
            if (photo != null) b.putBytes(byteArrayOf(Photo.JPEG) + photo) else if (extra != null) b.putBytes(extra)
        }.toByteArray()
        val body = fields + ByteArray(Packet.padding(Packet.OVERHEAD + fields.size, pad))
        val sig = sign(signed(id, ts, body)); require(sig.size == 64) { "signature must be r ‖ s" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv)); c.updateAAD("$id|$ts".toByteArray())
        return iv + c.doFinal(sig + body)
    }

    /** An opened packet: the message, its signature, SHA-256 of what it signs, and the raw 4th field. Not checked yet. */
    class Opened(val message: Message, val signature: ByteArray, val digest: ByteArray, val extra: ByteArray?) {
        /** The message key that opened it, if one did. */
        var leaf: Leaf? = null
        /**
         * Names what a signature check of this packet is about: its id, and what it signs together with the signature.
         * Packets that share an id differ in it, unless they are the same signed message sealed again ([KeyWait]).
         */
        val key: String get() {
            val signs = digest; val sig = signature
            return message.id + ":" + java.security.MessageDigest.getInstance("SHA-256").run { update(signs); digest(sig) }.take(16).joinToString("") { "%02x".format(it) }
        }
        /**
         * Names the message this packet carries: its id and what was signed, without the signature. The same signed
         * message sealed again has the same mark, and so has one whose signature was rewritten (every ECDSA signature
         * has a twin that checks too): a chat shows it once, however many packets bring it ([StoreCap.name]).
         */
        val mark: String get() = message.id.take(16) + ":" + digest.take(8).joinToString("") { "%02x".format(it) }
    }

    private fun headerMask(iv: ByteArray) = MessageKeys.hmac(keyBytes, "darkproof-header-v1".toByteArray() + iv)

    /** Which sender's which message a packet says it is (spec "Message keys"): 3 bytes after the IV, readable with this key. */
    fun header(p: Packet): Pair<Int, Int>? {
        if (p.cipher.size < 12 + 3 + 16) return null
        val m = headerMask(p.cipher.copyOf(12))
        return ((p.cipher[12].toInt() xor m[0].toInt()) and 0xFF) to
            ((((p.cipher[13].toInt() xor m[1].toInt()) and 0xFF) shl 8) or ((p.cipher[14].toInt() xor m[2].toInt()) and 0xFF))
    }

    /** Seals a message with its own key [mk]: message [counter] of the sender at [index] in the epoch's member list. */
    fun sealWith(mk: ByteArray, index: Int, counter: Int, id: String, ts: Long, sender: String, name: String, text: String, photo: ByteArray? = null,
                 iv: ByteArray = ByteArray(12).also(rnd::nextBytes), pad: Pad = Pad.SIZE, sign: (ByteArray) -> ByteArray): ByteArray {
        require(photo == null || photo.size <= Photo.MAX_BYTES) { "photo too big" }
        val fields = ByteArrayOutputStream().also { b ->
            b.putStr(sender); b.putStr(name); b.putStr(text)
            if (photo != null) b.putBytes(byteArrayOf(Photo.JPEG) + photo)
        }.toByteArray()
        val body = fields + ByteArray(Packet.padding(Packet.OVERHEAD + 3 + fields.size, pad))
        val sig = sign(signedWith(index, counter, id, ts, body)); require(sig.size == 64) { "signature must be r ‖ s" }
        val h = header(index, counter); val m = headerMask(iv)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(mk, "AES"), GCMParameterSpec(128, iv)); c.updateAAD("$id|$ts".toByteArray() + h)
        return iv + byteArrayOf((h[0].toInt() xor m[0].toInt()).toByte(), (h[1].toInt() xor m[1].toInt()).toByte(), (h[2].toInt() xor m[2].toInt()).toByte()) + c.doFinal(sig + body)
    }

    /** Opens a message sealed with [sealWith]. Its time is taken from the blurred header, or [at] when the packet is local. */
    fun openWith(mk: ByteArray, index: Int, counter: Int, p: Packet, at: Long? = null): Opened? = try {
        val ts = at ?: realTime(p.ts, p.cipher)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(mk, "AES"), GCMParameterSpec(128, p.cipher, 0, 12))
        c.updateAAD("${p.id}|$ts".toByteArray() + header(index, counter))
        parsed(p.id, ts, c.doFinal(p.cipher, 15, p.cipher.size - 15)) { body -> signedWith(index, counter, p.id, ts, body) }
    } catch (_: Exception) { null }

    /** [covered]: what the signature covers, given the body. */
    private fun parsed(id: String, ts: Long, plain: ByteArray, covered: (ByteArray) -> ByteArray = { body -> signed(id, ts, body) }): Opened? = try {
        if (plain.size < 64 + 6) null else {
            val body = plain.copyOfRange(64, plain.size)
            DataInputStream(ByteArrayInputStream(body)).run {
                val sender = getStr(); val name = getStr(); val text = getStr()
                val extra = if (available() >= 2) runCatching { getBytes() }.getOrNull()?.takeIf { it.isNotEmpty() } else null // padding reads as an empty field
                val photo = extra?.takeIf { it.size > 1 && it[0] == Photo.JPEG && it.size - 1 <= Photo.MAX_BYTES }?.copyOfRange(1, extra.size)
                Opened(Message(id, ts, sender, name, text, photo = photo), plain.copyOf(64),
                    java.security.MessageDigest.getInstance("SHA-256").digest(covered(body)), extra)
            }
        }
    } catch (_: Exception) { null }

    private fun timeMask(cipher: ByteArray): Long = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(keyBytes, "HmacSHA256")); update("darkproof-time-v1".toByteArray()); doFinal(cipher.copyOf(12))
    }.let { (((it[0].toLong() and 0xFF) shl 16) or ((it[1].toLong() and 0xFF) shl 8) or (it[2].toLong() and 0xFF)) and (TIME_WINDOW - 1) }

    /** The time to put in the clear header of a packet sealed at [ts] (spec "Times"): up to 35 minutes back, and only this key can tell the real one. */
    fun hideTime(ts: Long, cipher: ByteArray): Long = (ts and (TIME_WINDOW - 1).inv()) - TIME_WINDOW + ((ts and (TIME_WINDOW - 1)) xor timeMask(cipher))
    private fun realTime(wire: Long, cipher: ByteArray): Long = (wire and (TIME_WINDOW - 1).inv()) + TIME_WINDOW + ((wire and (TIME_WINDOW - 1)) xor timeMask(cipher))

    /** A packet's [Message.ts] is the real time. A packet whose header wasn't blurred (test vectors) opens too. */
    fun openSigned(p: Packet): Opened? = openAt(p, realTime(p.ts, p.cipher)) ?: openAt(p, p.ts)

    private fun openAt(p: Packet, ts: Long): Opened? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, p.cipher, 0, 12)); c.updateAAD("${p.id}|$ts".toByteArray())
        parsed(p.id, ts, c.doFinal(p.cipher, 12, p.cipher.size - 12))
    } catch (_: Exception) { null }

    /** The message without checking its signature: tests and debug tools only. */
    fun open(p: Packet): Message? = openSigned(p)?.message

    companion object {
        private val keys = HashMap<String, ByteArray>()
        const val TIME_WINDOW = 1L shl 20 // ms, about 17 minutes

        /** A group's keys from a 32-byte epoch secret instead of a code (spec/DESIGN-v0.6-groups.md, "Keys"). */
        fun fromSecret(secret: ByteArray): GroupCrypto { require(secret.size == 32); return GroupCrypto(secret.copyOf(), null) }

        /**
         * scrypt (N 32768, r 8, p 1) over the UTF-8 bytes of the group code, normalized to NFC first so that "à" typed
         * as one character or as "a" + accent gives the same key on every keyboard and platform. Each code is derived
         * once (it takes 32 MiB and tens of milliseconds); then it comes from memory.
         */
        fun deriveKey(code: String): ByteArray {
            val nfc = java.text.Normalizer.normalize(code, java.text.Normalizer.Form.NFC)
            synchronized(keys) { keys[nfc] }?.let { return it.copyOf() }
            val k = Scrypt.derive(nfc.toByteArray(Charsets.UTF_8), "darkproof-group-v2".toByteArray(), 32768, 8, 1, 32)
            synchronized(keys) { keys[nfc] = k }
            return k.copyOf()
        }
        /** First 2 bytes of HMAC-SHA256(group key, "darkproof-relay-mailbox-v1"), as a number 0-65535. */
        fun deriveMailbox(groupKey: ByteArray): Int = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(groupKey, "HmacSHA256")); doFinal("darkproof-relay-mailbox-v1".toByteArray())
        }.let { ((it[0].toInt() and 0xFF) shl 8) or (it[1].toInt() and 0xFF) }
        /** HKDF-SHA256 (RFC 5869) of the group key, no salt, info "darkproof-receipt-v1", 32 bytes. */
        fun deriveReceiptKey(groupKey: ByteArray): ByteArray {
            val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(ByteArray(32), "HmacSHA256")); doFinal(groupKey) }
            return Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(prk, "HmacSHA256")); update("darkproof-receipt-v1".toByteArray()); doFinal(byteArrayOf(1))
            }
        }
        /** HKDF-SHA256 of the group key, no salt, info "darkproof-intro-v1", 32 bytes. */
        fun deriveIntroKey(groupKey: ByteArray): ByteArray = hkdf(groupKey, "darkproof-intro-v1")
        internal fun hkdf(k: ByteArray, info: String): ByteArray {
            val prk = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(ByteArray(32), "HmacSHA256")); doFinal(k) }
            return Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(prk, "HmacSHA256")); update(info.toByteArray()); doFinal(byteArrayOf(1)) }
        }
        /** Text field: 2-byte big-endian length, then standard UTF-8 (not Java's modified UTF-8, so other platforms can read it). */
        private fun ByteArrayOutputStream.putStr(s: String) = putBytes(s.toByteArray(Charsets.UTF_8))
        private fun ByteArrayOutputStream.putBytes(b: ByteArray) {
            require(b.size <= 0xFFFF) { "field too long" }
            write(b.size ushr 8); write(b.size and 0xFF); write(b)
        }
        private fun DataInputStream.getStr(): String = String(getBytes(), Charsets.UTF_8)
        private fun DataInputStream.getBytes(): ByteArray = ByteArray(readUnsignedShort()).also { readFully(it) }

        /** Code of the Public channel: everyone knows it, so anyone can read and post (spec/FORMAT.md). */
        const val PUBLIC_CODE = "blackout-public"
    }
}

/**
 * A group's epoch secrets (spec/DESIGN-v0.6-groups.md, "Keys"): a phone reads with every one it holds and writes with
 * [current], the highest epoch, and among two of the same epoch the one whose secret has the smaller SHA-256 (every
 * phone picks the same without talking). An epoch goes 7 days after a newer one replaced it; the current one stays.
 */
class Keyring {
    /**
     * [members] and [admins]: member ids, from the rekey that brought it. [by]: who made it. After a removal, [removes]
     * is who went, [code] the group's new code, [via] the code the removal came through, and [rank] where its maker
     * stood among the admins of the epoch before (0 = listed first, the group's creator). Any other key has [BY_ADMIN]
     * there if an admin of the epoch before made it. [taken]: when this phone got it, by its own clock; [made] is
     * whatever its maker wrote.
     */
    class Epoch(val number: Long, val made: Long, val secret: ByteArray, val members: List<String> = emptyList(), val admins: List<String> = emptyList(),
                val code: String? = null, val via: String? = null, val removes: String? = null, val by: String? = null, val rank: Int = Int.MAX_VALUE,
                @Volatile var messageKeys: MessageKeys? = null, val taken: Long = made) {
        val group = GroupCrypto.fromSecret(secret); val receipts = group.receipts(); val intros = group.intros()
        val hash: String = sha256(secret)
        /**
         * What tells this epoch from every other on this phone: its secret together with its number, maker and, for a removal,
         * new code and person removed. The secret alone doesn't: whoever was given one can send it again in a key of their own.
         */
        val id: String = sha256("$hash|$number|${by ?: ""}|${code ?: ""}|${removes ?: ""}".toByteArray())
        /** From when this phone counts this epoch's age: its date, or its arrival here if that was later. A maker can't move it back. */
        val since: Long get() = maxOf(made, taken)
        /** The same epoch with no member list. Numbered below the current one, it opens old messages and proves nothing about who is in. */
        fun forReadingOnly() = Epoch(number, made, secret, emptyList(), admins, code, via, removes, by, rank, messageKeys, taken)

        /** Everyone this epoch's secret was sealed to: its message keys keep the list when [members] is left empty ([forReadingOnly]). */
        val roster: List<String> get() = messageKeys?.members ?: members

        /** True if [sender] (a member id; a `web-` in front doesn't count) is in this epoch. Only they write in it. */
        fun lists(sender: String) = sender.removePrefix("web-") in roster

        /**
         * A packet of this epoch: with its own message key if it has one, else (a sender whose numbers ran out, an epoch from
         * before message keys) with the epoch's key. Either way only from someone in the epoch. Every member holds the epoch's
         * key, and so does someone removed since: under it, an id nobody was let in with would be shown as "not verified
         * yet" for good, with any name.
         */
        fun open(p: Packet): GroupCrypto.Opened? {
            val keys = messageKeys
            if (keys != null) group.header(p)?.let { (i, n) -> keys.key(i, n)?.let { mk -> group.openWith(mk, i, n, p)?.let { o ->
                if (keys.members.getOrNull(i) != o.message.sender.removePrefix("web-")) return null // sealed under someone else's position: it must not use up their key
                o.leaf = Leaf(this, i, n); return o
            } } }
            return group.openSigned(p)?.takeIf { lists(it.message.sender) }
        }

        /** A receipt of this epoch (spec "Delivery receipts"), from someone in it. */
        fun openReceipt(p: Packet): GroupCrypto.Opened? = receipts.openSigned(p)?.takeIf { lists(it.message.sender) }

        companion object {
            /** A new epoch from its random [secret], which isn't kept: only what it derives is, each sender's message keys included (spec "Message keys"). */
            fun fresh(number: Long, made: Long, secret: ByteArray, members: List<String>, admins: List<String>, code: String? = null, via: String? = null,
                      removes: String? = null, by: String? = null, rank: Int = Int.MAX_VALUE, taken: Long = made) =
                Epoch(number, made, MessageKeys.outer(secret), members, admins, code, via, removes, by, rank, MessageKeys.of(secret, members), taken)
            private fun sha256(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
        }
    }
    private val list = ArrayList<Epoch>()

    /**
     * A removal went past this phone while it was still joining: its code no longer works, so no first key is taken through
     * it any more, or the person removed, whom an invite made earlier still names, could let the phone into a group of their
     * own. The engine saves it. Only a removal made by an admin the invite names does this: anyone who has the code can
     * sign one, and must not be able to shut a phone out of the group it is joining.
     */
    @get:Synchronized @set:Synchronized var closed = false

    /**
     * False if this epoch was there already. The same secret under another number, maker or kind is another epoch, judged
     * like any other: if the first key to bring a secret kept out every later one, a member could send an admin's secret
     * on in a key of their own and so have the admin's key ignored.
     */
    @Synchronized fun add(e: Epoch): Boolean {
        if (list.any { it.id == e.id }) return false
        list += e
        // An epoch kept only to read with decides nothing, and a member can make as many as the hourly limits allow: one
        // maker has at most a few here, and when the keyring is full they go before any epoch that was the group's own.
        if (e.members.isEmpty() && e.by != null) list.filter { it.members.isEmpty() && it.by == e.by }.let { theirs -> if (theirs.size > MAX_READING_PER_MAKER) list.remove(theirs.maxWith(order)) }
        if (list.size > MAX_EPOCHS) list.remove(list.filter { it.members.isEmpty() }.ifEmpty { list }.maxWith(order)) // every packet is tried with each of them: a flood can't make that endless
        return true
    }

    /** Everyone in a member list this phone holds: in the group now, or until a removal or a new key not long ago. */
    @Synchronized fun everyone(): Set<String> = list.flatMapTo(HashSet()) { it.members }

    /**
     * True if [id] is in the group as far as this phone knows: in the member list of an epoch it holds that says who is
     * in, and not taken out by a removal that won. What such a person sends through the door (their introduction, a new
     * key) is kept like the group's messages; anyone else's has a small room of its own ([StoreCap.Kind.DOOR]).
     */
    @Synchronized fun inGroup(id: String) = list.any { id in it.members } && list.none { it.removes == id && won(it) }

    private val parts = RecentIds(MAX_PARTS) // sealed parts this phone has opened ([partMark]), oldest first
    private var partsChanged = false

    /** The sealed parts this phone has opened, oldest first: the engine saves them after the keyring and gives them back with [restoreParts]. */
    @Synchronized fun openedParts(): List<String> = parts.toList()
    @Synchronized fun restoreParts(marks: Collection<String>) { marks.forEach { parts.add(it) } }
    /** True, once, if a part was opened since the last call: time to save [openedParts]. */
    @Synchronized fun partsToSave(): Boolean { val c = partsChanged; partsChanged = false; return c }

    private val unopened = HashMap<String, ArrayDeque<Long>>() // maker -> when their last parts for this phone didn't open

    /**
     * True if no more parts of [maker] are tried for now: [MAX_UNOPENED_PER_HOUR] of theirs didn't open in the last hour.
     * A phone with no epoch ([joining]) can't tell who is in the group, and a maker is then whoever holds the code: it
     * stops at [MAX_UNOPENED_JOINING] in all.
     */
    private fun triedOut(maker: String, now: Long, joining: Boolean): Boolean {
        fun recent(q: ArrayDeque<Long>) = q.count { kotlin.math.abs(now - it) < HOUR_MS }
        if ((unopened[maker]?.let(::recent) ?: 0) >= MAX_UNOPENED_PER_HOUR) return true
        return joining && unopened.values.sumOf(::recent) >= MAX_UNOPENED_JOINING
    }

    private fun didNotOpen(maker: String, now: Long) {
        if (unopened.size > MAX_MEMBERS * 4) unopened.clear() // only limits a flood: forgetting is harmless
        val q = unopened.getOrPut(maker) { ArrayDeque() }
        q.addLast(now); while (q.size > MAX_UNOPENED_PER_HOUR) q.removeFirst()
    }

    /**
     * True if an epoch numbered [number] and dated [made] is past its week at [now]: a newer one replaced it more than 7
     * days ago, so [expire] would drop it at once.
     */
    private fun past(number: Long, made: Long, now: Long) = list.filter { it.number > number }.minOfOrNull { it.since }?.let { maxOf(it, made) < now - KEEP_MS } == true

    @Synchronized fun current(): Epoch = currentOrNull()!!
    @Synchronized fun currentOrNull(): Epoch? = list.minWithOrNull(order)

    /** The newest removal: its code is the one the group follows. */
    @Synchronized fun lastMove(): Epoch? = list.filter { it.code != null }.minWithOrNull(order)

    /** True if removal [e] is now the one to follow: the newest, or a late one that beat the rival this phone had followed. */
    @Synchronized fun leads(e: Epoch) = won(e) && (lastMove() === e || list.any { it !== e && it.code != null && it.number == e.number })

    /**
     * Who the removals numbered [number] took out, most senior admin first. A removal by someone a more senior one removed
     * doesn't count. Nor does one that lost, once its maker is no longer an admin of the current epoch: removed since, they
     * could still send one late through an older door, and a phone can't tell when it was made.
     */
    private fun goneAt(number: Long): Set<String> {
        val admins = currentOrNull()?.admins ?: return emptySet()
        val out = HashSet<String>()
        for (e in list.filter { it.code != null && it.number == number }.sortedWith(order)) if (e.by !in out && (won(e) || e.by in admins)) e.removes?.let { out += it }
        return out
    }

    /** True if a removal that won its number, [from] or above, took [id] out. */
    private fun outSince(id: String?, from: Long) = id != null && list.any { it.removes == id && it.number >= from && won(it) }

    /** People a removal that lost took out, who are still in the current epoch: an admin's phone finishes the job. */
    @Synchronized fun stillToRemove(): List<String> {
        val cur = currentOrNull() ?: return emptyList()
        val gone = list.filter { it.code != null }.map { it.number }.distinct().flatMap { goneAt(it) }.toSet()
        return cur.members.filter { it in gone }
    }

    /** Admins added by rekeys of the current number that didn't win: the next rekey an admin makes keeps them. */
    @Synchronized fun rivalAdmins(): List<String> {
        val cur = currentOrNull() ?: return emptyList(); val gone = goneAt(cur.number)
        return list.filter { it.number == cur.number && it !== cur && it.by !in gone }.flatMap { it.admins }.distinct() - cur.admins.toSet() - gone
    }

    /**
     * True if removal [r], whose signature checked out, tells a phone that is asking its way back that the group has moved
     * on without it: its maker is an admin of the current epoch whom no removal that won has taken out. Anyone who has the
     * code can sign a removal, so one from anybody else says nothing.
     */
    @Synchronized fun movedOn(r: Rekey, maker: String): Boolean {
        val cur = currentOrNull() ?: return false
        return r.removal && maker in cur.admins && !outSince(maker, 0)
    }

    /** What a phone does with a rekey whose signature checked out. */
    sealed class Taken {
        /** Not allowed, or nothing for this phone. */
        object Ignored : Taken()
        /** This phone was removed: that removal's epoch number, its maker's rank and its maker. */
        class Removed(val number: Long, val rank: Int, val by: String) : Taken()
        /** This phone is still joining and a removal went past without it: its code no longer works. */
        object Closed : Taken()
        /** A new epoch. [moveTo]: the code the group follows now. [back]: a removal that outranks the one that removed this phone. */
        class Added(val epoch: Epoch, val moveTo: String?, val back: Boolean) : Taken()
        /**
         * A new key numbered [number] lists this phone, but the part it carries for it doesn't open. The others can't see that
         * and may have moved on to it, so this phone asks its way back with a key of its own, as one that was away does.
         * [rank]: that key's [Epoch.rank], to tell later whether a key that did get here beats it.
         */
        class LeftOut(val number: Long, val rank: Int) : Taken()
    }

    /**
     * The whole decision about rekey [r] (spec "New key"), the same on both apps so that phones given the same rekeys
     * in any order agree. [door]: the code it came through; [oldDoor]: the group has moved on from that code. [me]: this
     * phone's member id. [removedAt]: the removal that removed this phone, and [removedBy] its maker. [pinned]: its maker
     * is one the invite named, or the invite named nobody. [named]: the invite named admins and its maker is one of them:
     * only then does a removal that leaves a joining phone out close its invite. [inUse]: the codes of the other groups
     * saved on this phone: a removal can't move this group onto one of them. [open] opens this phone's sealed part.
     */
    @Synchronized fun take(r: Rekey, maker: String, me: String, door: String, oldDoor: Boolean, removedAt: Pair<Long, Int>?,
                           now: Long = System.currentTimeMillis(), pinned: Boolean = true, removedBy: String? = null, named: Boolean = pinned,
                           inUse: Collection<String> = emptyList(), open: (ByteArray) -> ByteArray?): Taken {
        val seniority = rank(r, maker); val mine = r.parts.firstOrNull { it.first == me }
        if (mine == null && me in r.members) return Taken.Ignored // this phone's part is in another packet of the same key
        if (removedAt != null && !(r.removal && mine != null && undoes(r, seniority, removedAt, removedBy))) return Taken.Ignored
        val admins = admit(r, maker, if (oldDoor) door else null, now, pinned) ?: return Taken.Ignored
        val cur = currentOrNull()
        val below = oldDoor && overrules(r, maker, door) // numbered below the removal this phone followed, and by a more senior admin: it leads all the same
        if (r.removal && r.answers == me && cur != null && (r.epoch >= cur.number || below) && !outranked(r, maker)) return Taken.Removed(r.epoch, seniority, maker) // a later rejoin has a higher epoch
        if (mine == null) return if (r.removal && cur == null && named) { closed = true; Taken.Closed } else Taken.Ignored
        // Kept only to read with, and already past the week such an epoch is kept: not taken, or a stored new key read
        // again would bring back an epoch this phone deleted, with every message key in it.
        if (!r.removal && cur != null && r.epoch < cur.number && past(r.epoch, r.made, now)) return Taken.Ignored
        val level = standing(r, maker)
        // A part is opened once. The phone reads its stored new keys again at every start and after each new epoch, and
        // each opening is a key agreement in its secure hardware; an epoch it has since deleted must not come back either.
        val mark = partMark(mine.second, maker, r)
        if (mark in parts) return Taken.Ignored
        // Nor is a part tried once its maker has sent a few that don't open: it then counts as one that doesn't.
        val tried = !triedOut(maker, now, cur == null)
        // A part that doesn't open, in a key the others may be writing with by now: one above the current epoch, or one that could come before it.
        val (secret, code) = (if (tried) open(mine.second) else null)?.let { Rekey.unbox(it, r.removal) }
            ?: run {
                if (tried) didNotOpen(maker, now)
                return if (!r.removal && !oldDoor && cur != null && (r.epoch > cur.number || (r.epoch == cur.number && cur.code == null && level <= cur.rank))) Taken.LeftOut(r.epoch, level) else Taken.Ignored
            }
        if (code != null && code in inUse) return Taken.Ignored // that code is another group's on this phone: following it would put this group in its place
        parts.add(mark); partsChanged = true
        val e = Epoch.fresh(r.epoch, r.made, secret, r.members, admins, code, if (r.removal) door else null, if (r.removal) r.answers else null, maker, level, now)
        val counted = !exempt(r, maker)
        // A removal can become the current epoch again even when it arrives late, and only an admin can make one.
        if (!add(if (cur != null && r.epoch < cur.number && !r.removal) e.forReadingOnly() else e)) return Taken.Ignored
        if (counted) arrived(maker, now)
        val follow = code != null && (leads(e) || (below && won(e)))
        if (follow) dropAbove(e.number)
        return Taken.Added(e, if (follow) code else null, removedAt != null)
    }

    /**
     * True if removal [r] outranks the one that removed this phone ([at]: its number and its maker's rank; [by]: its maker):
     * the same number from a more senior admin, or a lower number from an admin who stands before [by] in the admin list
     * of the epoch before [r]. A removal numbered above it never does.
     */
    private fun undoes(r: Rekey, seniority: Int, at: Pair<Long, Int>, by: String?) =
        if (r.epoch == at.first) seniority < at.second else r.epoch < at.first && by != null && seniority < place(r.epoch - 1, by)

    /**
     * True if removal [r], through the old door [door], is numbered below the removal this phone followed out of that door
     * and its maker stands before the maker of every removal held above it, in the admin list of the epoch before [r].
     * That is a senior admin's removal of someone who got their own keys here first: a key and then a removal one number
     * higher would otherwise shut the senior admin's removal out for good. Without the seniority, someone removed could
     * pick a lower number and undo their own removal.
     */
    private fun overrules(r: Rekey, maker: String, door: String): Boolean {
        val left = list.filter { it.code != null && it.via == door }.minWithOrNull(order) ?: return false
        if (!r.removal || r.epoch >= left.number) return false
        val mine = rank(r, maker)
        return mine != Int.MAX_VALUE && list.none { it.code != null && it.number > r.epoch && (it.by == null || place(r.epoch - 1, it.by) <= mine) }
    }

    /** After a removal: anything numbered above it was made through the old door by someone who hadn't heard. */
    @Synchronized fun dropAbove(number: Long) { list.removeAll { it.number > number } }

    /** True if [id] was removed before [ts]: what a removed member writes afterwards isn't shown. A removal that lost doesn't count. */
    @Synchronized fun removedBefore(id: String, ts: Long) = list.any { it.removes == id && ts > it.made && won(it) }

    /**
     * True if a message or receipt under the id [id], dated [ts], isn't shown, whoever signed it.
     * - No epoch here that says who is in lists [id]. An epoch kept only to read with opens packets, but its list is
     *   whatever its maker wrote: a member could put a made-up id in one and write under it.
     * - A removal that won took [id] out. [had]: this phone had accepted the packet before (its own copy of the message,
     *   or one waiting for its sender's key): then its date decides ([removedBefore]). Seen for the first time, it isn't
     *   shown whatever its date. The date is the sender's to write, and someone removed still has the keys of the epochs
     *   before, which phones read with for another week: dated a minute before the removal, anything they wrote in that
     *   week would pass.
     * A keyring with no member list at all (the Public channel's) shuts nobody out.
     */
    @Synchronized fun shutOut(id: String, ts: Long, had: Boolean): Boolean {
        val lists = list.filter { it.members.isNotEmpty() }
        if (lists.isNotEmpty() && lists.none { id in it.members }) return true
        return list.any { it.removes == id && won(it) && (!had || ts > it.made) }
    }

    /** True if no other epoch with [e]'s number comes before it. */
    @Synchronized fun won(e: Epoch) = list.none { it !== e && it.number == e.number && order.compare(it, e) < 0 }

    /** Where [maker] stood among the admins of the epoch before [r]: the lower, the more senior. Read from the epochs [admit] reads, for the same reasons. */
    @Synchronized fun rank(r: Rekey, maker: String): Int = place(r.epoch - 1, maker)

    /** Where [id] stands among the admins of the epochs numbered [number] that count: the lower, the more senior. */
    private fun place(number: Long, id: String): Int {
        val cur = currentOrNull() ?: return Int.MAX_VALUE
        if (list.none { it.number == number }) return Int.MAX_VALUE
        return counting(number, cur).map { it.admins.indexOf(id) }.filter { it >= 0 }.minOrNull() ?: Int.MAX_VALUE
    }

    /**
     * The [Epoch.rank] of the epoch rekey [r] brings. A removal's is its maker's seniority. Any other key made by an admin
     * of the epoch before it has [BY_ADMIN], so it comes before one of the same number that wasn't, whatever the hashes:
     * a member picks their key's secret, and could otherwise undo an admin's choice to let someone in. A phone still
     * joining goes by the admin list of the key that lets it in. The engines use this for the keys they make too.
     */
    @Synchronized fun standing(r: Rekey, maker: String): Int {
        if (r.removal) return rank(r, maker)
        val cur = currentOrNull() ?: return if (maker in r.admins) BY_ADMIN else Int.MAX_VALUE
        return if (counting(r.epoch - 1, cur).any { maker in it.admins }) BY_ADMIN else Int.MAX_VALUE
    }

    /** True if a removal this phone holds outranks [r], so [r] can't take effect. */
    @Synchronized fun outranked(r: Rekey, maker: String): Boolean { val mine = rank(r, maker); return list.any { it.code != null && it.number == r.epoch && it.rank < mine } }

    /**
     * The admins rekey [r] gives its epoch on this phone, or null if it must be ignored (spec "New key"). [maker] is
     * its checked signer; [oldDoor]: the code it came through if the group has moved on from it, else null.
     * - A phone still joining takes the first one that includes it, from an admin its invite named ([pinned]). With a typed
     *   code it has nothing better to trust than the code. Once [closed], it takes none.
     * - Someone a removal that won its number took out decides nothing afterwards, even if a rival epoch this phone holds
     *   still lists them as an admin, and adds nothing: no key of theirs is taken, whatever its number and door. The epoch
     *   before the removal still lists them for a week, and a key they numbered below it, through the old door, would be
     *   kept to read with: dated late, it outlives the removal, and then nothing says its maker was removed. Only a
     *   removal of theirs is still judged: refused when numbered one above that removal, or below it through the current
     *   door (they may have learnt the new code); below it through the old door, seniority decides ([overrules]).
     * - Only admins of the epoch before it may let someone in, leave people out, change the admins or remove someone. A removal needs
     *   that epoch here: picking a higher number can't put it ahead of a removal that outranks it.
     * - Through an old door only a rival removal counts, numbered the same as the removal this phone followed out of it,
     *   or a key numbered below that one, which arrived late. A removal numbered below it counts only from an admin
     *   more senior than whoever made the removals held above it ([overrules]).
     * - Older than the current epoch: kept only to read with, so it can't change who is in, and only from someone who
     *   has been a member, or anyone with an old code could fill the phone with keys.
     * - At most one per member per hour, except admins'.
     * - Numbers and times that make no sense, and groups over [MAX_MEMBERS], are refused.
     */
    @Synchronized fun admit(r: Rekey, maker: String, oldDoor: String?, now: Long = System.currentTimeMillis(), pinned: Boolean = true): List<String>? {
        if (r.epoch !in 1..MAX_EPOCH || r.made < 0 || r.made > now + MAX_AHEAD_MS || r.members.size > MAX_MEMBERS) return null
        val cur = currentOrNull() ?: return if (oldDoor == null && pinned && !closed) r.admins else null
        if (r.epoch > cur.number + MAX_JUMP) return null
        if (list.any { it.removes == maker && won(it) && (!r.removal || it.number == r.epoch - 1 || (oldDoor == null && it.number > r.epoch)) }) return null
        if (r.removal && list.none { it.number == r.epoch - 1 }) return null
        val before = counting(r.epoch - 1, cur)
        val byAdmin = before.any { maker in it.admins }
        if (r.removal && (!byAdmin || r.answers in r.members)) return null
        if (oldDoor != null) {
            val left = list.filter { it.code != null && it.via == oldDoor }.minWithOrNull(order) ?: return null
            if (if (r.removal) r.epoch > left.number || (r.epoch < left.number && !overrules(r, maker, oldDoor)) else r.epoch >= left.number) return null
        }
        if (!byAdmin && (tooSoon(maker, r.made) || manyLately(maker, now))) return null
        val knownMaker = list.any { maker in it.members }
        if (r.epoch < cur.number) return if (knownMaker) (if (byAdmin) r.admins else before[0].admins) else null
        if (!byAdmin && (maker !in before[0].members || r.members.toSet() != before[0].members.toSet())) return null
        return if (byAdmin) r.admins else before[0].admins
    }

    /** Every epoch, the current one first: the order phones try them in. */
    @Synchronized fun all(): List<Epoch> { val c = currentOrNull() ?: return emptyList(); return listOf(c) + list.filter { it !== c } }

    /**
     * Drops the epochs replaced more than 7 days before [now], never the current one; returns what went. Counted from
     * the next epoch, not this one: a message written on its last day can still arrive a week later. What lost to an epoch
     * that goes, goes with it: dated later and left alone, a rival removal would count as the one that won. A newer epoch
     * replaced it when this phone got that one, if that was after its date ([Epoch.since]): a member's key dated long ago
     * would otherwise have this phone delete the epoch before it at once.
     */
    @Synchronized fun expire(now: Long): List<Epoch> {
        val c = currentOrNull() ?: return emptyList()
        val old = list.filter { e -> e !== c && list.filter { it.number > e.number }.minOfOrNull { it.since }?.let { maxOf(it, e.made) < now - KEEP_MS } == true }
        val gone = old + list.filter { e -> e !== c && e !in old && old.any { it.number == e.number && won(it) } }
        list.removeAll(gone.toSet()); return gone
    }


    private val lately = HashMap<String, ArrayDeque<Long>>() // maker -> when this phone took their last new keys

    /** True if [maker] brought [MAX_KEYS_PER_HOUR] new keys in the last hour by this phone's clock: the date in a key is whatever its maker wrote. */
    private fun manyLately(maker: String, now: Long) = (lately[maker]?.count { now - it < HOUR_MS } ?: 0) >= MAX_KEYS_PER_HOUR

    private fun arrived(maker: String, now: Long) {
        if (lately.size > MAX_MEMBERS * 4) lately.clear() // only limits a flood: forgetting is harmless
        val q = lately.getOrPut(maker) { ArrayDeque() }
        q.addLast(now); while (q.size > MAX_KEYS_PER_HOUR) q.removeFirst()
    }

    /**
     * The epochs that say who is in, who decides and how senior they are, from those numbered [number], just before a key:
     * not one kept only for reading, which a member can write with any list they like and so would make themselves an admin.
     * Nor, of several, one that lost and whose maker a removal has taken out, then or since: through an old door they can
     * still send a rival, and its admin list would decide about their next key. Else [cur].
     */
    private fun counting(number: Long, cur: Epoch) = list.filter { it.number == number && it.members.isNotEmpty() }.sortedWith(order)
        .filterIndexed { i, e -> i == 0 || !outSince(e.by, number) }.ifEmpty { listOf(cur) }

    /** True if rules about how often a member may make a key don't apply to [r]: admins, and keys that really let someone in. */
    private fun exempt(r: Rekey, maker: String): Boolean {
        val cur = currentOrNull() ?: return true
        return counting(r.epoch - 1, cur).any { maker in it.admins }
    }

    /** True if [maker] already made an epoch within an hour of [made]. */
    @Synchronized fun tooSoon(maker: String, made: Long) = list.any { it.by == maker && kotlin.math.abs(it.made - made) < HOUR_MS }

    private val answered = HashMap<String, Long>() // member -> when this phone last counted a key of theirs as one from a phone that is behind

    /**
     * True if member [maker] made [r] after this phone's current epoch but numbered it lower: their phone missed our keys.
     * Not with a date more than 10 minutes ahead, which no later key could ever be newer than; and for one member only
     * once an hour by this phone's clock, since each time some phone answers with a full new key for everyone.
     */
    @Synchronized fun behind(r: Rekey, maker: String, now: Long = System.currentTimeMillis()): Boolean {
        val c = currentOrNull() ?: return false
        if (r.removal || r.epoch >= c.number || r.made <= c.made || r.made > now + MAX_AHEAD_MS || maker !in c.members) return false
        if (answered[maker]?.let { kotlin.math.abs(now - it) < HOUR_MS } == true) return false
        if (answered.size > MAX_MEMBERS * 4) answered.clear() // only limits a flood: forgetting is harmless
        answered[maker] = now
        return true
    }

    companion object {
        const val KEEP_MS = 7 * 24 * 3600_000L
        const val HOUR_MS = 3600_000L
        /** A phone waits a random time up to this after the week is up, so the group's phones don't all make a new key at once. */
        const val MAX_DELAY_MS = 6 * HOUR_MS
        const val MAX_MEMBERS = 100
        private const val MAX_EPOCHS = 64
        private const val MAX_READING_PER_MAKER = 4    // epochs kept only to read with, from one maker
        private const val MAX_PARTS = 512              // opened parts remembered
        private const val MAX_UNOPENED_PER_HOUR = 4    // parts of one maker's keys that didn't open, before no more are tried
        private const val MAX_UNOPENED_JOINING = 16    // the same from all makers together, on a phone with no epoch yet
        private const val MAX_KEYS_PER_HOUR = 4        // from one member, except admins and joins, as they arrive here
        private const val MAX_EPOCH = 1L shl 53
        private const val MAX_JUMP = 1000L             // how far ahead of this phone's epoch a rekey may be numbered
        private const val MAX_AHEAD_MS = 10 * 60_000L  // clocks differ; a date further ahead would put off the weekly key

        /** The [Epoch.rank] of a key that isn't a removal, made by an admin of the epoch before it: after every removal, before any other key. */
        const val BY_ADMIN = Int.MAX_VALUE - 1

        /** True if an epoch this phone has had since [made] ([Epoch.since]) is due for its weekly replacement on a phone whose random delay is [delay]. */
        fun weeklyDue(made: Long, now: Long, delay: Long) = now >= made + KEEP_MS + delay
        /** True if the epoch is past every phone's delay: this phone missed the group's new key, or the whole group was quiet. */
        fun overdue(made: Long, now: Long) = now >= made + KEEP_MS + MAX_DELAY_MS
        /** Names one member's sealed part of one new key without opening it: SHA-256 of the box and of the key's maker, number, date and kind, the first 16 bytes in hex. */
        fun partMark(box: ByteArray, maker: String, r: Rekey): String = java.security.MessageDigest.getInstance("SHA-256")
            .run { update(box); digest("|$maker|${r.epoch}|${r.made}|${if (r.removal) 1 else 0}".toByteArray()) }.take(16).joinToString("") { "%02x".format(it) }
        /**
         * Highest number first. For the same number a removal beats anything else (or the removed person would still be
         * in), then the most senior admin's removal: its maker can't choose that, as they could a hash. Then a key an admin
         * made, before one from a member who isn't. Then the smallest hash, and for one secret in two keys the smallest
         * maker id, then code.
         */
        private val order = compareByDescending<Epoch> { it.number }.thenBy { it.code == null }.thenBy { it.rank }.thenBy { it.hash }.thenBy { it.by ?: "" }.thenBy { it.code ?: "" }
    }
}

/**
 * A rekey's payload, the 4th field after the type byte (spec/DESIGN-v0.6-groups.md, "New key"): a new epoch, its
 * maker's signing key, the admins, whose join request it answers, and the epoch secret sealed for each member.
 * Type 0x05 is a [removal]: [answers] is then the person removed, and each sealed part also holds the group's new code.
 */
class Rekey(val epoch: Long, val made: Long, val maker: ByteArray, val admins: List<String>, val answers: String?,
            val parts: List<Pair<String, ByteArray>>, val removal: Boolean = false,
            /** Everyone in the new epoch. [parts] can hold only some of them: a big group's key is split over several packets. */
            val members: List<String> = parts.map { it.first }) {

    fun encode(): ByteArray = ByteArrayOutputStream().also { b ->
        DataOutputStream(b).run {
            writeByte((if (removal) REMOVAL else TYPE).toInt()); writeLong(epoch); writeLong(made); write(maker)
            writeByte(admins.size); admins.forEach { write(hex(it)) }
            write(answers?.let(::hex) ?: ByteArray(8))
            writeShort(members.size); members.forEach { write(hex(it)) }
            writeShort(parts.size); parts.forEach { (id, box) -> write(hex(id)); writeShort(box.size); write(box) }
        }
    }.toByteArray()

    companion object {
        const val TYPE: Byte = 6; const val REMOVAL: Byte = 7 // 4 and 5 were the shape without a separate member list
        const val PARTS_PER_PACKET = 10
        /** How many packets a new key for [n] members travels in. Only three counts exist, so the number says little about the group's size. */
        fun packets(n: Int) = when { n <= PARTS_PER_PACKET -> 1; n <= 3 * PARTS_PER_PACKET -> 3; else -> 10 }
        /** [items] spread evenly over that many packets. */
        fun <T> split(items: List<T>): List<List<T>> { val k = packets(items.size); return (0 until k).map { i -> items.filterIndexed { j, _ -> j % k == i } } }
        private const val MAX_CODE = 200 // bytes
        fun hex(id: String): ByteArray = id.chunked(2).map { it.toInt(16).toByte() }.toByteArray().also { require(it.size == 8 || it.size == 16) }
        private const val HEX = "0123456789abcdef"
        private fun str(b: ByteArray): String { val c = CharArray(b.size * 2); for (i in b.indices) { val v = b[i].toInt() and 0xFF; c[2 * i] = HEX[v ushr 4]; c[2 * i + 1] = HEX[v and 15] }; return String(c) }

        fun decode(e: ByteArray): Rekey? = runCatching {
            DataInputStream(ByteArrayInputStream(e)).run {
                val type = readByte()
                if (type != TYPE && type != REMOVAL) return null
                val epoch = readLong(); val made = readLong(); val maker = ByteArray(33).also(::readFully)
                // The counts are checked as they are read: this runs before the signature is checked, on a packet anyone with the
                // code can seal, and a list as long as the packet allows would cost far more to read than it did to write.
                val admins = (0 until readUnsignedByte().also { if (it > Keyring.MAX_MEMBERS) return null }).map { str(ByteArray(8).also(::readFully)) }
                val answers = str(ByteArray(8).also(::readFully)).takeIf { it != "0000000000000000" }
                val members = (0 until readUnsignedShort().also { if (it > Keyring.MAX_MEMBERS) return null }).map { str(ByteArray(8).also(::readFully)) }
                val parts = (0 until readUnsignedShort().also { if (it > PARTS_PER_PACKET) return null }).map { str(ByteArray(8).also(::readFully)) to ByteArray(readUnsignedShort()).also(::readFully) }
                if (available() != 0 || (type == REMOVAL && answers == null) || !whole(members, parts.map { it.first })) return null
                Rekey(epoch, made, maker, admins, answers, parts, type == REMOVAL, members)
            }
        }.getOrNull()

        /**
         * True if a packet that lists [members] carries parts for exactly the people one packet of that key holds ([split]):
         * all of them up to [PARTS_PER_PACKET] members, else every 3rd or 10th. Every phone can check this, so a maker can't
         * list someone and quietly give them no part: only an admin may leave a member out, and has to say so.
         */
        fun whole(members: List<String>, parts: List<String>) = split(members).any { it == parts }

        /** What is sealed for each member: the epoch secret, then after a removal the group's new code. */
        fun box(secret: ByteArray, code: String?) = secret + (code?.toByteArray(Charsets.UTF_8) ?: ByteArray(0))
        /** The secret and new code from an opened part, or null if it isn't the right shape: anyone with the code can write one. */
        fun unbox(plain: ByteArray, removal: Boolean): Pair<ByteArray, String?>? {
            if (plain.size < 32 || plain.size > 32 + MAX_CODE || (plain.size > 32) != removal) return null
            if (!removal) return plain.copyOf(32) to null
            // Strict, like the iPhone: a code one app accepted and the other refused would split the group.
            val code = runCatching { Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(plain, 32, plain.size - 32)).toString() }.getOrNull() ?: return null
            if (!Invite.isGeneratedCode(code)) return null // a removal can't move the group to a code that can be guessed
            return plain.copyOf(32) to code
        }

        /** HPKE info for a group's rekeys: binds the sealed secret to the door it travels through. */
        fun info(groupId: String) = "darkproof-rekey-v1".toByteArray() + hex(groupId)
        /** HPKE aad for one member's part: binds it to this packet and this member. */
        fun aad(packetId: String, member: String) = hex(packetId) + hex(member)
    }
}

/** Flooding with deduplication and store-and-forward. No Android dependencies. */
class MeshRouter(
    private val send: (peer: String, p: Packet) -> Unit,
    private val deliver: (Packet) -> Unit,
    private val now: () -> Long = System::currentTimeMillis,
    private val retentionMs: Long = 7 * 24 * 3600_000L,
    private val maxStored: Int = 500,
    private val minCipher: Int = 0,
    private val maxPerMinute: Int = 0,
    private val unlimited: (String) -> Boolean = { false },
    /** A copy of a stored packet came with more hops left: the caller saves the higher ttl, so it survives a restart. */
    private val raised: (Packet) -> Unit = { },
) {
    companion object {
        /** The smallest real packet: IV, tag, signature and three empty text fields. Anything shorter is junk. */
        const val MIN_SEALED = 12 + 16 + 64 + 6
        /** New packets taken from one link in a minute: far more than phones really send, so a flood costs its sender time. */
        const val LINK_PER_MINUTE = 3_000
        /** Hops a new packet gets. A received packet with more (v0.4 decoding allows up to 64) is lowered to this. */
        const val MAX_TTL = 16
        /** Packets dated more than this ahead of this phone's clock are dropped (spec/FORMAT.md, "Forwarding rules"). */
        const val MAX_FUTURE_MS = 10 * 60_000L
        private const val MAX_SEEN = 50_000 // packets remembered, so a stream of new ones can't fill the memory
        /** Who the packets that were here before a restart count against, all together, when nothing says who brought them. */
        const val RESTORED = "restored"
        fun inFuture(ts: Long, now: Long) = ts > now + MAX_FUTURE_MS
        fun clamp(p: Packet) = if (p.ttl > MAX_TTL) p.withTtl(MAX_TTL) else p
        /**
         * What makes two packets the same: the id, the header time and the content. An id alone isn't enough: someone who
         * sees an id could send junk under it first, and the real packet would then be dropped as a duplicate. The seal is
         * bound to the header time, so a copy with another time can't be opened: it is a different packet too. The ttl is
         * left out, because it changes on every hop.
         */
        fun key(p: Packet): String = p.id + ":" + java.security.MessageDigest.getInstance("SHA-256").run {
            update(java.nio.ByteBuffer.allocate(8).putLong(p.ts).array()); digest(p.cipher)
        }.take(8).joinToString("") { "%02x".format(it) }
    }
    private val peers = LinkedHashSet<String>()
    private var seen = HashSet<String>(); private var seenBefore = HashSet<String>() // two generations: old ones are forgotten
    private var rotatedAt = now()
    private val stored = LinkedHashMap<String, Packet>() // by key, oldest first
    private val cameFrom = HashMap<String, String>()     // key -> the link that brought it (not for this phone's own)
    private val raisedByOther = HashSet<String>()        // keys whose stored copy came, with more hops, from another link than the first
    private val held = HashMap<String, Int>()            // sender -> packets of it stored here
    private val pace = HashMap<String, LongArray>()      // sender -> [start of this minute, new packets in it]
    // A link id names one connection, and a neighbour can open as many as it likes: the limits count per sender. That
    // is the address at the link's other end, when the link says one ([peerUp]); else the link itself.
    private val senders = HashMap<String, String>()      // link -> its sender, for the links that are up
    private val chargedTo = HashMap<String, String>()    // key -> the sender it counts against (not for this phone's own)
    private var paceSwept = now()
    /** A link that takes its packets in pieces ([peerUp] with room): how much its queue still takes, and how far it got. */
    private class Window(val maxBytes: Int, val maxPackets: Int) { var bytes = maxBytes; var packets = maxPackets; var at = 0L }
    private val windows = HashMap<String, Window>()
    private val arrival = HashMap<String, Long>()        // key -> the order it was stored in
    private var arrivals = 0L
    @Synchronized fun peerCount() = peers.size
    /**
     * After a restart: [all] is passed on again; [seenKeys] are packets already handled ([key]), so they aren't shown
     * twice. Packets dated in the future are left out. Peers already linked get the packets that are new to the router.
     * [from]: the link that brought a packet ([key]) before the restart, if the caller kept that ("" if not): the
     * packet doesn't go back to it (the relays, see [FromRelays]). Only the newest [maxStored] are taken, whoever
     * brought them: which packets come back must not depend on what the caller knows about them. The packets nobody is
     * named for count together as one sender's ([RESTORED]), not as this phone's own: a neighbour's packets saved
     * before the restart must not hold the store against what links bring afterwards.
     */
    @Synchronized fun restore(all: List<Packet>, seenKeys: Collection<String> = emptyList(), from: (String) -> String = { "" }) {
        seen += seenKeys
        val t = now()
        val known = all.filter { !inFuture(it.ts, t) && key(it) !in stored }.sortedBy { it.ts }
        known.forEach { seen += key(it) }
        val fresh = known.takeLast(maxStored).map(::clamp)
        fresh.forEach { val f = from(key(it)); keep(it, f, if (f.isEmpty()) RESTORED else sender(f)) }
        for (p in fresh) { val k = key(p); if (stored.containsKey(k)) peers.forEach { if (cameFrom[k] != it) forward(it, p) } }
    }
    /**
     * A packet made on this phone. [from]: empty for this phone's own; a label no link uses for packets other people
     * typed here (the Wi-Fi board), so they count against one share of the store, like the packets of one link.
     */
    @Synchronized fun publish(p: Packet, from: String = "") { seen += key(p); keep(p, from); peers.forEach { forward(it, p) } }
    /**
     * Where this very packet ([key]) came from: the link that brought it; "" if this phone made it or held it before
     * a restart; null if it isn't held for passing on. Another packet sent under the same id has its own answer, so
     * the caller can tell a packet this phone wrote from one that only carries its id. May be called from [send].
     */
    @Synchronized fun source(p: Packet): String? { val k = key(p); return if (stored.containsKey(k)) cameFrom[k] ?: "" else null }
    /** The link's minute is kept: closing a link and opening another doesn't start a new one. */
    @Synchronized fun peerDown(peer: String) { peers -= peer; senders -= peer; windows -= peer }
    /**
     * A link that comes up gets everything stored, except what it brought itself: it has that already, and a packet
     * that came from the relays never goes back up (spec/FORMAT.md, "Publish"). A packet another link brought later
     * with more hops left does go to it.
     * [sender]: who is at the other end, if the link layer can tell (an address): all links of one sender share one
     * allowance (spec/FORMAT.md, "Limits on links"). null leaves what was said before.
     * [roomBytes], [roomPackets]: for a link with a small send queue (Bluetooth): what the queue takes. Such a link gets
     * the stored packets oldest first as far as they fit, and the rest, like every later packet, as it reports room
     * again ([room]): what doesn't fit waits here, instead of pushing older packets out of the link's queue. Called
     * again without room for a link that has it, everything stored goes to it once more, in pieces as before.
     */
    @Synchronized fun peerUp(peer: String, sender: String? = null, roomBytes: Int = 0, roomPackets: Int = 0) {
        peers += peer; prune()
        if (sender != null) senders[peer] = sender
        if (roomBytes > 0 && roomPackets > 0) windows[peer] = Window(roomBytes, roomPackets)
        val w = windows[peer]
        if (w != null) { w.at = 0; hand(peer, w) }
        else stored.forEach { (k, p) -> if (cameFrom[k] != peer || k in raisedByOther) forward(peer, p) }
    }
    /** A link that takes its packets in pieces sent [bytes] of [packets] packets (or dropped them): it has that much room again. */
    @Synchronized fun room(peer: String, bytes: Int, packets: Int) {
        val w = windows[peer] ?: return
        w.bytes = minOf(w.bytes + bytes, w.maxBytes); w.packets = minOf(w.packets + packets, w.maxPackets)
        hand(peer, w)
    }
    /**
     * Packets older than 7 days or more than 10 minutes in the future are dropped; ttl above 16 is lowered to 16. A copy
     * of a packet still stored here that has more hops left replaces it and is passed on again: the ttl isn't
     * authenticated, so a copy that came first with a low one must not decide how far the packet goes.
     * True if the packet was new to this phone, so [from] is the link that brought it.
     */
    @Synchronized fun receive(from: String, packet: Packet): Boolean {
        val t = now()
        if (packet.ts < t - retentionMs || inFuture(packet.ts, t) || packet.cipher.size < minCipher) return false
        val k = key(packet)
        if (k in seen || k in seenBefore) {
            val had = stored[k] ?: return false
            val p = clamp(packet)
            if (p.ttl <= had.ttl || !paced(from, t)) return false // the ttl must rise each time: at most 15 times a packet
            stored[k] = p; raised(p)
            if (cameFrom[k] != from) raisedByOther += k
            peers.filter { it != from }.forEach { forward(it, p, k) }
            return false
        }
        if (!paced(from, t)) return false // not marked as seen: it can still come later, or from someone else
        if (t - rotatedAt > retentionMs || seen.size > MAX_SEEN) { seenBefore = seen; seen = HashSet(); rotatedAt = t }
        seen += k
        val p = clamp(packet)
        keep(p, from); deliver(p)
        peers.filter { it != from }.forEach { forward(it, p) }
        return true
    }
    /** Counts one more packet taken from [from]. False once its sender is over its share of this minute. */
    private fun paced(from: String, t: Long): Boolean {
        if (maxPerMinute <= 0 || unlimited(from)) return true
        if (t - paceSwept >= 60_000) { pace.values.removeAll { t - it[0] >= 60_000 }; paceSwept = t } // minutes that are over
        val w = pace.getOrPut(sender(from)) { longArrayOf(t, 0) }
        if (t - w[0] >= 60_000) { w[0] = t; w[1] = 0 }
        return ++w[1] <= maxPerMinute
    }
    private fun sender(from: String) = senders[from] ?: from
    /** [raised]: the key, when [p] is a copy with more hops of a packet that was stored before. */
    private fun forward(peer: String, p: Packet, raised: String? = null) {
        val w = windows[peer]
        if (w == null) { if (p.ttl > 1) send(peer, p.withTtl(p.ttl - 1)); return }
        // A link that takes its packets in pieces gets them in the order they were stored, as far as its queue has room.
        if (raised != null && (arrival[raised] ?: 0) <= w.at) { // it has this one, with fewer hops: the new copy goes at once
            if (p.ttl > 1) { w.bytes -= size(p); w.packets -= 1; send(peer, p.withTtl(p.ttl - 1)) }
        } else hand(peer, w)
    }
    private fun size(p: Packet) = 18 + p.cipher.size // the encoded packet
    /** The stored packets [peer] hasn't had yet, oldest first, while its queue has room for the next one. */
    private fun hand(peer: String, w: Window) {
        if (w.at >= arrivals) return
        for ((k, p) in stored) {
            val n = arrival[k] ?: continue
            if (n <= w.at) continue
            if (p.ttl > 1 && (cameFrom[k] != peer || k in raisedByOther)) {
                val empty = w.bytes >= w.maxBytes && w.packets >= w.maxPackets // an empty queue takes one packet, whatever its size
                if (!empty && (w.packets < 1 || w.bytes < size(p))) return
                w.bytes -= size(p); w.packets -= 1; w.at = n
                send(peer, p.withTtl(p.ttl - 1))
            } else w.at = n
        }
    }
    private fun keep(p: Packet, from: String, pays: String = sender(from)) {
        val k = key(p)
        if (stored.put(k, p) == null) {
            arrival[k] = ++arrivals
            if (from.isNotEmpty()) cameFrom[k] = from
            if (pays.isNotEmpty()) { chargedTo[k] = pays; held[pays] = (held[pays] ?: 0) + 1 }
        }
        prune()
    }
    private fun drop(k: String) {
        stored.remove(k); raisedByOther.remove(k); arrival.remove(k); cameFrom.remove(k)
        chargedTo.remove(k)?.let { f -> val n = (held[f] ?: 1) - 1; if (n > 0) held[f] = n else held.remove(f) }
    }
    private fun prune() {
        val cut = now() - retentionMs
        stored.filterValues { it.ts < cut }.keys.toList().forEach(::drop)
        while (stored.size > maxStored) {
            // One sender can't push everyone else's packets out: while it holds more than a quarter, its own oldest go first.
            // And however many senders there are, what they bring can't push out what this phone wrote: while the
            // packets that came from elsewhere hold more than half, the oldest of those goes.
            val top = held.maxByOrNull { it.value }
            drop(when {
                top != null && top.value > maxStored / 4 -> stored.keys.first { chargedTo[it] == top.key }
                chargedTo.size > maxStored / 2 -> stored.keys.first { it in chargedTo }
                else -> stored.keys.first()
            })
        }
    }
}

/**
 * Which stored packets to remove when the store is over its cap (spec/FORMAT.md, "Storage"): first packets no saved
 * group can read, oldest first, then the oldest Public messages, and only then the oldest messages and receipts of
 * the saved groups. Same rules as the iPhone's StoreCap.
 */
/**
 * When a member's encryption key changes (spec "Sealing for one member"). Each key is used for a week, then kept for two
 * more so new keys sealed to it can still be opened, then deleted: after that, recorded traffic sealed to it can't be
 * opened, even by someone who takes the phone. Pure rules; the keys are in [EncKeys]. Same as the iPhone's.
 */
object EncSchedule {
    const val ROTATE_MS = 7 * 24 * 3_600_000L
    const val KEEP_MS = 14 * 24 * 3_600_000L
    const val MAX_KEYS = 8

    /** [replaced]: when a newer key took over; 0 for the current key. Oldest first in a list. */
    data class Entry(val n: Int, val made: Long, val replaced: Long = 0)

    fun parse(s: String): List<Entry> = s.split(',').mapNotNull { e ->
        e.split(':').takeIf { it.size == 3 }?.let { runCatching { Entry(it[0].toInt(), it[1].toLong(), it[2].toLong()) }.getOrNull() }
    }
    fun save(list: List<Entry>) = list.joinToString(",") { "${it.n}:${it.made}:${it.replaced}" }

    fun due(list: List<Entry>, now: Long) = list.lastOrNull()?.let { now - it.made >= ROTATE_MS } ?: true

    /** The list once a new key has taken over. */
    fun rotated(list: List<Entry>, now: Long) =
        list.map { if (it.replaced == 0L) it.copy(replaced = now) else it } + Entry((list.maxOfOrNull { it.n } ?: -1) + 1, now)

    /** The keys that can be deleted now. The current key never is. */
    fun expired(list: List<Entry>, now: Long): List<Entry> {
        val old = list.filter { it.replaced != 0L && now - it.replaced >= KEEP_MS }
        return old + (list - old.toSet()).dropLast(MAX_KEYS)
    }

    /** An introduction replaces a member's encryption key only if it is newer: one played back can't bring back a key they deleted. */
    fun isNewer(known: Long, ts: Long) = ts > known
}

object StoreCap {
    const val MAX_BYTES = 40L * 1024 * 1024
    const val MAX_COUNT = 20_000
    /** The room [Kind.DOOR] packets have inside the cap, all saved groups together. */
    const val DOOR_BYTES = 4L * 1024 * 1024
    const val DOOR_COUNT = 1_000
    /**
     * In the order they go: [UNREADABLE] first, [GROUP] last. [DOOR]: an introduction or a new key that came through a
     * saved group's door from someone who isn't in that group ([door]). The door opens with the code alone, so these
     * are not the group's own: they have a small room of their own and never push a message out.
     */
    enum class Kind { UNREADABLE, DOOR, PUBLIC, GROUP }
    /** [id]: what the packet goes by in the store ([name]). [size]: the encoded packet's length. */
    class Entry(val id: String, val ts: Long, val size: Int, val kind: Kind)

    /**
     * Ids to remove so that at most [maxBytes] and [maxCount] remain, and of [Kind.DOOR] packets at most [doorBytes] and
     * [doorCount], their oldest first; empty if the store fits.
     */
    fun overflow(entries: Collection<Entry>, maxBytes: Long = MAX_BYTES, maxCount: Int = MAX_COUNT, doorBytes: Long = DOOR_BYTES, doorCount: Int = DOOR_COUNT): List<String> {
        val out = ArrayList<String>()
        val door = entries.filter { it.kind == Kind.DOOR }
        var held = door.sumOf { it.size.toLong() }; var n = door.size
        if (held > doorBytes || n > doorCount) for (e in door.sortedWith(compareBy<Entry>({ it.ts }, { it.id }))) {
            if (held <= doorBytes && n <= doorCount) break
            out += e.id; held -= e.size; n--
        }
        val gone = out.toHashSet()
        val rest = if (gone.isEmpty()) entries else entries.filter { it.id !in gone }
        var bytes = rest.sumOf { it.size.toLong() }; var count = rest.size
        if (bytes <= maxBytes && count <= maxCount) return out
        for (e in rest.sortedWith(compareBy<Entry>({ it.kind.ordinal }, { it.ts }, { it.id }))) {
            if (bytes <= maxBytes && count <= maxCount) break
            out += e.id; bytes -= e.size; count--
        }
        return out
    }

    /**
     * The class of a packet a saved group's door opened: an introduction that checks, or a new key. [mine]: this phone
     * wrote it. [member]: it is signed by someone in the group ([Keyring.inGroup]).
     */
    fun door(mine: Boolean, member: Boolean) = if (mine || member) Kind.GROUP else Kind.DOOR

    /** True once the [Kind.DOOR] packets take twice their room: the store is then trimmed without waiting for the cap. */
    fun doorFull(count: Int, bytes: Long) = count > 2 * DOOR_COUNT || bytes > 2 * DOOR_BYTES

    /**
     * What a packet goes by in the store and, if it is a message, in the chat. [first]: no packet is stored under its
     * id yet. The first one goes by the id; any other packet with that id goes by its key ([MeshRouter.key]), so that
     * every packet has a place of its own: whoever sends something first under an id doesn't keep the real packet out.
     */
    fun name(p: Packet, first: Boolean): String = if (first) p.id else MeshRouter.key(p)

    /** The packet id inside a [name]. */
    fun packetId(name: String): String = name.take(16)

    /**
     * A packet of the Everyone channel, for [everyone]. [holder]: who it counts for: its sender if the signature
     * checked, and one name for all senders that couldn't be checked, one for all introductions. [own]: this phone's.
     */
    class Held(val id: String, val ts: Long, val holder: String, val own: Boolean = false)

    /**
     * The Everyone channel keeps [max] packets (spec/FORMAT.md, "Storage on the phone"): the ids to remove when there
     * are more. As in the router's store: while one holder has more than a quarter of [max], its own oldest go first,
     * so one sender can't push everyone else's messages and places out; otherwise the oldest of all. This phone's own
     * go last, only when nothing else is left.
     */
    fun everyone(entries: Collection<Held>, max: Int): List<String> {
        var over = entries.size - max
        if (over <= 0) return emptyList()
        val oldestFirst = compareBy<Held>({ it.ts }, { it.id })
        val others = entries.filter { !it.own }.sortedWith(oldestFirst)
        val byHolder = HashMap<String, ArrayDeque<Held>>()
        for (e in others) byHolder.getOrPut(e.holder) { ArrayDeque() }.addLast(e)
        val big = HashMap(byHolder.filterValues { it.size > max / 4 }) // the holders over a quarter: few
        val out = ArrayList<String>(); val gone = HashSet<String>(); var next = 0
        while (over > 0 && out.size < others.size) {
            val top = big.entries.maxWithOrNull(compareBy({ it.value.size }, { it.key }))
            val e = if (top != null) top.value.removeFirst().also { if (top.value.size <= max / 4) big.remove(top.key) } else {
                while (others[next].id in gone) next++
                others[next].also { byHolder[it.holder]?.removeFirst() } // the oldest of all is its holder's oldest
            }
            gone += e.id; out += e.id; over--
        }
        if (over > 0) entries.filter { it.own }.sortedWith(oldestFirst).take(over).mapTo(out) { it.id }
        return out
    }
}

/**
 * People asking to join a group (spec/FORMAT.md, "Joining"). Anyone with the code can introduce as many made-up keys
 * as they like through the door, so a phone keeps the keys of at most [MAX_ASKING] people who aren't in the group, the
 * first to ask: a flood can't bury the chat under requests, and can't push out one that is waiting.
 */
object Joining {
    const val MAX_ASKING = 20
    const val ALERT_EVERY_MS = 60_000L

    /**
     * Who is asking, by the date of their introduction, at most [MAX_ASKING]. [introduced]: member id -> the date of the
     * introduction that brought the key this phone keeps for them; older than 7 days no longer counts. [members]: the
     * current epoch's; [declined]: turned down on this phone.
     */
    fun asking(introduced: Map<String, Long>, members: Set<String>, declined: Set<String>, me: String, now: Long): List<String> =
        introduced.entries.filter { (id, at) -> id != me && id !in members && id !in declined && at >= now - Keyring.KEEP_MS }
            .sortedWith(compareBy({ it.value }, { it.key })).take(MAX_ASKING).map { it.key }

    /**
     * True if the key of [id], which this phone doesn't know yet, is kept: this phone's own, that of someone in a member
     * list it holds ([listed], [Keyring.everyone]), or there is room among those [asking].
     */
    fun keeps(id: String, asking: Collection<String>, listed: Set<String>, me: String) = id == me || id in listed || asking.size < MAX_ASKING

    /** True if an "asks to join" alert may be raised in a group whose last one was at [last]: at most one a minute. */
    fun alertDue(last: Long, now: Long) = now - last >= ALERT_EVERY_MS || now < last
}

/**
 * When a phone sends its introduction to the Public channel (spec/FORMAT.md, "Introductions"): when its user writes
 * there, and after that only while one of its own Everyone posts is still shown (7 days), so that readers can check
 * it. A phone whose user never posts on Everyone never announces itself there. Same as the iPhone's PublicIntro.
 */
object PublicIntro {
    const val SHOWN_MS = 7 * 24 * 3600_000L
    /** [writing]: a post to Everyone is being written now. [lastOwnPost]: the time of this phone's newest Everyone post, null if it has none. */
    fun wanted(writing: Boolean, lastOwnPost: Long?, now: Long) = writing || (lastOwnPost != null && now - lastOwnPost < SHOWN_MS)
}

/**
 * Two links between the same two phones (spec/FORMAT.md, "Wi-Fi networks"): which one stays. When both phones dialed
 * each other at about the same time (the older link is less than 10 s old), the link dialed by the smaller node id
 * stays, so both phones keep the same one. Otherwise, or when the same phone dialed both, the new link replaces the
 * old one: after a restart the old one may be dead without either side knowing.
 */
object DuplicateLinks {
    const val SAME_TIME_MS = 10_000L
    fun keepNew(myId: String, remoteId: String, newDialedByMe: Boolean, oldDialedByMe: Boolean, oldAgeMs: Long): Boolean {
        if (newDialedByMe == oldDialedByMe || oldAgeMs >= SAME_TIME_MS) return true
        val meSmaller = BleProtocol.keepMyCentralLink(myId, remoteId) // byte comparison of the node ids
        return if (newDialedByMe) meSmaller else !meSmaller
    }
}

/**
 * Who gets a place when links or connections run out, and which addresses are on the local network (spec/FORMAT.md,
 * "Node ids prove nothing", "Wi-Fi networks"). Pure rules, the same as the iPhone's LinkLimits.
 */
object LinkLimits {
    /** Wi-Fi links one address may hold: several phones can sit behind one address, but one device must not take every place. */
    const val PER_ADDRESS = 8
    /** Connections that haven't said HELLO yet, and how many of them one address may have. */
    const val WAITING = 16
    const val WAITING_PER_ADDRESS = 4
    /** Discovered devices being dialed at once, and how many are remembered. */
    const val DIALS = 8
    const val FOUND = 256
    /** With every place taken and nobody holding more than one, a link at random gives way, at most once in this time. */
    const val ROTATE_MS = 30_000L
    const val ROOM = -1
    const val FULL = -2

    /**
     * Whether [address] can have one more of [max] places. [held]: the address of each holder, oldest first. Returns
     * [ROOM] if there is one; else the index of the holder that gives way: the oldest of [address] itself once it has
     * [perAddress], else the oldest of the address that holds the most, if that is more than one; [FULL] if every
     * holder has a different address (the caller then decides: a link at random, or the one that waited longest).
     */
    fun giveWay(held: List<String>, address: String, max: Int, perAddress: Int): Int {
        if (held.count { it == address } >= perAddress) return held.indexOf(address)
        if (held.size < max) return ROOM
        val most = held.groupingBy { it }.eachCount().maxByOrNull { it.value } ?: return FULL
        return if (most.value > 1) held.indexOf(most.key) else FULL
    }

    /**
     * Whether an address (4 or 16 bytes) is on a local network: private or link-local (10/8, 172.16/12, 192.168/16,
     * 169.254/16, fe80::/10, fc00::/7), or in the same network as [mine], this phone's own address on that connection
     * (the first 24 bits for IPv4, 64 for IPv6). Loopback isn't: that is another app on this phone.
     */
    fun local(address: ByteArray, mine: ByteArray? = null): Boolean {
        val a = unmapped(address); val m = mine?.let(::unmapped)
        fun b(i: Int) = a[i].toInt() and 0xff
        fun same(n: Int) = m != null && m.size == a.size && (0 until n).all { m[it] == a[it] }
        return when (a.size) {
            4 -> b(0) != 127 && (b(0) == 10 || (b(0) == 172 && b(1) in 16..31) || (b(0) == 192 && b(1) == 168) || (b(0) == 169 && b(1) == 254) || (b(0) != 0 && same(3)))
            16 -> !(a.take(15).all { it.toInt() == 0 } && b(15) <= 1) && ((b(0) == 0xfe && (b(1) and 0xc0) == 0x80) || (b(0) and 0xfe) == 0xfc || same(8))
            else -> false
        }
    }
    /** An IPv4 address written as IPv6 (::ffff:a.b.c.d) is that IPv4 address. */
    private fun unmapped(a: ByteArray) =
        if (a.size == 16 && (0 until 10).all { a[it].toInt() == 0 } && a[10] == 0xff.toByte() && a[11] == 0xff.toByte()) a.copyOfRange(12, 16) else a
}

/** Nearby links in the router (Android): the endpoint id behind a prefix, like `ble:` and `wifi:`, so that no id a device picks can be taken for the fixed names `lora`, `meshcore` or `nostr`. */
object NearbyPeers {
    const val PREFIX = "nearby:"
    fun owns(peer: String) = peer.startsWith(PREFIX)
    fun peer(endpoint: String) = PREFIX + endpoint
    fun endpoint(peer: String) = peer.removePrefix(PREFIX)
}

/** An ordered set of ids that forgets the oldest beyond [max], for lists saved on the phone. Not thread-safe. */
class RecentIds(private val max: Int, initial: Collection<String> = emptyList()) {
    private val set = LinkedHashSet<String>()
    init { initial.forEach(::add) }
    /** True if [id] is new. */
    fun add(id: String): Boolean {
        if (!set.add(id)) return false
        while (set.size > max) set.remove(set.first())
        return true
    }
    operator fun contains(id: String) = id in set
    val size get() = set.size
    fun toList(): List<String> = set.toList()
}

/** The `sender` field of a received packet (spec/FORMAT.md, "Member ids"). */
object Senders {
    /** A member id: 16 lowercase hex chars. */
    fun isMemberId(s: String) = s.length == 16 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /**
     * What the sender of a received message or receipt is called on this phone ([Message.sender]), or null if the packet
     * is to be treated like one nobody can open. [wire]: the packet's `sender`; [me]: this phone's member id in the
     * channel that opened it; [device]: the mark this phone puts on its own messages, which is never sent.
     *
     * - A sender has to be a member id, or `web-` and one: no key can ever be known for anything else, so such a packet
     *   could never be checked.
     * - Only this phone's member id becomes [device]; that packet's signature is then checked with this phone's own key.
     *   A `sender` that already equals [device] is refused, whatever its shape: it would be shown as written here.
     */
    fun shown(wire: String, me: String, device: String): String? = when {
        wire == device || !isMemberId(wire.removePrefix("web-")) -> null
        wire == me -> device
        else -> wire
    }
}

/**
 * What waits for a sender's public key (spec/FORMAT.md, "Waiting for a key"): messages shown as "not verified yet" and
 * receipts, each checked when that sender's introduction arrives in its channel (the Public channel, or one group).
 *
 * - Packets are told apart by [GroupCrypto.Opened.key], not by their id: several packets can carry one id, and not each
 *   gets a row in the chat ([StoreCap.name]). A message waits only as the one its row shows, so that the check of
 *   another packet with that id never marks or removes that row.
 * - Each channel has room for [max] of its own, and when it is full its oldest goes. The Public channel, where anyone
 *   can write under ids that are never introduced, can't use up a group's room, nor one group another's.
 * - What waited for a row that left the chat goes with it ([forget]).
 *
 * Not thread-safe: the caller's lock guards it.
 */
class KeyWait<C, T>(private val max: Int = MAX) {
    /** [row]: the id of the chat row this packet is shown as, or null for a receipt. */
    class Entry<T>(val key: String, val sender: String, val row: String?, val item: T)
    private val channels = HashMap<C, LinkedHashMap<String, Entry<T>>>() // channel -> what waits there by key, oldest first
    private val rows = HashMap<String, Pair<C, String>>()                 // chat row -> the channel and key of the packet it shows

    /**
     * A message whose sender's key isn't known. [shown]: the chat row [id] was just made from this very packet. False,
     * and nothing kept, if it wasn't: the row then shows another packet, and only that one's check may touch it.
     */
    fun message(key: String, channel: C, sender: String, id: String, shown: Boolean, item: T): Boolean {
        if (!shown) return false
        rows[id]?.let { (c, k) -> remove(c, k) } // the row was made again, from this packet: what waited for the old one is void
        return put(channel, Entry(key, sender.removePrefix("web-"), id, item))
    }

    /** A receipt whose sender's key isn't known. False if this very receipt already waits. */
    fun receipt(key: String, channel: C, sender: String, item: T): Boolean = put(channel, Entry(key, sender.removePrefix("web-"), null, item))

    /** The key of member [sender] arrived in [channel]: what waited for it there, oldest first. It no longer waits. */
    fun take(channel: C, sender: String): List<Entry<T>> {
        val out = channels[channel]?.values?.filter { it.sender == sender } ?: return emptyList()
        out.forEach { remove(channel, it.key) }
        return out
    }

    /** The chat rows [ids] are gone (the store was trimmed): nothing waits for them any more. */
    fun forget(ids: Collection<String>) { for (id in ids) rows[id]?.let { (c, k) -> remove(c, k) } }

    /** How many packets wait in [channel]. */
    fun count(channel: C): Int = channels[channel]?.size ?: 0

    private fun put(channel: C, e: Entry<T>): Boolean {
        val list = channels.getOrPut(channel) { LinkedHashMap() }
        if (e.key in list) return false
        while (list.size >= max && list.isNotEmpty()) list.values.first().let { old -> list.remove(old.key); if (old.row != null && rows[old.row]?.second == old.key) rows.remove(old.row) }
        list[e.key] = e
        if (e.row != null) rows[e.row] = channel to e.key
        return true
    }

    private fun remove(channel: C, key: String) {
        val list = channels[channel] ?: return
        val e = list.remove(key) ?: return
        if (e.row != null && rows[e.row]?.second == key) rows.remove(e.row)
        if (list.isEmpty()) channels.remove(channel)
    }

    companion object { const val MAX = 1_000 }
}

/**
 * When the next delivery receipt goes out (spec/FORMAT.md, "Delivery receipts"): 2 s after the last message to
 * confirm arrived, or 10 s after the first one, so a burst of arriving messages shares one receipt.
 */
object ReceiptBatch {
    const val QUIET_MS = 2_000L
    const val MAX_WAIT_MS = 10_000L
    fun due(firstMs: Long, lastMs: Long, nowMs: Long) = nowMs - lastMs >= QUIET_MS || nowMs - firstMs >= MAX_WAIT_MS
}
