package it.blackout.mesh

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.TreeMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * One sender's message keys in an epoch (spec "Message keys"): the leaves of a 16-level binary tree. A leaf can be used
 * and deleted in any order, because packets on a mesh arrive late and out of order. What is kept is only the nodes that
 * still lead to unused leaves, so nothing here can bring back a key that was deleted. Node ids: root 1, children 2x and 2x+1.
 * Not thread-safe: [MessageKeys] guards it.
 */
class SenderTree internal constructor(private val nodes: TreeMap<Int, ByteArray>) {
    constructor(root: ByteArray) : this(TreeMap<Int, ByteArray>().also { it[1] = root })

    private fun holder(leaf: Int): Int { var at = leaf; while (at >= 1 && at !in nodes) at = at shr 1; return at }
    private fun depth(node: Int) = 31 - Integer.numberOfLeadingZeros(node)

    /** Leaf [i], or null if it was deleted. Deletes nothing. */
    fun key(i: Int): ByteArray? {
        if (i !in 0 until LEAVES) return null
        val leaf = LEAVES or i; val at = holder(leaf)
        if (at < 1) return null
        var k = nodes[at]!!
        for (bit in DEPTH - depth(at) - 1 downTo 0) k = child(k, (leaf shr bit) and 1)
        return k
    }

    /** Deletes leaf [i], keeping the branches that lead to every other leaf. Nothing happens if it is already gone. */
    fun forget(i: Int) {
        if (i !in 0 until LEAVES || nodes.size >= MAX_NODES) return
        val leaf = LEAVES or i; var at = holder(leaf)
        if (at < 1) return
        var k = nodes.remove(at)!!
        for (bit in DEPTH - depth(at) - 1 downTo 0) {
            val b = (leaf shr bit) and 1
            nodes[(at shl 1) or (1 - b)] = child(k, 1 - b)
            k = child(k, b); at = (at shl 1) or b
        }
    }

    internal fun write(o: DataOutputStream) { o.writeShort(nodes.size); nodes.forEach { (id, k) -> o.writeInt(id); o.write(k) } }

    companion object {
        const val DEPTH = 16; const val LEAVES = 1 shl DEPTH; const val MAX_NODES = 4096
        private fun child(k: ByteArray, b: Int) = MessageKeys.hmac(k, byteArrayOf(b.toByte()))
        internal fun read(i: DataInputStream): SenderTree {
            val m = TreeMap<Int, ByteArray>()
            repeat(i.readUnsignedShort()) { val id = i.readInt(); m[id] = ByteArray(32).also(i::readFully) }
            return SenderTree(m)
        }
    }
}

/** Every member's message keys in one epoch, and how far this phone has got with its own (spec "Message keys"). Any thread. */
class MessageKeys internal constructor(val members: List<String>, private val trees: List<SenderTree>, private var next: Int = 0) {
    @Synchronized fun index(member: String) = members.indexOf(member)

    /** The key of [sender]'s message number [n], if it is still there. */
    @Synchronized fun key(sender: Int, n: Int): ByteArray? = trees.getOrNull(sender)?.key(n)?.let { hmac(it, "darkproof-message-v1".toByteArray()) }

    @Synchronized fun forget(sender: Int, n: Int) { trees.getOrNull(sender)?.forget(n) }

    /** The number of this phone's next message, or null when an epoch's numbers have run out. */
    @Synchronized fun takeNext(): Int? = if (next >= SenderTree.LEAVES) null else next++

    @Synchronized fun encode(): ByteArray = ByteArrayOutputStream().also { b ->
        DataOutputStream(b).run {
            writeInt(next); writeShort(members.size)
            members.forEach { write(Rekey.hex(it)) }
            trees.forEach { it.write(this) }
        }
    }.toByteArray()

    companion object {
        internal fun hmac(key: ByteArray, msg: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(msg) }

        /** What an epoch's random secret becomes for mailboxes, receipts and headers; the secret itself isn't kept. */
        fun outer(secret: ByteArray) = GroupCrypto.hkdf(secret, "darkproof-epoch-outer-v1")

        fun of(secret: ByteArray, members: List<String>) = MessageKeys(members, members.map { SenderTree(hmac(secret, "darkproof-tree-v1".toByteArray() + Rekey.hex(it))) })

        fun decode(b: ByteArray): MessageKeys? = runCatching {
            DataInputStream(ByteArrayInputStream(b)).run {
                val next = readInt(); val n = readUnsignedShort()
                val members = (0 until n).map { ByteArray(8).also(::readFully).joinToString("") { x -> "%02x".format(x) } }
                MessageKeys(members, (0 until n).map { SenderTree.read(this) }, next)
            }
        }.getOrNull()
    }
}

/** Which message key opened a packet: deleted once its signature has checked. */
class Leaf(val epoch: Keyring.Epoch, val index: Int, val counter: Int) {
    fun forget() { epoch.messageKeys?.forget(index, counter) }
}

/**
 * This phone's readable copy of a message whose key it has deleted (spec "Message keys"), sealed with a key that stays on
 * the phone. It goes when the packet goes or the epoch does, so history lasts as long as before.
 */
object History {
    class Saved(val group: String, val epoch: String, val opened: GroupCrypto.Opened, val index: Int, val counter: Int)

    fun seal(key: ByteArray, id: String, group: String, epoch: String, o: GroupCrypto.Opened, index: Int, counter: Int): ByteArray {
        val plain = ByteArrayOutputStream().also { b ->
            DataOutputStream(b).run {
                write(Rekey.hex(group)); writeUTF(epoch); writeLong(o.message.ts); write(o.digest); write(o.signature)
                writeShort(index); writeInt(counter); writeUTF(o.message.sender); writeUTF(o.message.name); writeInt(o.message.text.toByteArray().size); write(o.message.text.toByteArray())
                val extra = o.extra ?: ByteArray(0); writeInt(extra.size); write(extra)
            }
        }.toByteArray()
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES")); c.updateAAD(id.toByteArray())
        return c.iv + c.doFinal(plain)
    }

    fun open(key: ByteArray, id: String, blob: ByteArray): Saved? = runCatching {
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, 12)); c.updateAAD(id.toByteArray())
        DataInputStream(ByteArrayInputStream(c.doFinal(blob, 12, blob.size - 12))).run {
            val group = ByteArray(16).also(::readFully).joinToString("") { "%02x".format(it) }; val epoch = readUTF(); val ts = readLong()
            val digest = ByteArray(32).also(::readFully); val signature = ByteArray(64).also(::readFully)
            val index = readUnsignedShort(); val counter = readInt(); val sender = readUTF(); val name = readUTF()
            val text = String(ByteArray(readInt()).also(::readFully)); val extra = ByteArray(readInt()).also(::readFully).takeIf { it.isNotEmpty() }
            val photo = extra?.takeIf { it.size > 1 && it[0] == Photo.JPEG && it.size - 1 <= Photo.MAX_BYTES }?.copyOfRange(1, extra.size)
            Saved(group, epoch, GroupCrypto.Opened(Message(id, ts, sender, name, text, photo = photo), signature, digest, extra), index, counter)
        }
    }.getOrNull()

    /**
     * True if copy [s] goes with the epochs in [gone], which this phone has just deleted from its group: the copy goes
     * when the epoch is deleted (spec "This phone's copy"), at once and not at the next read of the store. A copy kept
     * before epochs had an id names its epoch by hash: it goes only if no epoch still [held] has that hash or id, since
     * it would still be shown with that one.
     */
    fun goesWith(s: Saved, gone: List<Keyring.Epoch>, held: List<Keyring.Epoch>): Boolean =
        gone.any { it.id == s.epoch } || (gone.any { it.hash == s.epoch } && held.none { it.id == s.epoch || it.hash == s.epoch })
}
