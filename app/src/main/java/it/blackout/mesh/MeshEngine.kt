package it.blackout.mesh

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.util.UUID
import java.util.concurrent.Executors

private class Db(c: Context) : SQLiteOpenHelper(c, "mesh.db", null, 6) {
    override fun onCreate(d: SQLiteDatabase) {
        d.execSQL("CREATE TABLE p(id TEXT PRIMARY KEY, ts INTEGER, ttl INTEGER, cipher BLOB)")
        onUpgrade(d, 2, 3)
    }
    /**
     * 1 → 2 (protocol v0.5): older packets were sealed with v0.4 keys that no phone uses any more; don't pass them on.
     * 2 → 3: members' public keys learned from introductions (spec "Signatures"), per group id ([GroupCrypto.groupId]).
     * 5 → 6: the id of a row in p (and h) is the name its packet goes by ([StoreCap.name]): the packet id, or the packet's
     * key for another packet under an id that was taken. The tables stay as they are; an older app can't read such rows.
     */
    override fun onUpgrade(d: SQLiteDatabase, a: Int, b: Int) {
        if (a < 2) d.execSQL("DELETE FROM p")
        if (a < 3) d.execSQL("CREATE TABLE k(grp TEXT, id TEXT, pub BLOB, seen INTEGER, PRIMARY KEY(grp, id))")
        if (a < 4) d.execSQL("ALTER TABLE k ADD COLUMN enc BLOB") // 3 → 4: their encryption keys too (v0.6)
        if (a < 5) { // 4 → 5: when that key was introduced, so an older one can't replace it, and their ML-KEM key
            d.execSQL("ALTER TABLE k ADD COLUMN encAt INTEGER DEFAULT 0"); d.execSQL("ALTER TABLE k ADD COLUMN pq BLOB")
            d.execSQL("CREATE TABLE h(id TEXT PRIMARY KEY, data BLOB)") // readable copies of messages whose keys are deleted
        }
    }
}

/** Someone with the code asking to be let into a group; its admins decide (spec "Joining"). */
class JoinRequest(val id: String, val name: String, val pub: ByteArray)

/** Where one of my messages is: still on this phone, given to a phone in range or the relays, or confirmed. */
sealed class Delivery {
    object Waiting : Delivery()
    object Sent : Delivery()
    data class Delivered(val readers: List<Reader>) : Delivery()
}

/** State shared between the service and the UI. */
object MeshEngine {
    const val MAX_TTL = MeshRouter.MAX_TTL
    private const val WEEK = 7 * 24 * 3600_000L // how long phones pass messages on (MeshRouter)
    private const val MAX_PUBLIC = 2_000        // Public messages kept on the phone; older ones are removed
    private const val HANDED_OFF_MAX = 2_000    // "Sent" labels remembered across restarts
    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newSingleThreadExecutor()
    private var app: Context? = null
    private var db: SQLiteDatabase? = null

    /** What a group's code opens (spec/DESIGN-v0.6-groups.md, "Keys"): introductions, new keys, and messages from phones not in yet. */
    private class Door(val code: String) {
        val crypto = GroupCrypto(code); val receipts = crypto.receipts(); val intros = crypto.intros(); val rekeys = crypto.rekeys()
        val id: String = crypto.groupId()
    }

    /**
     * A saved group's keys (spec/FORMAT.md, "Encryption", "Delivery receipts", "Introductions"), this phone's member
     * key there (in the Keystore), and the members' public keys this phone knows ([known], guarded by itself).
     */
    private class Keys(code: String, c: Context) {
        /** The door in use. It changes when someone is removed; the [oldDoors] stay a week, for removals that crossed. */
        @Volatile var door = Door(code)
        @Volatile var oldDoors: List<Door> = emptyList()
        val code get() = door.code
        val intros get() = door.intros
        val rekeys get() = door.rekeys
        /** Never changes for the group, even when its code does: member keys hang off it. */
        val id: String = Vault.get(c, "origin.${door.id}")?.let { String(it) } ?: door.id
        /** The group's random epoch secrets. Empty while this phone is joining. */
        val ring = Keyring()
        val joined get() = ring.currentOrNull() != null
        /** This phone was removed from the group: that removal's epoch number and its maker's rank, and [removedBy] its maker. */
        @Volatile var removedAt: Pair<Long, Int>? = null
        @Volatile var removedBy: String? = null
        /** A new key that lists this phone but gave it no part it can open: this phone asks its way back with a key of its own. */
        @Volatile var leftOut: LeftOut? = null
        val removed get() = removedAt != null
        /** Still joining or rejoining, and a removal came through this door: this invite no longer works. */
        @Volatile var closed = false
        /** This phone had been away past the weekly key and asked to come back (its new key is the request): since when, or 0. */
        @Volatile var rejoiningSince = 0L
        val rejoining get() = rejoiningSince > 0
        /** How long after the week is up this phone makes the new key. */
        val weeklyDelay = rnd.nextInt(Keyring.MAX_DELAY_MS.toInt()).toLong()
        /** Written with: the current epoch's keys, or the door's while joining. */
        val group get() = ring.currentOrNull()?.group ?: door.crypto
        val receipts get() = ring.currentOrNull()?.receipts ?: door.receipts
        val members: List<String> get() = ring.currentOrNull()?.members ?: emptyList()
        val pair = MemberKeys.forGroup(id)
        val pub: ByteArray = P256.compress(pair.public)
        val me = P256.memberId(pub)
        /** The HPKE keys other members seal new epoch secrets to: a new one every week. */
        val encs = EncKeys(c, id)
        val encPub: ByteArray get() = encs.currentPub()
        /** Member id -> their keys and name; the most recently used stay, so a flood of made-up members can't fill the memory. */
        val known = LinkedHashMap<String, Known>(16, 0.75f, true)
        fun sign(msg: ByteArray) = P256.sign(pair.private, msg)
        val isPublic get() = code == GroupCrypto.PUBLIC_CODE
    }

    /** A key this phone couldn't open ([Keyring.Taken.LeftOut]): its number and rank, and how many keys this phone has made to get back in. */
    private class LeftOut(val number: Long, val rank: Int, val tries: Int)

    /** A member's public keys, from their introduction. */
    private class Known(val pub: ByteArray, val key: java.security.PublicKey, val enc: ByteArray?, val name: String, val encAt: Long = 0, val pq: ByteArray? = null)

    /** A packet opened with one of [Keys]: not shown before its signature is checked (spec "Signatures"). */
    private sealed class Seen {
        class Msg(val m: Message, val k: Keys, val o: GroupCrypto.Opened, val fromHistory: Boolean = false) : Seen()
        class Receipt(val r: Message, val k: Keys, val o: GroupCrypto.Opened) : Seen()
        class Intro(val k: Keys, val id: String, val pub: ByteArray, val key: java.security.PublicKey, val enc: ByteArray, val name: String, val ts: Long, val pq: ByteArray?) : Seen()
        class NewKey(val k: Keys, val o: GroupCrypto.Opened, val r: Rekey, val packetId: String, val door: Door) : Seen()
        object Forged : Seen() // an introduction that doesn't hold up: like a packet nobody can open
    }

    /** A message or receipt from a member whose public key isn't known yet; checked when the introduction comes. */
    private class Pending(val k: Keys, val o: GroupCrypto.Opened, val receipt: Message?)
    /** What waits for a key, each group and the Public channel apart ([KeyWait]); guarded by the messages lock. */
    private val unchecked = KeyWait<Keys, Pending>()
    private class Waiting(val from: String, val text: String, val photo: ByteArray?)
    private val waiting = HashMap<String, MutableList<Waiting>>() // group id -> what was written before an admin let this phone in
    private const val ACK_SPREAD_MS = 20_000
    private const val MAX_NAME_BYTES = 200                 // names are 40 characters at most in the app
    private const val MAX_KNOWN = 500                      // public keys kept per group
    private const val INTRO_EVERY = 3 * 24 * 3600_000L     // spec "Introductions"
    private val rnd = java.security.SecureRandom()
    private val rescanQueued = java.util.concurrent.atomic.AtomicBoolean() // new keys arriving together: one reading of the store
    private val keyCache = HashMap<String, Keys>() // code -> keys: each derivation takes 32 MiB of scrypt, so only once
    private var publicKeys: Keys? = null              // the Public channel's
    @Volatile private var active: Keys? = null     // the group on screen
    @Volatile private var others: List<Keys> = emptyList() // the other saved groups: read, alerted and confirmed too
    @Volatile private var allKeys = false          // every saved group's key has been tried on the whole store
    @Volatile private var activeCode = ""
    /**
     * The node id other phones see when they link (spec/FORMAT.md, "Link ids"): random, new at every app start,
     * unrelated to member ids, so a phone seen over the air can't be matched to a person or followed across restarts.
     */
    val linkId: String = ByteArray(6).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

    // This lock guards messages, messageIds, deliveries, index, the database writes and the key lists while they
    // change, so a packet that arrives during a group switch is neither lost nor shown twice.
    private val messages = ArrayList<Message>()      // every readable message: all saved groups and the Public channel
    private val messageIds = HashSet<String>()
    private val shownAs = HashMap<String, String>()  // what was signed ([GroupCrypto.Opened.mark]) -> the row that shows it
    private var deliveries = Deliveries()            // who confirmed which message
    private var index = HashMap<String, StoreCap.Entry>() // every stored packet, for the store cap
    private var indexBytes = 0L
    private var doorCount = 0; private var doorBytes = 0L // what the index holds of [StoreCap.Kind.DOOR]
    private val joinAlertAt = HashMap<String, Long>() // group id -> when this phone last alerted "asks to join" there
    @Volatile private var compacting = false
    private val ids = Any()                          // guards the sets below
    private val receiptIds = RecentIds(20_000)       // receipt packets this phone can open: kept off LoRa
    private val mine = HashSet<String>()             // ids of my own messages
    private val myReceipts = HashSet<String>()       // ids of receipts written on this phone (they go up to the relays first)
    private var handedOff = RecentIds(HANDED_OFF_MAX) // my messages already given to another phone, a radio or the relays
    @Volatile private var fromRelays = FromRelays()  // packets a relay brought first: they never go back up, after a restart either
    private val pendingAcks = ArrayList<Pair<String, Keys>>() // message id + its group's keys; main thread only
    private var firstAck = 0L; private var lastAck = 0L // when the first and the last pending ack came; main thread only
    @Volatile var router: MeshRouter? = null; private set
    var sender: ((String, Packet) -> Unit)? = null
    var lora: LoraLink? = null
    var meshcore: MeshCoreLink? = null
    var ble: BleLink? = null
    /** Phones on the same Wi-Fi network; runs without the service, so it works even without Bluetooth permission. */
    @Volatile var wifi: WifiLink? = null; private set
    /** Public Nostr relays while there is internet; also bridges this phone's neighbourhood. */
    @Volatile var nostr: NostrLink? = null; private set
    /** Set by the service: node ids (Nearby endpoint names) of the phones linked over Nearby right now. */
    @Volatile var nearbyNodes: () -> Set<String> = { emptySet() }
    var listener: (() -> Unit)? = null
    /** A new message from someone else in any saved group, on the main thread (for notifications); see [Message.group]. */
    var onIncoming: ((Message) -> Unit)? = null
    /** Marks this phone's own messages on this phone only ([Message.sender]); never sent: packets carry member ids. */
    var deviceId = ""; private set
    var name = ""; private set
    var transportStatus = "Starting…"
    private var startedAt = 0L

    /**
     * Opens the store and the group's keys. Called by the screen and by the service; only the first call does anything.
     * The other saved groups' keys are derived afterwards in the background, then their messages are read too.
     */
    @Synchronized fun start(c: Context, name: String, code: String) {
        if (router != null) return
        app = c.applicationContext
        val prefs = c.getSharedPreferences("mesh", 0)
        val upgrade = prefs.contains("device") // this phone ran GoDark before (a device id exists from then)
        deviceId = prefs.getString("device", null) ?: UUID.randomUUID().toString().take(12).also { prefs.edit().putString("device", it).apply() }
        this.name = name
        startedAt = System.currentTimeMillis()
        synchronized(ids) { handedOff = RecentIds(HANDED_OFF_MAX, prefs.getString("handedOff", "")!!.split(',').filter { it.isNotEmpty() }) }
        db = Db(c.applicationContext).writableDatabase
        if (!prefs.getBoolean("v06", false)) { // groups saved before v0.6 count as founded here (spec "Making the first epoch")
            val saved = if (upgrade) (listOfNotNull(Groups.current(c)) + Groups.others(c)).map { it.code }.toSet() else emptySet()
            Groups.setFounded(c, Groups.founded(c) + saved)
            prefs.edit().putBoolean("v06", true)
                .apply { prefs.all.keys.filter { it.startsWith("introAt.") }.forEach(::remove) }.apply() // introductions now carry the encryption key
        }
        publicKeys = keys(GroupCrypto.PUBLIC_CODE)
        val k = keys(code)
        activeCode = code; active = k
        val loaded = scan()
        synchronized(messages) { apply(loaded) }
        val relayed = FromRelays(prefs.getString(FromRelays.PREF, "") ?: "").also { fromRelays = it }
        router = MeshRouter(send = ::route, deliver = ::onDeliver, minCipher = MeshRouter.MIN_SEALED, maxPerMinute = MeshRouter.LINK_PER_MINUTE, unlimited = NostrLink::owns, raised = ::onRaised)
            .also { it.restore(loaded.recent, loaded.seen) { key -> if (key in relayed) NostrLink.PEER else "" } } // what the relays brought doesn't go back to them
        if (prefs.getBoolean("wifiNetwork", true)) setWifi(true)
        if (prefs.getBoolean("internet", true)) setInternet(true)
        notifyUi()
        io.execute { savedGroupsChanged(code) }
        hourly()
    }

    private fun hourly() { main.postDelayed({ io.execute { weeklyCheck(); compact() }; hourly() }, Keyring.HOUR_MS) }

    /** Makes the weekly new key of every saved group that is due. Background thread. */
    fun weeklyCheck() = (listOfNotNull(active) + others).forEach { rekeyIfDue(it); finishRemovals(it); answerLeftOut(it) }

    /**
     * A new key when the current one is a week old (spec "Keys"), after this phone's random delay so that the group's
     * phones don't all do it at once; the first to do it settles it for the rest. Well past that delay this phone has
     * missed the group's new keys, or the whole group was quiet: its new key is then also how it asks to come back.
     */
    private fun rekeyIfDue(k: Keys) {
        val cur = k.ring.currentOrNull() ?: return
        val now = clock()
        // Counted from when this phone got the key, if that was after its date: a member's key dated long ago isn't due at once.
        if (k.isPublic || k.removed || !Keyring.weeklyDue(cur.since, now, k.weeklyDelay)) return
        val away = Keyring.overdue(cur.since, now)
        if (makeRekey(k, emptyList(), null) && away) setRejoining(k, System.currentTimeMillis())
    }

    /** The time, for deciding when a key is due; tests can move it forward. */
    private fun clock() = System.currentTimeMillis() + DebugTools.ahead

    private fun setRejoining(k: Keys, since: Long) {
        if (k.rejoiningSince == since) return
        k.rejoiningSince = since
        app?.getSharedPreferences("mesh", 0)?.edit()?.putLong("rejoining.${k.id}", since)?.apply()
        notifyUi()
    }

    /**
     * The very packet a message is shown from ([MeshRouter.key]), or null: what a report of that message is about.
     * [id] is the name the packet goes by in the store ([StoreCap.name]): the packet stored first under an id goes by
     * that id, any other by its key.
     */
    private fun packetKey(id: String): String? = if (id.length > 16) id else try {
        db?.rawQuery("SELECT ts, cipher FROM p WHERE id = ?", arrayOf(id))?.use { q -> if (q.moveToNext()) MeshRouter.key(Packet(id, q.getLong(0), 1, q.getBlob(1))) else null }
    } catch (e: RuntimeException) { DebugTools.log("store: can't read a packet: $e"); null }

    /** Turns the internet relays on or off (Connections screen), and remembers it. */
    @Synchronized fun setInternet(on: Boolean) {
        val c = app ?: return
        c.getSharedPreferences("mesh", 0).edit().putBoolean("internet", on).apply()
        nostr?.stop(); nostr = null
        val tor = Tor.enabled(c) && DebugTools.relays(c) == null // the mock relay of debug builds is on this computer
        if (on) nostr = NostrLink(c, { router }, ::relayScopes, ::notifyUi, tor, ::markHandedOff, ::packetKey, fromRelays).also { it.start() }
        if (!on || !tor) main.post { Tor.stop(c) } // Tor runs only while the relays need it
        notifyUi()
    }

    /** Turns "Connect through Tor" on or off (Connections screen): the relays link again, through the app's own Tor or not. */
    @Synchronized fun setTor(on: Boolean) {
        val c = app ?: return
        Tor.setEnabled(c, on)
        OfflineMap.torChanged(on)
        if (nostr != null) setInternet(true) else notifyUi()
    }

    /** This phone's relay mailboxes (spec/FORMAT.md, "Mailboxes"): each saved group's apart, so it can have its own links, then the Public channel's. */
    private fun relayScopes(): List<NostrLink.Scope> =
        (listOfNotNull(active) + others).filter { !it.isPublic }.map { k ->
            NostrLink.Scope(k.id, (k.ring.all().map { it.group.mailbox } + (k.oldDoors + k.door).map { it.crypto.mailbox }).distinct())
        } + NostrLink.Scope("", listOf(Nostr.PUBLIC_MAILBOX))

    /** Turns linking over Wi-Fi networks on or off (Connections screen), and remembers it. */
    @Synchronized fun setWifi(on: Boolean) {
        val c = app ?: return
        c.getSharedPreferences("mesh", 0).edit().putBoolean("wifiNetwork", on).apply()
        if (on && wifi == null) wifi = WifiLink(c, linkId, { router }, ::notifyUi).also { w -> main.post { w.start(); notifyUi() } }
        if (!on) { wifi?.let { w -> main.post { w.stop() } }; wifi = null; notifyUi() }
    }

    /**
     * Shows another group. Confirmations owed so far go out first. Main thread; the work runs in the background, and
     * for a saved group it is quick: its key and messages are already there.
     */
    fun switchGroup(code: String) {
        flushAcks()
        activeCode = code // shown at once; messages written now use this group's key (see post)
        io.execute { savedGroupsChanged(code) }
    }

    fun rename(newName: String) { name = newName.trim().take(40).ifEmpty { name }; notifyUi() }

    /**
     * The cached keys of [code], derived the first time (slow: call in the background). A code its group has moved on
     * from (an old invite, an alert from before a removal) gives the keys that group has under its new code, if it is
     * saved here: a second holder would put the old door on the group's current keyring and save over it.
     */
    private fun keys(code: String, follow: Boolean = true): Keys = synchronized(keyCache) { keyCache[code] } ?: Keys(code, app!!).let { k ->
        if (follow) movedTo(k)?.let { return keys(it, false) }
        loadKnown(k)
        loadRing(k)
        synchronized(keyCache) { keyCache[code] = k }
        k
    }

    /** The code [k]'s group has now, if [k] was made from another one and the group is saved on this phone under it ([moveDoor] notes it). */
    private fun movedTo(k: Keys): String? {
        val c = app ?: return null
        return Vault.get(c, "door.${k.id}")?.let { String(it) }?.takeIf { it != k.code && Groups.find(c, it) != null }
    }

    /** The public keys saved for [k]'s group. */
    private fun loadKnown(k: Keys) {
        db?.rawQuery("SELECT id, pub, enc, encAt, pq FROM k WHERE grp = ?", arrayOf(k.id))?.use { q ->
            while (q.moveToNext()) {
                val pub = q.getBlob(1); val enc = if (q.isNull(2)) null else q.getBlob(2); val pq = if (q.isNull(4)) null else q.getBlob(4)
                P256.decompress(pub)?.let { key -> synchronized(k.known) { k.known[q.getString(0)] = Known(pub, key, enc, "", q.getLong(3), pq) } }
            }
        }
    }

    /**
     * [k]'s epoch secrets from the vault. A group this phone founded (created here, or saved before v0.6) and that
     * has none gets epoch 1 now, with this phone as its only member and admin (spec "Making the first epoch").
     */
    private fun loadRing(k: Keys) {
        val c = app ?: return
        if (k.isPublic) return
        Vault.get(c, "epochs.${k.id}")?.let { raw ->
            runCatching {
                val a = org.json.JSONArray(String(raw))
                for (i in 0 until a.length()) a.getJSONObject(i).let { o ->
                    fun ids(n: String) = o.getJSONArray(n).let { l -> (0 until l.length()).map(l::getString) }
                    fun text(n: String) = o.optString(n).ifEmpty { null }
                    k.ring.add(Keyring.Epoch(o.getLong("n"), o.getLong("made"), o.getString("s").chunked(2).map { h -> h.toInt(16).toByte() }.toByteArray(), ids("m"), ids("a"),
                        text("c"), text("v"), text("r"), text("b"), o.optInt("k", Int.MAX_VALUE), taken = o.optLong("t", o.getLong("made")))) // saved before "t": its date
                }
            }
        }
        Vault.get(c, "mkeys.${k.id}")?.let { raw ->
            runCatching {
                val i = java.io.DataInputStream(raw.inputStream()); val saved = HashMap<String, MessageKeys>()
                while (i.available() > 0) { val hash = i.readUTF(); MessageKeys.decode(ByteArray(i.readInt()).also(i::readFully))?.let { saved[hash] = it } }
                k.ring.all().forEach { e -> (saved[e.id] ?: saved[e.hash])?.let { e.messageKeys = it } } // by hash: saved before epochs had an id
            }
        }
        // The parts it opened, only together with the epochs they brought: without those, the stored new keys are read again.
        if (k.joined) Vault.get(c, "parts.${k.id}")?.let { raw -> k.ring.restoreParts(String(raw).split(',').filter { it.isNotEmpty() }) }
        k.oldDoors = k.ring.all().mapNotNull { it.via }.distinct().filter { it != k.code }.map(::Door)
        if (k.ring.lastMove()?.code == k.code && Vault.get(c, "door.${k.id}") == null) Vault.put(c, "door.${k.id}", k.code.toByteArray()) // moved before this was noted
        val prefs = c.getSharedPreferences("mesh", 0)
        prefs.getString("removedAt.${k.id}", null)?.split(':')?.let { k.removedAt = it[0].toLong() to it[1].toInt(); k.removedBy = it.getOrNull(2) }
        k.rejoiningSince = prefs.getLong("rejoining.${k.id}", 0L)
        if (prefs.getBoolean("closed.${k.id}", false)) { k.closed = true; k.ring.closed = true }
        if (!k.joined && k.code in Groups.founded(c)) {
            k.ring.add(Keyring.Epoch.fresh(1, System.currentTimeMillis(), ByteArray(32).also(rnd::nextBytes), listOf(k.me), listOf(k.me)))
            saveRing(k)
            Groups.setFounded(c, Groups.founded(c) - k.code)
            DebugTools.log("epoch 1 made for a group founded here")
        }
    }

    /** Each held epoch's message keys, in the vault: they are saved after every message whose key was deleted. */
    private fun saveMessageKeys(k: Keys) {
        val c = app ?: return
        synchronized(k) {
            val b = java.io.ByteArrayOutputStream(); val o = java.io.DataOutputStream(b)
            for (e in k.ring.all()) e.messageKeys?.encode()?.let { x -> o.writeUTF(e.id); o.writeInt(x.size); o.write(x) }
            Vault.put(c, "mkeys.${k.id}", b.toByteArray())
        }
    }

    private fun saveRing(k: Keys) {
        saveMessageKeys(k)
        val c = app ?: return
        val a = org.json.JSONArray()
        for (e in k.ring.all()) a.put(org.json.JSONObject().put("n", e.number).put("made", e.made)
            .put("s", e.secret.joinToString("") { "%02x".format(it) }).put("m", org.json.JSONArray(e.members)).put("a", org.json.JSONArray(e.admins))
            .put("c", e.code ?: "").put("v", e.via ?: "").put("r", e.removes ?: "").put("b", e.by ?: "").put("k", e.rank).put("t", e.taken))
        Vault.put(c, "epochs.${k.id}", a.toString().toByteArray())
        saveParts(k)
    }

    /** The sealed parts [k]'s keyring has opened ([Keyring.openedParts]): saved after the epochs they brought, never before. */
    private fun saveParts(k: Keys) {
        val c = app ?: return
        k.ring.partsToSave()
        Vault.put(c, "parts.${k.id}", k.ring.openedParts().joinToString(",").toByteArray())
    }

    /** Marks [code] as founded on this phone (a new group): its first epoch is made here. */
    fun found(c: Context, code: String) = Groups.setFounded(c, Groups.founded(c) + code)

    /** True while this phone has the code of [code]'s group but no epoch yet: it is asking to join. */
    fun joining(code: String?): Boolean = code != null && synchronized(keyCache) { keyCache[code] }?.let { !it.isPublic && !it.joined } ?: false

    /** The admins an invite to [code]'s group names (spec "Invites"), first listed first, or null until its keys are loaded. */
    fun invitePins(code: String): String? = held(code)?.let { k ->
        k.ring.currentOrNull()?.admins.orEmpty().mapNotNull { id -> if (id == k.me) k.pub else synchronized(k.known) { k.known[id]?.pub } }
            .take(Invite.MAX_PINS).joinToString("") { Invite.pin(it) }
    }

    /** True if this phone was removed from [code]'s group. */
    fun removed(code: String?): Boolean = held(code)?.removed ?: false

    /** True if [code] is an invite this phone is trying to join with and the group has moved on from it. */
    fun inviteClosed(code: String?): Boolean = held(code)?.let { it.closed && (!it.joined || it.rejoining) } ?: false

    /** True while this phone, back after more than a week, waits for someone in [code]'s group to answer. */
    fun rejoining(code: String?): Boolean = held(code)?.rejoining ?: false

    private fun held(code: String?) = synchronized(keyCache) { keyCache[code ?: return null] }
    private fun memberId(k: Keys, id: String) = if (id == deviceId) k.me else id.removePrefix("web-")

    fun isAdmin(code: String?, id: String): Boolean = held(code)?.let { k -> memberId(k, id) in (k.ring.currentOrNull()?.admins ?: emptyList()) } ?: false
    fun inGroup(code: String?, id: String): Boolean = held(code)?.let { k -> memberId(k, id) in k.members } ?: false

    /** Gives [id] the admin role, with a new key. [done] says on the main thread if it worked. */
    fun makeAdmin(code: String?, id: String, done: (Boolean) -> Unit) =
        adminChange(code, id, done) { k, m, cur -> m !in cur.admins && makeRekey(k, emptyList(), null, admins = cur.admins + m) }

    /** Removes [id]: a new key and a new code for everyone else (spec "Removing and the code"). */
    fun remove(code: String?, id: String, done: (Boolean) -> Unit) =
        adminChange(code, id, done) { k, m, _ -> m != k.me && makeRekey(k, emptyList(), null, remove = m) }

    private fun adminChange(code: String?, id: String, done: (Boolean) -> Unit, act: (Keys, String, Keyring.Epoch) -> Boolean) = io.execute {
        val k = held(code); val cur = k?.ring?.currentOrNull(); val m = k?.let { memberId(it, id) }
        val ok = k != null && cur != null && m != null && !k.removed && k.me in cur.admins && m in cur.members && act(k, m, cur)
        main.post { done(ok) }
        notifyUi()
    }

    /** What happened in [code]'s group, by name and when: "Marco joined", "Anna removed Marco", "Anna made Ben an admin". */
    fun groupLines(code: String?): List<Pair<Long, String>> {
        val k = held(code) ?: return emptyList()
        fun name(id: String?) = synchronized(k.known) { k.known[id]?.name }?.ifEmpty { null } ?: "Someone"
        fun subject(id: String?) = if (id == k.me) "You" else name(id)
        fun obj(id: String?) = if (id == k.me) "you" else name(id)
        return k.ring.all().filter(k.ring::won).sortedBy { it.number }.zipWithNext().flatMap { (a, b) ->
            (b.members - a.members.toSet() - k.me).map { id -> b.made to "${name(id)} joined" } +
                (b.admins - a.admins.toSet()).map { id -> b.made to "${subject(b.by)} made ${obj(id)} an admin" } +
                listOfNotNull(b.removes?.let { id -> b.made to "${subject(b.by)} removed ${obj(id)}" })
        }
    }

    /**
     * A new epoch from a rekey (spec "New key"): signed by its maker, allowed by [Keyring.admit], with a part this phone
     * can open. A removal also moves the group to its new code. True if it was new. Hold the messages lock or scan.
     */
    private fun acceptRekey(x: Seen.NewKey): Boolean {
        val k = x.k; val r = x.r; val maker = x.o.message.sender
        if (!signed(x)) return false
        val pins = Groups.pins(app ?: return false, k.code)
        val pinned = Invite.allows(pins, r.maker) // only read while this phone has no epoch
        if (!pinned && !k.joined) DebugTools.log("new key from someone this invite doesn't name: ignored")
        // The group may have moved on while this phone was away. Only on an admin's word: anyone who has the code can sign a removal.
        if (r.removal && k.rejoining && maker != k.me && x.door === k.door && k.ring.movedOn(r, maker)) k.closed = true
        val prefs = app?.getSharedPreferences("mesh", 0)
        return when (val t = k.ring.take(r, maker, k.me, x.door.code, x.door !== k.door, k.removedAt, pinned = pinned, removedBy = k.removedBy, named = Invite.names(pins, r.maker), inUse = otherCodes(k)) { box -> k.encs.open(box, Rekey.info(x.door.id), Rekey.aad(x.packetId, k.me)) }) {
            Keyring.Taken.Ignored -> false
            is Keyring.Taken.LeftOut -> {
                // The others may have taken this key and be writing with it; this phone can't. It asks its way back with a key of its own.
                DebugTools.log("epoch ${t.number} lists this phone, but its part doesn't open")
                if ((k.leftOut?.number ?: 0L) < t.number) k.leftOut = LeftOut(t.number, t.rank, 0) // read again from the store: the count stays
                main.postDelayed({ io.execute { answerLeftOut(k) } }, rnd.nextInt(3_000).toLong())
                false
            }
            Keyring.Taken.Closed -> { k.closed = true; prefs?.edit()?.putBoolean("closed.${k.id}", true)?.apply(); false } // saved: the keyring takes no key through this code from now on
            is Keyring.Taken.Removed -> {
                k.removedAt = t.number to t.rank; k.removedBy = t.by; prefs?.edit()?.putString("removedAt.${k.id}", "${t.number}:${t.rank}:${t.by}")?.apply()
                DebugTools.log("removed from a group")
                false
            }
            is Keyring.Taken.Added -> {
                if (t.back) { k.removedAt = null; k.removedBy = null; prefs?.edit()?.remove("removedAt.${k.id}")?.apply() }
                if (t.moveTo != null) moveDoor(k)
                saveRing(k)
                if (k.ring.current() === t.epoch && maker != k.me) setRejoining(k, 0)
                synchronized(waiting) { waiting.remove(k.id) }?.let { held -> io.execute { held.forEach { post(false, it.from, it.text, false, it.photo, k.code) } } }
                DebugTools.log("epoch ${r.epoch}: ${r.members.size} member(s)${if (r.removal) ", after a removal" else ""}")
                true
            }
        }.also { if (k.ring.partsToSave()) saveParts(k) } // a part opened for an epoch this phone holds already: not opened again either
    }

    /** The codes of the other groups on this phone, saved or held: a removal can't move [k]'s group onto one of them. */
    private fun otherCodes(k: Keys): List<String> {
        val c = app ?: return emptyList()
        return (Groups.all(c).map { it.code } + synchronized(keyCache) { keyCache.filterValues { it !== k }.keys.toList() }).filter { it != k.code }
    }

    /**
     * Two admins removed different people at once: only one removal won, so the other person is still in the current
     * epoch. An admin's phone finishes it, after 0-3 s unless another admin did (spec "Two new keys at the same time").
     */
    private fun finishRemovals(k: Keys) {
        if (k.removed || k.me !in (k.ring.currentOrNull()?.admins ?: return)) return
        for (m in k.ring.stillToRemove()) if (m != k.me && !makeRekey(k, emptyList(), null, remove = m)) return
    }

    /** The rekey really is from who it says: its key matches the sender's id, and it signed the packet. */
    private fun signed(x: Seen.NewKey): Boolean {
        if (P256.memberId(x.r.maker) != x.o.message.sender) return false
        val key = P256.decompress(x.r.maker) ?: return false
        return P256.verify(key, x.o.digest, x.o.signature)
    }

    /**
     * A member's phone missed our keys: a new epoch, sealed to everyone, brings it back (spec "Away for a while"). Not if
     * another member answered first, or this phone made a key in the last hour (a flood of these must not cost more than that).
     * [at]: this phone's current epoch when that member's key came. Another one since then is the answer, whatever date
     * the key carried: its maker writes the date, and one a few minutes ahead would have every phone answer.
     */
    private fun answerBehind(k: Keys, made: Long, at: Keyring.Epoch?) {
        val cur = k.ring.currentOrNull() ?: return
        if (k.removed || cur !== at || cur.made >= made || k.ring.tooSoon(k.me, clock())) return
        makeRekey(k, emptyList(), null)
    }

    /**
     * A new key listed this phone but its part didn't open ([Keyring.Taken.LeftOut]): the others may have moved on to it,
     * and can't tell. Like a phone that was away, this one makes a key of its own, sealed to everyone, and shows that it is
     * rejoining. That key has the same number as the one it couldn't open if that was the next one, so it can lose to it:
     * an hour later this phone makes one more, numbered above both. Not once a key that settles it got here: a
     * higher-numbered one, or one of the same number that comes before the one it couldn't open whatever the hashes.
     */
    private fun answerLeftOut(k: Keys) {
        val t = k.leftOut ?: return; val cur = k.ring.currentOrNull() ?: return
        if (k.removed || cur.number > t.number || (cur.number == t.number && (cur.code != null || cur.rank < t.rank))) { k.leftOut = null; return }
        if (k.ring.tooSoon(k.me, clock())) return // the hourly check tries again
        if (!makeRekey(k, emptyList(), null)) return
        setRejoining(k, System.currentTimeMillis())
        k.leftOut = if (t.tries == 0) LeftOut(t.number, t.rank, 1) else null
    }

    /**
     * The group follows the code of its newest removal ([Keyring.lastMove]): same group id, member keys and messages, a
     * new door and a new invite. Taken from the keyring, so a removal made here and one arriving at the same moment end
     * up on the same code. Locks in the order messages, then keys, like the delivery path.
     */
    private fun moveDoor(k: Keys) {
        val c = app ?: return
        while (true) {
            val code = k.ring.lastMove()?.code ?: return
            if (k.door.code == code) return
            val next = Door(code) // slow (scrypt): outside the locks
            val done = synchronized(messages) { synchronized(k) {
                if (k.ring.lastMove()?.code != code) return@synchronized false
                val old = k.door
                if (old.code == code) return@synchronized true
                Vault.put(c, "origin.${next.id}", k.id.toByteArray())
                k.oldDoors = listOf(old) + k.oldDoors.filter { it.code != code }
                k.door = next
                k.closed = false // that was about the code it left
                synchronized(keyCache) { keyCache.remove(old.code); keyCache[code] = k }
                Vault.put(c, "door.${k.id}", code.toByteArray()) // where the group is now: its old codes lead here ([keys])
                Groups.replaceCode(c, old.code, code)
                ReadMarks.rename(c, old.code, code)
                c.getSharedPreferences("mesh", 0).edit().remove("introAt.${k.id}").apply() // introduce ourselves through the new door
                if (activeCode == old.code) activeCode = code
                messages.replaceAll { if (it.group == old.code) it.copy(group = code) else it }
                true
            } }
            if (done) break
        }
        DebugTools.log("the group moved to a new code")
        notifyUi()
    }

    private fun declined(k: Keys): Set<String> = app?.getSharedPreferences("mesh", 0)?.getStringSet("declined.${k.id}", emptySet()) ?: emptySet()

    /**
     * Who is asking to join [k]'s group ([Joining.asking]): they introduced themselves through the door in the last week,
     * aren't in the group and weren't turned down. At most [Joining.MAX_ASKING]: anyone with the code can make up keys.
     */
    private fun asking(k: Keys): List<String> {
        val at = synchronized(k.known) { k.known.entries.filter { it.value.pq != null }.associate { it.key to it.value.encAt } }
        return Joining.asking(at, k.members.toSet(), declined(k), k.me, System.currentTimeMillis())
    }

    /**
     * People asking to join [code]'s group, for this phone to answer if it is an admin: they introduced themselves through
     * the door in the last week and aren't in the group, weren't removed and weren't turned down.
     */
    fun joinRequests(code: String?): List<JoinRequest> {
        val k = held(code) ?: return emptyList(); val cur = k.ring.currentOrNull() ?: return emptyList()
        if (k.removed || k.me !in cur.admins) return emptyList()
        val gone = k.ring.all().mapNotNull { it.removes }.toSet(); val ids = asking(k).filter { it !in gone }
        return synchronized(k.known) { ids.mapNotNull { id -> k.known[id]?.let { w -> JoinRequest(id, w.name.ifEmpty { "Someone" }, w.pub) } } }
    }

    /** An admin lets [id] in: a new epoch for everyone, them included (spec "Joining"). [done] says on the main thread if it worked. */
    fun approveJoin(code: String?, id: String, done: (Boolean) -> Unit) = io.execute {
        val k = held(code); val cur = k?.ring?.currentOrNull()
        val ok = k != null && cur != null && !k.removed && k.me in cur.admins && id !in cur.members && makeRekey(k, add = listOf(id), answers = id)
        main.post { done(ok) }
        notifyUi()
    }

    /** An admin turns [id] down. They can ask again only with a new key, that is by reinstalling. */
    fun declineJoin(code: String?, id: String) {
        val k = held(code) ?: return
        app?.getSharedPreferences("mesh", 0)?.edit()?.putStringSet("declined.${k.id}", declined(k) + id)?.apply()
        notifyUi()
    }

    /**
     * Makes and sends a new epoch for the current members plus [add], sealed to each member's encryption key. [admins]:
     * a new admin list. [remove]: who leaves; everyone else also gets a new code. False if a member's encryption key
     * hasn't reached this phone yet: leaving them out would quietly remove them.
     */
    private fun makeRekey(k: Keys, add: List<String>, answers: String?, admins: List<String>? = null, remove: String? = null): Boolean {
        val r = router ?: return false
        val cur = k.ring.currentOrNull() ?: return false
        val members = (cur.members + k.me + add).distinct().filter { it != remove }
        if (members.size > Keyring.MAX_MEMBERS) { DebugTools.log("rekey: the group is full"); return false }
        val door = k.door; val code = if (remove != null) Invite.newCode() else null
        val now = System.currentTimeMillis(); val secret = ByteArray(32).also(rnd::nextBytes); val plain = Rekey.box(secret, code)
        // An admin's rekey also keeps every admin added by a rekey of the same number that didn't win.
        val list = ((admins ?: cur.admins) + if (k.me in cur.admins) k.ring.rivalAdmins() else emptyList()).distinct().filter { it in members }
        // A big group's key goes in several packets, each with the whole member list and some members' parts.
        var rk: Rekey? = null
        val packets = Rekey.split(members).map { some ->
            val pid = Packet.newId(door.rekeys.mailbox)
            val parts = some.map { m ->
                val known = if (m == k.me) null else synchronized(k.known) { k.known[m] }
                val to = (if (m == k.me) k.encPub else known?.enc)?.let(P256::fromUncompressed)
                val pq = if (m == k.me) k.encs.currentPq() else known?.pq
                val box = if (to != null && pq != null) Hybrid.seal(plain, to, pq, Rekey.info(door.id), Rekey.aad(pid, m)) else null
                m to (box ?: run { DebugTools.log("rekey: no encryption key for a member yet"); return false })
            }
            val one = Rekey(cur.number + 1, now, k.pub, list, remove ?: answers, parts, remove != null, members).also { rk = it }
            door.rekeys.packet(pid, now, door.rekeys.seal(pid, now, k.me, name, "", extra = one.encode(), pad = Pad.FULL) { k.sign(it) }) // always the largest size: its length would count the members
        }
        val made = rk ?: return false
        k.ring.add(Keyring.Epoch.fresh(made.epoch, now, secret, members, list, code, if (remove != null) door.code else null, remove, k.me, k.ring.standing(made, k.me)))
        if (code != null) moveDoor(k)
        saveRing(k)
        for (p in packets) {
            synchronized(ids) { myReceipts += p.id }
            synchronized(messages) { save(p, StoreCap.Kind.GROUP) }
            r.publish(p)
        }
        if (code != null) introIfDue(k)
        nostr?.resubscribe() // the new epoch's mailbox
        DebugTools.log("epoch ${made.epoch} made: ${members.size} member(s) in ${packets.size} packet(s)" + (if (answers != null) ", answering a join" else "") + (if (remove != null) ", removing a member" else ""))
        notifyUi()
        return true
    }

    /**
     * A member's public key from a checked introduction: saved (the [MAX_KNOWN] most recently seen per group stay),
     * then that member's messages waiting for it are checked. True if it was new.
     */
    private fun learn(k: Keys, id: String, pub: ByteArray, key: java.security.PublicKey, enc: ByteArray?, who: String, encAt: Long, pq: ByteArray?): Boolean {
        val members = k.members.toSet()
        // Someone who isn't in the group and isn't known here yet: kept only while there is room among those asking to join.
        if (!k.isPublic && id != k.me && synchronized(k.known) { !k.known.containsKey(id) } && !Joining.keeps(id, asking(k), k.ring.everyone(), k.me)) return false
        val (fresh, cur, changed) = synchronized(k.known) {
            val had = k.known[id]
            val newer = enc != null && EncSchedule.isNewer(had?.encAt ?: 0L, encAt)
            val now = Known(pub, key, if (newer) enc else had?.enc, who.ifEmpty { had?.name ?: "" }, if (newer) encAt else had?.encAt ?: 0L, if (newer) pq else had?.pq)
            k.known[id] = now
            // Full: the least recently used go, but never someone in the group, or new keys for them couldn't be sealed.
            if (k.known.size > MAX_KNOWN) k.known.keys.firstOrNull { it != id && it !in members }?.let { k.known.remove(it) }
            Triple(had == null, now, had == null || newer || !had.pub.contentEquals(pub))
        }
        // An introduction that brings nothing new (one read again from the store, or played back) writes nothing.
        if (changed) db?.let { d ->
            d.insertWithOnConflict("k", null, ContentValues().apply { put("grp", k.id); put("id", id); put("pub", pub); if (cur.enc != null) put("enc", cur.enc); put("encAt", cur.encAt); if (cur.pq != null) put("pq", cur.pq); put("seen", System.currentTimeMillis()) },
                SQLiteDatabase.CONFLICT_REPLACE)
            if (fresh) d.execSQL("DELETE FROM k WHERE grp = ? AND id NOT IN (${members.joinToString(",") { "?" }.ifEmpty { "''" }}) AND id NOT IN (SELECT id FROM k WHERE grp = ? ORDER BY seen DESC LIMIT $MAX_KNOWN)", (listOf(k.id) + members + k.id).toTypedArray())
        }
        return fresh
    }

    /** Messages and receipts of [id] in [k]'s group that waited for its key: shown as checked, or dropped. Hold the messages lock. */
    private fun resolve(k: Keys, id: String) {
        if (id != k.me && synchronized(k.known) { !k.known.containsKey(id) }) return // its key wasn't kept ([Joining]): nothing can be checked
        val waited = unchecked.take(k, id)
        if (waited.isEmpty()) return
        for (e in waited) {
            val w = e.item
            val ok = check(k, w.o, had = true) == true
            if (w.receipt != null) { if (ok) deliveries.add(k.id, w.receipt); continue }
            // Only a packet that is the one shown under its id waits ([KeyWait.message]), so this row is that packet's.
            val row = e.row ?: continue; val i = messages.indexOfFirst { it.id == row }
            if (i < 0 || messages[i].verified) continue
            if (ok) { messages[i] = messages[i].copy(verified = true); w.o.leaf?.forget(); saveMessageKeys(w.k) } else { messages.removeAt(i); messageIds.remove(row); shownAs.remove(w.o.mark); index[row]?.let { x -> index[x.id] = StoreCap.Entry(x.id, x.ts, x.size, StoreCap.Kind.UNREADABLE) } }
        }
        DebugTools.log("a member's key: checked ${waited.size} waiting packet(s)")
    }

    /**
     * true: signed by that member; false: not (forged or broken), or its sender isn't in the group or was removed; null:
     * the member's public key isn't known yet. [had]: this phone accepted the packet before, so it is read from its own
     * copy or was waiting for its sender's key. Only then does a removed member's date count ([Keyring.shutOut]).
     */
    private fun check(k: Keys, o: GroupCrypto.Opened, had: Boolean = false): Boolean? {
        val id = o.message.sender.removePrefix("web-")
        if (k.ring.shutOut(id, o.message.ts, had)) return false // not in the group; or removed, and seen only now or dated after the removal
        val key = if (id == k.me) k.pair.public else synchronized(k.known) { k.known[id]?.key } ?: return null
        return P256.verify(key, o.digest, o.signature)
    }

    /**
     * Sends this phone's introduction to [k]'s group when the last one there is more than 3 days old (or there was
     * none), so members' introductions are always among the packets of the last 7 days (spec "Introductions").
     */
    private fun introIfDue(k: Keys, writing: Boolean = false) {
        val c = app ?: return; val r = router ?: return
        if (k.removed) return
        val prefs = c.getSharedPreferences("mesh", 0); val now = System.currentTimeMillis()
        // The Public channel: only when the user writes there, then while a post of theirs (or one typed on this phone's
        // Wi-Fi board) is still shown. A phone whose user never posts on Everyone doesn't announce itself there.
        if (k.isPublic && !PublicIntro.wanted(writing, synchronized(messages) { messages.filter { it.public && (it.sender == deviceId || it.sender == "web-${k.me}") }.maxOfOrNull { it.ts } }, now)) return
        val rotated = !k.isPublic && k.encs.rotateIfDue(clock()) // a new encryption key has to be introduced at once
        if (!rotated && now - prefs.getLong("introAt.${k.id}", 0L) < INTRO_EVERY) return
        val id = Packet.newId(k.intros.mailbox)
        // No name on the Public channel: nothing reads it there, and a post carries its sender's name itself.
        val p = k.intros.packet(id, now, k.intros.seal(id, now, k.me, if (k.isPublic) "" else name, "", extra = if (k.isPublic) byteArrayOf(2) + k.pub + k.encPub else byteArrayOf(3) + k.pub + k.encPub + k.encs.currentPq()) { k.sign(it) })
        synchronized(ids) { myReceipts += id } // written here: goes up to the relays first, like receipts
        synchronized(messages) { save(p, if (k.isPublic) StoreCap.Kind.PUBLIC else StoreCap.Kind.GROUP) }
        prefs.edit().putLong("introAt.${k.id}", now).apply()
        r.publish(p)
        DebugTools.log("introduction sent to ${if (k.isPublic) "Everyone" else "a group"}")
    }

    /** The group on screen. */
    val currentCode: String get() = activeCode

    // People whose emoji the user compared (spec "Person emoji"): "<group id>|<member id>|<name key>".
    private fun tagOf(code: String?) = synchronized(keyCache) { keyCache[code ?: GroupCrypto.PUBLIC_CODE] }?.id
    private fun checkedSet(): Set<String> = app?.getSharedPreferences("mesh", 0)?.getStringSet("checked", emptySet()) ?: emptySet()

    fun isChecked(code: String?, id: String): Boolean { val t = tagOf(code) ?: return false; return checkedSet().any { it.startsWith("$t|$id|") } }

    /** The user compared [id]'s emoji and they matched: this key is that person's from now on (an older one for the name goes). */
    fun markChecked(code: String?, id: String, name: String) {
        val c = app ?: return; val t = tagOf(code) ?: return
        c.getSharedPreferences("mesh", 0).edit().putStringSet("checked", Checked.marked(checkedSet(), t, id, name)).apply()
        notifyUi()
    }

    /** True if [name] belongs to a checked person but [id] is another key: a reinstall, or someone using their name. */
    fun newKeyFor(code: String?, id: String, name: String): Boolean {
        if (id == deviceId) return false
        val t = tagOf(code) ?: return false; val checked = checkedSet()
        return checked.isNotEmpty() && Checked.newKey(checked, t, id, name)
    }

    /**
     * The id of the group whose code is or was [code] ([Message.group]): it stays when the code changes, so blocks hang
     * off it ([Blocks]). The door a group has just left still counts, for a message read a moment before the move.
     */
    fun groupId(code: String?): String? {
        if (code == null) return null
        return synchronized(keyCache) { keyCache[code] ?: keyCache.values.firstOrNull { k -> k.oldDoors.any { it.code == code } } }?.id
    }

    /**
     * The code the group of [code] has now, if [code] is one it has moved on from ([moveDoor] notes where it went), or
     * null. Through the saved notes, not only the cache, so it also works right after a restart. Slow the first time
     * (derives the door): call in the background.
     */
    fun movedCode(code: String): String? {
        val c = app ?: return null
        synchronized(keyCache) { keyCache.values.firstOrNull { k -> k.oldDoors.any { it.code == code } } }?.let { return it.door.code }
        val door = Door(code).id
        val id = Vault.get(c, "origin.$door")?.let { String(it) } ?: door
        return Vault.get(c, "door.$id")?.let { String(it) }?.takeIf { it != code }
    }

    /** This phone's public key in [code]'s group (Person emoji: "your emoji"), or null if its keys aren't ready. */
    fun myPublicKey(code: String?): ByteArray? = synchronized(keyCache) { keyCache[code ?: GroupCrypto.PUBLIC_CODE] }?.pub

    /** The public key of member [id] in [code]'s group, if an introduction brought it. */
    fun publicKeyOf(code: String?, id: String): ByteArray? =
        synchronized(keyCache) { keyCache[code ?: GroupCrypto.PUBLIC_CODE] }?.let { k -> synchronized(k.known) { k.known[id.removePrefix("web-")]?.pub } }

    /**
     * [code] is the group on screen, and the saved list may have changed: derives the keys not seen before, reads the
     * store again only if there are any, then removes what the store cap says. Background thread (io).
     */
    private fun savedGroupsChanged(code: String) {
        val c = app ?: return
        val known = synchronized(keyCache) { keyCache.keys.toSet() }
        val a = keys(code)
        if (a.code != code) { Groups.follow(c, code, a.code); return savedGroupsChanged(a.code) } // an old code of a group saved here: that group is shown, not a second one
        val o = Groups.others(c).map { it.code }.filter { it != code }.distinct()
            .map { old -> keys(old).also { if (it.code != old) Groups.follow(c, old, it.code) } }.distinct().filter { it !== a } // an old code among the saved ones isn't kept: its group is saved too
        val fresh = (o.map { it.code } + code).any { it !in known }
        synchronized(messages) { activeCode = code; active = a; others = o }
        if (fresh) scan().let { l -> synchronized(messages) { apply(l) } } // the screen keeps working while the store is read
        allKeys = true
        (listOf(a) + o + listOfNotNull(publicKeys)).forEach(::introIfDue)
        (listOf(a) + o).forEach(::rekeyIfDue)
        compact()
        nostr?.resubscribe() // the relays now send every saved group's mailbox
        notifyUi()
    }

    /** The name of the saved group whose code is [code] ([Message.group]), for alerts and labels; null if unknown. */
    fun groupName(code: String?): String? {
        val c = app ?: return null
        if (code == null) return null
        return Groups.current(c)?.takeIf { it.code == code }?.name ?: Groups.others(c).firstOrNull { it.code == code }?.name
    }

    /** What [scan] found in the store. */
    private class Loaded(val recent: List<Packet>, val seen: Set<String>, val messages: List<Message>, val receipts: List<Pair<String, Message>>,
                         val index: Map<String, StoreCap.Entry>, val own: Set<String>, val ownReceipts: Set<String>,
                         val receiptIds: Set<String>, val future: List<String>, val pending: List<Pending>,
                         /** This phone's own group messages: group id and message id ([Deliveries.sent]). [receipts] carry their group's id too. */
                         val sent: List<Pair<String, String>>,
                         /** Chat row -> what was signed there ([GroupCrypto.Opened.mark]): a message is shown once, whatever packets bring it. */
                         val marks: Map<String, String> = emptyMap())

    /**
     * Reads the database one row at a time with every key known so far, without holding the messages lock (the
     * screen keeps working meanwhile). Also returns what the router keeps passing on (the newest 500 of the last 7
     * days) and every id it has seen in that time. Background thread.
     */
    private fun scan(): Loaded {
        val d = db ?: return Loaded(emptyList(), emptySet(), emptyList(), emptyList(), emptyMap(), emptySet(), emptySet(), emptySet(), emptyList(), emptyList(), emptyList())
        val now = System.currentTimeMillis(); val cut = now - WEEK
        val recent = ArrayDeque<Packet>(); val seen = HashSet<String>()
        val msgs = ArrayList<Message>(); val recs = ArrayList<Pair<String, Message>>(); val idx = HashMap<String, StoreCap.Entry>(); val opened = ArrayList<Seen>()
        val sent = ArrayList<Pair<String, String>>()
        val copies = HashMap<String, ByteArray>()
        d.rawQuery("SELECT id,data FROM h", null).use { q -> while (q.moveToNext()) copies[q.getString(0)] = q.getBlob(1) }
        val own = HashSet<String>(); val ownReceipts = HashSet<String>(); val rIds = HashSet<String>(); val future = ArrayList<String>()
        d.rawQuery("SELECT id,ts,ttl,cipher FROM p ORDER BY ts", null).use { q ->
            while (q.moveToNext()) {
                val name = q.getString(0) // what the packet goes by: its id, or its key if another packet had that id first
                val p = MeshRouter.clamp(Packet(StoreCap.packetId(name), q.getLong(1), q.getInt(2), q.getBlob(3)))
                if (MeshRouter.inFuture(p.ts, now)) { future += name; continue }
                if (p.ts >= cut) { seen += MeshRouter.key(p); recent.addLast(p); if (recent.size > 500) recent.removeFirst() }
                // Introductions are learned at once; messages and receipts are checked after the loop, when every
                // introduction in the store is known, whatever their order. This phone's own introductions and new
                // keys count as written here, like its receipts: after a restart too they go up on their group's
                // relay links, not with the packets it passes on (Nostr.scope).
                // What came through a group's door is the group's own only from someone in it ([doorKind]).
                val kind = when (val x = copies[name]?.let { fromHistory(name, it) } ?: see(p)) {
                    is Seen.Intro -> { if (x.id == x.k.me) ownReceipts += p.id; learn(x.k, x.id, x.pub, x.key, x.enc, x.name, x.ts, x.pq); if (x.k.isPublic) StoreCap.Kind.PUBLIC else doorKind(x.k, x.id, true) }
                    is Seen.NewKey -> { val ok = signed(x); if (x.o.message.sender == x.k.me && ok) ownReceipts += p.id; acceptRekey(x); doorKind(x.k, x.o.message.sender, ok) }
                    is Seen.Msg -> { opened += if (x.m.id == name) x else Seen.Msg(x.m.copy(id = name), x.k, x.o, x.fromHistory); if (x.m.public) StoreCap.Kind.PUBLIC else StoreCap.Kind.GROUP }
                    is Seen.Receipt -> { opened += x; rIds += p.id; StoreCap.Kind.GROUP }
                    else -> StoreCap.Kind.UNREADABLE
                }
                idx[name] = StoreCap.Entry(name, p.ts, 18 + p.cipher.size, kind)
            }
        }
        val waiting = ArrayList<Pending>(); val spent = HashSet<Keys>(); val marks = HashMap<String, String>()
        // The packet stored under an id first: another packet that brings the same message again is not a second row
        // ([apply]), and one that names this phone as its sender is never a row of its own.
        for (x in opened.sortedBy { it is Seen.Msg && it.m.id.length > 16 }) when (x) {
            is Seen.Msg -> if (x.m.id.length > 16 && x.m.sender == deviceId) Unit else when (check(x.k, x.o, x.fromHistory)) {
                true -> { msgs += x.m; marks[x.m.id] = x.o.mark; if (x.m.sender == deviceId) { own += x.m.id; if (!x.m.public) sent += x.k.id to x.m.id }; if (!x.fromHistory) remember(x.m.id, x.k, x.o); if (x.o.leaf != null) { x.o.leaf?.forget(); spent += x.k } }
                null -> { msgs += x.m.copy(verified = false); marks[x.m.id] = x.o.mark; waiting += Pending(x.k, x.o, null); if (!x.fromHistory) remember(x.m.id, x.k, x.o) }
                false -> idx[x.m.id]?.let { e -> idx[e.id] = StoreCap.Entry(e.id, e.ts, e.size, StoreCap.Kind.UNREADABLE) }
            }
            is Seen.Receipt -> when (check(x.k, x.o)) {
                true -> { recs += x.k.id to x.r; if (x.r.sender == deviceId) ownReceipts += x.r.id }
                null -> waiting += Pending(x.k, x.o, x.r)
                false -> {}
            }
            else -> {}
        }
        spent.forEach(::saveMessageKeys)
        return Loaded(recent.toList(), seen, msgs, recs, idx, own, ownReceipts, rIds, future, waiting, sent, marks)
    }

    /**
     * The class of a packet [k]'s door opened ([StoreCap.door]): the group's own only if someone in the group wrote it,
     * or this phone. [signed]: the packet names [by] and their signature checks. The door opens with the code alone, so
     * anything else gets the small room of people who aren't in ([StoreCap.Kind.DOOR]) and can't push a message out.
     */
    private fun doorKind(k: Keys, by: String, signed: Boolean) = StoreCap.door(signed && by == k.me, signed && k.ring.inGroup(by))

    /**
     * Adds what [scan] found to what is shown (packets that arrived meanwhile stay, none shows twice), and removes
     * packets dated more than 10 minutes ahead. Hold the messages lock.
     */
    private fun apply(l: Loaded) {
        if (l.future.isNotEmpty()) { delete(l.future); DebugTools.log("store: removed ${l.future.size} packets dated in the future") }
        synchronized(ids) { mine += l.own; myReceipts += l.ownReceipts; l.receiptIds.forEach { receiptIds.add(it) } }
        val added = HashSet<String>()
        for (m in l.messages) {
            val mark = l.marks[m.id]
            if (mark != null && shownAs[mark].let { it != null && it != m.id }) continue // another packet already shows this very message
            if (messageIds.add(m.id)) { messages += m; added += m.id }
            if (mark != null) shownAs[mark] = m.id
        }
        if (added.isNotEmpty()) messages.sortBy { it.ts }
        for ((group, id) in l.sent) deliveries.sent(group, id) // before the receipts: one counts only for a message written here, in its group
        for ((group, r) in l.receipts) deliveries.add(group, r)
        // A message waits only if its row was made just now from the stored packet: a row that was there already may show another packet with that id.
        for (w in l.pending) {
            if (w.receipt != null) unchecked.receipt(w.o.key, w.k, w.o.message.sender, w)
            else unchecked.message(w.o.key, w.k, w.o.message.sender, w.o.message.id, w.o.message.id in added, w)
        }
        index.putAll(l.index) // read with the newest keys: a packet may have become readable
        indexBytes = index.values.sumOf { it.size.toLong() }
        index.values.filter { it.kind == StoreCap.Kind.DOOR }.let { d -> doorCount = d.size; doorBytes = d.sumOf { it.size.toLong() } }
    }

    /**
     * Keeps the store small, once every saved group's key has been tried: packets older than 7 days that no saved group
     * can read go (phones stop passing them on after 7 days anyway), and so do those that came through a group's door
     * from someone who isn't in it; Public packets beyond 2,000 go (no sender more than its share: StoreCap.everyone),
     * and then the store cap (StoreCap: about 40 MB and 20,000 packets, unreadable packets first, and the door's own
     * small room). Background thread.
     */
    private fun compact() {
        if (!allKeys) return
        val now = System.currentTimeMillis()
        val expired = HashMap<String, Pair<List<Keyring.Epoch>, List<Keyring.Epoch>>>() // group id -> the epochs deleted now, and those still held
        synchronized(keyCache) { keyCache.values.toList() }.forEach { k -> // keys replaced more than 7 days ago go (v0.6), from the vault too
            // A removed phone still deletes its replaced encryption keys on time (spec "Changing keys"); it only stops introducing itself.
            if (k.removed && !k.isPublic) k.encs.rotateIfDue(clock())
            val gone = k.ring.expire(now)
            if (gone.isNotEmpty()) { saveRing(k); k.oldDoors = k.oldDoors.filter { d -> k.ring.all().any { it.via == d.code } }; expired[k.id] = gone to k.ring.all() }
        }
        val stale = copiesOf(expired)
        val gone = synchronized(messages) {
            val cut = System.currentTimeMillis() - WEEK
            val drop = LinkedHashSet<String>()
            index.values.filter { (it.kind == StoreCap.Kind.UNREADABLE || it.kind == StoreCap.Kind.DOOR) && it.ts < cut }.mapTo(drop) { it.id }
            drop += stale // the messages of an epoch deleted now: their packets no longer open either
            val pub = index.values.filter { it.kind == StoreCap.Kind.PUBLIC }
            if (pub.size > MAX_PUBLIC) {
                // Not simply the oldest: one sender can't push everyone else's messages and places out (StoreCap.everyone).
                // A Public packet that isn't a message is an introduction; this phone's own are the ones it wrote.
                val shown = messages.filter { it.public }.associateBy { it.id }
                val written = synchronized(ids) { pub.filter { it.id in myReceipts }.mapTo(HashSet()) { it.id } }
                drop += StoreCap.everyone(pub.map { e ->
                    val m = shown[e.id]
                    StoreCap.Held(e.id, e.ts, if (m == null) "introductions" else if (m.verified) m.sender.removePrefix("web-") else "not verified",
                        if (m == null) e.id in written else m.sender == deviceId)
                }, MAX_PUBLIC)
            }
            drop += StoreCap.overflow(index.values.filter { it.id !in drop })
            if (drop.isNotEmpty()) {
                delete(drop.toList())
                for (id in drop) index.remove(id)?.let { indexBytes -= it.size; if (it.kind == StoreCap.Kind.DOOR) { doorCount--; doorBytes -= it.size } }
                messages.removeAll { it.id in drop }; messageIds.removeAll(drop); shownAs.values.removeAll(drop)
                unchecked.forget(drop); deliveries.forget(drop) // nothing waits for, or confirms, a message that is gone
                app?.let { Notifier.forget(it, drop) } // nor does an alert show its text
            }
            drop.size
        }
        compacting = false
        if (gone > 0) { DebugTools.log("store: removed $gone packets"); notifyUi() }
    }

    /**
     * The ids of the copies in table h that go with the epochs [compact] just deleted ([History.goesWith]): group id ->
     * the epochs deleted, and those still held. Background thread.
     */
    private fun copiesOf(expired: Map<String, Pair<List<Keyring.Epoch>, List<Keyring.Epoch>>>): List<String> {
        if (expired.isEmpty()) return emptyList()
        val d = db ?: return emptyList(); val key = historyKey ?: return emptyList()
        val out = ArrayList<String>()
        runCatching {
            d.rawQuery("SELECT id,data FROM h", null).use { q ->
                while (q.moveToNext()) {
                    val id = q.getString(0); val s = History.open(key, id, q.getBlob(1)) ?: continue
                    val (gone, held) = expired[s.group] ?: continue
                    if (History.goesWith(s, gone, held)) out += id
                }
            }
        }
        return out
    }

    /** The store grew well past its cap while running: trim it in the background. */
    private fun compactIfFull() {
        if (compacting || !allKeys) return
        val full = synchronized(messages) { indexBytes > StoreCap.MAX_BYTES * 11 / 10 || index.size > StoreCap.MAX_COUNT + 1_000 || StoreCap.doorFull(doorCount, doorBytes) }
        if (full) { compacting = true; io.execute(::compact) }
    }

    /** Hold the messages lock. */
    private fun delete(ids: List<String>) {
        val d = db ?: return
        d.beginTransaction()
        try {
            ids.chunked(500).forEach { c -> d.delete("p", "id IN (${c.joinToString(",") { "?" }})", c.toTypedArray()); d.delete("h", "id IN (${c.joinToString(",") { "?" }})", c.toTypedArray()) }
            d.setTransactionSuccessful()
        } finally { d.endTransaction() }
    }

    /**
     * Keeps [p] and returns the name it goes by ([StoreCap.name]). The first packet stored under an id goes by that id;
     * any other packet with that id is kept too, by its key. Nothing replaces anything: whoever sends junk, or a message
     * of their own, first under an id doesn't keep the real packet out of the store. Hold the messages lock.
     */
    private fun save(p: Packet, kind: StoreCap.Kind): String {
        var name = p.id
        if (index.containsKey(p.id)) {
            name = StoreCap.name(p, false)
            if (packetKey(p.id) == name) return p.id // this very packet is the one stored under its id
            if (index.containsKey(name)) return name
        }
        try {
            db?.insertWithOnConflict("p", null, ContentValues().apply {
                put("id", name); put("ts", p.ts); put("ttl", p.ttl); put("cipher", p.cipher)
            }, SQLiteDatabase.CONFLICT_IGNORE)
        } catch (e: android.database.sqlite.SQLiteException) { DebugTools.log("store: can't save a packet: $e"); return name } // a full disk must not end the app
        val e = StoreCap.Entry(name, p.ts, 18 + p.cipher.size, kind)
        index[name] = e; indexBytes += e.size
        if (kind == StoreCap.Kind.DOOR) { doorCount++; doorBytes += e.size }
        return name
    }

    /**
     * Called by the router while it holds its lock: a copy of a stored packet came with more hops left. The saved ttl
     * is raised too, or a restart would pass the packet on with the first copy's. Only the row of this very packet:
     * the one stored under its id may be another, and this one then goes by its key ([StoreCap.name]).
     */
    private fun onRaised(p: Packet) {
        try { db?.execSQL("UPDATE p SET ttl = ? WHERE (id = ? OR id = ?) AND ts = ? AND ttl < ? AND cipher = ?", arrayOf<Any>(p.ttl, p.id, MeshRouter.key(p), p.ts, p.ttl, p.cipher)) }
        catch (e: android.database.sqlite.SQLiteException) { DebugTools.log("store: can't raise a ttl: $e") }
    }

    /** Called by the router while it holds its lock: every transport only queues the packet. */
    private fun route(peer: String, p: Packet) {
        val lora = peer == LoraLink.PEER || peer == MeshCoreLink.PEER
        if (lora && synchronized(ids) { p.id in receiptIds }) return // receipts stay off LoRa, where airtime is scarce
        // For the relays and the radios: did this phone write this very packet, or did a link bring it? Its id alone
        // doesn't say: anyone can send another packet under the id of one of this phone's (MeshRouter.source).
        val from = if (lora || NostrLink.owns(peer)) router?.source(p) else null
        val own = from == "" && synchronized(ids) { p.id in mine || p.id in myReceipts }
        when {
            WifiLinks.owns(peer) -> wifi?.links?.send(peer, p)
            // Written on this phone (a message or a receipt): goes up first. "Sent" once a relay accepts it.
            NostrLink.owns(peer) -> { nostr?.send(p, mine = own, from = from ?: ""); return }
            // The radios send this phone's own packets first (LoraQueue).
            peer == LoraLink.PEER -> (this.lora ?: return).offer(p, own)
            peer == MeshCoreLink.PEER -> (meshcore ?: return).offer(p, own)
            else -> (sender ?: return)(peer, p)
        }
        if (lora && !(if (peer == LoraLink.PEER) Meshtastic.fits(p) else MeshCore.fits(p))) return // too long for the radio: not really sent
        markHandedOff(p.id)
    }

    /** One of my messages left this phone: to a phone, a radio or the internet relays ("Sent"). Saved, so it survives restarts. */
    private fun markHandedOff(id: String) {
        val list = synchronized(ids) { if (id in mine && handedOff.add(id)) handedOff.toList() else null } ?: return
        app?.getSharedPreferences("mesh", 0)?.edit()?.putString("handedOff", list.joinToString(","))?.apply()
        notifyUi()
    }

    /**
     * A packet seen for the first time: keep it, and show it if a saved group or the Public channel can read it and
     * its signature checks (or its sender's key isn't known yet: shown as not verified, checked when it comes).
     */
    private fun onDeliver(p: Packet) {
        var incoming: Message? = null; var receiptKey: Keys? = null; var newEpoch = false
        synchronized(messages) {
            when (val x = see(p)) {
                is Seen.Intro -> {
                    save(p, if (x.k.isPublic) StoreCap.Kind.PUBLIC else doorKind(x.k, x.id, true)) // through a group's door: the group's own only from someone in it
                    val fresh = learn(x.k, x.id, x.pub, x.key, x.enc, x.name, x.ts, x.pq)
                    if (fresh) DebugTools.log("introduction ${p.id}: a new member key")
                    resolve(x.k, x.id)
                    // Not in the current epoch: a request to join. It waits for an admin here to let them in.
                    val k = x.k
                    // At most one alert a minute in a group: the requests themselves are in the chat ([joinRequests]).
                    val at = System.currentTimeMillis()
                    if (fresh && !k.isPublic && !k.removed && x.id != k.me && x.id !in k.members && k.me in (k.ring.currentOrNull()?.admins ?: emptyList()) && x.id !in declined(k)
                        && Joining.alertDue(joinAlertAt[k.id] ?: 0L, at)) {
                        joinAlertAt[k.id] = at
                        main.post { onIncoming?.invoke(Message("join-${x.id}", System.currentTimeMillis(), x.id, x.name, "asks to join", group = k.code)) }
                    }
                }
                is Seen.NewKey -> {
                    val ok = signed(x); val was = x.k.ring.currentOrNull()
                    if (acceptRekey(x)) {
                        newEpoch = true
                        // Our introduction again, at once: the newcomers need our keys to check our messages.
                        app?.getSharedPreferences("mesh", 0)?.edit()?.remove("introAt.${x.k.id}")?.apply()
                    }
                    val k = x.k
                    // Classed once the keyring has decided: the key that lets this phone in is from someone in the group it now knows.
                    save(p, doorKind(k, x.o.message.sender, ok))
                    // Made after our current epoch, yet numbered below it: that phone missed our keys. Answered after 0-3 s unless another member did.
                    if (x.door === k.door && ok && k.ring.behind(x.r, x.o.message.sender))
                        main.postDelayed({ io.execute { answerBehind(k, x.r.made, was) } }, rnd.nextInt(3_000).toLong())
                    if (k.ring.stillToRemove().isNotEmpty()) main.postDelayed({ io.execute { finishRemovals(k) } }, rnd.nextInt(3_000).toLong())
                }
                is Seen.Msg -> {
                    val ok = check(x.k, x.o)
                    if (ok == false) { save(p, StoreCap.Kind.UNREADABLE); DebugTools.log("dropped ${p.id}: signature doesn't check") }
                    // Another packet under an id that is taken, which only brings again a message already shown, or names this
                    // phone as its sender (the same message sealed again): nothing to keep or show.
                    else if (index.containsKey(p.id) && (shownAs.containsKey(x.o.mark) || x.m.sender == deviceId)) DebugTools.log("${p.id} again: already shown")
                    else {
                        // Any other packet under an id that is taken is a message of its own: kept and shown by its name ([StoreCap.name]).
                        val name = save(p, if (x.m.public) StoreCap.Kind.PUBLIC else StoreCap.Kind.GROUP)
                        val m = (if (ok == true) x.m else x.m.copy(verified = false)).let { if (name == p.id) it else it.copy(id = name) }
                        remember(name, x.k, x.o)
                        if (ok == true && x.o.leaf != null) { x.o.leaf?.forget(); saveMessageKeys(x.k) } // this message's key is gone: only this phone's copy can show it now
                        val fresh = messageIds.add(m.id)
                        if (fresh) { messages.add(messages.indexOfLast { it.ts <= m.ts } + 1, m); shownAs[x.o.mark] = m.id } // oldest first
                        // It waits for its sender's key only as the message shown under its id: another packet with that id, checked later, must not mark or remove this row.
                        if (ok == null) unchecked.message(x.o.key, x.k, x.o.message.sender, m.id, fresh, Pending(x.k, x.o, null))
                        if (fresh && !m.public && m.sender == deviceId) deliveries.sent(x.k.id, m.id) // written here before the store was lost: its receipts count again
                        DebugTools.log("received ${p.id} ${if (m.public) "public" else "group"} photo=${m.photo?.size ?: 0} verified=${m.verified}")
                        // Not for a message already shown: another packet under its id, sealed again by a member, alerts and confirms nothing.
                        if (fresh && !m.public && m.sender != deviceId) { incoming = m; receiptKey = x.k }
                        if (x.k.rejoining && m.sender != deviceId && m.ts >= x.k.rejoiningSince) setRejoining(x.k, 0) // someone wrote in a key this phone has: it's back
                    }
                }
                is Seen.Receipt -> {
                    save(p, StoreCap.Kind.GROUP)
                    synchronized(ids) { receiptIds.add(p.id) }
                    when (check(x.k, x.o)) {
                        true -> {
                            deliveries.add(x.k.id, x.r)
                            val confirmed = Receipt.ids(x.r.text); val mineNow = synchronized(ids) { confirmed.count { it in mine } }
                            DebugTools.log("receipt ${p.id} confirms ${confirmed.size} message(s), $mineNow of mine")
                        }
                        null -> unchecked.receipt(x.o.key, x.k, x.o.message.sender, Pending(x.k, x.o, x.r))
                        false -> DebugTools.log("dropped receipt ${p.id}: signature doesn't check")
                    }
                }
                else -> save(p, StoreCap.Kind.UNREADABLE)
            }
        }
        incoming?.let { m ->
            val key = receiptKey
            main.post { if (key != null) ack(p.id, key); onIncoming?.invoke(m) } // alerts for every saved group; confirmed by its packet id, whatever name it goes by here
        }
        // A new epoch: messages stored before it came may open now; relays follow its mailbox; we introduce ourselves.
        if (newEpoch && rescanQueued.compareAndSet(false, true)) io.execute {
            rescanQueued.set(false)
            scan().let { l -> synchronized(messages) { apply(l) } }
            nostr?.resubscribe()
            (listOfNotNull(active) + others).forEach(::introIfDue)
            notifyUi()
        }
        compactIfFull()
        notifyUi()
    }

    private fun keysOf(code: String?): Keys? = active?.takeIf { it.code == code } ?: others.firstOrNull { it.code == code }

    /**
     * What [p] is: tried with this group's keys, then the Public channel's (photos are group-only: dropped; others'
     * words filtered), then the other saved groups'. [Message.group] says which group. Nothing is checked yet, except
     * introductions, which carry their own key.
     */
    private fun see(p: Packet): Seen? {
        val box = Packet.mailbox(p.id) // every key has one mailbox: junk costs one try, not one per key this phone holds
        for (k in listOfNotNull(active, publicKeys) + others) {
            for (e in k.ring.all()) {
                if (e.group.mailbox != box) continue
                e.open(p)?.let { o -> return message(k, o) }
                e.openReceipt(p)?.let { o -> return asMine(o.message, k.me)?.let { r -> Seen.Receipt(r, k, o) } ?: Seen.Forged }
            }
            // Only the Public channel reads through its door: in a group the code alone doesn't let anyone write.
            if (k.isPublic && k.door.crypto.mailbox == box) k.door.crypto.openSigned(p)?.let { o -> return message(k, o) }
            if (k.intros.mailbox == box) k.intros.openSigned(p)?.let { o -> return introduction(k, o) ?: Seen.Forged }
            if (!k.isPublic) for (d in listOf(k.door) + k.oldDoors) if (d.rekeys.mailbox == box) d.rekeys.openSigned(p)?.let { o -> // old doors: for removals that crossed
                val r = o.extra?.let(Rekey::decode) ?: return Seen.Forged
                return Seen.NewKey(k, o, r, p.id, d)
            }
        }
        return null
    }

    private fun message(k: Keys, o: GroupCrypto.Opened): Seen {
        val m = asMine(o.message, k.me) ?: return Seen.Forged // a sender that is no member id: like a packet nobody can open
        return Seen.Msg(if (k.isPublic) filtered(m.copy(public = true, photo = null)) else m.copy(group = k.code), k, o)
    }

    private val historyKey: ByteArray? by lazy {
        val c = app ?: return@lazy null
        Vault.get(c, "history") ?: ByteArray(32).also(rnd::nextBytes).also { Vault.put(c, "history", it) }
    }

    /** Keeps a readable copy of a message opened with its own key: that key is about to be deleted. */
    private fun remember(id: String, k: Keys, o: GroupCrypto.Opened) {
        val leaf = o.leaf ?: return; val key = historyKey ?: return
        runCatching { db?.insertWithOnConflict("h", null, ContentValues().apply { put("id", id); put("data", History.seal(key, id, k.id, leaf.epoch.id, o, leaf.index, leaf.counter)) }, SQLiteDatabase.CONFLICT_IGNORE) }
    }

    /** A message from this phone's copy, while its epoch is still held: when the epoch goes, the message goes too. */
    private fun fromHistory(id: String, blob: ByteArray): Seen.Msg? {
        val s = History.open(historyKey ?: return null, id, blob) ?: return null
        val k = (listOfNotNull(active) + others).firstOrNull { it.id == s.group } ?: return null
        val e = k.ring.all().let { all -> all.firstOrNull { it.id == s.epoch } ?: all.firstOrNull { it.hash == s.epoch } } ?: return null // by hash: copies kept before epochs had an id
        s.opened.leaf = Leaf(e, s.index, s.counter)
        return Seen.Msg((asMine(s.opened.message, k.me) ?: return null).copy(group = k.code), k, s.opened, fromHistory = true)
    }

    private fun GroupCrypto.packet(id: String, ts: Long, cipher: ByteArray) = Packet(id, hideTime(ts, cipher), MAX_TTL, cipher)

    /** A valid introduction: the 4th field is 0x02 and a public key whose hash starts with the sender's id, and it signed it. */
    private fun introduction(k: Keys, o: GroupCrypto.Opened): Seen.Intro? {
        val e = o.extra ?: return null
        val withPq = e.size == 99 + MlKem.PUBLIC_SIZE && e[0] == 3.toByte() // 0x03, signing key (33), encryption key (65), ML-KEM key (1184)
        if (!withPq && (!k.isPublic || e.size != 99 || e[0] != 2.toByte())) return null // 0x02, without the ML-KEM key: the Public channel only
        if (withPq && MlKem.encapsulate(e.copyOfRange(99, e.size)) == null) return null  // a key nobody could seal to would block every new key
        val pub = e.copyOfRange(1, 34); val enc = e.copyOfRange(34, 99); val id = o.message.sender
        if (P256.memberId(pub) != id || P256.fromUncompressed(enc) == null || o.message.name.toByteArray().size > MAX_NAME_BYTES) return null
        val key = P256.decompress(pub) ?: return null
        return if (P256.verify(key, o.digest, o.signature)) Seen.Intro(k, id, pub, key, enc, o.message.name, o.message.ts, if (withPq) e.copyOfRange(99, e.size) else null) else null
    }

    /**
     * On this phone, its own messages carry [deviceId] as sender: one id for "me" in every group. Null for a packet whose
     * sender is no member id, or is [deviceId] itself ([Senders.shown]): nothing received may pass for written here.
     */
    private fun asMine(m: Message, me: String): Message? = Senders.shown(m.sender, me, deviceId)?.let { if (it == m.sender) m else m.copy(sender = it) }

    /** Someone else's Everyone message or place with offensive words masked (WordFilter); mine as written. */
    private fun filtered(m: Message) = if (m.sender == deviceId) m else m.copy(name = WordFilter.clean(m.name), text = WordFilter.clean(m.text))

    /**
     * Confirms a group message in the next receipt, with that group's key. Messages arriving less than 2 s apart share
     * one receipt, for at most 10 s (ReceiptBatch). Main thread.
     */
    private fun ack(id: String, key: Keys) {
        val now = SystemClock.uptimeMillis()
        if (pendingAcks.isEmpty()) { firstAck = now; main.postDelayed(::ackTimer, ReceiptBatch.QUIET_MS) }
        lastAck = now
        pendingAcks += id to key
    }

    private fun ackTimer() {
        if (pendingAcks.isEmpty()) return
        val now = SystemClock.uptimeMillis()
        if (ReceiptBatch.due(firstAck, lastAck, now)) main.postDelayed(::flushAcks, rnd.nextInt(ACK_SPREAD_MS).toLong()) // a receipt doesn't show how soon this phone got the message
        else main.postDelayed(::ackTimer, maxOf(10L, minOf(lastAck + ReceiptBatch.QUIET_MS, firstAck + ReceiptBatch.MAX_WAIT_MS) - now))
    }

    private fun flushAcks() {
        val r = router ?: return
        val batch = pendingAcks.toList(); pendingAcks.clear()
        for ((k, msgIds) in batch.groupBy({ it.second }, { it.first })) for (b in Receipt.batches(msgIds)) {
            val rc = k.receipts
            val id = Packet.newId(rc.mailbox); val ts = System.currentTimeMillis()
            val p = rc.packet(id, ts, rc.seal(id, ts, k.me, name, Receipt.text(b)) { k.sign(it) })
            synchronized(ids) { receiptIds.add(id); myReceipts += id }
            synchronized(messages) { save(p, StoreCap.Kind.GROUP) }
            r.publish(p)
        }
    }

    /**
     * Returns false if the message is too long for a LoRa packet. [public]: send on the Public channel. [photo]: small
     * JPEG. [group]: the code of the saved group to send to (an answer from a notification); the group on screen if null.
     */
    fun send(text: String, public: Boolean = false, photo: ByteArray? = null, group: String? = null): Boolean =
        post(false, name, text, public, photo, group)

    /**
     * A Public message typed on the Wi-Fi board by someone without the app (WifiBoard.kt): someone else's, not mine.
     * In the mesh it is a packet this phone passes on: it takes no turn of this phone's own packets on the relays, and
     * all board posts together count as one link's share of the packets kept for passing on ([BOARD]).
     */
    fun sendFromBoard(who: String, text: String) { post(true, "$who (Wi-Fi board)", text, public = true) }

    /** What the router counts Wi-Fi board posts under: no link has this name. */
    const val BOARD = "board"

    private fun post(board: Boolean, from: String, text: String, public: Boolean, photo: ByteArray? = null, to: String? = null): Boolean {
        val r = router ?: return true
        val ts = System.currentTimeMillis()
        val p: Packet; val id: String
        // The group on screen (or [to]); right after switching to a new group its key may still be on its way: derive it here.
        val code = to ?: activeCode
        val group = if (public) null else active?.takeIf { it.code == code } ?: others.firstOrNull { it.code == code } ?: keys(code)
        val k = (if (public) publicKeys else group) ?: return true
        if (!public && k.removed) return true // the screen no longer offers this
        if (!public && !k.joined) { synchronized(waiting) { waiting.getOrPut(k.id) { ArrayList() } += Waiting(from, text, photo) }; return true } // sent once an admin lets this phone in
        introIfDue(k, writing = true) // members can check this message only with this phone's key
        synchronized(messages) {
            val cr = k.group
            id = Packet.newId(cr.mailbox)
            val wire = if (board) "web-${k.me}" else k.me // member ids (spec "Member ids")
            p = cr.packet(id, ts, sealOne(k, cr, public, id, ts, wire, from, text, photo))
            save(p, if (public) StoreCap.Kind.PUBLIC else StoreCap.Kind.GROUP)
            val m = Message(id, ts, if (board) wire else deviceId, from, text, public, if (public) null else photo, if (public) null else group?.code)
            messages += if (public) filtered(m) else m; messageIds += id // Wi-Fi board posts are someone else's
            if (!public) deliveries.sent(k.id, id) // only this group's receipts confirm it
        }
        if (!board) synchronized(ids) { mine += id } // a board post is someone else's: on the relays it waits its turn like any packet passed on
        r.publish(p, if (board) BOARD else ""); notifyUi()
        return Meshtastic.fits(p)
    }

    /** A group message goes under its own key, deleted here at once: from then on only this phone's copy can show it (spec "Message keys"). */
    private fun sealOne(k: Keys, cr: GroupCrypto, public: Boolean, id: String, ts: Long, wire: String, from: String, text: String, photo: ByteArray?): ByteArray {
        val e = if (public) null else k.ring.currentOrNull(); val keys = e?.messageKeys
        val i = keys?.index(k.me) ?: -1; val n = if (i >= 0) keys?.takeNext() else null; val mk = if (n != null) keys?.key(i, n) else null
        if (e == null || keys == null || n == null || mk == null) return cr.seal(id, ts, wire, from, text, if (public) null else photo) { k.sign(it) }
        val c = cr.sealWith(mk, i, n, id, ts, wire, from, text, photo) { k.sign(it) }
        cr.openWith(mk, i, n, Packet(id, ts, 0, c), at = ts)?.let { o -> o.leaf = Leaf(e, i, n); remember(id, k, o) }
        keys.forget(i, n)
        saveMessageKeys(k)
        return c
    }

    /** This group's messages and the Public channel's, oldest first. */
    fun snapshot(): List<Message> { val code = activeCode; return synchronized(messages) { messages.filter { it.public || it.group == code } } }

    /** Every saved group's messages and the Public channel's, oldest first; [Message.group] tells which group. */
    fun snapshotAll(): List<Message> = synchronized(messages) { messages.toList() }

    /** "Battery saver" (Connections): slower Bluetooth search, Nearby search in bursts, fewer relay pings. Remembered. */
    fun batterySaver(c: Context) = c.getSharedPreferences("mesh", 0).getBoolean("batterySaver", false)
    fun setBatterySaver(on: Boolean) {
        val c = app ?: return
        c.getSharedPreferences("mesh", 0).edit().putBoolean("batterySaver", on).apply()
        ble?.setSaver(on)
        if (nostr != null) setInternet(true) // relinks with the new ping interval
        notifyUi()
    }

    /** Stops every link without changing any setting, before the process ends ("Stop GoDark"). */
    fun shutdown() {
        flushAcks()
        nostr?.stop(); nostr = null
        wifi?.stop(); wifi = null
        app?.let { Tor.stop(it) }
    }

    /** Distinct node ids of the phones linked directly right now (Nearby, Bluetooth LE, Wi-Fi network): each phone once. */
    fun linkedNodes(): Set<String> = nearbyNodes() + (ble?.nodes() ?: emptySet()) + (wifi?.links?.nodes() ?: emptySet())

    /** null for other people's messages, and for my older ones that haven't gone out yet. */
    fun delivery(m: Message): Delivery? {
        if (m.sender != deviceId) return null
        if (!m.public) synchronized(messages) { deliveries.readers(m.id) }.takeIf { it.isNotEmpty() }?.let { return Delivery.Delivered(it) }
        if (synchronized(ids) { m.id in handedOff }) return Delivery.Sent
        return if (m.ts >= startedAt) Delivery.Waiting else null
    }

    fun notifyUi() = main.post { listener?.invoke() }
}
