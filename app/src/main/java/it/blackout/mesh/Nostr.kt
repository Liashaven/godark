package it.blackout.mesh

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/**
 * GoDark packets as Nostr events on public relays (spec/FORMAT.md, "Internet relays"). Pure functions, so unit
 * tests run; [NostrLink] does the WebSockets. Each phone signs with a throwaway key made at every start.
 */
object Nostr {
    const val KIND = 3871  // a regular (stored) kind no one else uses (relay survey, 2026-11); see spec
    const val TAG_PREFIX = "dp1-"
    const val KEEP_S = 7 * 24 * 3600L    // relays may delete events after 7 days (NIP-40 expiration)

    fun tag(mailbox: Int) = TAG_PREFIX + "%04x".format(mailbox and 0xFFFF)

    /** NIP-01 string escaping, for computing event ids exactly as relays do. */
    fun quote(s: String): String = buildString {
        append('"')
        for (ch in s) when (ch) {
            '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n"); '\r' -> append("\\r")
            '\t' -> append("\\t"); '\b' -> append("\\b"); '\u000C' -> append("\\f")
            else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
        }
        append('"')
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** The event id: SHA-256 of [0, pubkey, created_at, kind, tags, content] serialized as NIP-01 says. */
    fun eventId(pubkey: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): String {
        val t = tags.joinToString(",", "[", "]") { tag -> tag.joinToString(",", "[", "]") { quote(it) } }
        val ser = "[0,${quote(pubkey)},$createdAt,$kind,$t,${quote(content)}]"
        return hex(MessageDigest.getInstance("SHA-256").digest(ser.toByteArray(Charsets.UTF_8)))
    }

    /** A signed event carrying one packet in the packet's mailbox, findable by packet id, kept by relays for 7 days. */
    fun event(p: Packet, secret: ByteArray, now: Long = System.currentTimeMillis() / 1000, aux: ByteArray? = null): JSONObject {
        val pub = hex(Schnorr.publicKey(secret))
        val tags = listOf(listOf("t", tag(Packet.mailbox(p.id))), listOf("x", p.id), listOf("expiration", (now + KEEP_S).toString()))
        val content = Base64.getEncoder().encodeToString(p.encode())
        val id = eventId(pub, now, KIND, tags, content)
        val sig = if (aux == null) Schnorr.sign(secret, unhex(id)) else Schnorr.sign(secret, unhex(id), aux)
        return JSONObject().put("id", id).put("pubkey", pub).put("created_at", now).put("kind", KIND)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", content).put("sig", hex(sig))
    }

    fun publish(event: JSONObject) = JSONArray().put("EVENT").put(event).toString()

    /** The Public channel's mailbox (spec/FORMAT.md, "Mailboxes"): worldwide, so it is caught up one page only. */
    const val PUBLIC_MAILBOX = 0x9576
    const val PAGE = 500                 // events per catch-up REQ
    const val MAX_PAGES = 4              // pages per group mailbox and relay link
    const val SINCE_MARGIN_S = 1_500L    // catch-up starts 25 min before the last time seen: events are dated up to 17 min back, and clocks differ
    /** An event's date: the current time, rounded down to about 17 minutes, so stored events don't give away when they were sent. */
    fun blurred(now: Long) = now - now % 1024
    const val RELAY_PER_MINUTE = 6_000   // messages taken from one relay link in a minute (100 a second)

    /**
     * New events for all these mailboxes, as they arrive. `since` 7 days back so events from phones with a slow clock
     * still match; `limit` 1 because stored events come from the catch-up REQs.
     */
    fun live(subId: String, mailboxes: Collection<Int>, now: Long = System.currentTimeMillis() / 1000): String =
        JSONArray().put("REQ").put(subId).put(JSONObject().put("kinds", JSONArray().put(KIND))
            .put("#t", JSONArray(mailboxes.map(::tag))).put("since", now - KEEP_S).put("limit", 1)).toString()

    /** One catch-up page of one mailbox: the newest [PAGE] events since [since], and not newer than [until] if set. */
    fun catchUp(subId: String, mailbox: Int, since: Long, until: Long?): String {
        val f = JSONObject().put("kinds", JSONArray().put(KIND)).put("#t", JSONArray().put(tag(mailbox))).put("since", since)
        if (until != null) f.put("until", until)
        return JSONArray().put("REQ").put(subId).put(f.put("limit", PAGE)).toString()
    }

    /** Asks which of these packets the relay already has (by the "x" tag), before passing them on. */
    fun have(subId: String, packetIds: Collection<String>): String =
        JSONArray().put("REQ").put(subId).put(JSONObject().put("kinds", JSONArray().put(KIND))
            .put("#x", JSONArray(packetIds)).put("limit", packetIds.size)).toString()

    fun close(subId: String) = JSONArray().put("CLOSE").put(subId).toString()

    private val random = java.security.SecureRandom()
    /**
     * A subscription id: [prefix], then 8 random bytes in hex, new for each link set and each use (spec/FORMAT.md,
     * "Subscribe"). Nothing in it comes from this phone's clock or is shared with its other link sets, so a relay
     * can't use it to tell that the links of two groups belong to one phone.
     */
    fun subId(prefix: String): String = prefix + hex(ByteArray(8).also(random::nextBytes))

    /**
     * The link set a packet goes up on (spec/FORMAT.md, "One set of links per group"): its group's only if this phone
     * wrote it ([mine]: a message, receipt, introduction or new key); everything it only passes on goes up with the
     * Public channel's (""). The mailbox in a packet id is whatever its sender chose, so for anyone else's packet it
     * must never pick a group's links and key: a neighbour could then see, from the key a junk packet came back under,
     * which mailboxes this phone holds. [boxes]: scope id -> its mailboxes.
     */
    fun scope(packetId: String, mine: Boolean, boxes: Map<String, List<Int>>): String {
        if (!mine) return ""
        val box = Packet.mailbox(packetId)
        return boxes.entries.firstOrNull { it.key.isNotEmpty() && box in it.value }?.key ?: ""
    }

    /**
     * True if a link set takes a packet a relay sent on it (spec/FORMAT.md, "Mailboxes of a link"): only a packet of
     * one of its own [mailboxes], or the answer to its `#x` lookup in flight ([asked]: the packet ids it named). A
     * relay chooses what it sends on a link; anything else it sends there is dropped, so it can't plant a packet on
     * one group's link that this phone would later name on another.
     */
    fun takes(p: Packet, mailboxes: Collection<Int>, asked: Collection<String>): Boolean = Packet.mailbox(p.id) in mailboxes || p.id in asked

    /** A relay's answer to an event: ["OK", event id, accepted, message]. "duplicate:" refusals count as accepted. */
    class Ok(val eventId: String, val accepted: Boolean, val reason: String)
    fun ok(text: String): Ok? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) != "OK" || a.length() < 3) return null
        val why = a.optString(3)
        Ok(a.getString(1), a.getBoolean(2) || why.lowercase().startsWith("duplicate"), why)
    }.getOrNull()

    /** The end of a subscription's stored events: ["EOSE", id] ([complete]) or ["CLOSED", id, reason] (not complete). */
    class End(val subId: String, val complete: Boolean)
    fun end(text: String): End? = runCatching {
        val a = JSONArray(text)
        when (a.getString(0)) { "EOSE" -> End(a.getString(1), true); "CLOSED" -> End(a.getString(1), false); else -> null }
    }.getOrNull()

    /**
     * What makes two copies of a packet the same packet on the relays: its timestamp and cipher (ttl changes on every
     * hop). First 16 bytes of SHA-256(ts as 8 bytes big-endian ‖ cipher), in hex.
     */
    fun digest(p: Packet): String = hex(MessageDigest.getInstance("SHA-256").run {
        update(java.nio.ByteBuffer.allocate(8).putLong(p.ts).array()); digest(p.cipher)
    }.copyOf(16))

    /** The reason, if this is a relay refusing an event (["OK", id, false, reason]); else null. */
    fun refusal(text: String): String? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) == "OK" && !a.getBoolean(2)) a.optString(3) else null
    }.getOrNull()

    /** A refusal that means "slow down": NIP-01's "rate-limited:" and "blocked:", and what relays really say
     *  ("rate limited", "banned: too many rate-limit violations"). */
    fun isThrottle(reason: String) = reason.lowercase().let { r -> listOf("rate", "banned", "blocked").any { r.startsWith(it) } }

    /** A NIP-56 report of the event that carried a Public message (kind 1984, type "spam"/"other"…). */
    fun report(eventId: String, eventPubkey: String, secret: ByteArray, now: Long = System.currentTimeMillis() / 1000): JSONObject {
        val pub = hex(Schnorr.publicKey(secret))
        val tags = listOf(listOf("e", eventId, "other"), listOf("p", eventPubkey))
        val id = eventId(pub, now, 1984, tags, "")
        return JSONObject().put("id", id).put("pubkey", pub).put("created_at", now).put("kind", 1984)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", "").put("sig", hex(Schnorr.sign(secret, unhex(id))))
    }

    /**
     * The event that carried a Public packet, as a report names it. Its id is the hash of its own fields, so the id
     * stands for this author, kind and content; whether the author really signed it is checked when a report is made
     * ([signed]), not for every event that arrives.
     */
    class Subject(val eventId: String, val pubkey: String, val sig: String)

    /**
     * What a relay sent: a GoDark packet (with the event id and author; its time and subscription, for catching
     * up), or null for anything else, also for an event whose id or author isn't 32 bytes of lowercase hex.
     * [reaches]: the event is one the packet's recipients get, so the packet may count as on the relays.
     * [subject]: what a report of this packet may name, if the event is fit for that.
     */
    class Received(val packet: Packet, val eventId: String, val pubkey: String, val createdAt: Long = 0, val subId: String = "",
                   val reaches: Boolean = false, val subject: Subject? = null)
    fun received(text: String): Received? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) != "EVENT" || a.length() < 3) return null
        val e = a.getJSONObject(2)
        if (e.getInt("kind") != KIND) return null
        val raw = Base64.getDecoder().decode(e.getString("content"))
        val p = Packet.decode(raw) ?: return null
        val created = e.optLong("created_at")
        if (created < 0) return null // no event is from before 1970: a hostile relay
        // Kept for reports: a relay can make them as long as a whole message, and a real id or key is never longer.
        val id = e.opt("id") as? String ?: return null; val pub = e.opt("pubkey") as? String ?: return null
        if (!isHex(id, 32) || !isHex(pub, 32)) return null
        val tags = tagsOf(e)
        Received(p, id, pub, created, a.getString(1), tags != null && reaches(tags, p, created),
            if (tags == null) null else subject(e, tags, p, id, pub, created))
    }.getOrNull()

    /**
     * The subscription and date of any event a relay sent, whatever it carries; null for other messages. A catch-up
     * counts every event of a page ([CatchUp.frame]): anyone can post events that carry no packet under a mailbox's tag.
     */
    class Dated(val subId: String, val createdAt: Long)
    fun dated(text: String): Dated? = runCatching {
        val a = JSONArray(text)
        if (a.getString(0) != "EVENT" || a.length() < 3) return null
        Dated(a.getString(1), a.getJSONObject(2).optLong("created_at"))
    }.getOrNull()

    /** [bytes] bytes of lowercase hex, as NIP-01 writes ids, keys and signatures. */
    private fun isHex(s: String, bytes: Int) = s.length == bytes * 2 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** An event's tags, or null if they aren't lists of strings (no real event has anything else). */
    private fun tagsOf(e: JSONObject): List<List<String>>? {
        val all = e.optJSONArray("tags") ?: return null
        return (0 until all.length()).map { i ->
            val t = all.optJSONArray(i) ?: return null
            (0 until t.length()).map { j -> t.opt(j) as? String ?: return null }
        }
    }

    /**
     * True if subscribers of the packet's mailbox get this event (spec/FORMAT.md, "Publish"): it carries their tag, no
     * relay may delete it before the 7 days are over, and it isn't dated before the packet (a catch-up asks by date).
     * A copy in any other event must not stop this phone from posting the packet.
     */
    private fun reaches(tags: List<List<String>>, p: Packet, created: Long): Boolean {
        val box = tag(Packet.mailbox(p.id))
        if (tags.none { it.size >= 2 && it[0] == "t" && it[1] == box }) return false
        val kept = if (created > Long.MAX_VALUE - KEEP_S) Long.MAX_VALUE else created + KEEP_S
        if (tags.any { it.isNotEmpty() && it[0] == "expiration" && (it.getOrNull(1)?.toLongOrNull() ?: 0L) < kept }) return false
        return created >= p.ts / 1000 - SINCE_MARGIN_S
    }

    /** What a report of [p] may name: only for the Public channel's mailbox, and only if [id] is the hash of the event's own fields. */
    private fun subject(e: JSONObject, tags: List<List<String>>, p: Packet, id: String, pub: String, created: Long): Subject? {
        if (Packet.mailbox(p.id) != PUBLIC_MAILBOX) return null // only Public messages are reported
        val sig = e.opt("sig") as? String ?: return null
        if (!isHex(sig, 64) || eventId(pub, created, KIND, tags, e.getString("content")) != id) return null
        return Subject(id, pub, sig)
    }

    /** True if [s]'s author signed it (BIP-340). With the id being the hash of the event's fields, the event is then really theirs. */
    fun signed(s: Subject): Boolean = isHex(s.eventId, 32) && isHex(s.pubkey, 32) && isHex(s.sig, 64) &&
        runCatching { Schnorr.verify(unhex(s.pubkey), unhex(s.eventId), unhex(s.sig)) }.getOrDefault(false)
}

/**
 * Which relay event a report of a Public message names (spec/FORMAT.md, "Reports"). A relay, and whoever posts to it,
 * chooses everything an EVENT frame says, so: only events whose id is the hash of their own fields are kept
 * ([Nostr.Subject]); they are kept under the very packet they carried ([MeshRouter.key]), so an event with another
 * packet under the same packet id never stands in for it; each relay's first event for a packet stays, so no relay
 * replaces what another sent; and the one named is the first whose signature checks. Thread-safe. Same as the iPhone's.
 */
class ReportSubjects(private val max: Int = MAX) {
    companion object { const val MAX = 2_000; const val PER_PACKET = 8 }
    private class Seen(val relay: String, val s: Nostr.Subject) { var checked = false }
    private val ids = HashMap<String, Int>() // packet id -> packets kept under it
    private val byPacket = object : LinkedHashMap<String, ArrayList<Seen>>() { // MeshRouter.key -> each relay's first event, oldest packet first
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, ArrayList<Seen>>?): Boolean {
            if (size <= max) return false
            e?.let { gone(it.key) }
            return true
        }
    }
    private fun gone(key: String) { val id = key.substringBefore(':'); val n = (ids[id] ?: 1) - 1; if (n > 0) ids[id] = n else ids.remove(id) }

    /** [relay] sent the event [r]. */
    @Synchronized fun note(relay: String, r: Nostr.Received) {
        val s = r.subject ?: return
        val k = MeshRouter.key(r.packet)
        val list = byPacket[k] ?: ArrayList<Seen>().also { ids[r.packet.id] = (ids[r.packet.id] ?: 0) + 1; byPacket[k] = it }
        if (list.size < PER_PACKET && list.none { it.relay == relay || (it.s.eventId == s.eventId && it.s.pubkey == s.pubkey && it.s.sig == s.sig) }) list += Seen(relay, s)
    }

    /** True if some relay event carried a packet with this id: only then is it worth finding out which packet the phone shows. */
    @Synchronized fun knows(packetId: String) = packetId in ids

    /** The event a report of exactly this packet ([MeshRouter.key]) names: the first one kept whose signature checks. Null: the report waits. */
    @Synchronized fun of(packetKey: String): Nostr.Subject? {
        val list = byPacket[packetKey] ?: return null
        while (list.isNotEmpty()) {
            val c = list[0]
            if (c.checked || Nostr.signed(c.s)) { c.checked = true; return c.s }
            list.removeAt(0) // not its author's: a relay made it up
        }
        byPacket.remove(packetKey); gone(packetKey)
        return null
    }

    @Synchronized fun size() = byPacket.size
}

/**
 * Reads WebSocket frame headers as they arrive, and fails as soon as a message would be longer than [max], before its
 * bytes are kept. OkHttp puts a message together in memory however long it is, so one relay could send a message that
 * ends the app (the iPhone's URLSession has maximumMessageSize). A frame of an extension (compression) fails too: what
 * it counts is the bytes as sent. For one reader at a time.
 */
class WsFrameGuard(private val max: Long = MAX) {
    companion object {
        const val MAX = 1L shl 20
        private const val MAX_HTTP = 512 * 1024 // OkHttp itself takes 256 KiB of headers: past this, the frames below were never reached
        private const val AT_START = 0; private const val AFTER_CR = 1; private const val IN_LINE = 2
    }
    private var upgraded = false
    private var httpBytes = 0; private var line = AT_START; private var firstLine = true; private val status = StringBuilder()
    private val head = ByteArray(14); private var have = 0
    private var skip = 0L; private var message = 0L; private var endsMessage = false

    /**
     * The HTTP answer, whose lines end with LF or CRLF as OkHttp reads them. Anything but 101 ends the link: a relay has
     * no reason to send 100 or 103 first, and two of those make OkHttp 4.12 throw on a thread where it ends the app.
     */
    private fun http(x: Int) {
        if (++httpBytes > MAX_HTTP) throw java.io.IOException("relay's HTTP answer is too long")
        if (firstLine && status.length < 16 && x != '\r'.code && x != '\n'.code) status.append(x.toChar())
        when {
            x == '\n'.code && line != IN_LINE -> { // an empty line: the end of the answer
                val s = status.toString()
                val code = if (s.startsWith("HTTP/1.") && s.length >= 12) s.substring(9, 12) else if (s.startsWith("ICY ") && s.length >= 7) s.substring(4, 7) else ""
                if (code != "101") throw java.io.IOException("relay didn't upgrade the link")
                upgraded = true
            }
            x == '\n'.code -> { line = AT_START; firstLine = false }
            x == '\r'.code && line == AT_START -> line = AFTER_CR
            else -> line = IN_LINE
        }
    }

    fun look(b: ByteArray, off: Int, n: Int) {
        var i = off; val end = off + n
        while (i < end) {
            if (!upgraded) { http(b[i++].toInt() and 0xFF); continue }
            if (skip > 0) {
                val s = minOf(skip, (end - i).toLong()); i += s.toInt(); skip -= s
                if (skip == 0L && endsMessage) message = 0
                continue
            }
            head[have++] = b[i++]
            if (have >= 2 && have == needed()) frame()
        }
    }

    private fun needed(): Int = 2 + (when (head[1].toInt() and 0x7F) { 126 -> 2; 127 -> 8; else -> 0 }) + (if (head[1].toInt() and 0x80 != 0) 4 else 0)

    private fun frame() {
        // No extension is ever agreed on a relay link, so the reserved bits must be 0 (RFC 6455, 5.2). RSV1 marks a
        // compressed message: its length here says nothing about what it inflates to, so the link ends before it is read.
        if ((head[0].toInt() and 0x70) != 0) throw java.io.IOException("relay frame uses an extension that was not agreed")
        val len7 = head[1].toInt() and 0x7F
        val len = when (len7) {
            126 -> ((head[2].toLong() and 0xFF) shl 8) or (head[3].toLong() and 0xFF)
            127 -> (0 until 8).fold(0L) { v, k -> (v shl 8) or (head[2 + k].toLong() and 0xFF) }
            else -> len7.toLong()
        }
        if (len < 0) throw java.io.IOException("relay frame length is out of range")
        val data = (head[0].toInt() and 0x0F) < 8 // control frames can come in the middle of a message and aren't part of it
        if (data) {
            if (len > max - message) throw java.io.IOException("relay message is too long")
            message += len
        }
        endsMessage = data && (head[0].toInt() and 0x80) != 0
        have = 0; skip = len
        if (skip == 0L && endsMessage) message = 0
    }
}

/** Puts [WsFrameGuard] between the relay's socket and OkHttp: on the decrypted stream, so it can see the frames. And keeps compression off. */
object WsLimit {
    /**
     * No compression on relay links: a hostile relay could inflate a small message into hundreds of MB and end the app.
     * OkHttp 4.12 offers permessage-deflate by itself, and turns it on from the relay's answer alone, offered or not,
     * and then inflates with no limit. So the header goes out of the request and out of the answer: OkHttp never
     * learns of an extension, and fails a compressed frame by itself.
     */
    val noExtensions = okhttp3.Interceptor { c ->
        // An unchecked exception from what a relay answered would end the app on OkHttp's thread: it ends the link instead.
        try {
            c.proceed(c.request().newBuilder().removeHeader("Sec-WebSocket-Extensions").build())
                .newBuilder().removeHeader("Sec-WebSocket-Extensions").build()
        } catch (e: RuntimeException) { throw java.io.IOException("relay's answer broke the link", e) }
    }

    /**
     * Everything a relay link's client needs: [noExtensions] and the frame guard.
     * [plain]: ws://, only the mock relay of debug builds. There the guard goes on the plain socket, which with TLS would carry only encrypted bytes.
     */
    fun apply(b: okhttp3.OkHttpClient.Builder, plain: Boolean) {
        b.addInterceptor(noExtensions)
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as java.security.KeyStore?) }
        val tm = tmf.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().first() // the phone's own trust store, as OkHttp's default
        val tls = javax.net.ssl.SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }.socketFactory
        b.sslSocketFactory(GuardedTls(tls), tm)
        if (plain) b.socketFactory(GuardedPlain)
    }

    private class GuardedInput(s: java.io.InputStream) : java.io.FilterInputStream(s) {
        private val guard = WsFrameGuard()
        private val one = ByteArray(1)
        override fun read(): Int = if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
        override fun read(b: ByteArray, off: Int, len: Int): Int { val n = super.read(b, off, len); if (n > 0) guard.look(b, off, n); return n }
    }

    private object GuardedPlain : javax.net.SocketFactory() {
        override fun createSocket(): java.net.Socket = object : java.net.Socket() {
            private val input by lazy { GuardedInput(super.getInputStream()) }
            override fun getInputStream(): java.io.InputStream = input
        }
        override fun createSocket(h: String, p: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: String, p: Int, l: java.net.InetAddress, lp: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: java.net.InetAddress, p: Int) = throw UnsupportedOperationException()
        override fun createSocket(h: java.net.InetAddress, p: Int, l: java.net.InetAddress, lp: Int) = throw UnsupportedOperationException()
    }

    private class GuardedTls(private val f: javax.net.ssl.SSLSocketFactory) : javax.net.ssl.SSLSocketFactory() {
        private fun w(s: java.net.Socket): java.net.Socket = GuardedSocket(s as javax.net.ssl.SSLSocket)
        override fun getDefaultCipherSuites(): Array<String> = f.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = f.supportedCipherSuites
        override fun createSocket(s: java.net.Socket, h: String, p: Int, auto: Boolean) = w(f.createSocket(s, h, p, auto))
        override fun createSocket(h: String, p: Int) = w(f.createSocket(h, p))
        override fun createSocket(h: String, p: Int, l: java.net.InetAddress, lp: Int) = w(f.createSocket(h, p, l, lp))
        override fun createSocket(h: java.net.InetAddress, p: Int) = w(f.createSocket(h, p))
        override fun createSocket(h: java.net.InetAddress, p: Int, l: java.net.InetAddress, lp: Int) = w(f.createSocket(h, p, l, lp))
    }

    /** The phone's TLS socket with [GuardedInput] on what it decrypts; everything else is passed through. */
    private class GuardedSocket(private val s: javax.net.ssl.SSLSocket) : javax.net.ssl.SSLSocket() {
        private val input by lazy { GuardedInput(s.inputStream) }
        override fun getInputStream(): java.io.InputStream = input
        override fun getOutputStream(): java.io.OutputStream = s.outputStream
        override fun getSupportedCipherSuites(): Array<String> = s.supportedCipherSuites
        override fun getEnabledCipherSuites(): Array<String> = s.enabledCipherSuites
        override fun setEnabledCipherSuites(v: Array<String>) { s.enabledCipherSuites = v }
        override fun getSupportedProtocols(): Array<String> = s.supportedProtocols
        override fun getEnabledProtocols(): Array<String> = s.enabledProtocols
        override fun setEnabledProtocols(v: Array<String>) { s.enabledProtocols = v }
        override fun getSession(): javax.net.ssl.SSLSession = s.session
        override fun getHandshakeSession(): javax.net.ssl.SSLSession? = s.handshakeSession
        override fun addHandshakeCompletedListener(l: javax.net.ssl.HandshakeCompletedListener) = s.addHandshakeCompletedListener(l)
        override fun removeHandshakeCompletedListener(l: javax.net.ssl.HandshakeCompletedListener) = s.removeHandshakeCompletedListener(l)
        override fun startHandshake() = s.startHandshake()
        override fun setUseClientMode(v: Boolean) { s.useClientMode = v }
        override fun getUseClientMode() = s.useClientMode
        override fun setNeedClientAuth(v: Boolean) { s.needClientAuth = v }
        override fun getNeedClientAuth() = s.needClientAuth
        override fun setWantClientAuth(v: Boolean) { s.wantClientAuth = v }
        override fun getWantClientAuth() = s.wantClientAuth
        override fun setEnableSessionCreation(v: Boolean) { s.enableSessionCreation = v }
        override fun getEnableSessionCreation() = s.enableSessionCreation
        override fun getSSLParameters(): javax.net.ssl.SSLParameters = s.sslParameters
        override fun setSSLParameters(p: javax.net.ssl.SSLParameters) { s.sslParameters = p }
        override fun close() = s.close()
        override fun isClosed() = s.isClosed
        override fun isConnected() = s.isConnected
        override fun isBound() = s.isBound
        override fun isInputShutdown() = s.isInputShutdown
        override fun isOutputShutdown() = s.isOutputShutdown
        override fun shutdownInput() = s.shutdownInput()
        override fun shutdownOutput() = s.shutdownOutput()
        override fun getSoTimeout() = s.soTimeout
        override fun setSoTimeout(t: Int) { s.soTimeout = t }
        override fun getTcpNoDelay() = s.tcpNoDelay
        override fun setTcpNoDelay(v: Boolean) { s.tcpNoDelay = v }
        override fun getKeepAlive() = s.keepAlive
        override fun setKeepAlive(v: Boolean) { s.keepAlive = v }
        override fun getInetAddress(): java.net.InetAddress? = s.inetAddress
        override fun getLocalAddress(): java.net.InetAddress? = s.localAddress
        override fun getPort() = s.port
        override fun getLocalPort() = s.localPort
        override fun getRemoteSocketAddress(): java.net.SocketAddress? = s.remoteSocketAddress
        override fun getLocalSocketAddress(): java.net.SocketAddress? = s.localSocketAddress
    }
}

/** Reports of Public messages waiting to go to the internet relays (spec/FORMAT.md, "Internet relays"). */
object NostrReports {
    private fun prefs(c: Context) = c.getSharedPreferences("mesh", 0)
    fun report(c: Context, messageId: String) {
        val s = (pending(c) + messageId).toList().takeLast(200).toSet()
        prefs(c).edit().putStringSet("reports", s).apply()
    }
    fun pending(c: Context): Set<String> = prefs(c).getStringSet("reports", emptySet())!!.toSet()
    fun sent(c: Context, ids: Collection<String>) = prefs(c).edit().putStringSet("reports", pending(c) - ids.toSet()).apply()
}

/**
 * The packets a relay brought this phone first (spec/FORMAT.md, "Publish": they never go back up), remembered across
 * restarts: [MeshRouter.key] of the [max] with the newest packet time. The packets a phone passes on again after a
 * restart are the 500 newest it holds, so every one of them that came from a relay is still in here, whatever a relay
 * sends in between. Saved on the phone as "<key>=<packet time>,…". Thread-safe. Same as the iPhone's FromRelays.
 */
class FromRelays(saved: String = "", private val max: Int = MAX) {
    companion object { const val MAX = 1_000; const val PREF = "fromRelays" }
    private val at = HashMap<String, Long>() // key -> packet time
    /** True when something was added since [save]. */
    @Volatile var changed = false; private set
    init {
        for (e in saved.split(',')) { val i = e.lastIndexOf('='); if (i > 0) e.substring(i + 1).toLongOrNull()?.let { at[e.substring(0, i)] = it } }
        trim()
    }
    /** A relay brought [p], and it was new to this phone. */
    @Synchronized fun add(p: Packet) {
        val k = MeshRouter.key(p)
        if (k in at) return
        at[k] = p.ts; trim()
        if (k in at) changed = true
    }
    @Synchronized operator fun contains(key: String) = key in at
    @Synchronized fun size() = at.size
    @Synchronized fun save(): String { changed = false; return at.entries.joinToString(",") { "${it.key}=${it.value}" } }
    /** Full: the packets with the oldest time go, the ones a restart would pass on last. */
    private fun trim() { while (at.size > max) at.remove(at.minByOrNull { it.value }!!.key) }
}

/**
 * A [NostrLink]'s link sets by scope id, their mailboxes, and whether the link runs. All of it changes under one lock,
 * so a link that was stopped never gets or starts a link set, whichever thread asks: a resubscribe that overlapped the
 * Internet or Tor switch used to leave relay links running with the old setting (audit of 2026-11). [make] and [start]
 * run under that lock and must not call the router. Stopping a link set does, so [stop] and [sync] hand the link sets
 * to stop back to the caller. Thread-safe.
 */
class LinkSets<T>(private val make: (String) -> T, private val start: (T) -> Unit) {
    private val sets = LinkedHashMap<String, T>()
    private var running = false
    /** Scope id -> its mailboxes, as of the last [sync]. */
    @Volatile var boxes: Map<String, List<Int>> = emptyMap(); private set

    fun start() { synchronized(sets) { running = true } }

    /** The link stops: returns the link sets there were, for the caller to stop. None is made after this, until [start]. */
    fun stop(): List<T> = synchronized(sets) { running = false; sets.values.toList().also { sets.clear() } }

    /**
     * The scopes are now what [now] says (scope id -> mailboxes). It is read before the lock is taken, because it may
     * wait for a group's keys; whether the link still runs is decided after it, under the lock, where each new scope's
     * link set is made and started. Returns the link sets of the scopes that are gone, for the caller to stop; null if
     * the link doesn't run, and then nothing was made.
     */
    fun sync(now: () -> Map<String, List<Int>>): List<T>? {
        val b = now()
        return synchronized(sets) {
            if (!running) return null
            boxes = b
            val gone = sets.keys.filter { it !in b }.mapNotNull { sets.remove(it) }
            b.keys.filter { it !in sets }.forEach { id -> make(id).also { sets[id] = it; start(it) } }
            gone
        }
    }

    operator fun get(id: String): T? = synchronized(sets) { sets[id] }
    fun all(): List<T> = synchronized(sets) { sets.values.toList() }
}

/**
 * One link set's sockets: at most one for each relay, and only that one counts. With Tor, the reconnect after a loss
 * and the connect after the Tor check both ask for the same relay; a second socket used to replace the first, which
 * stayed open with nothing tracking it, closing it or counting its messages (audit of 2026-11). Thread-safe.
 */
class RelaySockets<S : Any> {
    private val byRelay = HashMap<String, S>()
    private var closed = false

    /**
     * Opens the link to [relay] with [open], unless there is one or the link set was stopped: false then, and nothing
     * is opened. [open] runs under the lock, so the socket is tracked before any of its callbacks can ask ([tracks]);
     * it must only start the connection.
     */
    @Synchronized fun connect(relay: String, open: () -> S): Boolean {
        if (closed || relay in byRelay) return false
        byRelay[relay] = open()
        return true
    }
    /** True if [s] is this set's link to [relay] right now. Nothing from any other socket is handled. */
    @Synchronized fun tracks(relay: String, s: S) = byRelay[relay] === s
    /** [s] ended: true if it was this set's link to [relay], which can now be linked again. */
    @Synchronized fun lost(relay: String, s: S): Boolean {
        if (byRelay[relay] !== s) return false
        byRelay.remove(relay)
        return true
    }
    @Synchronized fun all(): List<S> = byRelay.values.toList()
    @Synchronized fun size() = byRelay.size
    /**
     * The link set stops, for good: forgets every socket and returns them, for the caller to close. From then on
     * [tracks] is false for all of them and [connect] opens nothing, whatever task of the link set still runs.
     */
    @Synchronized fun close(): List<S> { closed = true; return byRelay.values.toList().also { byRelay.clear() } }
}

/**
 * Where the catch-up of each relay and mailbox starts next time (spec/FORMAT.md, "Subscribe"), in seconds, saved on the
 * phone as "<relay url>|<mailbox hex>=<seconds>,…". Same format as the iPhone's RelaySince. Thread-safe.
 */
class RelaySince(saved: String = "") {
    companion object { const val MAX = 400; private const val FROM = "|from"; private const val UNTIL = "|until" }
    private val at = LinkedHashMap<String, Long>()
    /** True when something moved since [save]. */
    @Volatile var changed = false; private set
    init {
        for (e in saved.split(',')) { val i = e.lastIndexOf('='); if (i > 0) e.substring(i + 1).toLongOrNull()?.let { at[e.substring(0, i)] = it } }
    }
    @Synchronized fun get(relay: String, mailbox: Int): Long? = at[key(relay, mailbox)]
    /** Moves the start forward to [t]; never back. */
    @Synchronized fun advance(relay: String, mailbox: Int, t: Long) {
        val k = key(relay, mailbox); val old = at[k]
        if (old != null && old >= t) return
        at.remove(k); at[k] = t; changed = true
        while (at.size > MAX) at.remove(at.keys.first())
    }
    /**
     * What a catch-up of [mailbox] on [relay] left out when it stopped at its page limit: the events dated from the
     * first time to the second. The next links fetch it ([CatchUp]). Null if nothing is owed. Saved with the starts,
     * as "<relay url>|<mailbox hex>|from=<seconds>" and "…|until=<seconds>".
     */
    @Synchronized fun owed(relay: String, mailbox: Int): Pair<Long, Long>? {
        val k = key(relay, mailbox); val from = at[k + FROM] ?: return null; val until = at[k + UNTIL] ?: return null
        return if (from < until) from to until else null
    }
    /** What is owed from now on: the events dated [from] to [until]; nothing if [from] isn't before [until]. */
    @Synchronized fun owe(relay: String, mailbox: Int, from: Long, until: Long) {
        val k = key(relay, mailbox)
        if (at[k + FROM] == from && at[k + UNTIL] == until) return
        val had = (at.remove(k + FROM) != null) or (at.remove(k + UNTIL) != null)
        if (from < until) { at[k + FROM] = from; at[k + UNTIL] = until; while (at.size > MAX) at.remove(at.keys.first()) }
        if (had || from < until) changed = true
    }
    @Synchronized fun save(): String { changed = false; return at.entries.joinToString(",") { "${it.key}=${it.value}" } }
    private fun key(relay: String, mailbox: Int) = relay + "|" + "%04x".format(mailbox and 0xFFFF)
}

/** A relay's messages this minute. Outlives its links: dropping the link and coming back doesn't buy a new share. */
class RelayPace { @Volatile var from = 0L; @Volatile var n = 0 }

/**
 * Catch-up on one relay link (spec/FORMAT.md, "Subscribe"): one REQ per mailbox, one mailbox at a time, in the order
 * given (groups before the Public channel), so a busy mailbox never crowds out another. A page that comes back full is
 * followed by an older one (`until`), up to [Nostr.MAX_PAGES] for a group and one for the Public channel. A mailbox
 * whose catch-up ends with EOSE starts next time where this one started; a refused one (CLOSED) or one with no answer
 * is left for the next link. Every event of a page counts, whatever it carries ([frame]). A group mailbox whose last
 * page was still full was not read to the end: what is older is owed ([RelaySince.owed]), and the next links fetch it
 * with the pages they have left, so a full mailbox never makes a phone skip older events for good.
 * Times in seconds. Not thread-safe: the caller locks. Same as the iPhone's CatchUp.
 */
class CatchUp(private val relay: String, private val since: RelaySince, private val prefix: String = "cu", private val pace: RelayPace = RelayPace()) {
    class Req(val subId: String, val mailbox: Int, val since: Long, val until: Long?) {
        fun text() = Nostr.catchUp(subId, mailbox, since, until)
    }
    private val todo = ArrayDeque<Int>()
    /** Mailboxes caught up on this link: their live events move the saved start forward. */
    val done = HashSet<Int>()
    /** The REQ waiting for its EOSE, and when it was sent. */
    var current: Req? = null; private set
    var sentAt = 0L; private set
    private var startedAt = 0L
    private var pages = 0; private var count = 0; private var oldest = Long.MAX_VALUE; private var n = 0
    private var throttled = false
    private var owed = false // the REQ waiting asks for what an earlier catch-up left out

    /**
     * One more message from this relay: false if it is over its share for this minute. Relays aren't held to the limit
     * for links, which would let one of them use up the share of the others, so each has its own. What this drops is
     * fetched again on the next link: nothing moves the saved start forward once a link went over.
     */
    fun allow(now: Long): Boolean {
        if (now - pace.from >= 60) { pace.from = now; pace.n = 0 }
        if (++pace.n > Nostr.RELAY_PER_MINUTE) { throttled = true; return false }
        return true
    }

    fun add(mailboxes: Collection<Int>) { for (m in mailboxes) if (m !in done && m !in todo && m != current?.mailbox) todo.addLast(m) }

    /** The next REQ to send, if none is waiting for its answer. */
    fun next(now: Long): Req? {
        if (current != null) return null
        val m = todo.removeFirstOrNull() ?: return null
        startedAt = now; pages = 0; owed = false
        return page(m, maxOf(now - Nostr.KEEP_S, (since.get(relay, m) ?: 0L) - Nostr.SINCE_MARGIN_S), null, now)
    }

    fun event(subId: String, createdAt: Long) { if (current?.subId == subId) { count++; oldest = minOf(oldest, createdAt) } }

    /**
     * A message from the relay. If it is an event of the page waiting, it counts, also when it carries no packet or
     * one this link doesn't take: 500 such events are a full page, and an older one follows. Counting only packets
     * let anyone end a catch-up early with junk under the mailbox's tag.
     */
    fun frame(text: String) { Nostr.dated(text)?.let { event(it.subId, it.createdAt) } }

    /** [subId] ended: EOSE ([complete]) or CLOSED / no answer. Returns the next REQ: an older page, or the next mailbox. */
    fun end(subId: String, complete: Boolean, now: Long): Req? {
        val c = current?.takeIf { it.subId == subId } ?: return null
        current = null
        if (complete && !throttled) {
            val max = if (c.mailbox == Nostr.PUBLIC_MAILBOX) 1 else Nostr.MAX_PAGES
            val full = count >= Nostr.PAGE
            val older = if (oldest == c.until) oldest - 1 else oldest // where an older page starts
            if (owed) since.owe(relay, c.mailbox, c.since, if (full) older else c.since) // a page that isn't full was the last of it
            else {
                if (full && pages < max) return page(c.mailbox, c.since, older, now)
                done += c.mailbox
                since.advance(relay, c.mailbox, startedAt)
                // Still full at the page limit: what is older was not read, and the start has moved past it. It is owed,
                // together with what was owed before. Not for the Public channel, which is one page by design.
                if (full && c.mailbox != Nostr.PUBLIC_MAILBOX) since.owe(relay, c.mailbox, minOf(c.since, since.owed(relay, c.mailbox)?.first ?: c.since), older)
            }
            // What an earlier catch-up left out, with the pages this link has left; never more than 7 days back.
            val left = since.owed(relay, c.mailbox)
            if (left != null && pages < max) {
                val from = maxOf(left.first, now - Nostr.KEEP_S)
                if (from < left.second) { owed = true; return page(c.mailbox, from, left.second, now) }
                since.owe(relay, c.mailbox, 0, 0) // too old to matter
            }
        }
        return next(now)
    }

    /** A live event of [mailbox] made at [createdAt]: once caught up, the saved start follows it (never past now). */
    fun live(mailbox: Int, createdAt: Long, now: Long) { if (mailbox in done && !throttled) since.advance(relay, mailbox, minOf(createdAt, now)) }

    private fun page(m: Int, from: Long, until: Long?, now: Long): Req {
        count = 0; oldest = Long.MAX_VALUE; pages++; sentAt = now
        return Req(prefix + (++n), m, from, until).also { current = it }
    }
}

/**
 * What this phone still has to post to the relays (spec/FORMAT.md, "Publish"), and what they confirmed. Own packets
 * go first, newest first; anyone else's are first looked up with `#x` and posted only if no relay returned the same
 * packet ([MeshRouter.key]) in an event its recipients get ([Nostr.Received.reaches]). A packet counts as sent only once
 * a relay answered ["OK", <event id>, true, …]; if every
 * relay it went to refused it, or none accepted it within 30 s, it is queued again, up to 3 tries. The queues keep
 * the newest packets when full. Thread-safe. Same rules as the iPhone's RelayOutbox.
 *
 * Everything here tells packets apart as the router does ([MeshRouter.key]: id, time and content), never by id alone:
 * another packet sent under the id of a real one neither takes its place in a queue nor counts as it once posted.
 * A packet this phone wrote is never held up by packets it only passes on: an older one is looked up before them and
 * then goes up with the own packets. The links that brought the others take turns, so the packets of one link,
 * whatever time they claim, can't take every lookup and every post; and the two queues for them are bounded in
 * bytes as well as in number.
 */
class RelayOutbox(
    sent: Collection<String> = emptyList(),
    private val now: () -> Long = System::currentTimeMillis,
    private val jitter: () -> Long = { kotlin.random.Random.nextLong(JITTER_MS) },
) {
    companion object {
        const val OWN_MAX = 500; const val CANDIDATES_MAX = 5_000; const val MISSING_MAX = 2_000
        const val SENT_MAX = 3_000; const val ON_RELAYS_MAX = 5_000; const val FLIGHTS_MAX = 300
        /** The most bytes of packets (encoded sizes) waiting for the lookup, and as many waiting to be posted after it.
         *  A packet can be 16 KB: the counts alone let a neighbour park over 100 MB of junk here. */
        const val QUEUE_BYTES = 8L * 1024 * 1024
        const val FRESH_MS = 40 * 60_000L   // own packets younger than this go up without asking first (their date is up to 35 minutes back)
        const val ANSWER_MS = 30_000L       // how long a post waits for a relay to accept it
        const val TRIES = 3
        /** A bridged packet waits up to this long, at random, before the relays are asked about it: phones that got it
         *  at the same moment then don't all find it missing and all post it. Own packets never wait. */
        const val JITTER_MS = 30_000L
        private const val HANDED_MAX = 200; private const val LINKS_MAX = 256
    }
    /** A queued packet. [k]: what tells it from every other ([MeshRouter.key]). [mine]: written on this phone. [from]: the link that brought it, "" if none did. */
    private class Item(val p: Packet, val k: String, val mine: Boolean, val from: String) { val size = 18L + p.cipher.size }
    /** A queue of packets by [MeshRouter.key], and the bytes they take. */
    private class Lane(val max: Int, val maxBytes: Long = Long.MAX_VALUE) {
        val q = HashMap<String, Item>(); var bytes = 0L; private set
        operator fun contains(k: String) = k in q
        fun add(i: Item) { remove(i.k); q[i.k] = i; bytes += i.size }
        fun remove(k: String): Item? = q.remove(k)?.also { bytes -= it.size }
    }
    private class Flight(val i: Item, val relays: Set<String>, val at: Long) {
        val refused = HashSet<String>(); var over = false
    }
    private val own = Lane(OWN_MAX)                            // written on this phone: up first, newest first
    private val candidates = Lane(CANDIDATES_MAX, QUEUE_BYTES) // not yet looked up: anyone else's, and this phone's older ones
    private val missing = Lane(MISSING_MAX, QUEUE_BYTES)       // anyone else's, looked up: no relay has them, so this phone posts them
    private val flying = HashSet<String>()             // posted, waiting for an answer
    private val sent = RecentIds(SENT_MAX, sent.filter { ':' in it }) // on the relays already; what older builds saved by id alone is dropped
    private val onRelays = bounded<Boolean>(ON_RELAYS_MAX) // the packets a relay sent in an event their recipients get
    private val flights = object : LinkedHashMap<String, Flight>() { // event id -> post; ended ones stay for late answers
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, Flight>?): Boolean {
            if (size <= FLIGHTS_MAX) return false
            e?.value?.let { if (!it.over) flying -= it.i.k }
            return true
        }
    }
    private val tries = bounded<Int>(MISSING_MAX)
    private val due = bounded<Long>(CANDIDATES_MAX)    // candidate -> when the relays may be asked about it
    private val handed = bounded<Item>(HANDED_MAX)     // given out by toCheck or next, until the caller says what became of them
    private val served = HashMap<String, Long>()       // link -> the turn in which a packet it brought was last posted
    private var turns = 0L
    private val newestFirst = compareByDescending<Item> { it.p.ts }.thenBy { it.k }
    /** True when the sent list changed since [sentList]: the caller saves it. */
    @Volatile var changed = false; private set

    private fun <V> bounded(max: Int) = object : LinkedHashMap<String, V>() {
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, V>?) = size > max
    }

    /**
     * The router offers a packet. [mine]: this very packet was written on this phone (a message or a receipt), not
     * another one sent under its id. [from]: the link that brought it, "" if none did.
     */
    @Synchronized fun offer(p: Packet, mine: Boolean, from: String = "") {
        val t = now(); val k = MeshRouter.key(p)
        if (k in sent || k in flying || k in onRelays || p.ts < t - Nostr.KEEP_S * 1000) return
        tries.remove(k)
        val i = Item(p, k, mine, if (mine) "" else from)
        if (mine && p.ts > t - FRESH_MS) put(own, i)
        else if (k !in missing && k !in own && put(candidates, i)) due.getOrPut(k) { t + jitter() }
    }

    /** The next packet to post: the newest own one, else (if [bridged]) one no relay had. Too old ones are skipped. */
    @Synchronized fun next(bridged: Boolean): Pair<Packet, Boolean>? {
        val i = newest(own) ?: (if (bridged) turn(missing) else null) ?: return null
        handed[i.k] = i
        return i.p to i.mine
    }
    private fun old(q: Lane) { // checked again right before posting
        val cut = now() - Nostr.KEEP_S * 1000
        q.q.values.filter { it.p.ts < cut }.forEach { q.remove(it.k) }
    }
    private fun newest(q: Lane): Item? { old(q); return q.q.values.maxByOrNull { it.p.ts }?.also { q.remove(it.k) } }
    /**
     * The next of the packets this phone only passes on: the links that brought them take turns, the one whose turn
     * was longest ago first, and of its packets the newest. A link that keeps sending packets dated ahead of everyone
     * else's gets its turn and no more.
     */
    private fun turn(q: Lane): Item? {
        old(q)
        // A link seen for the first time waits behind the ones already here: a new link name doesn't jump the queue.
        q.q.values.filter { it.from !in served }.sortedWith(newestFirst).forEach { if (it.from !in served) served[it.from] = ++turns }
        val i = q.q.values.minWithOrNull(compareBy<Item> { served[it.from] ?: 0L }.then(newestFirst)) ?: return null
        q.remove(i.k); served[i.from] = ++turns
        if (served.size > LINKS_MAX) served.keys.retainAll(q.q.values.mapTo(HashSet()) { it.from })
        return i
    }

    /** [p] went out as event [eventId] to [relays]. */
    @Synchronized fun posted(eventId: String, p: Packet, fromOwn: Boolean, relays: Set<String>) {
        val k = MeshRouter.key(p)
        flights[eventId] = Flight(handed.remove(k) ?: Item(p, k, fromOwn, ""), relays, now()); flying += k
    }

    /** A relay answered an event. Returns the packet id if this made a packet written on this phone sent (the caller reports it), else null. */
    @Synchronized fun answer(relay: String, ok: Nostr.Ok): String? {
        val f = flights[ok.eventId] ?: return null
        if (ok.accepted) { flights.remove(ok.eventId); flying -= f.i.k; return told(f.i) }
        f.refused += relay
        if (!f.over && f.refused.containsAll(f.relays)) fail(f)
        return null
    }

    /** Posts that no relay accepted within 30 s are queued again. */
    @Synchronized fun expire() { val t = now(); flights.values.filter { !it.over && t - it.at >= ANSWER_MS }.forEach(::fail) }

    private fun fail(f: Flight) {
        f.over = true; flying -= f.i.k
        if (f.i.k in sent) return
        val n = (tries[f.i.k] ?: 0) + 1; tries[f.i.k] = n
        if (n >= TRIES) return // until the router offers it again (next link to the relays)
        put(if (f.i.mine) own else missing, f.i)
    }

    /**
     * A relay sent this event. Returns the packet's id if a queued copy is the same packet, which is now sent, and this
     * phone wrote it; else null.
     * An event the packet's recipients don't get ([Nostr.Received.reaches]) counts for nothing: anyone can post one,
     * and it must not stop this phone from posting the packet where they do get it.
     */
    fun fromRelay(r: Nostr.Received): String? = if (r.reaches) fromRelay(r.packet) else null

    /** A relay has this packet in an event its recipients get. Returns its id if a queued copy is the same packet, which is now sent, and this phone wrote it; else null. */
    @Synchronized fun fromRelay(p: Packet): String? {
        val k = MeshRouter.key(p); onRelays[k] = true
        val queued = own.q[k] ?: candidates.q[k] ?: missing.q[k] ?: flights.values.firstOrNull { it.i.k == k && !it.over }?.i
        return queued?.let(::told)
    }

    /**
     * Up to [n] packets to look up on the relays (`#x`): first the ones this phone wrote, then the others, the links
     * that brought them taking turns; of each, the newest first.
     */
    @Synchronized fun toCheck(n: Int): List<Packet> {
        val t = now()
        val ready = candidates.q.values.filter { (due[it.k] ?: 0L) <= t }
        val links = ready.filter { !it.mine }.groupBy { it.from }.values.map { it.sortedWith(newestFirst) }
        val inTurn = (0 until (links.maxOfOrNull { it.size } ?: 0)).asSequence().flatMap { r -> links.mapNotNull { it.getOrNull(r) }.sortedWith(newestFirst) }
        return (ready.filter { it.mine }.sortedWith(newestFirst).asSequence() + inTurn).take(n).toList()
            .onEach { candidates.remove(it.k); due.remove(it.k); handed[it.k] = it }.map { it.p }
    }

    /**
     * After the lookup: packets a relay returned with the same contents are sent (the ids of those this phone wrote
     * are returned), the rest get posted: this phone's own with its own packets, the others in their turn.
     */
    @Synchronized fun checked(batch: List<Packet>): List<String> {
        val found = ArrayList<String>()
        for (p in batch) {
            val k = MeshRouter.key(p); val i = handed.remove(k) ?: Item(p, k, false, "")
            if (k in onRelays) told(i)?.let { found += it }
            else if (k !in sent && k !in flying) put(if (i.mine) own else missing, i)
        }
        return found
    }

    /** What is saved on the phone: the packets that went up, as [MeshRouter.key]. */
    @Synchronized fun sentList(): List<String> { changed = false; return sent.toList() }
    /** True if a packet with this id is on the relays; [isSent] with the packet says whether that very packet is. */
    @Synchronized fun isSent(id: String) = sent.toList().any { it.startsWith("$id:") }
    @Synchronized fun isSent(p: Packet) = MeshRouter.key(p) in sent
    @Synchronized fun queued() = own.q.size + candidates.q.size + missing.q.size
    /** The bytes of packets (encoded sizes) in the three queues. */
    @Synchronized fun queuedBytes() = own.bytes + candidates.bytes + missing.bytes

    private fun markSent(k: String): Boolean {
        if (!sent.add(k)) return false
        changed = true; own.remove(k); candidates.remove(k); missing.remove(k)
        return true
    }

    /** [i] is on the relays now. Its id, for the caller to show "Sent", only if this phone wrote this very packet. */
    private fun told(i: Item): String? = if (markSent(i.k) && i.mine) i.p.id else null

    /** Queues [i], making room if the queue is full ([loser]). False if it was not taken. */
    private fun put(q: Lane, i: Item): Boolean {
        if (i.k !in q) while (q.q.size >= q.max || q.bytes + i.size > q.maxBytes) q.remove((loser(q, i) ?: return false).k)
        q.add(i)
        return true
    }

    /**
     * Full queue, in packets or in bytes: which packet makes room for [i], or null if [i] is the one that isn't taken.
     * A packet this phone wrote never gives way to one it only passes on. Among those, as in the router's store
     * (spec/FORMAT.md, "A full queue"): while one link's packets are more than a quarter of the queue, that link's
     * oldest goes, also for its own next packet; otherwise the oldest of all, if [i] is newer.
     */
    private fun loser(q: Lane, i: Item): Item? {
        val others = q.q.values.filter { !it.mine }
        if (others.isEmpty()) return if (i.mine) q.q.values.minByOrNull { it.p.ts }?.takeIf { it.p.ts < i.p.ts } else null
        val byCount = q.q.size >= q.max
        val held = HashMap<String, Long>()
        for (x in others) held[x.from] = (held[x.from] ?: 0L) + if (byCount) 1L else x.size
        if (!i.mine) held[i.from] = (held[i.from] ?: 0L) + if (byCount) 1L else i.size
        val top = held.maxByOrNull { it.value }
        if (top != null && top.value > (if (byCount) q.max.toLong() else q.maxBytes) / 4) {
            val oldest = others.filter { it.from == top.key }.minByOrNull { it.p.ts }
            if (oldest != null) return oldest.takeIf { i.mine || top.key != i.from || it.p.ts < i.p.ts }
        }
        return others.minByOrNull { it.p.ts }?.takeIf { i.mine || it.p.ts < i.p.ts }
    }
}

/**
 * Links to public Nostr relays while there is internet (spec/FORMAT.md, "Internet relays"). One peer for forwarding:
 * the router gives it every packet and it hands the router what arrives for this phone's mailboxes. Packets written on
 * this phone go up first. Anyone else's (this phone bridging its neighbourhood) go up only if no relay has them yet,
 * and slowly, so the same packet isn't posted by every phone that holds it and relays don't throttle us ([RelayOutbox]).
 * Each group has its own connections, key and subscription ([RelayScope]), so one connection never shows that two
 * groups share a phone. Packets this phone only passes on go out with the Everyone channel's, whatever mailbox their
 * id names ([Nostr.scope]); a link set takes only packets of its own mailboxes ([Nostr.takes]); and what came from the
 * relays never goes back up ([MeshRouter.peerUp], [FromRelays]).
 */
class NostrLink(
    private val ctx: Context,
    private val router: () -> MeshRouter?,
    private val scopes: () -> List<Scope>,
    private val changed: () -> Unit,
    private val viaTor: Boolean = false, // "Connect through Tor": links go only through the app's own Tor
    private val onRelays: (String) -> Unit = {}, // a relay accepted a packet, or had it already
    private val packetKey: (String) -> String? = { null }, // message id -> the packet this phone shows under it (MeshRouter.key), for reports
    private val fromRelays: FromRelays = FromRelays(), // the packets relays brought first; the caller gives them to the router after a restart
) {
    /** One group's mailboxes; [id] is empty for the Everyone channel. */
    class Scope(val id: String, val mailboxes: List<Int>)

    companion object {
        const val PEER = "nostr"
        fun owns(peer: String) = peer == PEER
        /** Free public relays that stored a 22 KB event of this kind from a new key (tested 2026-11-06). */
        val RELAYS = listOf("wss://nos.lol", "wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub")
        /** Through Tor: nos.lol and nostr.mom don't answer Tor exits (tested 2026-11-06), so two others take their place. */
        val TOR_RELAYS = listOf("wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub", "wss://relay.nostr.net", "wss://nostr.data.haus")
    }

    private val h = android.os.Handler(android.os.Looper.getMainLooper())
    private val rnd = java.security.SecureRandom()
    private val POST_SPREAD_MS = 8_000 // so the time a packet reaches a relay says less about when it was written
    /** Scope id -> its links. Whether this link runs is decided under the same lock, so once stopped it never gets a new link set. */
    private val links: LinkSets<RelayScope> = LinkSets(
        { id -> RelayScope(ctx, id, router, ::scopeUp, { links.boxes[id] ?: emptyList() }, changed, viaTor, onRelays, packetKey, fromRelays) },
        { it.start() }, // only queues tasks: nothing here calls the router
    )
    private val upLock = Any()
    private var linksUp = 0 // scopes with at least one relay linked (lock upLock)

    private val everyone get() = links[""]
    val connected get() = links.all().maxOfOrNull { it.connected } ?: 0
    val isUp get() = synchronized(upLock) { linksUp > 0 }
    val total get() = everyone?.total ?: 0
    val throughTor get() = everyone?.throughTor
    val torStuck get() = everyone?.torStuck == true
    fun statusLine() = everyone?.statusLine() ?: "Internet: off"

    fun start() { links.start(); sync() }

    /** For good: the Internet or Tor switch makes a new NostrLink. A resubscribe still running on another thread finds this one stopped. */
    fun stop() = links.stop().forEach { it.stop() }

    /** The groups or their keys changed: new groups get their own links, and each link whose mailboxes changed asks for them. */
    fun resubscribe() { sync(); links.all().forEach { it.resubscribe() } }

    /**
     * Called by the router: a packet written on this phone goes up on the links of its group, and anything else with
     * the Everyone channel's ([Nostr.scope]). This phone's own wait a moment, at random. [mine]: this very packet was
     * written here, not another one under its id. [from]: the link that brought it ([MeshRouter.source]), for its turn
     * among the packets passed on ([RelayOutbox]).
     */
    fun send(p: Packet, mine: Boolean, from: String = "") { if (mine) h.postDelayed({ route(p, true, "") }, rnd.nextInt(POST_SPREAD_MS).toLong()) else route(p, false, from) }

    private fun route(p: Packet, mine: Boolean, from: String) { (links[Nostr.scope(p.id, mine, links.boxes)] ?: links[""])?.send(p, mine, from) }

    private fun sync() { links.sync { scopes().distinctBy { it.id }.associate { it.id to it.mailboxes } }?.forEach { it.stop() } }

    /** The router sees one peer, up while any scope has a relay. */
    private fun scopeUp(on: Boolean) {
        val edge = synchronized(upLock) { linksUp += if (on) 1 else -1; if (on) linksUp == 1 else linksUp == 0 }
        if (edge) router()?.let { if (on) it.peerUp(PEER) else it.peerDown(PEER) }
    }
}

/** One group's links to the relays (or the Everyone channel's, when [scope] is empty): its own sockets, key and subscription. */
private class RelayScope(
    private val ctx: Context,
    private val scope: String,
    private val router: () -> MeshRouter?,
    private val onUp: (Boolean) -> Unit,
    private val mailboxes: () -> List<Int>,
    private val changed: () -> Unit,
    private val viaTor: Boolean,
    private val onRelays: (String) -> Unit,
    private val packetKey: (String) -> String?,
    private val fromRelays: FromRelays,
) {
    companion object {
        private const val START_SPREAD_MS = 8_000   // groups link at different moments, so their connections don't line up
        private const val TICK_MS = 1_500L          // at most one own packet per tick
        private const val BRIDGE_EVERY = 3          // and one bridged packet every 3 ticks
        private const val CHECK_MS = 10_000L        // how often to ask relays which bridged packets they have
        private const val CHECK_WAIT_MS = 6_000L    // how long to wait for their answers
        private const val CHECK_BATCH = 50
        private const val REST_MS = 10 * 60_000L    // pause posting to a relay that says to slow down
        private const val CATCH_UP_WAIT_S = 20L     // a catch-up REQ with no EOSE by then is given up on this link
    }

    private val secret = Schnorr.newSecret() // a new throwaway key every start and for each group: relays can't link them by key
    private val relays = DebugTools.relays(ctx) ?: if (viaTor) NostrLink.TOR_RELAYS else NostrLink.RELAYS // the override exists in debug builds only
    private val saved = if (scope.isEmpty()) "" else ".$scope" // the Everyone links keep the names older builds used
    private val torUser = ByteArray(8).also(java.security.SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) } // its own Tor circuits
    private val h = android.os.Handler(android.os.Looper.getMainLooper())
    // Battery saver: the radio wakes less often for keep-alive pings.
    private val direct = okhttp3.OkHttpClient.Builder().pingInterval(if (MeshEngine.batterySaver(ctx)) 120L else 30L, java.util.concurrent.TimeUnit.SECONDS)
        // No compression and no message over 1 MiB: a hostile relay could otherwise end the app (WsLimit).
        .apply { WsLimit.apply(this, plain = relays.any { it.startsWith("ws://") }) }.build()
    private var client = direct // through Tor's proxy once Tor is up (viaTor)
    private val open = java.util.concurrent.ConcurrentHashMap<String, okhttp3.WebSocket>()
    private val sockets = RelaySockets<okhttp3.WebSocket>() // one for each relay; nothing from any other socket is handled
    private val subscribed = java.util.concurrent.ConcurrentHashMap<String, List<Int>>() // relay -> the mailboxes its live subscription asks for
    private val backoff = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val resting = java.util.concurrent.ConcurrentHashMap<String, Long>() // relay -> post again after
    private val catchUps = java.util.concurrent.ConcurrentHashMap<String, CatchUp>() // relay -> its catch-up (lock it)
    private val paces = java.util.concurrent.ConcurrentHashMap<String, RelayPace>()  // relay -> what it sent this minute
    private val prefs = ctx.getSharedPreferences("mesh", 0)
    private val outbox = RelayOutbox(prefs.getString("relaySent$saved", "")!!.split(',').filter { it.isNotEmpty() })
    private val since = RelaySince(prefs.getString("relaySince$saved", "") ?: "")
    private val subjects = ReportSubjects() // the relay events that carried Public packets, for reports
    private val shown = object : LinkedHashMap<String, String>() { // reported message id -> the packet shown under it ("" if none); main thread
        override fun removeEldestEntry(e: MutableMap.MutableEntry<String, String>?) = size > 200
    }
    @Volatile private var running = false
    @Volatile private var stopped = false // a link set that was stopped never starts again
    @Volatile private var up = false
    @Volatile private var live = Nostr.subId("live") // random: an id made from the clock would be almost the same on every link set of this phone
    @Volatile private var lookup: Set<String> = emptySet() // the packet ids of the #x lookup in flight
    private var ticks = 0
    private var checking = false
    private var torCheck = false // a Tor check is running

    /** With Tor: true once a check says traffic leaves through Tor, false while Tor starts. Null without Tor. */
    @Volatile var throughTor: Boolean? = if (viaTor) false else null; private set
    /** Since when this link has been waiting for Tor (0 while it isn't). */
    @Volatile private var torWaitSince = if (viaTor) System.currentTimeMillis() else 0L
    /** Tor has been trying for over 2 minutes without a working circuit (no internet, or Tor blocked). */
    val torStuck get() = throughTor == false && torWaitSince > 0 && System.currentTimeMillis() - torWaitSince > 120_000L

    val connected get() = open.size
    /** True while at least one relay is linked (it then counts as one peer for the router, not as a phone). */
    val isUp get() = up
    val total get() = relays.size

    /**
     * OkHttp has no limit on one message, so a hostile relay could send one big enough to end the app. When memory runs
     * short, every relay link is dropped, which frees what it was reading; they reconnect as after any failure.
     */
    private val memoryWatch = object : Runnable {
        override fun run() {
            if (!running) return
            val rt = Runtime.getRuntime()
            if (rt.totalMemory() - rt.freeMemory() > rt.maxMemory() / 10 * 8) { DebugTools.log("relays: memory is short, dropping links"); sockets.all().forEach { it.cancel() } }
            h.postDelayed(this, 2_000)
        }
    }

    fun start() {
        if (running || stopped) return
        running = true
        h.removeCallbacks(memoryWatch); h.post(memoryWatch)
        val wait = if (scope.isEmpty()) 0L else java.security.SecureRandom().nextInt(START_SPREAD_MS).toLong()
        h.postDelayed({ if (!viaTor) relays.forEach(::connect) else waitForTor() }, wait) // Tor checks run on the main thread
        h.postDelayed(::pump, TICK_MS)
        h.postDelayed(::check, CHECK_MS)
    }

    fun stop() {
        stopped = true; running = false
        h.removeCallbacksAndMessages(null)
        sockets.close().forEach { it.close(1000, null) }; open.clear(); catchUps.clear(); subscribed.clear()
        if (up) { up = false; onUp(false) }
        save()
        changed()
    }

    /**
     * The groups changed: if this link set's mailboxes did, every relay gets the new live subscription and catches up
     * the new mailboxes. A link set whose mailboxes are the same sends nothing, so a change in one group doesn't show
     * on the links of all the others at the same moment.
     */
    fun resubscribe() {
        val boxes = mailboxes()
        if (open.keys.all { subscribed[it] == boxes }) return
        val old = live; live = Nostr.subId("live")
        for ((url, ws) in open) {
            ws.send(Nostr.close(old)); ws.send(Nostr.live(live, boxes)); subscribed[url] = boxes
            val cu = catchUps[url] ?: continue
            synchronized(cu) { cu.add(boxes); cu.next(nowS()) }?.let { ws.send(it.text()) }
        }
    }

    /**
     * Called by the router: queues the packet unless it came from the relays, is on them already or is too old.
     * [mine] = written on this phone (a message or a receipt). Older own packets may be on the relays already (the
     * app can be killed before it saves what it posted), so they are looked up first, like anyone else's.
     */
    fun send(p: Packet, mine: Boolean, from: String = "") = outbox.offer(p, mine, from)

    /**
     * Starts the app's Tor if needed, waits for it, checks through it that traffic leaves through Tor, then links to
     * the relays; else tries again soon.
     */
    private fun waitForTor() {
        if (!running || torCheck) return
        Tor.start(ctx)
        val port = Tor.socksPort() ?: run { h.postDelayed(::waitForTor, 2_000); return } // still starting
        val socks = Socks5.factory(port, torUser)
        client = direct.newBuilder().socketFactory(socks).dns(Socks5.noDns).build()
        torCheck = true
        val c = okhttp3.OkHttpClient.Builder().socketFactory(socks).dns(Socks5.noDns).build() // an ordinary request: the relay links' guard takes only WebSocket answers
        Thread {
            val ok = Tor.check(c, scope.take(6).ifEmpty { "everyone" })
            h.post {
                torCheck = false
                if (!running) return@post
                throughTor = ok; if (ok) torWaitSince = 0L; changed()
                if (ok) relays.forEach(::connect) else h.postDelayed(::waitForTor, 15_000) // relays that still have a socket are left alone
            }
        }.start()
    }

    private fun connect(url: String) {
        if (!running || (viaTor && throughTor != true)) return // with Tor: only after the check
        // One link for each relay: the reconnect after a loss and the connect after a Tor check can both ask for the same one.
        sockets.connect(url) { client.newWebSocket(okhttp3.Request.Builder().url(url).build(), listener(url)) }
    }

    private fun listener(url: String) = object : okhttp3.WebSocketListener() {
            override fun onOpen(ws: okhttp3.WebSocket, r: okhttp3.Response) {
                if (!sockets.tracks(url, ws)) { ws.cancel(); return } // not this set's link to the relay (any more)
                open[url] = ws; backoff.remove(url)
                DebugTools.log("relay open ${url.substringAfter("//")} ${scope.take(6).ifEmpty { "everyone" }}")
                val boxes = mailboxes()
                ws.send(Nostr.live(live, boxes)); subscribed[url] = boxes
                val cu = CatchUp(url, since, pace = paces.getOrPut(url) { RelayPace() }).also { it.add(boxes) }
                catchUps[url] = cu
                synchronized(cu) { cu.next(nowS()) }?.let { ws.send(it.text()) }
                if (!up) { up = true; onUp(true) } // the router then offers every stored packet
                changed()
            }
            override fun onMessage(ws: okhttp3.WebSocket, text: String) {
                if (!sockets.tracks(url, ws)) { ws.cancel(); return } // nothing from a socket this set doesn't track is handled
                Nostr.ok(text)?.let { ok ->
                    if (!ok.accepted) {
                        android.util.Log.w("GoDark", "relay $url refused an event: ${ok.reason.take(150)}")
                        if (Nostr.isThrottle(ok.reason)) resting[url] = System.currentTimeMillis() + REST_MS
                    }
                    outbox.answer(url, ok)?.let(onRelays) // "Sent" only once a relay took it
                    return
                }
                Nostr.end(text)?.let { e ->
                    val cu = catchUps[url] ?: return
                    synchronized(cu) { cu.end(e.subId, e.complete, nowS()) }?.let { ws.send(it.text()) } // older page or next mailbox
                    return
                }
                val cu = catchUps[url] ?: return // no catch-up, no share of the relay's limit: nothing is taken without being counted
                if (!synchronized(cu) { cu.allow(nowS()) }) return
                synchronized(cu) { cu.frame(text) } // every event of a catch-up page counts, also one that carries no packet or isn't taken
                val r = Nostr.received(text) ?: return
                // Only this link set's own mailboxes, or what its lookup asked for: a relay can't plant anything else here.
                if (!Nostr.takes(r.packet, mailboxes(), lookup)) return
                subjects.note(url, r)
                if (r.subId == live) synchronized(cu) { cu.live(Packet.mailbox(r.packet.id), r.createdAt, nowS()) }
                outbox.fromRelay(r)?.let(onRelays) // a copy the packet's recipients don't get isn't "on the relays"
                // Also answers to the #x lookups: the router ignores packets it already has. One that is new came from
                // the relays: it never goes back up, after a restart either.
                if (router()?.receive(NostrLink.PEER, r.packet) == true) fromRelays.add(r.packet)
            }
            override fun onClosed(ws: okhttp3.WebSocket, code: Int, reason: String) = lost(url, ws)
            override fun onFailure(ws: okhttp3.WebSocket, t: Throwable, r: okhttp3.Response?) = lost(url, ws)
    }

    private fun lost(url: String, ws: okhttp3.WebSocket) {
        if (!sockets.lost(url, ws)) return
        open.remove(url); catchUps.remove(url); subscribed.remove(url)
        if (open.isEmpty() && up) { up = false; onUp(false) }
        if (open.isEmpty() && throughTor == true) { throughTor = false; torWaitSince = System.currentTimeMillis(); h.post(::waitForTor) } // Tor lost its circuits? check again
        changed()
        if (!running) return
        val wait = ((backoff[url] ?: 2_500L) * 2).coerceAtMost(120_000L) // no internet: try again, less and less often
        backoff[url] = wait
        h.postDelayed({ connect(url) }, wait)
    }

    /**
     * Every tick: one own packet, else (every few ticks) one bridged packet no relay had, else pending reports. Only
     * to relays that aren't resting; with none, packets stay queued.
     */
    private fun pump() {
        if (!running) return
        ticks++
        outbox.expire() // posts no relay accepted in time go back in the queue
        val now = System.currentTimeMillis()
        val ready = open.filterKeys { (resting[it] ?: 0L) < now }
        if (ready.isNotEmpty()) {
            val next = outbox.next(bridged = ticks % BRIDGE_EVERY == 0)
            if (next != null) post(next.first, next.second, ready) else sendReports()
        }
        save()
        h.postDelayed(::pump, TICK_MS)
    }

    private fun post(p: Packet, fromOwn: Boolean, to: Map<String, okhttp3.WebSocket>) {
        val e = Nostr.event(p, secret, Nostr.blurred(nowS()))
        val msg = Nostr.publish(e)
        outbox.posted(e.getString("id"), p, fromOwn, to.filter { (_, ws) -> ws.send(msg) }.keys.toSet())
    }

    /** The sent list, the catch-up starts and what came from the relays, when they changed. */
    private fun save() {
        if (outbox.changed) prefs.edit().putString("relaySent$saved", outbox.sentList().joinToString(",")).apply()
        if (since.changed) prefs.edit().putString("relaySince$saved", since.save()).apply()
        if (fromRelays.changed) prefs.edit().putString(FromRelays.PREF, fromRelays.save()).apply()
    }

    /** Asks the relays which of the newest unchecked bridged packets they have; the rest get posted. Also ends stuck catch-ups. */
    private fun check() {
        if (!running) return
        h.postDelayed(::check, CHECK_MS)
        catchUpTimeouts()
        if (checking || open.isEmpty()) return
        val batch = outbox.toCheck(CHECK_BATCH)
        if (batch.isEmpty()) return
        checking = true
        val subId = Nostr.subId("have")
        lookup = batch.mapTo(HashSet()) { it.id } // answers to it are taken whatever their mailbox (Nostr.takes)
        val req = Nostr.have(subId, batch.map { it.id })
        open.values.forEach { it.send(req) }
        h.postDelayed({
            open.values.forEach { it.send(Nostr.close(subId)) }
            outbox.checked(batch).forEach(onRelays) // only copies with the same contents count (Nostr.digest), in an event the recipients get
            lookup = emptySet(); checking = false
        }, CHECK_WAIT_MS)
    }

    private fun catchUpTimeouts() {
        val now = nowS()
        for ((url, cu) in catchUps) {
            val ws = open[url] ?: continue
            val next = synchronized(cu) {
                val c = cu.current ?: return@synchronized null
                if (now - cu.sentAt < CATCH_UP_WAIT_S) return@synchronized null
                ws.send(Nostr.close(c.subId)); cu.end(c.subId, false, now)
            }
            next?.let { ws.send(it.text()) }
        }
    }

    private fun nowS() = System.currentTimeMillis() / 1000

    private fun sendReports() {
        val done = ArrayList<String>()
        for (id in NostrReports.pending(ctx)) {
            if (!subjects.knows(id)) continue // only messages that came from relays can be reported there
            val key = shown.getOrPut(id) { packetKey(id) ?: "" }
            // Named: an event that carried the very packet this phone shows, and that its author signed. Else the report waits.
            val subject = subjects.of(key) ?: continue
            val msg = Nostr.publish(Nostr.report(subject.eventId, subject.pubkey, secret))
            open.values.forEach { it.send(msg) }
            done += id
        }
        if (done.isNotEmpty()) NostrReports.sent(ctx, done)
    }

    fun statusLine(): String = when {
        !running -> "Internet: off"
        throughTor == false -> "Internet: waiting for Tor"
        else -> "Internet: $connected of $total relays" + if (throughTor == true) " through Tor" else ""
    }
}
