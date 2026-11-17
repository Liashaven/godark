package it.blackout.mesh

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * What a relay, or someone posting to a relay, could do to the phone (audit of 2026-11). Each of these failed before
 * its fix. The iPhone's RelayIntakeTests check the same, except the WebSocket ones (the iPhone uses URLSession, not
 * OkHttp). Dummy keys and packets only; where a relay is needed, it is a socket on 127.0.0.1.
 */
class RelayIntakeTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun key(label: String) = MessageDigest.getInstance("SHA-256").digest(label.toByteArray())
    private val poster = key("dummy poster"); private val second = key("dummy second poster")

    private fun frame(e: JSONObject) = JSONArray().put("EVENT").put("s").put(e).toString()
    private fun tagsOf(e: JSONObject): List<List<String>> = e.getJSONArray("tags").let { t ->
        (0 until t.length()).map { i -> t.getJSONArray(i).let { a -> (0 until a.length()).map(a::getString) } }
    }
    /** The event's id as NIP-01 computes it from the fields it has now. */
    private fun idOf(e: JSONObject) = Nostr.eventId(e.getString("pubkey"), e.getLong("created_at"), e.getInt("kind"), tagsOf(e), e.getString("content"))
    /** A correctly signed event of the app's kind with any tags: what anyone can post to a relay. */
    private fun signedEvent(p: Packet, secret: ByteArray, created: Long, tags: List<List<String>>): JSONObject {
        val e = JSONObject().put("pubkey", hex(Schnorr.publicKey(secret))).put("created_at", created).put("kind", Nostr.KIND)
            .put("tags", JSONArray(tags.map { JSONArray(it) })).put("content", Base64.getEncoder().encodeToString(p.encode()))
        val id = idOf(e)
        return e.put("id", id).put("sig", hex(Schnorr.sign(secret, unhex(id))))
    }

    // ---- A copy of a packet on the relays ends posting only if the packet's recipients get that copy ----

    private val nowMs = 1_800_000_000_000L; private val nowS = nowMs / 1000
    private val bridged = Packet("a8d00000000000c3", nowMs - 10 * 60_000L, 15, ByteArray(100) { 5 })
    private val box = listOf("t", "dp1-a8d0"); private val x = listOf("x", bridged.id)
    private fun keptFrom(created: Long) = listOf("expiration", (created + Nostr.KEEP_S).toString())

    /** Someone else's packet through the outbox as RelayScope does it, with [copy] as an answer to the #x lookup. True if this phone still posts it. */
    private fun stillPosted(copy: JSONObject?): Boolean {
        val o = RelayOutbox(now = { nowMs }, jitter = { 0L })
        o.offer(bridged, mine = false)
        val batch = o.toCheck(50)
        assertEquals(listOf(bridged.id), batch.map { it.id })
        val marked = copy?.let { o.fromRelay(Nostr.received(frame(it))!!) }
        val found = o.checked(batch)
        val still = marked == null && found.isEmpty() && !o.isSent(bridged.id) && o.next(bridged = true)?.first?.id == bridged.id
        if (!still) { o.offer(bridged, mine = false); assertEquals("counted as on the relays: never queued again", 0, o.queued()) }
        return still
    }

    @Test fun aCopyTheRecipientsDontGetDoesNotEndPosting() {
        assertTrue("control: no relay has it", stillPosted(null))
        assertFalse("control: the event the app posts ends posting", stillPosted(Nostr.event(bridged, poster, nowS)))
        assertFalse("control: dated as the app dates it", stillPosted(Nostr.event(bridged, poster, Nostr.blurred(nowS - 300))))
        assertFalse("control: without an expiration it is kept for good", stillPosted(signedEvent(bridged, poster, nowS, listOf(box, x))))

        assertTrue("only the x tag: no subscription returns it", stillPosted(signedEvent(bridged, poster, nowS, listOf(x))))
        assertTrue("another mailbox's tag", stillPosted(signedEvent(bridged, poster, nowS, listOf(listOf("t", "dp1-0794"), x, keptFrom(nowS)))))
        assertTrue("the tag without its prefix", stillPosted(signedEvent(bridged, poster, nowS, listOf(listOf("t", "a8d0"), x, keptFrom(nowS)))))
        assertTrue("gone in a minute", stillPosted(signedEvent(bridged, poster, nowS, listOf(box, x, listOf("expiration", (nowS + 60).toString())))))
        assertTrue("a second expiration, gone in a minute", stillPosted(signedEvent(bridged, poster, nowS, listOf(box, x, keptFrom(nowS), listOf("expiration", (nowS + 60).toString())))))
        assertTrue("an expiration that is no number", stillPosted(signedEvent(bridged, poster, nowS, listOf(box, x, listOf("expiration", "never")))))
        assertTrue("an expiration without a value", stillPosted(signedEvent(bridged, poster, nowS, listOf(box, x, listOf("expiration")))))
        val old = nowS - 6 * 24 * 3600
        assertTrue("dated days before the packet: a catch-up doesn't ask that far back", stillPosted(signedEvent(bridged, poster, old, listOf(box, x, keptFrom(old)))))
        val bad = signedEvent(bridged, poster, nowS, listOf(box, x)).put("tags", JSONArray().put(JSONArray(box)).put(JSONArray().put("x").put(7)))
        assertTrue("tags that aren't strings", stillPosted(bad))
    }

    @Test fun whatReachesTheRecipientsIsSaidForEachEvent() {
        assertTrue(Nostr.received(frame(Nostr.event(bridged, poster, nowS)))!!.reaches)
        assertFalse(Nostr.received(frame(signedEvent(bridged, poster, nowS, listOf(x))))!!.reaches)
        val edge = bridged.ts / 1000 - Nostr.SINCE_MARGIN_S
        assertTrue(Nostr.received(frame(Nostr.event(bridged, poster, edge)))!!.reaches)
        assertFalse(Nostr.received(frame(Nostr.event(bridged, poster, edge - 1)))!!.reaches)
        // A date at the end of time must not wrap around (or, on the iPhone, end the app).
        val last = signedEvent(bridged, poster, Long.MAX_VALUE, listOf(box, x, listOf("expiration", Long.MAX_VALUE.toString())))
        assertTrue(Nostr.received(frame(last))!!.reaches)
        assertFalse(Nostr.received(frame(signedEvent(bridged, poster, Long.MAX_VALUE, listOf(box, x, listOf("expiration", "5")))))!!.reaches)
    }

    @Test fun anEchoWithoutTheMailboxTagDoesNotMakeAnOwnMessageSent() {
        val o = RelayOutbox(now = { nowMs }, jitter = { 0L })
        val mine = Packet("a8d00000000000c4", nowMs - 1_000, 16, ByteArray(100) { 6 })
        o.offer(mine, mine = true)
        val (p, own) = o.next(bridged = false)!!
        o.posted("ev1", p, own, setOf("r1"))
        assertNull(o.fromRelay(Nostr.received(frame(signedEvent(mine, second, nowS, listOf(listOf("x", mine.id)))))!!))
        assertFalse(o.isSent(mine.id))
        assertEquals(mine.id, o.fromRelay(Nostr.received(frame(Nostr.event(mine, poster, nowS)))!!)) // the real one, as the live subscription returns it
        assertTrue(o.isSent(mine.id))
    }

    // ---- An event id and author are 32 bytes of hex each, never more ----

    private fun rawEvent(packetId: String, id: Any, pubkey: Any) = frame(JSONObject().put("id", id).put("pubkey", pubkey).put("created_at", 1).put("kind", Nostr.KIND)
        .put("tags", JSONArray()).put("content", Base64.getEncoder().encodeToString(Packet(packetId, nowMs, 16, ByteArray(98)).encode())))

    @Test fun anEventIdOrAuthorOfAnyOtherLengthOrFormIsRefused() {
        val id = "ab".repeat(32); val pub = "cd".repeat(32)
        val ok = Nostr.received(rawEvent("0000000000000001", id, pub))!!
        assertEquals(id, ok.eventId); assertEquals(pub, ok.pubkey)

        val long = "a".repeat(1_000_000)
        assertTrue("under the 1 MiB message limit: nothing before Nostr.received stops it", rawEvent("0000000000000002", long, "b").toByteArray().size < WsFrameGuard.MAX)
        assertNull("an id of 1,000,000 characters", Nostr.received(rawEvent("0000000000000002", long, pub)))
        assertNull("an author of 1,000,000 characters", Nostr.received(rawEvent("0000000000000003", id, long)))
        for (bad in listOf<Any>("", "a", "ab".repeat(31) + "a", "ab".repeat(32) + "a", "ab".repeat(64), "AB".repeat(32), "zz".repeat(32), "ab".repeat(31) + "a ", "ab".repeat(31) + "éé", 7, JSONArray())) {
            assertNull("id $bad", Nostr.received(rawEvent("0000000000000004", bad, pub)))
            assertNull("author $bad", Nostr.received(rawEvent("0000000000000005", id, bad)))
        }
    }

    // ---- A report names an event that really carried the reported packet and is really its author's ----

    private val now = 1_793_990_000L
    private val shown = Packet("9576000000000001", 1_793_990_000_000, 16, ByteArray(120) { 1 }) // the Public message the user reports

    @Test fun aReportNeverNamesAnEventOrAuthorTheRelayMadeUp() {
        val real = Nostr.event(shown, poster, now)
        // The frame of the audit: id and author replaced by the relay, signature left as it was.
        val forged = JSONObject(real.toString()).put("id", "a".repeat(64)).put("pubkey", "b".repeat(64))
        val r = Nostr.received(frame(forged))!! // still a packet for the router
        assertNull("its id is not the hash of its fields", r.subject)
        val s = ReportSubjects()
        s.note("wss://hostile", r)
        assertFalse(s.knows(shown.id)); assertNull(s.of(MeshRouter.key(shown)))

        // A relay can hash, but it can't sign for someone else: an account that has nothing to do with it as the author, under the right id.
        val uninvolved = JSONObject(real.toString()).put("pubkey", hex(Schnorr.publicKey(key("dummy uninvolved account"))))
        uninvolved.put("id", idOf(uninvolved))
        val u = Nostr.received(frame(uninvolved))!!
        assertNotNull(u.subject)
        s.note("wss://hostile", u)
        assertTrue(s.knows(shown.id))
        assertNull("not signed by the author it names: the report waits", s.of(MeshRouter.key(shown)))
        assertFalse("and that event is forgotten", s.knows(shown.id))

        // The made-up event first, the real one from another relay: the real one is named.
        s.note("wss://hostile", u); s.note("wss://honest", Nostr.received(frame(real))!!)
        val named = s.of(MeshRouter.key(shown))!!
        assertEquals(real.getString("id"), named.eventId); assertEquals(real.getString("pubkey"), named.pubkey)
        val report = Nostr.report(named.eventId, named.pubkey, key("dummy reporting phone"), now + 100)
        assertEquals("[[\"e\",\"${real.getString("id")}\",\"other\"],[\"p\",\"${real.getString("pubkey")}\"]]", report.getJSONArray("tags").toString())
    }

    @Test fun aSignatureThatIsNotOneGivesNoReportSubject() {
        val e = Nostr.event(shown, poster, now)
        for (sig in listOf<Any>("", "ab".repeat(63), "AB".repeat(64), "a".repeat(500_000), 7))
            assertNull("sig $sig", Nostr.received(frame(JSONObject(e.toString()).put("sig", sig)))!!.subject)
        assertNull("no signature", Nostr.received(frame(JSONObject(e.toString()).also { it.remove("sig") }))!!.subject)
        assertNotNull(Nostr.received(frame(e))!!.subject)
        assertFalse(Nostr.signed(Nostr.Subject(e.getString("id"), e.getString("pubkey"), "00".repeat(64))))
        assertFalse(Nostr.signed(Nostr.Subject("x", "y", "z")))
    }

    @Test fun anotherPacketUnderTheSameIdNeverStandsInForTheOneShown() {
        val first = Nostr.received(frame(Nostr.event(shown, poster, now)))!!
        val decoy = Packet(shown.id, shown.ts, 16, ByteArray(120) { 2 }) // anyone can post any packet under a packet id they have seen
        val later = Nostr.received(frame(Nostr.event(decoy, second, now)))!!
        assertEquals(first.packet.id, later.packet.id); assertNotEquals(first.eventId, later.eventId)
        for (order in listOf(listOf(first, later), listOf(later, first))) {
            val s = ReportSubjects()
            order.forEach { s.note("r1", it) }; order.forEach { s.note("r2", it) }
            assertEquals("whichever came last", first.eventId, s.of(MeshRouter.key(shown))!!.eventId)
            assertEquals(first.pubkey, s.of(MeshRouter.key(shown))!!.pubkey)
            assertEquals(later.eventId, s.of(MeshRouter.key(decoy))!!.eventId)
        }
        // The same packet posted again by someone else: the first event for it stays.
        val s = ReportSubjects()
        s.note("r1", first); s.note("r1", Nostr.received(frame(Nostr.event(shown, second, now + 1024)))!!)
        assertEquals(first.eventId, s.of(MeshRouter.key(shown))!!.eventId)
    }

    @Test fun onlyPublicPacketsAreKeptForReportsAndOnlySoMany() {
        assertNull("a group's packet", Nostr.received(frame(Nostr.event(bridged, poster, nowS)))!!.subject)
        val s = ReportSubjects(max = 3)
        val all = (1..4).map { i -> Packet("957600000000000$i", shown.ts, 16, ByteArray(120) { i.toByte() }) }
        all.forEach { p -> s.note("r1", Nostr.received(frame(Nostr.event(p, poster, now)))!!) }
        assertEquals(3, s.size())
        assertFalse("the oldest made room", s.knows(all[0].id)); assertNull(s.of(MeshRouter.key(all[0])))
        assertTrue(s.knows(all[3].id)); assertNotNull(s.of(MeshRouter.key(all[3])))
        // One relay gets one place per packet, whatever it sends.
        val one = ReportSubjects()
        repeat(20) { i -> one.note("r1", Nostr.received(frame(Nostr.event(shown, key("dummy $i"), now)))!!) }
        one.note("r2", Nostr.received(frame(Nostr.event(shown, poster, now)))!!)
        assertEquals(1, one.size()); assertEquals(hex(Schnorr.publicKey(key("dummy 0"))), one.of(MeshRouter.key(shown))!!.pubkey)
    }

    // ---- No WebSocket extension on a relay link: a compressed message would pass the 1 MiB limit ----

    private val upgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".toByteArray()
    private fun header(first: Int, len: Long): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(first)
        when {
            len < 126 -> b.write(len.toInt())
            len <= 0xFFFF -> { b.write(126); b.write((len shr 8).toInt() and 0xFF); b.write(len.toInt() and 0xFF) }
            else -> { b.write(127); for (k in 7 downTo 0) b.write((len shr (8 * k)).toInt() and 0xFF) }
        }
        return b.toByteArray()
    }
    private fun fails(g: WsFrameGuard, vararg parts: ByteArray) = try { parts.forEach { g.look(it, 0, it.size) }; false } catch (_: java.io.IOException) { true }

    @Test fun aFrameOfAnExtensionEndsTheLinkBeforeItIsRead() {
        // RSV1 (compressed) on a text, a binary and an unfinished frame; RSV2; RSV3; on a continuation; on a ping.
        for (first in listOf(0xC1, 0xC2, 0x41, 0xA1, 0x91, 0xC0, 0xC9))
            assertTrue("first byte %02x".format(first), fails(WsFrameGuard().also { it.look(upgrade, 0, upgrade.size) }, header(first, 5)))
        val g = WsFrameGuard(); g.look(upgrade, 0, upgrade.size)
        assertFalse(fails(g, header(0x01, 10), ByteArray(10), header(0x89, 2), ByteArray(2)))
        assertTrue("in the middle of a message too", fails(g, header(0xC0, 3)))
        val honest = WsFrameGuard(); honest.look(upgrade, 0, upgrade.size)
        assertFalse(fails(honest, header(0x81, 300), ByteArray(300), header(0x01, 70_000), ByteArray(70_000), header(0x8A, 0), header(0x80, 5), ByteArray(5)))
    }

    /** A permessage-deflate payload: raw DEFLATE with a sync flush, without the trailing 00 00 FF FF. */
    private fun deflated(plain: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val d = java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true)
        java.util.zip.DeflaterOutputStream(out, d, 8192, true).run { write(plain); flush() }
        val all = out.toByteArray(); d.end()
        return all.copyOf(all.size - 4)
    }

    private class Seen {
        @Volatile var opened = false; @Volatile var extensions: String? = null
        @Volatile var text = -1; @Volatile var failure: Throwable? = null
        val done = CountDownLatch(1)
    }

    /** One link to a relay on 127.0.0.1 that answers 101, with or without the extensions header, and then writes [frames]. */
    private fun link(client: OkHttpClient, withExtensions: Boolean, frames: ByteArray): Seen {
        val s = Seen()
        java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { server ->
            val relay = Thread {
                try {
                    server.accept().use { sock ->
                        sock.soTimeout = 8_000
                        val input = sock.getInputStream(); val head = StringBuilder()
                        while (!head.endsWith("\r\n\r\n")) { val c = input.read(); if (c < 0) return@use; head.append(c.toChar()) }
                        val key = head.lines().first { it.lowercase().startsWith("sec-websocket-key:") }.substringAfter(':').trim()
                        val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()))
                        val answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n" +
                            (if (withExtensions) "Sec-WebSocket-Extensions: permessage-deflate\r\n" else "") + "\r\n"
                        sock.getOutputStream().run { write(answer.toByteArray()); write(frames); flush() }
                        try { while (input.read() >= 0) { } } catch (_: java.io.IOException) { }
                    }
                } catch (_: java.io.IOException) { }
            }
            relay.isDaemon = true; relay.start()
            val ws = client.newWebSocket(Request.Builder().url("ws://127.0.0.1:${server.localPort}/").build(), object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) { s.extensions = response.header("Sec-WebSocket-Extensions"); s.opened = true }
                override fun onMessage(webSocket: WebSocket, text: String) { s.text = text.length; s.done.countDown() }
                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { if (s.failure == null && s.text < 0) s.failure = t; s.done.countDown() }
            })
            assertTrue("nothing happened on the link for 20 s", s.done.await(20, TimeUnit.SECONDS))
            ws.cancel()
            client.dispatcher.executorService.shutdown(); client.connectionPool.evictAll()
        }
        return s
    }

    /** The client as RelayScope builds it: the same one call. */
    private fun relayClient() = OkHttpClient.Builder().apply { WsLimit.apply(this, plain = true) }.build()
    private fun messages(t: Throwable?): List<String> = generateSequence(t) { it.cause }.take(5).map { it.message ?: "" }.toList()
    private val twiceTheLimit = 2 * WsFrameGuard.MAX.toInt()
    private val bomb by lazy { deflated(ByteArray(twiceTheLimit) { 'a'.code.toByte() }).let { header(0xC1, it.size.toLong()) + it } } // about 2 KB that inflate to 2 MiB

    @Test fun aRelayThatTurnsCompressionOnInItsAnswerLosesTheLink() {
        assertTrue("the frame itself is far under the limit", bomb.size < 4_096)
        val s = link(relayClient(), withExtensions = true, frames = bomb)
        assertEquals("no message is delivered, least of all one over the limit", -1, s.text)
        assertTrue("the guard ended the link: ${messages(s.failure)}", messages(s.failure).any { it == "relay frame uses an extension that was not agreed" })
    }

    @Test fun okHttpNeverLearnsOfAnExtensionTheRelayAnswersWith() {
        // Without the frame guard, so that only the interceptor stands between the answer and OkHttp's inflater.
        val alone = { OkHttpClient.Builder().addInterceptor(WsLimit.noExtensions).build() }
        val s = link(alone(), withExtensions = true, frames = bomb)
        assertEquals(-1, s.text); assertTrue(s.opened); assertNull("the answer as OkHttp sees it", s.extensions)
        assertTrue("OkHttp refused the compressed frame itself: ${messages(s.failure)}", s.failure is java.net.ProtocolException)
        val bad = byteArrayOf(-1, -1, -1, -1) // not DEFLATE at all: it must not even reach an inflater
        val t = link(alone(), withExtensions = true, frames = header(0xC1, bad.size.toLong()) + bad)
        assertEquals(-1, t.text); assertTrue(messages(t.failure).toString(), t.failure is java.net.ProtocolException)
    }

    @Test fun anHonestRelayStillGetsThrough() {
        val hello = "hello".toByteArray()
        val plain = link(relayClient(), withExtensions = false, frames = header(0x81, hello.size.toLong()) + hello)
        assertEquals(hello.size, plain.text); assertNull(plain.failure)
        // A relay that answers with the header but doesn't compress: the header is dropped and its messages still arrive.
        val named = link(relayClient(), withExtensions = true, frames = header(0x81, hello.size.toLong()) + hello)
        assertEquals(hello.size, named.text); assertNull(named.failure); assertNull(named.extensions)
    }
}
